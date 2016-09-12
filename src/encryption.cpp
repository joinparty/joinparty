/*
 * This file is part of joinparty, a joinmarket compatible taker
 * client built on libbitcoin.
 * 
 * Copyright (C) 2016 Joinparty (joinparty@sigaint.org)
 *
 * Joinparty is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * Joinparty is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Joinparty.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "bitcoin/bitcoin.hpp"
#include "joinparty/encryption.hpp"

namespace joinparty
{

namespace encryption
{

    void generate_key_pair(EncKeyPair& key_pair)
    {
        std::memset(key_pair.pub_key.data(), 0, key_pair.pub_key.size());
        std::memset(key_pair.priv_key.data(), 0, key_pair.priv_key.size());
        crypto_box_keypair(
            key_pair.pub_key.data(), key_pair.priv_key.data());
    }

    void init_shared_key(
        EncPrivateKey& priv_key, EncPublicKey& pub_key,
        EncSharedKey& shared_key)
    {
        std::memset(shared_key.data(), 0, shared_key.size());
        if (crypto_box_beforenm(shared_key.data(),
            pub_key.data(), priv_key.data()) == -1)
        {
            throw std::runtime_error(
                "Critical error: crypto_box_beforenm failed");
        }
    }

    std::string get_encoded_signed_message(
        const libbitcoin::data_chunk& message,
        const libbitcoin::ec_secret& key)
    {
        static constexpr auto compressed = false;

        if (message.size() < 1)
        {
            throw std::runtime_error(
                "Message length must be at least 1 character long");
        }

        libbitcoin::data_chunk non_terminated_message(
            message.begin(), message.begin() + message.size() - 1);

        // We need to be sure the message isn't null terminated if it
        // was converted from a string type
        const libbitcoin::data_chunk& message_ref =
            ((message[message.size() - 1] == '\0') ?
                non_terminated_message : message);

        libbitcoin::wallet::message_signature signature;
        if (!libbitcoin::wallet::sign_message(
                signature, message_ref, key, compressed))
        {
            throw std::runtime_error("Failed to sign message");
        }
        return libbitcoin::encode_base64(signature);
    }

    libbitcoin::ec_signature get_ec_signature(std::string encoded_signature)
    {
        static constexpr uint8_t component_length = 33;
        static constexpr uint8_t signature_header = 0x30;
        static constexpr size_t message_signature_length =
            sizeof(message_signature);
        static constexpr uint8_t signature_prefix = 0x00;
        static constexpr uint8_t signature_delimiter = 0x02;

        libbitcoin::data_chunk decoded_signature;
        decoded_signature.reserve(message_signature_length);
        libbitcoin::decode_base64(decoded_signature, encoded_signature);
        JP_ASSERT(decoded_signature.size() == message_signature_length);

        libbitcoin::data_chunk r(decoded_signature.begin() + 1,
            decoded_signature.begin() + component_length);
        libbitcoin::data_chunk s(
            decoded_signature.begin() + component_length,
            decoded_signature.end());

        // FIXME: This is skipping a step for low 's' checks, but
        // seems to work in practice(?)
        auto canonicalize = [=](libbitcoin::data_chunk& slice)
        {
            if (slice[0] > 127)
            {
                libbitcoin::data_chunk new_slice(
                    libbitcoin::to_chunk(signature_prefix));
                libbitcoin::extend_data(new_slice, slice);
                slice = new_slice;
            }
        };

        canonicalize(r);
        canonicalize(s);

        auto size_to_chunk = [](size_t size)
        {
            std::stringstream hex_stream;
            hex_stream << std::hex << size;
            libbitcoin::data_chunk size_chunk;
            libbitcoin::decode_base16(size_chunk, hex_stream.str());
            return size_chunk;
        };

        const auto r_size = size_to_chunk(r.size());
        const auto s_size = size_to_chunk(s.size());

        auto extend = [](libbitcoin::data_chunk& a, libbitcoin::data_chunk b)
        {
            libbitcoin::extend_data(a, b);
        };

        const uint8_t total_length = 2 + r.size() + 2 + s.size();

        auto legacy_signature = libbitcoin::to_chunk(signature_header);
        extend(legacy_signature, libbitcoin::to_chunk(total_length));
        extend(legacy_signature, libbitcoin::to_chunk(signature_delimiter));
        extend(legacy_signature, r_size);
        extend(legacy_signature, r);
        extend(legacy_signature, libbitcoin::to_chunk(signature_delimiter));
        extend(legacy_signature, s_size);
        extend(legacy_signature, s);

        libbitcoin::ec_signature converted_signature;
        parse_signature(converted_signature,
            static_cast<der_signature>(legacy_signature), true);

        return converted_signature;
    }
    
    bool verify_encoded_signed_message(
        const std::string message, const std::string encoded_signature,
        const libbitcoin::wallet::ec_public pub_key)
    {
        if (message.size() < 1)
        {
            throw std::runtime_error(
                "Message length must be at least 1 character long");
        }

        libbitcoin::data_chunk non_terminated_message(
            message.begin(), message.begin() + message.size() - 1);

        // We need to be sure the message isn't null terminated if it
        // was converted from a string type
        const libbitcoin::data_chunk& message_ref =
            ((message[message.size() - 1] == '\0') ?
                non_terminated_message : to_chunk(message));

        return verify_encoded_signed_message(message_ref,
            encoded_signature, pub_key);
    }

    bool verify_encoded_signed_message(
        const libbitcoin::data_chunk message,
        const std::string encoded_signature,
        const libbitcoin::wallet::ec_public pub_key)
    {
        const auto converted_signature = get_ec_signature(encoded_signature);
        const auto message_digest = libbitcoin::wallet::hash_message(message);

        return libbitcoin::verify_signature(
            pub_key.point(), message_digest, converted_signature);
    }

    std::string encrypt_message(
        const std::string message, const EncSharedKey& shared_key)
    {
        Nonce nonce;
        static constexpr size_t buf_length = 8192;
        std::array<unsigned char, buf_length> buf{};

        JP_ASSERT(message[message.size()] == '\0');
        const size_t message_len = message.size();
        const size_t padded_len = crypto_box_ZEROBYTES + message_len;
        const size_t encrypted_len = crypto_box_BOXZEROBYTES + message_len;
        const auto& message_ptr = reinterpret_cast<
            const unsigned char*>(message.c_str());

        const auto use_buf = (buf_length > encrypted_len);
        auto output = (
            use_buf ? buf.data() : (unsigned char*)malloc(encrypted_len));
        std::memset(output, 0, encrypted_len);

        libbitcoin::data_chunk padded;
        padded.reserve(padded_len);

        std::memset(padded.data(), 0, crypto_box_ZEROBYTES);
        std::memcpy(padded.data() + crypto_box_ZEROBYTES,
            message_ptr, message_len);

        randombytes_buf(nonce.data(), sizeof(nonce));

        crypto_box_afternm(
            output, padded.data(), padded_len, nonce.data(), shared_key.data());

        libbitcoin::data_chunk encrypted(nonce.begin(), nonce.end());
        libbitcoin::data_chunk out(
            output + crypto_box_BOXZEROBYTES, output + padded_len);
        libbitcoin::extend_data(encrypted, out);

        if (use_buf)
        {
            std::memset(buf.data(), 0, buf.size());
        }
        else
        {
            free(output);
        }
        return libbitcoin::encode_base64(encrypted);
    }

    std::string decrypt_message(
        const std::string message, const EncSharedKey& shared_key)
    {
        Nonce nonce;
        static constexpr size_t buf_length = 8192;
        std::array<unsigned char, buf_length> buf{};

        JP_ASSERT(message[message.size()] == '\0');
        const size_t message_len = message.size();

        libbitcoin::data_chunk decoded_message;
        libbitcoin::decode_base64(decoded_message, message);
        JP_ASSERT(decoded_message.size() > 0);

        const size_t padded_len = crypto_box_BOXZEROBYTES +
            decoded_message.size() - crypto_box_NONCEBYTES;
        const auto& message_ptr = reinterpret_cast<const unsigned char*>(
            decoded_message.data() + crypto_box_NONCEBYTES);
        std::memcpy(
            nonce.data(), decoded_message.data(), crypto_box_NONCEBYTES);

        const auto use_buf = (buf_length > padded_len);
        auto output = (
            use_buf ? buf.data() : (unsigned char*)malloc(padded_len));
        std::memset(output, 0, padded_len);

        libbitcoin::data_chunk padded;
        padded.reserve(padded_len);

        std::memset(padded.data(), 0, crypto_box_BOXZEROBYTES);
        std::memcpy(padded.data() + crypto_box_BOXZEROBYTES,
            message_ptr, padded_len - crypto_box_BOXZEROBYTES);

        if (crypto_box_open_afternm(output, padded.data(), padded_len,
            nonce.data(), shared_key.data()) == -1)
        {
            throw std::runtime_error(
                "Critical error: crypto_box_afternm failed");
        }

        const auto decrypted = std::string(
            reinterpret_cast<const char*>(output + crypto_box_ZEROBYTES));

        if (use_buf)
        {
            std::memset(buf.data(), 0, buf.size());
        }
        else
        {
            free(output);
        }
        return decrypted;
    }

}; // namespace encryption

}; // namespace joinparty
