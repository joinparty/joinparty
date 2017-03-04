/*
 * This file is part of joinparty, a joinmarket compatible taker
 * client built on libbitcoin.
 * 
 * Copyright (C) 2016-2017 Joinparty (joinparty@protonmail.com)
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
#include "joinparty/nums.hpp"
#include "joinparty/log.hpp"

extern joinparty::log::Log logger;

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

    void generate_nick_key_pair(NickInfo& nick_info)
    {
        std::memset(nick_info.pub_key.data(), 0, nick_info.pub_key.size());
        std::memset(nick_info.priv_key.data(), 0, nick_info.priv_key.size());

        uint8_t* data = static_cast<uint8_t*>(nick_info.priv_key.data());
        joinparty::utils::generate_random_data(
            data, nick_info.priv_key.size() - 1);

        libbitcoin::secret_to_public(nick_info.pub_key, nick_info.priv_key);

        // convert public key to joinmarket compatible format for
        // hashing for use as a nickname
        const auto pub_key = libbitcoin::wallet::ec_public(nick_info.pub_key);
        const auto pkh_hash =
            libbitcoin::sha256_hash(to_chunk(pub_key.encoded()));
        const libbitcoin::data_chunk pkh_raw(
            &pkh_hash[0], &pkh_hash[nick_hash_length]);

        const auto nick_pkh = libbitcoin::encode_base58(pkh_raw);

        std::stringstream nick;
        nick << joinmarket_nick_header << joinmarket_version << nick_pkh;
        for(auto i = 0; i < nick_max_encoded - nick_pkh.size(); i++)
        {
            nick << "O";
        }

        nick_info.nick = nick.str();

        JP_ASSERT(verify_nick_name(nick_info.pub_key, nick_info.nick));
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

    bool verify_nick_name(
        const libbitcoin::wallet::ec_public& pub_key, const std::string& nick)
    {
        // check that counterparty nick matches the hash of the pubkey
        const auto pkh_hash =
            libbitcoin::sha256_hash(to_chunk(pub_key.encoded()));
        const libbitcoin::data_chunk pkh_raw(
            &pkh_hash[0], &pkh_hash[nick_hash_length]);

        // computed nick from the hash
        const auto nick_pkh = libbitcoin::encode_base58(pkh_raw);

        // parsed nick from the provided nickname, with trailing
        // padding stripped
        auto nick_stripped = nick.substr(2, nick_max_encoded);
        while(nick_stripped.rfind('O') != std::string::npos)
        {
            nick_stripped = nick_stripped.substr(0, nick_stripped.size() - 1);
        }

        const auto ret = ((nick.size() >= (2 + nick_max_encoded)) &&
            (nick_stripped == nick_pkh));
        if (!ret)
        {
            logger.debug("Failed to verify nick", nick, ", nick_stripped",
                nick_stripped, ", nick_pkh", nick_pkh);
        }
        return ret;
    }

    bool verify_nick_signature(const libbitcoin::wallet::ec_public& pub_key,
        const std::string& nick, const std::string& nick_signature,
        const std::string& message, const std::string& network)
    {
        return (joinparty::encryption::verify_encoded_signed_message(
                    message, nick_signature, pub_key) &&
                        verify_nick_name(pub_key, nick));
    }

    bool verify_nick_signature(const libbitcoin::wallet::ec_public& pub_key,
        const std::string& nick, const std::string& nick_signature,
        const std::vector<std::string>& chunks, const size_t start_index,
        const size_t end_index, const std::string& network)
    {
        std::stringstream message;
        for(auto i = start_index; i < end_index; i++)
        {
            message << chunks[i] << ((i != (end_index -1)) ? " " : "");
        }
        message << network;

        return verify_nick_signature(
            pub_key, nick, nick_signature, message.str(), network);
    }

    bool generate_podle(CommitmentList& out,
        const joinparty::Wallet::UnspentList& unspent,
        const uint64_t coin_join_amount, const size_t current_block_height,
        const size_t num_confirms, const uint32_t utxo_amount_percent,
        uint8_t nums_index)
    {
        static const NUMS nums;

        auto filter_by_age = [](
            const joinparty::Wallet::UnspentList& unspent,
            const uint64_t min_amount, const size_t current_block_height,
            const size_t num_confirms,
            joinparty::Wallet::UnspentList& filtered_unspent)
        {
            for(const auto& u : unspent)
            {
                const auto age = current_block_height - u.second.output_height;
                if ((age >= num_confirms) && (u.second.value >= min_amount))
                {
                    filtered_unspent.push_back(u);
                }
            }
        };

        auto gen_podle = [](Commitment& out, uint8_t nums_index)
        {
            libbitcoin::secret_to_public(out.p, out.unspent.first);

            libbitcoin::ec_secret k;
            libbitcoin::ec_compressed kG;

            uint8_t* data = static_cast<uint8_t*>(k.data());
            joinparty::utils::generate_random_data(
                data, libbitcoin::ec_secret_size);

            libbitcoin::secret_to_public(kG, k);

            libbitcoin::ec_compressed J;
            nums.get_NUMS(J, nums_index);

            libbitcoin::ec_compressed kJ = J;
            libbitcoin::ec_multiply(kJ, k);

            out.p2 = J;
            libbitcoin::ec_multiply(out.p2, out.unspent.first);

            out.commitment = libbitcoin::sha256_hash(out.p2);

            libbitcoin::data_chunk e_data = to_chunk(kG);
            libbitcoin::extend_data(e_data, to_chunk(kJ));
            libbitcoin::extend_data(e_data, to_chunk(out.p));
            libbitcoin::extend_data(e_data, to_chunk(out.p2));
            out.e = libbitcoin::sha256_hash(e_data);

            out.s = out.e;
            libbitcoin::ec_multiply(out.s, out.unspent.first);
            libbitcoin::ec_add(out.s, k);

            static const std::string separator = "|";

            auto utxo = out.unspent.second.output.hash();
            std::reverse(utxo.begin(), utxo.end());

            std::stringstream ss;
            ss << libbitcoin::encode_base16(utxo);
            ss << ":" << out.unspent.second.output.index();
            ss << separator << libbitcoin::encode_base16(out.p);
            ss << separator << libbitcoin::encode_base16(out.p2);
            ss << separator << libbitcoin::encode_base16(out.s);
            ss << separator << libbitcoin::encode_base16(out.e);

            out.serialized_revelation = ss.str();

            logger.debug("Generated commitment ", libbitcoin::encode_base16(
                out.commitment), "for nums index",
                    static_cast<uint32_t>(nums_index));
        };

        const uint64_t utxo_min_amount =
            (coin_join_amount * static_cast<float>(utxo_amount_percent / 100));

        joinparty::Wallet::UnspentList eligible_unspent;
        filter_by_age(unspent, utxo_min_amount, current_block_height,
            num_confirms, eligible_unspent);
        if (eligible_unspent.size() == 0)
        {
            throw std::runtime_error(
                "No eligible utxos can be found for the requested amount");
        }

        out.reserve(unspent.size());
        for(const auto& unspent : eligible_unspent)
        {
            out.emplace_back(unspent);
            auto& cur_commitment = out.back();
            gen_podle(cur_commitment, nums_index);
        }
    }

    std::string get_encoded_signed_message(
        const libbitcoin::data_chunk& message,
        const libbitcoin::ec_secret& key, const bool raw_signature)
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

        if (raw_signature)
        {
            const auto hashed_msg =
                libbitcoin::wallet::hash_message(message_ref);

            libbitcoin::ec_signature ecdsa_signature{};
            if (!libbitcoin::sign(ecdsa_signature, key, hashed_msg))
            {
                throw std::runtime_error("Failed to (raw) sign message");
            }

            libbitcoin::der_signature signature;
            libbitcoin::encode_signature(signature, ecdsa_signature);

            return libbitcoin::encode_base64(signature);
        }
        else
        {
            libbitcoin::wallet::message_signature signature{};
            if (!libbitcoin::wallet::sign_message(
                signature, message_ref, key, false))
            {
                throw std::runtime_error("Failed to sign message");
            }

            return libbitcoin::encode_base64(signature);
        }
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

        libbitcoin::ec_signature converted_signature;
        parse_signature(converted_signature,
            static_cast<der_signature>(to_chunk(decoded_signature)), true);

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
