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

#ifndef __ENCRYPTION_HPP
#define __ENCRYPTION_HPP

#include <sodium.h>
#include <bitcoin/bitcoin.hpp>

#include "utils.hpp"

namespace joinparty
{

namespace encryption
{
    typedef std::array<unsigned char, crypto_box_BEFORENMBYTES> EncSharedKey;
    typedef std::array<unsigned char, crypto_box_PUBLICKEYBYTES> EncPublicKey;
    typedef std::array<unsigned char, crypto_box_SECRETKEYBYTES> EncPrivateKey;
    typedef std::array<unsigned char, crypto_box_NONCEBYTES> Nonce;

    struct EncKeyPair
    {
        EncPublicKey pub_key;
        EncPrivateKey priv_key;
    };

    void generate_key_pair(EncKeyPair& key_pair);

    // given the specified private key and public key, generate a
    // shared key and populate the shared_key argument as an output
    void init_shared_key(
        EncPrivateKey& priv_key, EncPublicKey& pub_key,
        EncSharedKey& shared_key);

    // returns a base64 encoded string of the bitcoin signature of the
    // message using the specified private_key
    std::string get_encoded_signed_message(
        const libbitcoin::data_chunk& message,
        const libbitcoin::ec_secret& key);

    // converts the base64 encoded signature string into an ec_signature
    libbitcoin::ec_signature get_ec_signature(std::string encoded_signature);

    // verifies the message string given a base64 encoded string of
    // the bitcoin signature and using the specified public_key.
    // return true on successful verification
    bool verify_encoded_signed_message(
        const std::string message, const std::string encoded_signature,
        const libbitcoin::wallet::ec_public pub_key);

    // verifies the message chunk given a base64 encoded string of the
    // bitcoin signature and using the specified point.  returns true
    // on successful verification
    bool verify_encoded_signed_message(
        const libbitcoin::data_chunk message,
        const std::string encoded_signature,
        const libbitcoin::wallet::ec_public pub_key);

    // performs a joinmarket compatible encryption of the message and
    // returns a base64 encoded std::string suitable for network
    // transmission
    std::string encrypt_message(
        const std::string message, const EncSharedKey& shared_key);

    // performs a joinmarket compatible base64 decoding and decryption of the message and
    // returns a std::string of the plaintext message
    std::string decrypt_message(
        const std::string message, const EncSharedKey& shared_key);

}; // namespace encryption

}; // namespace joinparty


#endif // __ENCRYPTION_HPP
