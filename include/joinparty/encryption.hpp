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
#include "wallet.hpp"

namespace joinparty
{

namespace encryption
{
    static constexpr size_t joinmarket_version = 5;
    static constexpr char joinmarket_nick_header = 'J';

    static constexpr size_t nick_hash_length = 10;
    static constexpr size_t nick_max_encoded = 14;
    static constexpr size_t num_random_bytes = 16;

    typedef std::array<unsigned char, crypto_box_BEFORENMBYTES> EncSharedKey;
    typedef std::array<unsigned char, crypto_box_PUBLICKEYBYTES> EncPublicKey;
    typedef std::array<unsigned char, crypto_box_SECRETKEYBYTES> EncPrivateKey;
    typedef std::array<unsigned char, crypto_box_NONCEBYTES> Nonce;

    struct EncKeyPair
    {
        EncPublicKey pub_key;
        EncPrivateKey priv_key;
    };

    struct NickInfo
    {
        std::string nick;
        libbitcoin::ec_compressed pub_key;
        libbitcoin::ec_secret priv_key;
    };

    struct Commitment
    {
        explicit Commitment(const joinparty::Wallet::Unspent& u) :
          unspent(u), used(false) {}

        bool used;
        const joinparty::Wallet::Unspent& unspent;
        libbitcoin::ec_compressed p;
        libbitcoin::ec_compressed p2;
        libbitcoin::ec_secret e;
        libbitcoin::ec_secret s;
        libbitcoin::hash_digest commitment;
        std::string serialized_revelation;
    };

    typedef std::vector<Commitment> CommitmentList;

    // used to generate a new cryptobox compatible key pair
    void generate_key_pair(EncKeyPair& key_pair);

    // used to generate new nick information (nick and keypair) for
    // use with nick signatures
    void generate_nick_key_pair(NickInfo& nick_info);

    // given the specified private key and public key, generate a
    // shared key and populate the shared_key argument as an output
    void init_shared_key(
        EncPrivateKey& priv_key, EncPublicKey& pub_key,
        EncSharedKey& shared_key);

    // verifies the nick name along using the public key used at
    // generation time
    bool verify_nick_name(
        const libbitcoin::wallet::ec_public& pub_key, const std::string& nick);

    // verifies the maker provided nick signature. return true if
    // verified
    bool verify_nick_signature(const libbitcoin::wallet::ec_public& pub_key,
        const std::string& nick, const std::string& nick_signature,
        const std::string& message, const std::string& network);

    // verifies the maker provided nick signature.  the indices
    // dictate which segments should be included in the message.
    // returns true if verified
    bool verify_nick_signature(const libbitcoin::wallet::ec_public& pub_key,
        const std::string& nick, const std::string& nick_signature,
        const std::vector<std::string>& chunks, const size_t start_index,
        const size_t end_index, const std::string& network);

    // creates a list of PoDLE commitments based on the utxos suitable
    // for use with Joinmarket v2.  The nums index can be used for
    // retry attempts, as it dictates which nums point to use for the
    // commitment computation.
    bool generate_podle(CommitmentList& out,
        const joinparty::Wallet::UnspentList& unspent,
        const uint64_t coin_join_amount, const size_t current_block_height,
        const size_t num_confirms, const uint32_t utxo_amount_percent,
        uint8_t nums_index = 0);

    // returns a base64 encoded string of the bitcoin signature of the
    // message using the specified private_key. the method of signing
    // differs if raw_signature is true (ecdsa_sign) vs false (bitcoin
    // message signature).
    std::string get_encoded_signed_message(
        const libbitcoin::data_chunk& message,
        const libbitcoin::ec_secret& key,
        const bool raw_signature = false);

    // converts the base64 encoded signature string into an
    // ec_signature
    libbitcoin::ec_signature get_ec_signature(std::string encoded_signature);

    // verifies the message string given a base64 encoded string of
    // the bitcoin signature and using the specified public_key.
    // returns true on successful verification.
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
