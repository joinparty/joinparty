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

#ifndef __UTIL_HPP
#define __UTIL_HPP

#include <unistd.h>
#include <termios.h>

#include <vector>
#include <unordered_map>

#include <bitcoin/bitcoin.hpp>

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/random/mersenne_twister.hpp>

#include "constants.hpp"

using namespace libbitcoin;
using namespace libbitcoin::wallet;

#define JP_ASSERT BITCOIN_ASSERT

namespace joinparty
{

namespace utils
{

static constexpr size_t checksum_length = 4;

bool file_exists(std::string file);
void get_passphrase(std::string& passphrase);
void get_mnemonic_from_user_input(libbitcoin::wallet::word_list& words);

// converts data/types into a human readable bitcoin address
std::string bitcoin_address(const std::string hex_compressed);
std::string bitcoin_address(const libbitcoin::ec_secret& secret);
std::string bitcoin_address(const libbitcoin::ec_compressed& point);
std::string bitcoin_address(const libbitcoin::chain::script& script);

// returns a string representation of an output suitable for
// debugging/logging
std::string to_string(const libbitcoin::chain::output& output);

// returns a string representation of a transaction suitable for
// debugging/logging
std::string to_string(const libbitcoin::chain::transaction& tx);

// splits a message into a vector of strings each not exceeding
// max_chunk_length
void chunk_message(std::string message, size_t max_chunk_length,
    std::vector<std::string>& out_chunks);

data_chunk uncompressed_public_from_private(
    const libbitcoin::ec_secret& secret);
data_chunk compressed_public_from_private(
    const libbitcoin::ec_secret& secret);
data_chunk public_from_private(
    const libbitcoin::ec_secret& secret, const bool compress = true);

data_chunk generate_entropy(size_t num_bytes);

void get_passphrase_key(hash_digest& out_hash, const std::string& passphrase);

uint32_t get_random_number(uint32_t max);

std::string generate_random_nickname(const size_t length = 9);

void generate_random_data(uint8_t* data, const size_t data_len);

template<class T>
data_chunk get_checksum(T& data)
{
    data_chunk checksum(checksum_length);
    const auto hash = bitcoin_hash(bitcoin_hash(data));
    const auto hash_size = sizeof(hash);
    for(auto i = 0, j = 0; i < hash_size; i += (hash_size / checksum_length))
    {
        checksum[j++] = hash[i];
    }

    JP_ASSERT(checksum.size() == checksum_length);
    return checksum;
}

template<class T>
bool verify_checksum(data_chunk& checksum, T& data)
{
    JP_ASSERT(checksum.size() == checksum_length);

    data_chunk cur_checksum(checksum_length);
    const auto hash = bitcoin_hash(bitcoin_hash(data));
    const auto hash_size = sizeof(hash);
    for(auto i = 0, j = 0; i < hash_size; i += (hash_size / checksum_length))
    {
        cur_checksum[j++] = hash[i];
    }

    return ((cur_checksum.size() == checksum.size()) &&
            std::equal(checksum.begin(), checksum.end(), cur_checksum.begin()));
}

template<class T>
void encrypt_data(const libbitcoin::aes_secret& secret, T& data)
{
    const auto data_size = sizeof(data);
    if ((data_size % libbitcoin::aes256_block_size) != 0)
    {
        throw std::runtime_error("encrypt_data requires data size "
                                 "to be a multiple of 16");
    }

    if (sizeof(secret) != libbitcoin::aes256_key_size)
    {
        throw std::runtime_error("encrypt_data requires secret size "
                                 "to be 32");
    }

    const auto iterations = data_size / aes256_block_size;
    auto* start = reinterpret_cast<libbitcoin::aes_block*>(&data);

    for(auto i = 0; i < iterations; i++)
    {
        aes256_encrypt(secret, *start++);
    }
}

template<class T>
void decrypt_data(const libbitcoin::aes_secret& secret, T& data)
{
    const auto data_size = sizeof(data);
    if ((data_size % libbitcoin::aes256_block_size) != 0)
    {
        throw std::runtime_error("decrypt_data requires data size "
                                 "to be a multiple of 16");
    }

    if (sizeof(secret) != libbitcoin::aes256_key_size)
    {
        throw std::runtime_error("decrypt_data requires secret size "
                                 "to be 32");
    }

    const auto iterations = data_size / aes256_block_size;
    auto* start = reinterpret_cast<libbitcoin::aes_block*>(&data);

    for(auto i = 0; i < iterations; i++)
    {
        aes256_decrypt(secret, *start++);
    }
}

}; // namespace utils

}; // namespace joinparty

#endif // __UTIL_HPP
