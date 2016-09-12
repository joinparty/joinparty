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

#ifndef __WALLET_UTILS_HPP
#define __WALLET_UTILS_HPP

#include <unordered_map>

#include <bitcoin/bitcoin.hpp>

namespace joinparty
{

namespace wallet_utils
{

typedef std::unordered_map<std::string, std::string> WalletMap;

// populates the wallet_map with default values
void initialize_wallet_map(WalletMap& wallet_map);

// parses the json data in the specified wallet_file and populates the
// wallet_map with the contents
void parse_wallet_file(std::string wallet_file, WalletMap& wallet_map);

// transforms the contents of the wallet_map into json data and writes
// the json to the specified wallet_file
void write_wallet_map_to_wallet_file(
    std::string wallet_file, WalletMap& wallet_map);

// increments the index cache in the wallet_map for the specified
// mix_level and for_change index by the increment size
void update_index_cache(WalletMap& wallet_map, uint32_t mix_depth,
                        uint32_t for_change, size_t increment);

// returns true on success and populates the provided wallet_map
bool initialize_wallet_from_mnemonic(
    libbitcoin::wallet::word_list& mnemonic,
    WalletMap& wallet_map, bool first_time);

// on success, returns true and populates the wallet_map
bool initialize_new_wallet(WalletMap& wallet_map);

// on success, returns true, populates the wallet_map, and writes the
// wallet to the specified file name
bool initialize_wallet(
    std::string wallet_file, WalletMap& wallet_map, bool create);

bool recover_wallet(std::string wallet_file);

// prompts a user for their password in order to return the
// unencrypted seed stored in the encrypted seed field inside the
// already initialized wallet_map
libbitcoin::long_hash get_user_wallet_seed(WalletMap& wallet_map);

}; // namespace joinparty

}; // namespace wallet_utils

#endif // __WALLET_UTILS__HPP
