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

#ifndef __CONSTANTS_HPP
#define __CONSTANTS_HPP

#include "config.h"

namespace joinparty {

namespace constants {

const std::string joinparty_version = VERSION;

const std::string bitcoin_network = "mainnet";
static constexpr uint32_t bip32_mainnet_public_version = 0x0488B21E;
static constexpr uint32_t bip32_mainnet_private_version = 0x0488ADE4;

// Testnet currently unsupported
static constexpr uint32_t bip32_testnet_public_version = 0x043587CF;
static constexpr uint32_t bip32_testnet_private_version =  0x04358394;

static constexpr int64_t max_int64 = std::numeric_limits<int64_t>::max();
static constexpr uint64_t max_uint64 = std::numeric_limits<uint64_t>::max();

static constexpr size_t num_confirmations = 6;

static constexpr uint32_t unspent_index = std::numeric_limits<uint32_t>::max();

static constexpr size_t unspent_height = std::numeric_limits<size_t>::max();


} // namespace constants

} // namespace joinparty

#endif // __CONSTANTS_HPP
