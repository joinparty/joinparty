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

#ifndef __CONSTANTS_HPP
#define __CONSTANTS_HPP

#include "config.h"

namespace joinparty {

namespace constants {

const std::string joinparty_version = VERSION;

const std::string bitcoin_network = "mainnet";
constexpr uint32_t bip32_mainnet_public_version = 0x0488B21E;
constexpr uint32_t bip32_mainnet_private_version = 0x0488ADE4;

// Testnet currently unsupported
constexpr uint32_t bip32_testnet_public_version = 0x043587CF;
constexpr uint32_t bip32_testnet_private_version =  0x04358394;

} // namespace constants

} // namespace joinparty

#endif // __CONSTANTS_HPP
