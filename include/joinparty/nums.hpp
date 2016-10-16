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


#ifndef __NUMS_HPP
#define __NUMS_HPP

#include <bitcoin/bitcoin.hpp>

namespace joinparty
{

namespace nums
{

typedef const char* hex_nums;
typedef std::vector<hex_nums> hex_nums_list;

typedef std::vector<libbitcoin::ec_compressed> nums_list;

}; // namespace nums

class NUMS
{
  public:
    // computes all NUMS points and verifies them against a
    // pre-computed list
    NUMS();

    void get_NUMS(libbitcoin::ec_compressed& out, const uint8_t index = 0) const;

  private:
    const bool get_G(libbitcoin::ec_compressed& pub_key);
    void generate_NUMS(libbitcoin::ec_compressed& out, const uint8_t index = 0);

    joinparty::nums::nums_list computed_NUMS_;
    joinparty::nums::hex_nums_list precomputed_NUMS_;
};

}; // namespace joinparty

#endif // __NUMS_HPP
