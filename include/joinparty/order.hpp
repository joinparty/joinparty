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

#ifndef __ORDER_HPP
#define __ORDER_HPP

#include <vector>

#include "wallet.hpp"

namespace joinparty {

typedef uint16_t OrderID;
typedef int64_t OrderSize;
typedef double OrderFee;

constexpr auto null_order_id =  std::numeric_limits<uint16_t>::max();

enum class OrderType : uint8_t
{
    Absolute = 0,
    Relative = 1,
    Unknown = 255,
};

struct Order
{
    Order() {}
    Order(const std::string& nickname, const OrderType otype,
        const OrderID oid, const OrderSize min,
        const OrderSize max, const OrderFee tx, const OrderFee cj,
        const libbitcoin::wallet::ec_public& pub) :
    nick(nickname), order_type(otype),
        order_id(oid), min_size(min),
        max_size(max), tx_fee(tx), cj_fee(cj),
        nick_pub_key(pub) {}

    std::string nick;
    OrderType order_type = OrderType::Unknown;
    OrderID order_id = null_order_id;
    OrderSize min_size = 0;
    OrderSize max_size = 0;
    OrderFee tx_fee = 0;
    OrderFee cj_fee = 0;

    // used only for the nick signature
    libbitcoin::wallet::ec_public nick_pub_key;
};

typedef std::vector<Order> OrderList;

}; // namespace joinparty

#endif // __ORDER_HPP
