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

#ifndef __ORDER_STATE_HPP
#define __ORDER_STATE_HPP

#include <vector>

#include <boost/asio.hpp>

#include "order.hpp"
#include "wallet.hpp"
#include "encryption.hpp"


namespace joinparty {

// tracks the state of a fill in progress on a per maker basis
struct OrderState
{
    explicit OrderState(Order o, joinparty::Wallet::UnspentList& unspent,
        const joinparty::encryption::EncKeyPair& key_pair,
        const joinparty::encryption::NickInfo& ni, uint32_t ci, uint32_t ri) :
    order(o), nick_info(ni), taker_key_pair(key_pair), unspent_list(unspent),
        commitment_index(ci), nums_index(ri), maker_pub_key({}),
        ioauth_verified(false), signature_verified(false),
        request(new boost::asio::streambuf),
        response(new boost::asio::streambuf) {}

    Order order;

    // the following 5 fields are copies, and they're common across
    // all order_state objects for a particular coin join
    joinparty::encryption::NickInfo nick_info;
    joinparty::encryption::EncKeyPair taker_key_pair;
    joinparty::Wallet::UnspentList unspent_list;
    uint32_t commitment_index;
    uint8_t nums_index; // used as a retry index

    joinparty::encryption::EncPublicKey maker_pub_key;
    joinparty::encryption::EncSharedKey shared_key;

    // fields populated in fill order command
    joinparty::encryption::CommitmentList commitments;

    // fields populated from ioauth command
    libbitcoin::chain::output_point::list maker_utxo_list;
    libbitcoin::wallet::ec_public coin_join_pub_key;
    libbitcoin::wallet::payment_address maker_coin_join_address;
    libbitcoin::wallet::payment_address maker_change_address;
    bool ioauth_verified;

    // fields populated from the sig command
    bool signature_verified;

    // buffers used for reading/writing network requests related to
    // this order
    std::shared_ptr<boost::asio::streambuf> request;
    std::shared_ptr<boost::asio::streambuf> response;
};

typedef std::vector<OrderState> OrderStateList;

}; // namespace joinparty

#endif // __ORDER_STATE_HPP
