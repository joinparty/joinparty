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

#ifndef __ORDER_MANAGER_HPP
#define __ORDER_MANAGER_HPP

#include <deque>
#include <string>
#include <vector>
#include <unordered_map>

#include "wallet.hpp"
#include "order_state.hpp"

namespace joinparty {

class OrderManager;
typedef std::shared_ptr<OrderManager> OrderManagerPtr;

typedef std::unordered_map<std::string, OrderList> OrderBook;

class OrderManager
{
  public:
    explicit OrderManager(
        uint64_t amount, const std::vector<std::string>& blacklist,
        const std::vector<std::string>& preferred) :
    amount_(amount), blacklist_(blacklist), preferred_(preferred)
    {
        order_states_.clear();
        eligible_orders_.clear();
    }

    Order get_order(const std::string& nick, const OrderID& order_id);

    void add_order(const Order& order);

    void add_order(const std::string& nick, const OrderType& order_type,
        const OrderID& order_id, const OrderSize& min_size,
        const OrderSize& max_size, const OrderFee& tx_fee,
        const OrderFee& cj_fee, const libbitcoin::wallet::ec_public& pub_key);

    void cancel_order(const std::string& nick, const OrderID& order_id);

    void clear_all_orders();

    const Order& get_next_eligible_order();

    void add_order_state(const OrderState& order_state);

    OrderStateList& get_order_states();

    OrderState& get_order_state(const std::string& nick);

    void clear_order_states();

    libbitcoin::chain::transaction* get_order_transaction()
    {
        return order_transaction_;
    }

    void set_order_transaction(
        libbitcoin::chain::transaction* order_tx)
    {
        order_transaction_ = order_tx;
    }

    // not an ideal abstraction.  wallet is only used for
    // get_transaction_info method on wallet by irc_client
    std::shared_ptr<Wallet> get_wallet() { return wallet_; }
    void set_wallet(std::shared_ptr<Wallet> wallet) { wallet_ = wallet; }

    friend std::ostream& operator<<(std::ostream& out, OrderManager& om);

    typedef std::function<bool(OrderState& order_state)> ConstructTxCallback;
    void register_construct_tx_cb(ConstructTxCallback cb) { tx_builder_ = cb; }
    bool construct_tx_cb(OrderState& order_state) { tx_builder_(order_state); }

    typedef std::function<bool(libbitcoin::chain::transaction* tx,
        OrderState* order_state)> BroadcastTxCallback;
    void register_broadcast_tx_cb(
        BroadcastTxCallback cb) { tx_broadcaster_ = cb; }
    bool broadcast_tx_cb(libbitcoin::chain::transaction* tx,
        OrderState* order_state) { tx_broadcaster_(tx, order_state); }

  private:
    uint64_t compute_fee(const Order& order);

    bool fee_sorter(const Order& order1, const Order& order2);

    void check_if_eligible_order(const Order& order);

    uint64_t amount_;
    OrderBook order_book_;
    std::deque<Order> eligible_orders_;
    OrderStateList order_states_;
    ConstructTxCallback tx_builder_;
    BroadcastTxCallback tx_broadcaster_;
    std::shared_ptr<Wallet> wallet_;
    const std::vector<std::string>& blacklist_;
    const std::vector<std::string>& preferred_;
    libbitcoin::chain::transaction* order_transaction_;
};

}; // namespace joinparty

#endif // __ORDER_MANAGER_HPP
