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

#include <algorithm>
#include <boost/bind.hpp>

#include "joinparty/log.hpp"
#include "joinparty/utils.hpp"
#include "joinparty/order_state.hpp"
#include "joinparty/order_manager.hpp"

extern joinparty::log::Log logger;

namespace joinparty
{

    Order OrderManager::get_order(
        const std::string& nick, const OrderID& order_id)
    {
        Order null_order{};
        const auto ob_iter = order_book_.find(nick);
        if (ob_iter != order_book_.end())
        {
            const auto& orders = ob_iter->second;
            for(auto& order : orders)
            {
                if (order.order_id == order_id)
                {
                    return order;
                }
            }
        }
        return null_order;
    }

    bool OrderManager::fee_sorter(const Order& order1, const Order& order2)
    {
        auto compute_fee = [&](const Order& order)
        {
            if (order.order_type == OrderType::Absolute)
            {
                return order.tx_fee + order.cj_fee;
            }
            else
            {
                return order.tx_fee + (amount_ * order.cj_fee);
            }
        };
        return (compute_fee(order1) < compute_fee(order2));
    }

    void OrderManager::check_if_eligible_order(const Order& order)
    {
        const auto blacklist_iter1 =
            std::find(blacklist_.begin(), blacklist_.end(), order.nick);
        const auto blacklist_iter2 =
            std::find(blacklist_.begin(), blacklist_.end(), order.nick + "_");

        if ((amount_ >= order.min_size) && (amount_ <= order.max_size) &&
            (order.tx_fee > 0) && (blacklist_iter1 == blacklist_.end()) &&
            (blacklist_iter2 == blacklist_.end()))
        {
            eligible_orders_.push_back(order);
            std::sort(eligible_orders_.begin(), eligible_orders_.end(),
                boost::bind(&OrderManager::fee_sorter, this, _1, _2));
        }
    }

    void OrderManager::add_order(const Order& order)
    {
        check_if_eligible_order(order);
        auto ob_iter = order_book_.find(order.nick);
        if (ob_iter == order_book_.end())
        {
            OrderList orders;
            orders.push_back(order);
            order_book_[order.nick] = orders;
            return;
        }

        ob_iter = order_book_.find(order.nick);
        JP_ASSERT(ob_iter != order_book_.end());
        auto& orders = ob_iter->second;

        // make sure no one has sent us duplicate orders
        for(auto& cur_order : orders)
        {
            if (cur_order.order_id == order.order_id)
            {
                logger.info("Error: Skipping duplicate order id",
                    order.order_id, "for", order.nick);
                return;
            }
        }

        orders.push_back(order);
    }

    void OrderManager::add_order(
        const std::string& nick, const OrderType& order_type,
        const OrderID& order_id, const OrderSize& min_size,
        const OrderSize& max_size, const OrderFee& tx_fee,
        const OrderFee& cj_fee)
    {
        const Order order(nick, order_type, order_id, min_size,
                          max_size, tx_fee, cj_fee);

        add_order(order);
    }

    void OrderManager::cancel_order(
        const std::string& nick, const OrderID& order_id)
    {
        const auto ob_iter = order_book_.find(nick);
        if (ob_iter != order_book_.end())
        {
            auto& orders = ob_iter->second;
            for(auto it = orders.begin(); it != orders.end(); it++)
            {
                if (it->order_id == order_id)
                {
                    orders.erase(it);
                    return;
                }
            }
        }
    }

    void OrderManager::clear_all_orders()
    {
        for(auto& orders : order_book_)
        {
            orders.second.clear();
        }

        order_book_.clear();
    }

    const Order& OrderManager::get_next_eligible_order()
    {
        if (eligible_orders_.size() == 0)
        {
            throw std::runtime_error(
                "Error: get_next_eligible_order has no available orders");
        }

        auto& order = eligible_orders_.front();
        eligible_orders_.pop_front();
        return order;
    }

    void OrderManager::add_order_state(const OrderState& order_state)
    {
        order_states_.push_back(order_state);
    }

    OrderStateList& OrderManager::get_order_states()
    {
        
        return order_states_;
    }

    void OrderManager::clear_order_states()
    {
        order_states_.clear();
    }

    std::ostream& operator<<(std::ostream& out, OrderManager& om)
    {
        out << "***** OrderManager *****" << std::endl;
        for(auto& entry : om.order_book_)
        {
            out << "Order state from " << entry.first << std::endl;
            for(auto& order : entry.second)
            {
                const auto type = ((order.order_type == OrderType::Absolute) ?
                                   "absolute" : "relative");
                out << type << " [" << order.order_id << "] = "
                    << (uint32_t)order.min_size << " "
                    << (uint32_t)order.max_size << " "
                    << (double)order.tx_fee << " "
                    << (double)order.cj_fee << " ["
                    << order.nick << "]" << std::endl;
            }
        }

        out << "***** Eligible Orders *****" << std::endl;
        for(auto& order : om.eligible_orders_)
        {
            const auto type = ((order.order_type == OrderType::Absolute) ?
                               "absolute" : "relative");
            out << type << " [" << order.order_id << "] = "
                << (uint32_t)order.min_size << " "
                << (uint32_t)order.max_size << " "
                << (double)order.tx_fee << " "
                << (double)order.cj_fee << std::endl;
        }
        out << "***** Eligible Orders *****" << std::endl;
        out << "***** OrderManager *****" << std::endl;
        return out;
    }

}; // namespace joinparty
