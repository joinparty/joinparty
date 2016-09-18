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

#ifndef __IRCCLIENT_HPP
#define __IRCCLIENT_HPP

#include <iostream>
#include <string>
#include <vector>
#include <functional>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/bind.hpp>

#include "order_manager.hpp"

using boost::asio::ip::tcp;

namespace joinparty {

class IrcClient
{
  typedef std::vector<std::string> chunk_list;
  
  public:
    explicit IrcClient(boost::asio::io_service& io_service,
        const std::string server, const std::string port,
        const std::string nick, const std::string channel,
        const OrderManagerPtr order_manager);

    // ***************** Begin Taker Callbacks ******************
    void fill_order(
        joinparty::OrderState& order_state, uint32_t cj_amount);

    void send_unsigned_transaction(joinparty::OrderStateList& order_states,
        libbitcoin::chain::transaction tx);

    void issue_read();

    void shutdown();

    void logout();
    // ***************** End Taker Callbacks ********************

  private:
    void handle_error(const boost::system::error_code& err);

    void handle_signal();

    void handle_connect(const boost::system::error_code& err,
        tcp::resolver::iterator endpoint_iterator);

    // handles a write request completion and issues an async read
    // unless suppress_read is false
    void handle_write_request(
        const boost::system::error_code& err, bool suppress_read);
    void handle_write_request(
        const boost::system::error_code& err, bool suppress_read,
        boost::asio::streambuf& request, boost::asio::streambuf& response);

    void write_command(std::string command, bool suppress_read);
    void write_command(std::string command, bool suppress_read,
        boost::asio::streambuf& request, boost::asio::streambuf& response);

    void write_chunked_message(std::string header, std::string command,
        std::string message, bool suppress_read,
        boost::asio::streambuf& request, boost::asio::streambuf& response);

    void delayed_write_next_chunk(
        const boost::system::error_code error, std::string header,
        std::string command, chunk_list chunks,
        size_t index, boost::asio::streambuf& request,
        boost::asio::streambuf& response);

    // *************** Begin IRC Command Handlers ***************
    bool handle_quit(const std::string& line, const chunk_list& chunks);

    bool handle_kick(const std::string& line, const chunk_list& chunks);

    bool handle_nick_in_use(const std::string& line, const chunk_list& chunks);

    bool handle_ping(const std::string& line, const chunk_list& chunks);

    bool handle_pong(const std::string& line, const chunk_list& chunks);

    bool handle_privmsg(
        const std::string& line, const chunk_list& chunks);

    bool handle_end_of_motd(const std::string& line, const chunk_list& chunks);

    bool handle_end_of_names_list(const std::string& line, const chunk_list& chunks);

    bool handle_topic(const std::string& line, const chunk_list& chunks);

    bool handle_network(const std::string& line, const chunk_list& chunks);
    // *************** End IRC Command Handlers ***************

    bool handle_orderbook_entries(
        const chunk_list& chunks, const std::string& from, bool is_public);

    bool handle_orderbook_request(
        const chunk_list& chunks, const std::string& from, bool is_public);

    bool handle_pubkey_handshake(
        const chunk_list& chunks, const std::string& from, bool is_public);

    bool handle_ioauth(
        const chunk_list& chunks, const std::string& from, bool is_public);

    bool handle_sig(
        const chunk_list& chunks, const std::string& from, bool is_public);

    bool handle_error(
        const chunk_list& chunks, const std::string& from, bool is_public);

    bool handle_chunks(
        const std::string& line, const chunk_list& chunks);

    void handle_response(const boost::system::error_code& err);
    void handle_response(const boost::system::error_code& err,
        boost::asio::streambuf& request, boost::asio::streambuf& response);

    bool read_pending_;
    std::string nick_;
    std::string channel_;
    std::string network_;
    std::string persisted_line_;
    tcp::resolver resolver_;
    boost::asio::ssl::context ctx_;
    boost::asio::ssl::stream<tcp::socket> socket_;
    boost::asio::streambuf request_;
    boost::asio::streambuf response_;
    boost::asio::signal_set signals_;
    OrderManagerPtr order_manager_;
    std::vector<std::shared_ptr<boost::asio::deadline_timer>> delay_timers_;
};

}; // namespace joinparty

#endif // __IRCCLIENT_HPP
