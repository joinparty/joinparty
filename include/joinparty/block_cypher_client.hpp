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

#ifndef __BLOCK_CYPHER_HPP
#define __BLOCK_CYPHER_HPP

#include <iostream>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/bind.hpp>

using boost::asio::ip::tcp;

namespace joinparty {

class BlockCypherClient
{
  typedef std::vector<std::string> chunk_list;
  
  public:
    explicit BlockCypherClient(boost::asio::io_service& io_service,
        const std::string server, const std::string port);

    void get_fee_estimates(uint64_t& low_fee_per_kb,
        uint64_t& medium_fee_per_kb, uint64_t& high_fee_per_kb);

  private:
    void handle_error(const boost::system::error_code& err);

    void handle_signal();

    void handle_write_request(
        const boost::system::error_code& err);

    void handle_response(const boost::system::error_code& err);

    void process_data(
        const boost::system::error_code& err, const size_t target_length);

    uint64_t low_fee_per_kb_;
    uint64_t medium_fee_per_kb_;
    uint64_t high_fee_per_kb_;
    tcp::resolver resolver_;
    boost::asio::ssl::context ctx_;
    boost::asio::ssl::stream<tcp::socket> socket_;
    boost::asio::streambuf request_;
    boost::asio::streambuf response_;
    boost::asio::signal_set signals_;
    size_t content_buffer_length_;
    std::array<char, 1024> content_buffer_;
};
 
}; // namespace joinparty

#endif // __BLOCK_CYPHER_HPP
