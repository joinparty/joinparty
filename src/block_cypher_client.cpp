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

#include "joinparty/log.hpp"
#include "joinparty/block_cypher_client.hpp"

using boost::asio::ip::tcp;

namespace joinparty {

    BlockCypherClient::BlockCypherClient(boost::asio::io_service& io_service,
        const std::string server, const std::string port)
        : low_fee_per_kb_(0), medium_fee_per_kb_(0), high_fee_per_kb_(0),
        resolver_(io_service), ctx_(boost::asio::ssl::context::sslv23),
        socket_(io_service, ctx_), signals_(io_service, SIGINT, SIGTERM)
    {
        signals_.async_wait(
            boost::bind(&BlockCypherClient::handle_signal, this));

        std::ostream request_stream(&request_);
        request_stream << "GET /v1/btc/main HTTP/1.1\r\nHost: "
            << server << "\r\n\r\n";

        ctx_.set_default_verify_paths();

        tcp::resolver::query query{server, port};
        boost::asio::connect(socket_.lowest_layer(), resolver_.resolve(query));
        socket_.lowest_layer().set_option(tcp::no_delay(true));

        // for now we do not verify the peer's hostname in the cert
        socket_.set_verify_mode(boost::asio::ssl::verify_none);
        socket_.handshake(boost::asio::ssl::stream<tcp::socket>::client);

        boost::asio::async_write(socket_, request_,
            boost::bind(&BlockCypherClient::handle_write_request, this,
                boost::asio::placeholders::error));
    }

    void BlockCypherClient::get_fee_estimates(uint64_t& low_fee_per_kb,
        uint64_t& medium_fee_per_kb, uint64_t& high_fee_per_kb)
    {
        low_fee_per_kb = low_fee_per_kb_;
        medium_fee_per_kb = medium_fee_per_kb_;
        high_fee_per_kb = high_fee_per_kb_;
    }

    void BlockCypherClient::handle_error(const boost::system::error_code& err)
    {
        if (err && (err != boost::asio::error::operation_aborted))
        {
            throw std::runtime_error("Error: " + err.message());
        }
    }

    void BlockCypherClient::handle_signal()
    {
        socket_.lowest_layer().close();
        socket_.get_io_service().stop();
    }

    void BlockCypherClient::handle_write_request(
        const boost::system::error_code& err)
    {
        handle_error(err);

        boost::asio::async_read_until(socket_, response_, "\r\n",
            boost::bind(&BlockCypherClient::handle_response, this,
                boost::asio::placeholders::error));
    }

    void BlockCypherClient::handle_response(
        const boost::system::error_code& err)
    {
        handle_error(err);

        std::string line;
        std::istream response_stream(&response_);
        std::getline(response_stream, line);

        boost::algorithm::trim_if(line, boost::algorithm::is_any_of("\r\n"));

        static size_t target_length = 0;
        static constexpr size_t content_length_offset = 16;
        static const std::string content_length = "Content-Length: ";

        if (line.find(content_length) != std::string::npos)
        {
            content_buffer_length_ = 0;
            std::memset(content_buffer_.data(), 0, content_buffer_.size());

            target_length = strtoull(
                line.c_str() + content_length_offset, NULL, 10);
        }

        if (line.size() > 4)
        {
            boost::asio::async_read_until(socket_, response_, "\r\n",
                boost::bind(&BlockCypherClient::handle_response, this,
                    boost::asio::placeholders::error));
        }
        else
        {
            boost::asio::async_read(socket_, response_,
                boost::asio::transfer_at_least(1),
                    boost::bind(&BlockCypherClient::process_data, this,
                        boost::asio::placeholders::error, target_length));
        }
    }

    void BlockCypherClient::process_data(
        const boost::system::error_code& err, const size_t target_length)
    {
        handle_error(err);

        const auto ptr = content_buffer_.data() + content_buffer_length_;

        std::istream response_stream(&response_);
        content_buffer_length_ += response_stream.readsome(
            ptr, (target_length - content_buffer_length_));

        if (content_buffer_length_ == target_length)
        {
            socket_.lowest_layer().close();
            socket_.get_io_service().stop();

            std::vector<std::string> lines;
            boost::split(lines, content_buffer_, boost::is_any_of("\r\n"));

            for(const auto& line : lines)
            {
                if (line.find("low_fee_per_kb") != std::string::npos)
                {
                    std::vector<std::string> chunks;
                    boost::split(chunks, line, boost::is_any_of(":"));
                    low_fee_per_kb_ = strtoull(chunks[1].c_str(), NULL, 10);
                }
                else if (line.find("medium_fee_per_kb") != std::string::npos)
                {
                    std::vector<std::string> chunks;
                    boost::split(chunks, line, boost::is_any_of(":"));
                    medium_fee_per_kb_ = strtoull(chunks[1].c_str(), NULL, 10);
                }
                else if (line.find("high_fee_per_kb") != std::string::npos)
                {
                    std::vector<std::string> chunks;
                    boost::split(chunks, line, boost::is_any_of(":"));
                    high_fee_per_kb_ = strtoull(chunks[1].c_str(), NULL, 10);
                }
            }
        }
        else
        {
            boost::asio::async_read(socket_, response_,
                boost::asio::transfer_at_least(1),
                    boost::bind(&BlockCypherClient::process_data, this,
                        boost::asio::placeholders::error, target_length));
        }
    }

}; // namespace joinparty
