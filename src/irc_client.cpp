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
#include "joinparty/irc_client.hpp"
#include "joinparty/order_state.hpp"

using boost::asio::ip::tcp;

extern joinparty::log::Log logger;

namespace joinparty {

    static constexpr size_t max_chunk_length = 400;
    static const std::string command_prefix = "!";
    static const std::string command_tx = command_prefix + "tx";
    static const std::string command_sig = command_prefix + "sig";
    static const std::string command_auth = command_prefix + "auth";
    static const std::string command_fill = command_prefix + "fill";
    static const std::string command_error = command_prefix + "error";
    static const std::string command_pubkey = command_prefix + "pubkey";
    static const std::string command_ioauth = command_prefix + "ioauth";
    static const std::string command_absorder = command_prefix + "absorder";
    static const std::string command_relorder = command_prefix + "relorder";
    static const std::string command_orderbook = command_prefix + "orderbook";

    IrcClient::IrcClient(
        boost::asio::io_service& io_service,
        const std::string server, const std::string port,
        const std::string nick, const std::string channel,
        const OrderManagerPtr order_manager)
        : read_pending_(false), nick_(nick), channel_(channel),
        resolver_(io_service), ctx_(boost::asio::ssl::context::sslv23),
        socket_(io_service, ctx_), signals_(io_service, SIGINT, SIGTERM),
        order_manager_(order_manager)
    {
        signals_.async_wait(
            boost::bind(&IrcClient::handle_signal, this));

        std::ostream request_stream(&request_);
        request_stream << "USER " << nick_ << " b c :" << nick_ << "\r\n";
        request_stream << "NICK " << nick_ << "\r\n";
        request_stream << "MODE " << nick_ << " +i\r\n";
        request_stream << "MODE " << nick_ << " +B\r\n";
        request_stream << "MODE " << nick_ << " -R\r\n";
        request_stream << "MODE " << nick_ << " +I\r\n";

        ctx_.set_default_verify_paths();

        tcp::resolver::query query{server, port};
        boost::asio::connect(socket_.lowest_layer(), resolver_.resolve(query));
        socket_.lowest_layer().set_option(tcp::no_delay(true));

        // for now we do not verify the peer's hostname in the cert
        socket_.set_verify_mode(boost::asio::ssl::verify_none);
        socket_.handshake(boost::asio::ssl::stream<tcp::socket>::client);

        boost::asio::async_write(socket_, request_,
            boost::bind(&IrcClient::handle_write_request, this,
                boost::asio::placeholders::error, false));
    }

    void IrcClient::handle_error(const boost::system::error_code& err)
    {
        if (err && (err != boost::asio::error::operation_aborted))
        {
            throw std::runtime_error("Error: " + err.message());
        }
    }

    void IrcClient::handle_signal()
    {
        write_command("QUIT", true);
        socket_.shutdown();
    }

    void IrcClient::handle_connect(
        const boost::system::error_code& err,
        tcp::resolver::iterator endpoint_iterator)
    {
        handle_error(err);

        boost::asio::async_write(socket_, request_,
            boost::bind(&IrcClient::handle_write_request, this,
                boost::asio::placeholders::error, false));
    }

    void IrcClient::handle_write_request(
        const boost::system::error_code& err, bool suppress_read)
    {
        handle_write_request(err, suppress_read, request_, response_);
    }

    void IrcClient::handle_write_request(const boost::system::error_code& err,
        bool suppress_read, boost::asio::streambuf& request,
            boost::asio::streambuf& response)
    {
        handle_error(err);

        if (!suppress_read && !read_pending_)
        {
            read_pending_ = true;
            boost::asio::async_read_until(socket_, response_, "\r\n",
                boost::bind(&IrcClient::handle_response, this,
                    boost::asio::placeholders::error, boost::ref(request),
                        boost::ref(response)));
        }
    }

    void IrcClient::write_command(std::string command, bool suppress_read)
    {
        write_command(command, suppress_read, request_, response_);
    }

    void IrcClient::write_command(std::string command, bool suppress_read,
        boost::asio::streambuf& request, boost::asio::streambuf& response)
    {
        std::ostream request_stream(&request);
        request_stream << command << "\r\n";

        logger.debug("Writing:", command);

        // if suppress_read is true, do not issue a read in the
        // handler because the connection is either expected to go
        // down, or a read will be issued outside of this mechanism
        boost::asio::async_write(socket_, request,
            boost::bind(&IrcClient::handle_write_request, this,
                boost::asio::placeholders::error, suppress_read,
                    boost::ref(request), boost::ref(response)));
    }

    void IrcClient::delayed_write_next_chunk(
        const boost::system::error_code error, std::string header,
        std::string command, chunk_list chunks,
        size_t index, boost::asio::streambuf& request,
        boost::asio::streambuf& response)
    {
        handle_error(error);

        auto do_write =
            [this, header, command, chunks, index, &request, &response](
                const boost::system::error_code error)
        {
            handle_error(error);

            const auto num_chunks = chunks.size();
            JP_ASSERT(index <= num_chunks);

            if (index == num_chunks)
            {
                // we're done now and just need to issue a read if
                // there's not one pending already
                logger.debug(
                    "write_next_chunk complete: waiting for response");

                if (!read_pending_)
                {
                    read_pending_ = true;
                    boost::asio::async_read_until(socket_, response, "\r\n",
                        boost::bind(&IrcClient::handle_response, this,
                            boost::asio::placeholders::error,
                                boost::ref(request), boost::ref(response)));
                }
                return;
            }
            const auto cur_chunk = chunks[index];
            const auto trailer = (index == (num_chunks - 1)) ? " ~" : " ;";

            std::stringstream ss;

            std::ostream request_stream(&request);
            if (index == 0)
            {
                request_stream << header << ":" << command << " ";
                ss << header << ":" << command << " ";
            }
            else
            {
                request_stream << header;
                ss << header;
            }
            request_stream << cur_chunk << trailer << "\r\n";
            ss << cur_chunk << trailer << "\r\n";

            logger.debug("Writing:", ss.str());

            boost::asio::async_write(socket_, request, boost::bind(
                &IrcClient::delayed_write_next_chunk, this,
                    boost::asio::placeholders::error, header, command, chunks,
                        index + 1, boost::ref(request), boost::ref(response)));
        };

        const auto timer = std::make_shared<boost::asio::deadline_timer>(
            socket_.get_io_service(), boost::posix_time::seconds(
                chunks.size() - index));
        delay_timers_.push_back(timer);

        timer->async_wait(do_write);
    }

    void IrcClient::write_chunked_message(std::string header,
        std::string command, std::string message, bool suppress_read,
        boost::asio::streambuf& request, boost::asio::streambuf& response)
    {
        if ((header.size() + message.size() + 2) < max_chunk_length)
        {
            std::stringstream ss;
            ss << header << command << " " << message << " ~";

            return write_command(ss.str(), suppress_read, request, response);
        }

        chunk_list chunks;
        size_t num_chunks = chunks.size();

        joinparty::utils::chunk_message(message, max_chunk_length, chunks);
        auto write_fn =
            [this, &request, &response, header, command, chunks, num_chunks]()
        {
            delayed_write_next_chunk(boost::system::error_code(), header,
                command, chunks, num_chunks, request, response);
        };
        socket_.get_io_service().post(write_fn);
    }

    // ***************** Begin Taker Callbacks ******************

    void IrcClient::fill_order(const joinparty::OrderState& order_state,
        const joinparty::encryption::EncPublicKey taker_pub_key,
        uint32_t cj_amount)
    {
        std::stringstream ss;
        ss << "privmsg " << order_state.order.nick << " :"
           << command_fill << " ";
        ss << order_state.order.order_id << " " << cj_amount << " ";
        ss << libbitcoin::encode_base16(taker_pub_key) << " ~";

        logger.info(">>", ss.str());

        // suppress the read here since we should already have an
        // outstanding async_read pending
        write_command(ss.str(), read_pending_, *order_state.request.get(),
            *order_state.response.get());
    }

    void IrcClient::send_unsigned_transaction(
        joinparty::OrderStateList& order_states,
        libbitcoin::chain::transaction tx)
    {
        const auto num_order_states = order_states.size();
        for(auto i = 0; i < num_order_states; i++)
        {
            const auto& order_state = order_states[i];
            const auto encrypted_message =
                joinparty::encryption::encrypt_message(
                    libbitcoin::encode_base64(tx.to_data()),
                        order_state.shared_key);

            const auto header = "PRIVMSG " + order_state.order.nick + " ";
            auto write_fn = [&order_state, this, i, header,
                num_order_states, encrypted_message](
                    const boost::system::error_code error)
            {
                write_chunked_message(header, command_tx, encrypted_message,
                    (i != (num_order_states - 1)), *order_state.request.get(),
                        *order_state.response.get());
            };

            auto timer = std::make_shared<boost::asio::deadline_timer>(
                socket_.get_io_service(), boost::posix_time::seconds(i));
            delay_timers_.push_back(timer);

            timer->async_wait(write_fn);
        }
    }

    // ***************** End Taker Callbacks ********************

    // *************** Begin IRC Command Handlers ***************
    bool IrcClient::handle_quit(
        const std::string& line, const chunk_list& chunks)
    {
        if ((chunks[1] == "QUIT") && (chunks[0] == nick_))
        {
            throw std::runtime_error("Our nick has quit");
        }

        return false;
    }

    bool IrcClient::handle_kick(
        const std::string& line, const chunk_list& chunks)
    {
        if (chunks[3] == nick_)
        {
            throw std::runtime_error(
                "We have been kicked from the irc channel");
        }

        return false;
    }

    bool IrcClient::handle_nick_in_use(
        const std::string& line, const chunk_list& chunks)
    {
        throw std::runtime_error("Our nick is currently in use");
        return false;
    }

    bool IrcClient::handle_ping(
        const std::string& line, const chunk_list& chunks)
    {
        std::string tmp_line = line;
        const auto response = tmp_line.replace(
            tmp_line.begin(), tmp_line.begin() + 4, "PONG");
        write_command(response, false);
        return false;
    }

    bool IrcClient::handle_pong(
        const std::string& line, const chunk_list& chunks)
    {
        logger.debug("Received Pong:", line);
        return true;
    }

    bool IrcClient::handle_privmsg(
        const std::string& line, const chunk_list& chunks)
    {
        if (chunks.size() < 4)
        {
            logger.debug("Skipping privmsg:", line);
            return true;
        }

        const auto end_pos = chunks[0].find("!");
        if (end_pos == std::string::npos)
        {
            logger.debug("Skipping privmsg w/o valid command:", line);
            return true;
        }

        const auto from = chunks[0].substr(1, end_pos -1);
        const auto is_public = (chunks[2] == nick_) ? false : true;

        const auto msg_type = chunks[3].substr(1, chunks[3].size());
        if (!is_public &&
            ((msg_type == command_absorder) || (msg_type == command_relorder)))
        {
            return handle_orderbook_entries(chunks, from, is_public);
        }

        if (msg_type == command_orderbook)
        {
            return handle_orderbook_request(chunks, from, is_public);
        }

        logger.debug("Received Privmsg from", from, ":", line);
        if (msg_type == command_pubkey)
        {
            return handle_pubkey_handshake(chunks, from, is_public);
        }

        if (msg_type == command_ioauth)
        {
            return handle_ioauth(chunks, from, is_public);
        }

        if (msg_type == command_sig)
        {
            return handle_sig(chunks, from, is_public);
        }

        if (msg_type == command_error)
        {
            return handle_error(chunks, from, is_public);
        }

        logger.debug("Received message from", from, "Public? ", is_public);
        for(auto i = 0; i < chunks.size(); i++)
        {
            logger.debug("Privmsg chunk[", i, "]: ", chunks[i]);
        }
        return true;
    }

    bool IrcClient::handle_end_of_motd(
        const std::string& line, const chunk_list& chunks)
    {
        write_command("JOIN " + channel_, false);
        return false;
    }

    bool IrcClient::handle_end_of_names_list(
        const std::string& line, const chunk_list& chunks)
    {
        logger.info("Connected to IRC and joined channel");

        // send !orderbook
        write_command("privmsg " + channel_ + " " + command_orderbook, false);
        return false;
    }

    bool IrcClient::handle_topic(
        const std::string& line, const chunk_list& chunks)
    {
        logger.debug("Topic changed:", line);
        return true;
    }

    // *************** End IRC Command Handlers ***************

    bool IrcClient::handle_orderbook_entries(
        const chunk_list& chunks, const std::string& from, bool is_public)
    {
        constexpr auto chunk_start_index = 3;
        constexpr auto order_segment_count = 6;

        if (is_public)
        {
            logger.debug(
                "ERROR: Failed to receive private response to "
                "orderbook inquiry from", from);
            return true;
        }

        // make a pass, flattening out all tokens and making them
        // easier to parse since we now know exactly the format they
        // should be in
        std::stringstream order_stream;
        for(auto i = chunk_start_index; i < chunks.size(); i++)
        {
            chunk_list tokens;
            boost::split(tokens, chunks[i], boost::is_any_of(":!"));

            for(auto j = 0; j < tokens.size(); j++)
            {
                boost::algorithm::trim_if(
                    tokens[j], boost::algorithm::is_any_of(" "));

                if ((tokens[j] == ":") || (tokens[j] == "~"))
                {
                    continue;
                }

                order_stream << tokens[j] << " ";
            }
        }

        auto orders = order_stream.str();
        boost::algorithm::trim_if(
            orders, boost::algorithm::is_any_of(" "));

        // now we can split the flattened orders into pieces that
        // should be divisble by 6 in count
        chunk_list tokens;
        boost::split(tokens, orders, boost::is_any_of(" "));
        if ((tokens.size() % order_segment_count) != 0)
        {
            logger.debug(
                "Orderbook response in unexpected format -- skipping");
            return true;
        }

        for(auto i = 0; i < tokens.size(); i += order_segment_count)
        {
            OrderType order_type;
            if (tokens[i] == "absorder")
            {
                order_type = OrderType::Absolute;
            }
            else if (tokens[i] == "relorder")
            {
                order_type = OrderType::Relative;
            }
            else
            {
                logger.debug(
                    "Error: Unknown order type:", tokens[i], " ... skipping");
                return true;
            }

            const OrderID order_id = std::atol(tokens[i+1].c_str());
            const OrderSize min_size = std::atoll(tokens[i+2].c_str());
            const OrderSize max_size = std::atoll(tokens[i+3].c_str());
            const OrderFee tx_fee = std::atof(tokens[i+4].c_str());
            const OrderFee cj_fee = std::atof(tokens[i+5].c_str());

            order_manager_->add_order(
                from, order_type, order_id, min_size, max_size, tx_fee, cj_fee);
        }
        return true;
    }

    bool IrcClient::handle_orderbook_request(
        const chunk_list& chunks, const std::string& from, bool is_public)
    {
        logger.debug(
            "*** Ignoring orderbook request since we're not making");
        return true;
    }

    bool IrcClient::handle_pubkey_handshake(
        const chunk_list& chunks, const std::string& from, bool is_public)
    {
        const auto& pub_key_str = chunks[4];

        auto start_encryption = [this, from, pub_key_str](OrderState& order_state)
        {
            joinparty::encryption::init_shared_key(
                order_state.taker_key_pair.priv_key, order_state.maker_pub_key,
                order_state.shared_key);

            // use the first available utxo's key for btc signing
            JP_ASSERT(order_state.unspent_list.size() > 0);
            const auto& key = order_state.unspent_list.front().first;
            const auto btc_pub_key = joinparty::utils::public_from_private(key);

            const auto taker_pub_key = libbitcoin::encode_base16(
                order_state.taker_key_pair.pub_key);
            const auto btc_signature =
                joinparty::encryption::get_encoded_signed_message(
                    to_chunk(taker_pub_key), key);

            std::stringstream inner_ss;
            inner_ss << libbitcoin::encode_base16(btc_pub_key)
                << " " << btc_signature;

            const auto encrypted_message =
                joinparty::encryption::encrypt_message(
                    inner_ss.str(), order_state.shared_key);

            std::stringstream ss;
            ss << "PRIVMSG " << order_state.order.nick << " :";
            ss << command_auth << " " << encrypted_message << " ~";

            // suppress the read issued from the write, but return
            // true so the caller will issue a new read for us
            write_command(ss.str(), true, *order_state.request.get(),
                *order_state.response.get());
            return true;
        };

        auto& order_states = order_manager_->get_order_states();
        for(auto& order_state : order_states)
        {
            if ((order_state.order.nick == from) &&
                (libbitcoin::decode_base16(
                    order_state.maker_pub_key, pub_key_str)))
            {
                logger.info("*** Matched Maker Pubkey",
                    libbitcoin::encode_base16(order_state.maker_pub_key),
                        "from:", from);

                return start_encryption(order_state);
            }
        }
        return true;
    }

    bool IrcClient::handle_ioauth(
        const chunk_list& chunks, const std::string& from, bool is_public)
    {
        const auto& encrypted = chunks[4];
        logger.debug(
            "*** Handling encrypted ioauth from", from, ":", encrypted);

        joinparty::OrderState* order_state_ptr = nullptr;
        auto& order_states = order_manager_->get_order_states();
        for(auto& cur_order_state : order_states)
        {
            if (cur_order_state.order.nick == from)
            {
                order_state_ptr = &cur_order_state;
                break;
            }
        }

        if (!order_state_ptr)
        {
            throw std::runtime_error("Corrupt order state for user " + from);
        }
        auto& order_state = *order_state_ptr;

        // auth the counterparty
        // !ioauth <utxo list> <coinjoin pubkey> <change address>
        // <btc sig of maker encryption pubkey using coinjoin pubkey>
        const auto decrypted = joinparty::encryption::decrypt_message(
            encrypted, order_state.shared_key);
        logger.info("***", order_state.order.nick,
            ": Handling ioauth decrypted:", decrypted);

        chunk_list fields;
        boost::split(fields, decrypted, boost::is_any_of(" "));

        if (fields.size() != 4)
        {
            throw std::runtime_error("Ioauth response from maker " +
                                     from + " is not properly formatted");
        }

        chunk_list utxo_list;
        boost::split(utxo_list, fields[0], boost::is_any_of(","));

        const size_t utxo_count = utxo_list.size();
        order_state.maker_utxo_list.reserve(utxo_count);
        for(auto i = 0; i < utxo_count; i++)
        {
            // Each utxo has a point and an index, delimited by a colon
            chunk_list utxo_parts;
            boost::split(utxo_parts, utxo_list[i], boost::is_any_of(":"));
            if (utxo_parts.size() != 2)
            {
                throw std::runtime_error(
                    "A utxo in the list is malformatted or invalid");
            }

            order_state.maker_utxo_list.push_back(
                libbitcoin::chain::output_point{
                    libbitcoin::config::hash256(utxo_parts[0]),
                        static_cast<uint32_t>(
                            std::strtoul(utxo_parts[1].c_str(), NULL, 0))});
        }

        order_state.coin_join_pub_key =
            libbitcoin::wallet::ec_public(fields[1]);
        order_state.maker_change_address =
            libbitcoin::wallet::payment_address(fields[2]);

        const auto btc_signature = fields[3];
        const auto maker_pub_key =
            libbitcoin::encode_base16(order_state.maker_pub_key);

        if (!joinparty::encryption::verify_encoded_signed_message(
                maker_pub_key, btc_signature,
                order_state.coin_join_pub_key.point()))
        {
            throw std::runtime_error(
                "Signature verification failed for maker " + from);
        }

        logger.info("***", order_state.order.nick, ": Maker's ioauth is valid");
        order_state.ioauth_verified = true;

        // call the previously registered construct tx callback method
        auto construct_tx = [&]()
        {
            order_manager_->construct_tx_cb(order_state);
        };

        socket_.get_io_service().post(construct_tx);

        // suppress a read after this since we'll manually issue one
        // after the tx is written out
        return false;
    }

    bool IrcClient::handle_sig(
        const chunk_list& chunks, const std::string& from, bool is_public)
    {
        const auto& encrypted = chunks[4];
        logger.debug("***", from, ": Handling sig encrypted:", encrypted);

        joinparty::OrderState* order_state_ptr = nullptr;
        auto& order_states = order_manager_->get_order_states();
        for(auto& cur_order_state : order_states)
        {
            if (cur_order_state.order.nick == from)
            {
                order_state_ptr = &cur_order_state;
                break;
            }
        }

        if (!order_state_ptr)
        {
            throw std::runtime_error("Corrupt order state for user " + from);
        }
        auto& order_state = *order_state_ptr;

        // verify the signature from the maker 
        // !sig <signature>
        const auto b64_sig = joinparty::encryption::decrypt_message(
            encrypted, order_state.shared_key);
        logger.info("***", order_state.order.nick,
            ": Handling sig decrypted:", b64_sig);

        libbitcoin::data_chunk raw_data;
        libbitcoin::decode_base64(raw_data, b64_sig);

        libbitcoin::chain::script script_signature;
        script_signature.from_data(
            raw_data, false, libbitcoin::chain::script::parse_mode::strict);

        const auto wallet = order_manager_->get_wallet();
        if (wallet == nullptr)
        {
            throw std::runtime_error(
                "Wallet has not been set in the order_manager class!");
        }

        const auto maker_pub_key = libbitcoin::to_chunk(order_state.maker_pub_key);
        auto& tx = *order_manager_->get_order_transaction();
        for(auto& utxo : order_state.maker_utxo_list)
        {
            libbitcoin::chain::transaction output_tx;
            wallet->get_transaction_info(utxo.hash, output_tx);
            const auto& previous_output_script =
                output_tx.outputs[utxo.index].script;

            // set signed script on the input, but first find the
            // input's index in the tx we're building
            uint32_t input_index = std::numeric_limits<uint32_t>::max();
            for(uint32_t i = 0; i < tx.inputs.size(); i++)
            {
                if (tx.inputs[i].previous_output == utxo)
                {
                    input_index = i;
                    break;
                }
            }

            if (input_index == std::numeric_limits<uint32_t>::max())
            {
                throw std::runtime_error(
                    "Cannot find input that matches the provided signature!");
            }
            tx.inputs[input_index].script = script_signature;

            // validate input
            if (!libbitcoin::chain::script::verify(script_signature,
                previous_output_script, tx, input_index, 0xFFFFFF))
            {
                throw std::runtime_error("Maker signature is invalid");
            }
        }

        logger.info("***", order_state.order.nick, ": Maker's sig is valid");
        order_state.signature_verified = true;

        // call the previously registered finalize tx callback method
        // to set the signature on each of the inputs in the tx until
        // all are collected before being broadcast
        auto broadcast_tx = [&]()
        {
            // sign our inputs here
            order_manager_->broadcast_tx_cb(
                order_manager_->get_order_transaction(), order_state_ptr);
        };

        socket_.get_io_service().post(broadcast_tx);

        // suppress a read after this since we'll manually issue one
        // if needed
        return false;
    }

    bool IrcClient::handle_error(
        const chunk_list& chunks, const std::string& from, bool is_public)
    {
        logger.info("*** Received Error message");
        for(const auto& chunk : chunks)
        {
            logger.info("Chunk: ", chunk);
        }

        write_command("QUIT", true);
        shutdown();
        return false;
    }

    bool IrcClient::handle_chunks(
        const std::string& line, const chunk_list& chunks)
    {
        auto issue_read = true;
        static const std::unordered_map<std::string,
            std::function<bool(
                const std::string& line, const chunk_list& chunks)>>
            chunk_handler_map =
        {
            { "PONG", [this](const std::string& line, const chunk_list& chunks)
              { return handle_pong(line, chunks); } },
            { "TOPIC", [this](const std::string& line, const chunk_list& chunks)
              { return handle_topic(line, chunks); } },
            { "KICK", [this](const std::string& line, const chunk_list& chunks)
              { return handle_kick(line, chunks); } },
            { "QUIT", [this](const std::string& line, const chunk_list& chunks)
              { return handle_quit(line, chunks); } },
            { "PRIVMSG", [this](const std::string& line, const chunk_list& chunks)
              { return handle_privmsg(line, chunks); } },
            { "332", [this](const std::string& line, const chunk_list& chunks)
              { return handle_topic(line, chunks); } },
            { "366", [this](const std::string& line, const chunk_list& chunks)
              { return handle_end_of_names_list(line, chunks); } },
            { "376", [this](const std::string& line, const chunk_list& chunks)
              { return handle_end_of_motd(line, chunks); } },
            { "433", [this](const std::string& line, const chunk_list& chunks)
              { return handle_nick_in_use(line, chunks); } }
        };

        if (chunks.size() < 2)
        {
            logger.debug(line);
            return issue_read;
        }

        const auto command = boost::algorithm::to_upper_copy(chunks[1]);
        auto handler = chunk_handler_map.find(command);
        if (handler != chunk_handler_map.end())
        {
            // if the handler writes anything, it will return false so
            // the caller knows not to issue an async read since that
            // will be called automatically after the write from the
            // handler
            issue_read = handler->second(line, chunks);
        }
        else
        {
            // if we have no handler for this response, just log it
            logger.debug(line);
        }
        return issue_read;
    }

    void IrcClient::issue_read()
    {
        if (!read_pending_)
        {
            read_pending_ = true;
            boost::asio::async_read_until(socket_, response_, "\r\n",
                boost::bind(&IrcClient::handle_response, this,
                    boost::asio::placeholders::error, boost::ref(request_),
                        boost::ref(response_)));
        }
        else
        {
            logger.debug("issue_read called with a read already pending");
        }
    }

    void IrcClient::shutdown()
    {
        socket_.shutdown();
        socket_.get_io_service().stop();
    }

    void IrcClient::logout()
    {
        write_command("QUIT", true);
        shutdown();
    }

    void IrcClient::handle_response(const boost::system::error_code& err)
    {
        handle_response(err, request_, response_);
    }

    void IrcClient::handle_response(const boost::system::error_code& err,
        boost::asio::streambuf& request, boost::asio::streambuf& response)
    {
        handle_error(err);

        read_pending_ = false;

        std::string line;
        std::istream response_stream(&response);
        std::getline(response_stream, line);

        boost::algorithm::trim_if(line, boost::algorithm::is_any_of("\r\n"));

        // if we have a continued line, just store it and read again
        if (line.find(";") != std::string::npos)
        {
            persisted_line_ = line.substr(0, line.size() - 2);
            read_pending_ = true;
            boost::asio::async_read_until(socket_, response, "\r\n",
                boost::bind(&IrcClient::handle_response, this,
                    boost::asio::placeholders::error, boost::ref(request),
                        boost::ref(response)));
            return;
        }
        else if (persisted_line_.size())
        {
            // if we previously had a continued line, pre-pend it
            // after the second ':' where the message starts
            const auto first_colon = line.find(":");
            JP_ASSERT(first_colon != std::string::npos);
            const auto second_colon = line.find(":", first_colon + 1);

            line = persisted_line_ + line.substr(
                second_colon + 1, line.size() - 2);
            persisted_line_.resize(0);
        }

        chunk_list chunks;
        boost::split(chunks, line, boost::is_any_of(" "));

        // Ping is the only command found in position 0, so look for
        // that before other commands (note: ping handler issues a
        // read via the pong response)
        if (chunks[0] == "PING")
        {
            handle_ping(line, chunks);
            return;
        }

        // continue reading only if instructed to do so
        const auto issue_read = handle_chunks(line, chunks);
        if (issue_read && !read_pending_)
        {
            read_pending_ = true;
            boost::asio::async_read_until(socket_, response, "\r\n",
                boost::bind(&IrcClient::handle_response, this,
                    boost::asio::placeholders::error, boost::ref(request),
                        boost::ref(response)));
        }
    }

}; // namespace joinparty
