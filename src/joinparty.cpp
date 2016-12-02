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

#include <bitcoin/bitcoin.hpp>

#include "joinparty/sysconfdir.hpp"
#include "joinparty/log.hpp"
#include "joinparty/encryption.hpp"
#include "joinparty/wallet.hpp"
#include "joinparty/order_manager.hpp"
#include "joinparty/irc_client.hpp"
#include "joinparty/block_cypher_client.hpp"

#include <boost/filesystem.hpp>

using namespace boost;
using namespace boost::program_options;

static const std::vector<std::string> libbitcoin_server_addresses
{
    // HELP WANTED: add any known stable/reliable libbitcoin servers
    // to this list
    "tcp://libbitcoin1.openbazaar.org:9091",
    "tcp://libbitcoin2.openbazaar.org:9091",
    "tcp://libbitcoin1.thecodefactory.org:9091",
    "tcp://libbitcoin2.thecodefactory.org:9091",
// these servers appear to be down
//    "tcp://libbitcoin3.openbazaar.org:9091",
//    "tcp://obelisk.airbitz.co:9091",
};

static const auto irc_port = "6697";
static const auto irc_channel = "#joinmarket-pit";
static const auto irc_host = "irc.cyberguerrilla.org";

static const auto block_cypher_port = "443";
static const auto block_cypher_host = "api.blockcypher.com";

joinparty::log::Log logger;

struct Settings
{
    bool list_all;
    bool list;
    bool create;
    bool recover;
    bool verbose;
    bool send_payment;
    bool join_payment;
    bool constructing_tx;

    uint32_t mix_depth;
    uint32_t subtract_fee;
    uint32_t target_num_makers;
    uint32_t min_num_makers;
    uint32_t commitment_index;
    uint32_t retry_index;
    uint32_t num_maker_responses_remaining;

    uint64_t amount;
    uint64_t change_amount;
    uint64_t target_fee_per_kb;
    uint64_t estimated_fee;
    uint64_t total_maker_fee;

    std::string wallet_file;

    std::vector<std::string> servers;
    std::vector<std::string> blacklist;
    std::vector<std::string> preferred;
    std::vector<std::string> excluded;

    boost::asio::io_service io_service;

    joinparty::encryption::NickInfo nick_info;

    libbitcoin::chain::transaction coin_join_tx;
    libbitcoin::wallet::payment_address destination;
    libbitcoin::wallet::payment_address change_address;

    joinparty::wallet_utils::WalletMap wallet_map;
    joinparty::encryption::EncKeyPair key_pair;
    joinparty::Wallet::UnspentList selected_unspent_list;

    std::shared_ptr<joinparty::Wallet> wallet;
    std::shared_ptr<joinparty::IrcClient> irc_client;
    std::shared_ptr<joinparty::OrderManager> order_manager;

    std::unique_ptr<boost::asio::deadline_timer> min_num_maker_timer;
};


static void parse_arguments(int argc, char** argv, variables_map& args)
{
    int opt;
    options_description desc("Available options");
    desc.add_options()
        ("help,h", "show this help message")
        ("list,l", "list the contents of the wallet")
        ("listall,L", "list all addresses of the wallet")
        ("create,c", "create a new wallet file")
        ("recover,r", "recover a previously created wallet "
         "using mnemonic and passphrase")
        ("wallet,w", value<std::string>(),
         "Required: use the specified wallet file")
        ("server,S", value<std::string>(),
         "Optional: The url of a libbitcoin server to use "
         "(default is a random address that may or may not be up)")
        ("blacklist,B", value<std::string>(),
         "Optional: A comma separated list of maker nicknames to avoid join "
         "attempts with (default is none)")
        ("preferred,P", value<std::string>(),
         "Optional: A comma separated list of maker nicknames to prefer join "
         "attempts with (default is none)")
        ("sendpayment,s", "send a payment (requires -m, -d, and -a)")
        ("joinpayment,j", "send a coinjoin payment "
         "(requires -m, -n, -d, and -a)")
        ("mixdepth,m", value<uint32_t>(),
         "The mix depth to spend from")
        ("fee,f", value<uint32_t>(),
         "The target fee per kb (0=low, 1=medium, 2=high; default is 1)")
        ("destination,d", value<libbitcoin::wallet::payment_address>(),
         "The bitcoin payment address")
        ("nummakers,n", value<uint32_t>(),
         "The target number of parties to join with")
        ("minmakers,M", value<uint32_t>(),
         "The minimum number of parties to join with")
        ("commitmentindex,C", value<int32_t>(),
         "The index of commitment to use for this coin join; default is 0")
        ("retryindex,R", value<int32_t>(),
         "The retry attempt number of the commitment to use for this coin "
         "join; default is 0")
        ("exclude,E", value<std::string>(),
         "Exclude utxos from the comma separated list of bitcoin addresses")
        ("amount,a", value<uint64_t>(),
         "The bitcoin amount in Satoshis")
        ("subtractfee,F", value<uint32_t>(),
         "Subtract the fee from the amount if needed "
         "(0=no, 1=yes; default is 0)")
        ("verbose,v", "Display verbose logging")
        ;

    store(parse_command_line(argc, argv, desc), args);
    notify(args);

    if (args.count("help"))
    {
        std::cout << desc << "\n";
        std::exit(0);
    }

    if (!args.count("wallet"))
    {
        std::cerr << "Wallet file was not specified." << std::endl;
        std::exit(1);
    }

    if (args.count("sendpayment") && args.count("joinpayment"))
    {
        std::cerr << "Specify either the sendpayment (-s) or the "
            "joinpayment (-j) option, but not both of them" << std::endl;
        std::exit(1);
    }

    if (args.count("sendpayment"))
    {
        if (!args.count("mixdepth") || !args.count("destination") ||
            !args.count("amount"))
        {
            std::cerr << "The sendpayment option requires the mixdepth (-m), "
                "destination (-d), and amount (-a) options." << std::endl;
            std::exit(1);
        }
    }

    if (args.count("joinpayment"))
    {
        if (!args.count("mixdepth") || !args.count("destination") ||
            !args.count("amount") || !args.count("nummakers"))
        {
            std::cerr << "The joinpayment option requires the mixdepth (-m), "
                "destination (-d), nummakers (-n), and amount (-a) options."
                    << std::endl;
            std::exit(1);
        }
    }
}

// called directly from main to send funds from the specified wallet.
// this method does not involve a coinjoin
static int send_payment(Settings& settings)
{
    if (!settings.wallet->send_payment(
        settings.mix_depth, settings.amount, settings.destination,
            settings.target_fee_per_kb, settings.subtract_fee))
    {
        std::cout << "Error sending payment.  If there is enough btc in "
            "this mix level, perhaps the incoming transactions have not "
                "been confirmed?" << std::endl;
    }
    else
    {
        joinparty::wallet_utils::write_wallet_map_to_wallet_file(
            settings.wallet_file, settings.wallet_map);
    }
    return 0;
}

// a callback called after we've heard from all (or at least the
// minimum number) of the makers and it's time to broadcast the signed
// coin join transaction
static bool broadcast_transaction(
    Settings& settings, libbitcoin::chain::transaction* tx,
    joinparty::OrderState* order_state)
{
    logger.debug("*** OrderManager:",
        "registered broadcast tx callback called");
    JP_ASSERT(order_state && order_state->signature_verified);

    if (--settings.num_maker_responses_remaining == 0)
    {
        logger.debug(
            "Time to validate and broadcast transaction with hash:",
                libbitcoin::encode_base16(tx->hash()));

        JP_ASSERT(tx == &settings.coin_join_tx);
        settings.wallet->sign_transaction_inputs(
            settings.selected_unspent_list, settings.coin_join_tx);

        const auto ret =
            (settings.wallet->transaction_is_valid(settings.coin_join_tx) &&
                 settings.wallet->send_transaction(settings.coin_join_tx));
        if (ret)
        {
            joinparty::wallet_utils::update_index_cache(
                settings.wallet_map, settings.mix_depth, 0,
                settings.selected_unspent_list.size());
            settings.wallet->build_index_list_from_index_cache();

            joinparty::wallet_utils::write_wallet_map_to_wallet_file(
                settings.wallet_file, settings.wallet_map);
        }

        logger.info("Transaction is", (ret ? "Valid" : "Invalid"));
        logger.info(tx->to_string(0xFFFFFFFF));

        settings.irc_client->logout();
        return ret;
    }
    else
    {
        logger.debug("Still waiting for more signatures:",
            settings.num_maker_responses_remaining, "remaining");

        settings.irc_client->issue_read();
    }
    return false;
}

// a callback called after we've heard from all of the makers and it's
// time to construct the coin join transaction
static bool construct_transaction(
    Settings& settings, joinparty::OrderState& order_state)
{
    logger.debug("*** OrderManager: registered construct tx callback called");
    JP_ASSERT(order_state.ioauth_verified);

    settings.num_maker_responses_remaining--;

    const uint32_t num_valid_makers =
        settings.target_num_makers - settings.num_maker_responses_remaining;

    const auto have_min_makers = (num_valid_makers >= settings.min_num_makers);

    logger.info("min_makers", settings.min_num_makers, "target_num_makers",
        settings.target_num_makers, "num_valid_makers", num_valid_makers,
            "have_min_makers", (have_min_makers ? "TRUE" : "FALSE"));

    auto construct_tx = [&settings, &order_state, num_valid_makers](
        const boost::system::error_code error)
    {
        if (error && (error == boost::asio::error::operation_aborted))
        {
            logger.info("Construct Tx call via timer was canceled");
            return;
        }

        if (settings.constructing_tx)
        {
            logger.info("Got a late maker response, but ignoring because "
                "we're already constructing the transaction");
            return;
        }

        settings.constructing_tx = true;

        logger.info("Creating coinjoin transaction now with",
            num_valid_makers, "makers...");
        settings.num_maker_responses_remaining = num_valid_makers;

        if (!settings.wallet->create_coin_join_transaction(
            settings.coin_join_tx, settings.amount, settings.destination,
                settings.change_amount, settings.change_address,
                    settings.selected_unspent_list,
                        settings.order_manager->get_order_states(),
                            settings.estimated_fee, settings.subtract_fee))
        {
            throw std::runtime_error(
                "Failed to create coin join transaction");
        }

        settings.order_manager->set_order_transaction(&settings.coin_join_tx);

        settings.order_manager->register_broadcast_tx_cb(
            [&settings](libbitcoin::chain::transaction* tx,
                        joinparty::OrderState* order_state)
        {
            return broadcast_transaction(settings, tx, order_state);
        });

        logger.debug("Sending unsigned transaction now ...",
            settings.coin_join_tx.to_string(0xFFFFFFFF));
        logger.info("Sending unsigned transaction now ...");

        auto send_transaction = [&settings]()
        {
            settings.irc_client->send_unsigned_transaction(
                settings.order_manager->get_order_states(),
                    settings.coin_join_tx);
        };
        settings.io_service.post(send_transaction);
    };

    // if we have a minimum number of makers for a join, but not all
    // yet, start a timer that waits up to 30 seconds for a response.
    // if one is received, cancel the timer and re-issue it if we're
    // still waiting for more responses.  if another is never received
    // and the timer expires, we'll construct the transaction with the
    // makers we have communicated with already
    if (have_min_makers)
    {
        if (settings.min_num_maker_timer)
        {
            settings.min_num_maker_timer->cancel();
            settings.min_num_maker_timer = nullptr;
        }

        static constexpr size_t additional_wait_secs = 30;
        logger.info("Already have minimum number of required makers; "
            "waiting for additional responses");
        settings.min_num_maker_timer =
            std::make_unique<boost::asio::deadline_timer>(
                settings.io_service, boost::posix_time::seconds(
                    additional_wait_secs));

        settings.min_num_maker_timer->async_wait(construct_tx);

        // drops through to waiting for more makers
        // FIXME: needs to ignore all future calls to this when construct_tx is called
    }

    if (settings.num_maker_responses_remaining == 0)
    {
        // now that we have all maker responses, cancel the timer and
        // construct the tx
        if (settings.min_num_maker_timer)
        {
            settings.min_num_maker_timer->cancel();
            settings.min_num_maker_timer = nullptr;
        }

        construct_tx(boost::system::error_code{});
        return true;
    }
    else
    {
        logger.info("Still waiting for more makers:",
            settings.num_maker_responses_remaining);

        settings.irc_client->issue_read();
    }
    return false;
}

// a callback called after we've received a number of live orders from
// the orderbook.  this selects which orders to fill and continues the
// coin join process
static int process_join_orders(
    Settings& settings, const boost::system::error_code& ec)
{
    settings.order_manager->set_wallet(settings.wallet);

    // determine the orders to fill for our join and declare our
    // intention to fill them to the maker
    settings.num_maker_responses_remaining = settings.target_num_makers;
    for(auto i = 0; i < settings.target_num_makers; i++)
    {
        const auto& order =
            settings.order_manager->get_next_eligible_order();

        logger.info("[", i, ",", order.nick, "] Most eligible order is:",
            (uint32_t)order.order_id,
            (uint32_t)order.min_size, (uint32_t)order.max_size,
            (float)order.tx_fee, (float)order.cj_fee);

        settings.order_manager->add_order_state(joinparty::OrderState(
            order, settings.selected_unspent_list, settings.key_pair,
                settings.nick_info, settings.commitment_index,
                    settings.retry_index));

        // set a callback that will be called when it's time to
        // construct the actual bitcoin transaction
        settings.order_manager->register_construct_tx_cb(
            [&settings](joinparty::OrderState& order_state)
        {
            return construct_transaction(settings, order_state);
        });

        // attempt to fill the current order
        settings.io_service.post([&settings, i]()
        {
            auto& order_state =
                settings.order_manager->get_order_states()[i];

            settings.irc_client->fill_order(order_state, settings.amount);
        });
    }
    return 0;
}

// called directly from main to send funds from the specified wallet.
// this method attempts to perform a coinjoin.
static int initiate_join_payment(Settings& settings)
{
    if (!settings.wallet->retrieve_unspent_and_change_address(
        settings.selected_unspent_list, settings.change_address,
            settings.change_amount, settings.mix_depth, settings.amount,
                &settings.excluded))
    {
        throw std::runtime_error("Failed to retrieve enough unspent outputs "
            "required for this transaction from this mix depth");
    }

    // we have to come up with an estimated fee here based on our
    // estimated transaction size.
    const auto estimated_ins =
        (settings.selected_unspent_list.size() + 3) *
            settings.target_num_makers;
    const auto estimated_outs = 2 * (settings.target_num_makers + 1);

    const auto estimated_tx_size = 10 + (estimated_ins * 147) +
        (34 * estimated_outs);

    settings.estimated_fee = settings.target_fee_per_kb *
        static_cast<float>(
            (static_cast<float>(estimated_tx_size) / 1024) /
                settings.target_num_makers);

    logger.info("Target fee per KB is", settings.target_fee_per_kb,
        "and the estimated tx size is", estimated_tx_size);
    logger.info("Estimated fee is", settings.estimated_fee);

    // adjust the destination amount if we're pulling the fee from it
    if (settings.subtract_fee)
    {
        if (settings.amount <= settings.estimated_fee)
        {
            throw std::runtime_error("Cannot subtract fee from amount -- "
                "not enough unspent outputs required for this transaction "
                "from this mix depth");
        }
        settings.amount -= settings.estimated_fee;
    }
    else
    {
        // make sure that our utxos can cover both the amount and the
        // estimated fee
        const uint64_t target_amount = settings.amount + settings.estimated_fee;
        uint64_t input_total = 0;
        for(const auto& unspent : settings.selected_unspent_list)
        {
            input_total += unspent.second.value;
            if (input_total >= target_amount)
            {
                break;
            }
        }

        if (input_total < target_amount)
        {
            throw std::runtime_error("Cannot afford this amount as well as "
                "the estimated fee -- not enough unspent outputs required "
                    "for this transaction from this mix depth");
        }
    }

    // wallet->retrieve_unspent_and_change_address can change the
    // amount (if amount=0), so we initialize the order manager with
    // it after that has been finalized
    settings.order_manager =
        std::make_shared<joinparty::OrderManager>(
            settings.amount, settings.blacklist, settings.preferred);

    logger.info("Using nick name:", settings.nick_info.nick);

    settings.irc_client = std::make_shared<joinparty::IrcClient>(
        settings.io_service, irc_host, irc_port, settings.nick_info.nick,
            irc_channel, settings.order_manager);

    // initiate a timer to process received orders after 10 seconds
    boost::asio::deadline_timer timer{
        settings.io_service, boost::posix_time::seconds(10)};

    timer.async_wait(boost::bind(process_join_orders, boost::ref(settings),
        boost::asio::placeholders::error));

    logger.info("Waiting for orders from makers ...");
    settings.io_service.run();

    return 0;
}

int main(int argc, char** argv)
{
    try
    {
        variables_map args{};
        parse_arguments(argc, argv, args);

        Settings settings{};
        settings.list_all = args.count("listall");
        settings.list = args.count("list") || settings.list_all;
        settings.create = args.count("create");
        settings.recover = args.count("recover");
        settings.send_payment = args.count("sendpayment");
        settings.join_payment = args.count("joinpayment");
        settings.wallet_file = args["wallet"].as<std::string>();
        settings.servers = (args.count("server") ?
            std::vector<std::string>({args["server"].as<std::string>()}) :
                libbitcoin_server_addresses);
        settings.constructing_tx = false;

        auto bounds_check = [](const uint32_t value, const uint32_t lower,
            const uint32_t upper, std::string name)
        {
            if (value < lower || value > upper)
            {
                std::stringstream error_msg;
                error_msg << "Invalid " << name << " (";
                error_msg << value << " is outside the acceptable range from ";
                error_msg << lower << "-" << upper << ")";

                throw std::runtime_error(error_msg.str());
            }
        };

        settings.commitment_index = (args.count("commitmentindex") ?
            args["commitmentindex"].as<int32_t>() : 0);
        bounds_check(settings.commitment_index, 0,
            std::numeric_limits<uint8_t>::max(), "commitment index");
        settings.retry_index = (args.count("retryindex") ?
            args["retryindex"].as<int32_t>() : 0);
        bounds_check(settings.retry_index, 0,
            std::numeric_limits<uint8_t>::max(), "retry index");

        std::random_shuffle(settings.servers.begin(), settings.servers.end(),
            joinparty::utils::get_random_number);

        if (settings.recover)
        {
            if (joinparty::wallet_utils::recover_wallet(settings.wallet_file))
            {
                std::cout << std::endl << "Wallet recovered "
                    "and written to " << settings.wallet_file << std::endl;
            }
            else
            {
                std::cerr << std::endl << "Wallet recovery failed and was "
                    "not written to " << settings.wallet_file << std::endl;
            }
            return 0;
        }

        if (!joinparty::wallet_utils::initialize_wallet(
                settings.wallet_file, settings.wallet_map, settings.create))
        {
            throw std::runtime_error(
                "Failed to initialize wallet " + settings.wallet_file);
        }

        const auto network = settings.wallet_map.find("network");
        if (network == settings.wallet_map.end() ||
            network->second != joinparty::constants::bitcoin_network)
        {
            throw std::runtime_error("Currently only " +
                joinparty::constants::bitcoin_network +
                " is supported and must be used");
        }

        settings.wallet = std::make_shared<joinparty::Wallet>(
            settings.wallet_map, settings.servers);
        if (settings.create)
        {
            std::cout << std::endl << "Wallet created and written to "
                << settings.wallet_file << std::endl;
            return 0;
        }

        auto seed = joinparty::wallet_utils::get_user_wallet_seed(
            settings.wallet_map);
        sodium_mlock(seed.data(), sizeof(seed));
        settings.wallet->initialize_from_seed(seed);
        sodium_memzero(seed.data(), sizeof(seed));
        sodium_munlock(seed.data(), sizeof(seed));

        if (settings.list)
        {
            settings.wallet->set_list_all(settings.list_all);
            std::cout << *settings.wallet << std::endl;
            return 0;
        }

        // retrieve all fee estimates per kb from block cypher
        joinparty::BlockCypherClient block_cypher_client(
            settings.io_service, block_cypher_host, block_cypher_port);
        settings.io_service.run();
        settings.io_service.reset();

        uint64_t low_fee_per_kb, medium_fee_per_kb, high_fee_per_kb;
        block_cypher_client.get_fee_estimates(
            low_fee_per_kb, medium_fee_per_kb, high_fee_per_kb);

        settings.amount = args["amount"].as<uint64_t>();
        settings.mix_depth = args["mixdepth"].as<uint32_t>();
        settings.destination = args["destination"].as<
            libbitcoin::wallet::payment_address>();
        const auto fee  = (args.count("fee") ? args["fee"].as<uint32_t>() : 1);
        settings.subtract_fee = (args.count("subtractfee") ?
            ((args["subtractfee"].as<uint32_t>() == 1) ? true : false) : false);

        settings.target_fee_per_kb = (fee == 0 ? low_fee_per_kb :
            (fee == 1 ? medium_fee_per_kb : high_fee_per_kb));
        const auto target_fee_per_kb_str =
            (fee == 0 ? "low" : (fee == 1 ? "medium" : "high"));

        logger.info("Using", target_fee_per_kb_str, "fee of",
            settings.target_fee_per_kb, "per kb");

        if (settings.send_payment)
        {
            return send_payment(settings);
        }
        else if (settings.join_payment)
        {
            std::stringstream log_filename;
            boost::filesystem::create_directories("logs");
            generate_nick_key_pair(settings.nick_info);

            const auto log_level = (settings.verbose ? "verbose" : "normal");
            log_filename << "logs/" << settings.nick_info.nick << ".log";
            std::cout << "Logging " << log_level << " to "
                << log_filename.str() << std::endl;

            if (!logger.initialize(log_filename.str(), settings.verbose))
            {
                throw std::runtime_error(
                    "Failed to initialize logging to " + log_filename.str());
            }

            if (args.count("blacklist"))
            {
                const auto blacklist = args["blacklist"].as<std::string>();
                boost::split(settings.blacklist, blacklist, boost::is_any_of(", "));

                std::vector<std::string> alias_blacklist;
                alias_blacklist.reserve(settings.blacklist.size());

                for(const auto& maker : settings.blacklist)
                {
                    logger.info("Added maker", maker, "to the blacklist");
                    alias_blacklist.emplace_back(maker + "_");
                    logger.debug("Added maker", maker + "_", "to the blacklist");
                }
                settings.blacklist.insert(settings.blacklist.end(),
                    alias_blacklist.begin(), alias_blacklist.end());
            }

            if (args.count("preferred"))
            {
                const auto preferred = args["preferred"].as<std::string>();
                boost::split(settings.preferred, preferred, boost::is_any_of(", "));
            }

            if (args.count("exclude"))
            {
                const auto excluded = args["exclude"].as<std::string>();
                boost::split(settings.excluded, excluded, boost::is_any_of(", "));
            }

            settings.target_num_makers = args["nummakers"].as<uint32_t>();
            settings.min_num_makers = (args.count("minmakers") ?
                args["minmakers"].as<uint32_t>() : settings.target_num_makers);
            settings.change_amount = 0;
            settings.num_maker_responses_remaining = 0;
            joinparty::encryption::generate_key_pair(settings.key_pair);

            return initiate_join_payment(settings);
        }
    }
    catch(std::exception& e)
    {
        std::cout << "Exception: " << e.what() << "\n";
    }
    return 0;
}
