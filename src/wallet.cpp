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

#include <vector>
#include <utility>
#include <stdexcept>
#include <unordered_map>

#include <bitcoin/bitcoin.hpp>
#include <bitcoin/client/obelisk_client.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>

#include "joinparty/constants.hpp"
#include "joinparty/log.hpp"
#include "joinparty/utils.hpp"
#include "joinparty/wallet_utils.hpp"
#include "joinparty/address_info.hpp"
#include "joinparty/order_state.hpp"

extern joinparty::log::Log logger;

namespace joinparty
{
    static constexpr uint8_t num_retries = 0;
    static constexpr uint16_t timeout_seconds = 8;
    static constexpr uint32_t minimum_fee = 4499;
    static constexpr uint32_t dust_threshold = 2730;

    Wallet::Wallet(
        wallet_utils::WalletMap& wallet_map,
        const std::vector<std::string>& server_addresses,
        uint32_t max_mix_depth, uint32_t gap_limit, bool extend_mixdepth) :
    initialized_(false), list_all_(false), gap_limit_(gap_limit),
        extend_mixdepth_(extend_mixdepth), max_mix_depth_(max_mix_depth),
        server_addresses_(server_addresses), wallet_map_(wallet_map),
        client_{timeout_seconds, num_retries}
    {
        build_index_list_from_index_cache();
    }

    void Wallet::initialize_from_seed(libbitcoin::long_hash& seed)
    {
        const auto public_prefix = (
            joinparty::constants::bitcoin_network == "mainnet" ?
                joinparty::constants::bip32_mainnet_public_version :
                    joinparty::constants::bip32_testnet_public_version);
        const auto private_prefix = (
            joinparty::constants::bitcoin_network == "mainnet" ?
                joinparty::constants::bip32_mainnet_private_version :
                    joinparty::constants::bip32_testnet_private_version);

        const auto prefixes = libbitcoin::wallet::hd_private::to_prefixes(
            private_prefix, public_prefix);

        master_ = libbitcoin::wallet::hd_private(to_chunk(seed), prefixes);
        JP_ASSERT(master_);

        m_0_ = master_.derive_private(0);
        JP_ASSERT(m_0_);

        keys_.reserve(max_mix_depth_);
        if (index_list_.size() == 0)
            index_list_.reserve(max_mix_depth_);

        for(auto i = 0; i < max_mix_depth_; i++)
        {
            if (index_list_.size() == 0)
                index_list_.emplace_back(0, 0);

            const auto key = m_0_.derive_private(i);
            keys_.emplace_back(key.derive_private(0),
                               key.derive_private(1));
        }

        for(const auto& server_address : server_addresses_)
        {
            if (initialize_client_connection(server_address))
            {
                initialized_ = true;
                break;
            }
        }
    }

    bool Wallet::create_and_broadcast_transaction(
        const UnspentList& unspent, uint64_t& amount,
        const libbitcoin::wallet::payment_address destination_address,
        const uint64_t target_fee_per_kb, const uint64_t change_amount,
        const libbitcoin::wallet::payment_address change_address,
        bool subtract_fee_from_amount)
    {
        auto ret = false;
        std::stringstream error_msg;

        libbitcoin::chain::transaction tx;
        tx.locktime = locktime;
        tx.version = transaction_version;

        // add the destination output and change outputs (if any)
        chain::operation::stack amount_payment_ops =
            chain::operation::to_pay_key_hash_pattern(
                destination_address.hash());

        const libbitcoin::chain::output output{
            amount, chain::script{amount_payment_ops}};
        tx.outputs.push_back(output);

        // add our raw change amount
        if (change_amount)
        {
            logger.info("Using change amount of",
                change_amount, "back to our self");

            chain::operation::stack change_payment_ops =
                chain::operation::to_pay_key_hash_pattern(
                    change_address.hash());

            const libbitcoin::chain::output change_output{
                change_amount, chain::script{change_payment_ops}};

            tx.outputs.push_back(change_output);
        }

        // add all inputs to the tx
        for(const auto& cur_unspent : unspent)
        {
            const auto& key = cur_unspent.first;
            const auto& transfer = cur_unspent.second;
            if (transfer.is_spent())
            {
                return false;
            }

            libbitcoin::chain::input input;
            input.sequence = max_input_sequence;
            input.previous_output = libbitcoin::chain::output_point{
                transfer.output.hash, transfer.output.index};
            tx.inputs.push_back(input);
        }

        // sign all inputs to the tx
        sign_transaction_inputs(unspent, tx);

        const auto tx_size = static_cast<float>(tx.serialized_size());
        uint64_t estimated_fee = target_fee_per_kb *
            static_cast<float>(tx_size / 1024);

        logger.info("Estimated fee for tx of", tx_size,
            "bytes is", estimated_fee);

        auto fee_handled = false;

        // if we are expecting change back, pull the fee from there
        if (change_amount && (change_amount > estimated_fee))
        {
            chain::operation::stack change_payment_ops =
                chain::operation::to_pay_key_hash_pattern(
                    change_address.hash());

            const uint64_t adjusted_amount = change_amount - estimated_fee;
            const libbitcoin::chain::output change_output{
                adjusted_amount, chain::script{change_payment_ops}};

            logger.info("Using adjusted change amount of",
                adjusted_amount, "back to our self");

            tx.outputs[1] = change_output;

            fee_handled = true;
        }

        // if the fee hasn't been handled by pulling from the change,
        // if specified, we can pull the fee from the total amount to
        // send (assuming the amount is larger than the estimated fee)
        if (!fee_handled && subtract_fee_from_amount &&
            (amount > estimated_fee))
        {
            amount -= estimated_fee;

            logger.info("Subtracting fee from amount. "
                "Using adjusted destination amount of", amount);

            const libbitcoin::chain::output output{
                amount, chain::script{amount_payment_ops}};

            // adjust the amount that was previously already set
            tx.outputs[0] = output;

            fee_handled = true;
        }

        if (!fee_handled)
        {
            error_msg << "Not enough funds in this mix level for the amount "
                "of " << amount << " in addition to the estimated fee of "
                      << estimated_fee << std::endl;
            throw std::runtime_error(error_msg.str());
        }

        // re-sign all inputs to the tx after fee related modifications
        sign_transaction_inputs(unspent, tx);

        return transaction_is_valid(tx) && send_transaction(tx);
    }

    bool Wallet::retrieve_unspent_and_change_address(
        UnspentList& selected_unspent,
        libbitcoin::wallet::payment_address& change_address,
        uint64_t& change_amount, const uint32_t mix_depth, uint64_t& amount)
    {
        // retrieve all unspent for this mix depth
        UnspentList unspent_list;
        auto unspent = get_unspent_outputs_for_mix_depth(
            mix_depth, unspent_list, change_address);
        JP_ASSERT(unspent.size() == unspent_list.size());

        if (amount > 0)
        {
            libbitcoin::chain::points_info selected;
            libbitcoin::wallet::select_outputs::select(selected, unspent, amount);

            logger.info(
                "Retrieved", selected.points.size(), "selected points from "
                "unspent list with change of", selected.change, "btc");

            if (!selected.points.size())
            {
                return false;
            }

            // create new unspent_list to only contain the unspent objects
            // matching the selected outputs
            UnspentList selected_unspent_list;
            selected_unspent_list.reserve(selected.points.size());
            for(const auto& selected_point : selected.points)
            {
                for(const auto& unspent : unspent_list)
                {
                    if (selected_point == unspent.second.output)
                    {
                        selected_unspent_list.push_back(unspent);
                        break;
                    }
                }
            }

            if (selected_unspent_list.size() != selected.points.size())
            {
                throw std::runtime_error(
                    "Failed to select a coherent utxo set (Unconfirmed "
                    "transaction or Double spend involved?)");
            }

            // set change amount and swap newly created unspent list with
            // the outgoing parameter
            change_amount = selected.change;
            selected_unspent.swap(selected_unspent_list);

            return selected_unspent.size() == selected.points.size();
        }

        for(const auto& unspent : unspent_list)
        {
            amount +=
                (!unspent.second.is_spent() ? unspent.second.value : 0);
        }
        selected_unspent.swap(unspent_list);

        logger.info("Spendable total in mixdepth",
            mix_depth, "is", amount, "btc");

        return (selected_unspent.size() > 0);
    }

    void Wallet::sign_transaction_inputs(UnspentList unspent_list,
        libbitcoin::chain::transaction& output_tx)
    {
        for(auto& cur_unspent : unspent_list)
        {
            const auto& key = cur_unspent.first;
            const auto& transfer = cur_unspent.second;
            if (transfer.is_spent())
            {
                throw std::runtime_error(
                    "Error: our own utxo has been spent already");
            }

            libbitcoin::chain::transaction tmp_tx;
            get_transaction_info(transfer.output.hash, tmp_tx);
            const auto& previous_output_script =
                tmp_tx.outputs[transfer.output.index].script;

            const auto address = joinparty::utils::bitcoin_address(
                previous_output_script);

            // set our signed script on the input, but first find the
            // input's index in the tx we're building
            uint32_t input_index = std::numeric_limits<uint32_t>::max();
            for(uint32_t i = 0; i < output_tx.inputs.size(); i++)
            {
                if (output_tx.inputs[i].previous_output == transfer.output)
                {
                    input_index = i;
                    break;
                }
            }

            if (input_index == std::numeric_limits<uint32_t>::max())
            {
                throw std::runtime_error(
                    "Cannot find our own input to sign in the transaction!");
            }

            // create endorsement for the input index we're about to
            // assign (all inputs must already be added to the tx for
            // this to work)
            endorsement tx_endorse;
            if (!chain::script::create_endorsement(
                    tx_endorse, key, previous_output_script,
                    output_tx, input_index, hash_type))
            {
                throw std::runtime_error("Failed to create tx endorsement");
            }

            // create endorsement script
            const auto pub_key_data =
                joinparty::utils::public_from_private(key);

            std::string endorsement_script_str = "[ ";
            endorsement_script_str.append(
                libbitcoin::encode_base16(tx_endorse));
            endorsement_script_str.append(" ] [ ");
            endorsement_script_str.append(
                libbitcoin::encode_base16(pub_key_data));
            endorsement_script_str.append(" ]");

            libbitcoin::chain::script endorsement_script;
            if (!endorsement_script.from_string(endorsement_script_str))
            {
                throw std::runtime_error("failed to create endorsement script");
            }

            // set signed script on the input
            output_tx.inputs[input_index].script = endorsement_script;

            // validate input
            if (!libbitcoin::chain::script::verify(
                    endorsement_script, previous_output_script, output_tx,
                    input_index, 0xFFFFFF))
            {
                throw std::runtime_error("Maker signature is invalid");
            }
        }
    }

    bool Wallet::create_coin_join_transaction(
        libbitcoin::chain::transaction& out_tx, const uint64_t amount,
        const libbitcoin::wallet::payment_address& destination_address,
        const uint64_t change_amount,
        const libbitcoin::wallet::payment_address& change_address,
        joinparty::Wallet::UnspentList& unspent,
        std::vector<joinparty::OrderState>& order_states,
        const uint64_t estimated_fee, const bool subtract_fee)
    {
        JP_ASSERT(initialized_);
        out_tx.locktime = locktime;
        out_tx.version = transaction_version;

        uint64_t coinjoin_fee_total = 0;
        uint64_t maker_txfee_total = 0;
        for(const auto& order_state : order_states)
        {
            // add the maker's destination output
            const chain::operation::stack payment_ops =
                chain::operation::to_pay_key_hash_pattern(
                    libbitcoin::wallet::payment_address(
                        order_state.coin_join_pub_key).hash());

            const libbitcoin::chain::output output{
                amount, chain::script{payment_ops}};

            out_tx.outputs.push_back(output);

            // add all maker inputs to the tx
            for(const auto& maker_utxo : order_state.maker_utxo_list)
            {
                libbitcoin::chain::input input;
                input.sequence = max_input_sequence;
                input.previous_output = libbitcoin::chain::output_point{
                    maker_utxo.hash, maker_utxo.index};

                out_tx.inputs.push_back(input);
            }

            // a method to calculate coinjoin fee based on the maker order type
            auto calculate_coinjoin_fee = [](
                const joinparty::Order& order, const uint64_t amount)
            {
                return ((order.order_type == joinparty::OrderType::Absolute) ?
                    order.cj_fee : (amount * order.cj_fee));
            };
            const auto real_coinjoin_fee = static_cast<uint64_t>(
                std::rint(calculate_coinjoin_fee(order_state.order, amount)));

            uint64_t total_input = 0;
            for(const auto& utxo : order_state.maker_utxo_list)
            {
                libbitcoin::chain::transaction resolved_tx;
                if (!get_transaction_info(utxo.hash, resolved_tx) ||
                    (!resolved_tx.is_valid()))
                {
                    logger.info(
                        "Failed to get transaction info for tx hash: ",
                            libbitcoin::encode_base16(utxo.hash));
                    return false;
                }
                total_input += resolved_tx.outputs[utxo.index].value;
            }

            const uint64_t maker_change_amount = total_input - amount -
                order_state.order.tx_fee + real_coinjoin_fee;
            JP_ASSERT(total_input > maker_change_amount);

            logger.info("*****", order_state.order.nick,
                "total_input=", total_input, "real_coinjoin_fee=",
                real_coinjoin_fee, "maker_change_amount=",
                maker_change_amount);

            if (maker_change_amount < dust_threshold)
            {
                throw std::runtime_error(
                    "Invalid maker utxo amounts sent resulting in "
                    "sub-dust change");
            }

            const chain::operation::stack maker_change_payment_ops =
                chain::operation::to_pay_key_hash_pattern(
                    order_state.maker_change_address.hash());

            const libbitcoin::chain::output maker_change_output{
                maker_change_amount, chain::script{
                    maker_change_payment_ops}};

            out_tx.outputs.push_back(maker_change_output);

            coinjoin_fee_total += real_coinjoin_fee;
            maker_txfee_total += order_state.order.tx_fee;
        }

        // add all of our inputs to the tx
        for(const auto& cur_unspent : unspent)
        {
            const auto& key = cur_unspent.first;
            const auto& transfer = cur_unspent.second;
            if (transfer.is_spent())
            {
                logger.info(
                    "FATAL ERROR: our own utxo has been spent already");
                return false;
            }

            libbitcoin::chain::input input;
            input.sequence = max_input_sequence;
            input.previous_output = libbitcoin::chain::output_point{
                transfer.output.hash, transfer.output.index};

            out_tx.inputs.push_back(input);
        }

        const auto tx_size = static_cast<float>(out_tx.serialized_size());
        logger.info("Using specified fee estimate of", estimated_fee,
            "for tx of actual size", tx_size);

        // for joins, if the subtract fee option was used, the fee has
        // already been subtracted from the total amount
        auto fee_handled = subtract_fee;

        // if we are expecting change back, pull the fee from there
        if (change_amount)
        {
            chain::operation::stack change_payment_ops =
                chain::operation::to_pay_key_hash_pattern(
                    change_address.hash());

            uint64_t adjusted_amount = change_amount;
            if (!fee_handled && (change_amount > estimated_fee))
            {
                adjusted_amount -= estimated_fee;
            }
            const libbitcoin::chain::output change_output{
                adjusted_amount, chain::script{change_payment_ops}};

            logger.info("Using actual change amount of",
                adjusted_amount, "back to our self");

            out_tx.outputs.push_back(change_output);

            fee_handled = true;
        }

        if (!fee_handled)
        {
            std::stringstream error_msg;
            error_msg << "Not enough funds in this mix level for the amount "
                "of " << amount << " in addition to the estimated fee of "
                      << estimated_fee << std::endl;
            throw std::runtime_error(error_msg.str());
        }

        // add our destination output for the amount
        const chain::operation::stack payment_ops =
            chain::operation::to_pay_key_hash_pattern(
                destination_address.hash());

        const libbitcoin::chain::output output{
            amount, chain::script{payment_ops}};

        out_tx.outputs.push_back(output);

        // randomize all inputs and outputs
        std::random_shuffle(out_tx.inputs.begin(), out_tx.inputs.end(),
            joinparty::utils::get_random_number);
        std::random_shuffle(out_tx.outputs.begin(), out_tx.outputs.end(),
            joinparty::utils::get_random_number);

        return true;
    }

    bool Wallet::send_payment(const uint32_t mix_depth, uint64_t& amount,
        const libbitcoin::wallet::payment_address destination_address,
        const uint64_t target_fee_per_kb, bool subtract_fee_from_amount)
    {
        uint64_t change_amount = 0;
        UnspentList selected_unspent_list;
        libbitcoin::wallet::payment_address change_address{};

        auto ret = retrieve_unspent_and_change_address(
            selected_unspent_list, change_address, change_amount,
            mix_depth, amount);
        if (ret)
        {
            ret = create_and_broadcast_transaction(
                selected_unspent_list, amount, destination_address,
                target_fee_per_kb, change_amount, change_address,
                subtract_fee_from_amount);
            if (ret)
            {
                joinparty::wallet_utils::update_index_cache(
                    wallet_map_, mix_depth, 0, selected_unspent_list.size());
                build_index_list_from_index_cache();
            }
        }
        return ret;
    }

    libbitcoin::chain::output_info::list Wallet::get_unspent_outputs_for_mix_depth(
        const uint32_t mix_depth, UnspentList& unspent_list,
        libbitcoin::wallet::payment_address& change_address)
    {
        auto assigned_change_address = false;
        libbitcoin::chain::output_info::list unspent{};

        const auto cur_index = index_list_[mix_depth];
        const auto cur_height = get_current_block_height();
        for(auto for_change = 0; for_change < 2; for_change++)
        {
            const auto start_index =
                ((for_change == 0) ? cur_index.first : cur_index.second);

            for(auto k = 0; k < start_index + gap_limit_; k++)
            {
                const auto key = get_key(mix_depth, for_change, k);

                libbitcoin::ec_compressed point;
                libbitcoin::secret_to_public(point, key);
                const auto address = joinparty::utils::bitcoin_address(point);

                AddressInfo address_info;
                if (!fetch_address_info(
                    point, address, mix_depth, for_change, k, address_info))
                {
                    return {};
                }

                if (address_info.is_spent())
                {
                    continue;
                }

                if (for_change && k >= start_index)
                {
                    if (!assigned_change_address)
                    {
                        change_address =
                            libbitcoin::wallet::payment_address(point);
                        joinparty::wallet_utils::update_index_cache(
                            wallet_map_, mix_depth, for_change, 1);
                        assigned_change_address = true;

                        logger.info("Sending change to",
                            joinparty::utils::bitcoin_address(point));
                    }
                }

                for(const auto& transfer : address_info.transfers)
                {
                    if (transfer.confirmed(cur_height) && !transfer.is_spent())
                    {
                        logger.info("Adding unspent for mix level",
                            mix_depth, "with hash", libbitcoin::encode_base16(
                                transfer.output.hash), "and value",
                                    transfer.value);

                        unspent.push_back({transfer.output, transfer.value});
                        unspent_list.push_back({key, transfer});
                    }
                }
            }
        }

        build_index_list_from_index_cache();
        return unspent;
    }

    std::ostream& operator<<(std::ostream& out, Wallet& w)
    {
        if (!w.initialized())
        {
            return out;
        }

        const auto gap_limit = w.gap_limit();
        const auto index_list = w.index_list();
        const auto max_mix_depth = w.max_mix_depth();

        int64_t balance = 0;
        int64_t total_balance = 0;
        int64_t balance_depth = 0;
        auto cur_gap_limit = gap_limit;
        for(auto m = 0; m < max_mix_depth; m++)
        {
            out << "mixing depth " << m << " m/0/" << m << "/" << std::endl;
            balance_depth = 0;
            for(auto for_change = 0; for_change < 2; for_change++)
            {
                const auto level = (
                    (for_change == 0) ? "external" : "internal");
                out << " " << level << " addresses m/0/" << m << "/"
                    << for_change << "/" << std::endl;

                const auto cur_index = index_list[m];
                const auto start_index =
                    ((for_change == 0) ? cur_index.first : cur_index.second);

                cur_gap_limit = gap_limit;
                for(auto k = 0; k < start_index + cur_gap_limit; k++)
                {
                    balance = 0;
                    const auto& key = w.get_key(m, for_change, k);

                    libbitcoin::ec_compressed point;
                    libbitcoin::secret_to_public(point, key);
                    const auto address =
                        joinparty::utils::bitcoin_address(point);

                    AddressInfo address_info;
                    if (!w.fetch_address_info(
                            point, address, m, for_change, k, address_info))
                    {
                        return out;
                    }

                    if (!address_info.is_spent())
                    {
                        balance = address_info.total_value;
                        balance_depth += balance;
                    }

                    if ((balance == 0) && address_info.is_spent())
                    {
                        if (k >= start_index)
                        {
                            cur_gap_limit++;
                        }

                        if (!w.list_all())
                        {
                            continue;
                        }
                    }

                    if ((k < start_index) && !(balance > 0) && !w.list_all())
                    {
                        continue;
                    }

                    const auto used =
                        ((k < start_index) || balance ||
                         ((balance == 0) && address_info.is_spent()) ?
                         "used" : "new");

                    const auto balance_quotient = balance / 100000000;
                    const auto balance_remainder = balance % 100000000;
                    out << "   m/0/" << m << "/" << for_change << "/"
                        << std::setfill('0') << std::setw(4) << k
                        << std::setfill(' ') << std::setw(35) << address
                        << " " << std::setw(4) << used << " "
                        << balance_quotient << "." << std::setfill('0')
                        << std::setw(8) << balance_remainder
                        << " btc" << std::endl;
                }
            }

            const auto balance_depth_quotient = balance_depth / 100000000;
            const auto balance_depth_remainder = balance_depth % 100000000;
            out << "for mixdepth=" << m << " balance="
                << balance_depth_quotient << "." << std::setfill('0')
                << std::setw(8) << balance_depth_remainder
                << " btc" << std::endl;

            total_balance += balance_depth;
        }

        const auto total_balance_quotient = total_balance / 100000000;
        const auto total_balance_remainder = total_balance % 100000000;
        out << "total balance = " << total_balance_quotient << "."
            << std::setfill('0') << std::setw(8) << total_balance_remainder
            << " btc" << std::endl;

        return out;
    }

    const libbitcoin::ec_secret Wallet::get_key(
        uint32_t mix_depth, uint32_t for_change, uint32_t index) const
    {
        const auto key_pair = keys_[mix_depth];
        libbitcoin::wallet::hd_private key = (
            (for_change == 0) ? key_pair.first : key_pair.second);

        return key.derive_private(index).secret();
    }

    libbitcoin::ec_compressed Wallet::get_address(
        uint32_t mix_depth, uint32_t for_change, uint32_t index)
    {
        const auto& secret = get_key(mix_depth, for_change, index);
        libbitcoin::ec_compressed point;
        libbitcoin::secret_to_public(point, secret);
        return point;
    }

    const libbitcoin::ec_secret Wallet::get_key_from_address(
        std::string address) const
    {
        const auto address_info_iter = addresses_.find(address);
        return ((address_info_iter == addresses_.end()) ? ec_secret() :
                get_key(address_info_iter->second.mix_depth,
                    address_info_iter->second.for_change,
                        address_info_iter->second.index));
    }

    void Wallet::build_index_list_from_index_cache()
    {
        // initialize the index_cache from the wallet_map
        const auto index_cache_iter = wallet_map_.find("index_cache");
        JP_ASSERT(index_cache_iter != wallet_map_.end());

        std::vector<std::string> indices;
        boost::split(indices, index_cache_iter->second, boost::is_any_of("|"));
        if (max_mix_depth_ != indices.size())
        {
            logger.debug("Max mix depth", max_mix_depth_,
                "does not match index size", indices.size());
            max_mix_depth_ = indices.size();
        }

        index_list_.clear();
        index_list_.reserve(max_mix_depth_);
        for(auto i = 0; i < max_mix_depth_; i++)
        {
            const auto cur = indices[i];
            std::vector<std::string> values;
            boost::split(values, cur, boost::is_any_of(","));
            index_list_.emplace_back(std::atol(values[0].c_str()),
                                     std::atol(values[1].c_str()));
        }
    }

    bool Wallet::initialize_client_connection(const std::string server_address)
    {
        logger.info("Configured to use libbitcoin server", server_address);
        return client_.connect(server_address);
    }

    bool Wallet::fetch_address_info(
        libbitcoin::ec_compressed& point, const std::string& address,
        uint32_t mix_depth, uint32_t for_change, uint32_t index,
        AddressInfo& address_info)
    {
        auto ret = false;
        auto on_done = [this, point, address, mix_depth,
            for_change, index, &ret, &address_info](
                const chain::history::list& rows)
        {
            const auto& key = get_key(mix_depth, for_change, index);

            std::memset(&address_info, 0, sizeof(AddressInfo));

            address_info.transfers.reserve(rows.size());
            address_info.mix_depth = mix_depth;
            address_info.for_change = for_change;
            address_info.index = index;

            for(const auto& row : rows)
            {
                if ((row.spend_height == joinparty::unspent_height) &&
                    (row.spend.index == unspent_index))
                {
                    address_info.total_value += row.value;
                }
                address_info.transfers.emplace_back(
                    row.output, row.output_height, row.spend,
                    row.spend_height, row.value);
            }
            addresses_[address] = address_info;

            ret = true;
        };

        auto on_error = [this, &address, &ret](const code& error)
        {
            if (error)
            {
                logger.info(
                    "Failed to retrieve address information for", address);
                logger.info("It is likely that the libbitcoin server is down "
                    "or unreachable");

                ret = false;
            }
        };

        client_.address_fetch_history(on_error, on_done, address);
        client_.wait();

        return ret;
    }

    Wallet::AddressBalance Wallet::get_address_balance(
        const libbitcoin::wallet::payment_address& address)
    {
        Wallet::AddressBalance balance{0, 0, 0};

        auto on_done = [&balance, &address](
            const libbitcoin::chain::history::list& rows)
        {
            for(const auto& row : rows)
            {
                balance.total_received += row.value;

                if (row.spend.hash == null_hash)
                {
                    balance.unspent += row.value;
                }

                if (row.output_height != 0 &&
                    (row.spend.hash == null_hash || row.spend_height == 0))
                {
                    balance.confirmed += row.value;
                }
            }
            logger.info(
                "Current balance received in", address.encoded(),
                "is :", balance.total_received);
        };

        auto on_error = [](const code& error)
        {
            throw std::runtime_error("Failed to retrieve address balance");
        };

        client_.address_fetch_history2(on_error, on_done, address);
        client_.wait();

        return balance;
    }

    size_t Wallet::get_current_block_height()
    {
        size_t cur_height = 0;
        auto on_done = [&cur_height](size_t height)
        {
            cur_height = height;
        };

        auto on_error = [](const code& error)
        {
            throw std::runtime_error("Cannot retrieve block height.  It is "
                "likely that the libbitcoin server is down or unreachable");
        };

        client_.blockchain_fetch_last_height(on_error, on_done);
        client_.wait();

        return cur_height;
    }

    bool Wallet::get_transaction_info(
        const hash_digest& tx_hash, libbitcoin::chain::transaction& output_tx)
    {
        auto ret = false;
        size_t cur_height = 0;
        const auto str_hash = libbitcoin::encode_base16(tx_hash);
        memset(&output_tx, 0, sizeof(output_tx));

        auto on_done = [&](const libbitcoin::chain::transaction& tx)
        {
            output_tx = tx;
            ret = true;
        };

        auto on_error = [](const code& error)
        {
            logger.info("ERROR:", error.message());
        };

        client_.blockchain_fetch_transaction(on_error, on_done, tx_hash);
        client_.wait();

        return ret;
    }

    bool Wallet::transaction_is_valid(
        const libbitcoin::chain::transaction& transaction)
    {
        bool ret = false;

        auto on_done = [&ret](
            const libbitcoin::chain::point::indexes& indexes)
        {
            ret = (indexes.empty() ? true : false);
        };

        auto on_error = [&transaction](const code& error)
        {
            logger.info(
                "Failed to validate transaction: ", error.message());
            logger.info(
                "Failed transaction:", transaction.to_string(0xFFFFFF));
        };

        client_.transaction_pool_validate(on_error, on_done, transaction);
        client_.wait();

        return ret;
    }

    bool Wallet::send_transaction(
        const libbitcoin::chain::transaction& transaction)
    {
        bool ret = false;

        auto on_done = [&ret]()
        {
            logger.info("Payment has been sent");
            ret = true;
        };

        auto on_error = [](const code& error)
        {
            logger.info(
                "Failed to broadcast transaction ", error.message());
        };

        client_.protocol_broadcast_transaction(on_error, on_done, transaction);
        client_.wait();

        return ret;
    }

    bool Wallet::operator==(const Wallet& other) const
    {
        return (master_ == other.hd_private());
    }

    const joinparty::wallet_utils::WalletMap& Wallet::wallet_map() const
    {
        return wallet_map_;
    }

    const libbitcoin::wallet::hd_private Wallet::hd_private() const
    {
        return master_;
    }

    const std::string Wallet::encoded() const
    {
        return master_.encoded();
    }

    const void Wallet::set_list_all(bool list_all)
    {
        list_all_ = list_all;
    }

    const bool Wallet::list_all() const
    {
        return list_all_;
    }

    const bool Wallet::initialized() const
    {
        return initialized_;
    }

    const Wallet::IndexList Wallet::index_list() const
    {
        return index_list_;
    }

    const uint32_t Wallet::max_mix_depth() const
    {
        return max_mix_depth_;
    }

    const uint32_t Wallet::gap_limit() const
    {
        return gap_limit_;
    }

}; // namespace joinparty
