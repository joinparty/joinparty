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

#ifndef __WALLET_HPP
#define __WALLET_HPP

#include <vector>
#include <utility>
#include <stdexcept>
#include <unordered_map>

#include <bitcoin/bitcoin.hpp>
#include <bitcoin/client/obelisk_client.hpp>

#include <boost/foreach.hpp>

#include "constants.hpp"
#include "utils.hpp"
#include "wallet_utils.hpp"
#include "address_info.hpp"

namespace joinparty
{

class OrderState;

static constexpr uint32_t locktime = 0;
static constexpr uint32_t script_version = 5;
static constexpr uint32_t transaction_version = 1;
static constexpr auto hash_type =
    libbitcoin::chain::signature_hash_algorithm::all;

class Wallet
{
  public:
    typedef std::pair<libbitcoin::ec_secret, AddressInfo::Transfer> Unspent;
    typedef std::vector<Unspent> UnspentList;

    typedef std::pair<uint32_t, uint32_t> Index;
    typedef std::vector<Index> IndexList;

    typedef std::unordered_map<std::string, AddressInfo> AddressInfoMap;

    typedef std::vector<libbitcoin::wallet::hd_private> KeyList;
    typedef std::pair<libbitcoin::wallet::hd_private,
        libbitcoin::wallet::hd_private> KeyPair;
    typedef std::vector<KeyPair> KeyPairList;

    struct AddressBalance
    {
        uint64_t total_received;
        uint64_t confirmed;
        uint64_t unspent;
    };

    // creates a wallet either from scratch (if create is true) or
    // from an existing wallet file (if create is false)
    explicit Wallet(
        wallet_utils::WalletMap& wallet_map,
        const std::vector<std::string>& server_addresses,
        uint32_t max_mix_depth = 1, uint32_t gap_limit = 6,
        bool extend_mixdepth = false);

    // given a seed, initializes the master private key of this wallet
    // and related internal structures
    void initialize_from_seed(libbitcoin::long_hash& seed);

    // signs an input (previous output hash/index) and sets it at the
    // specified input_index in the provided transaction
    void sign_transaction_inputs(UnspentList unspent_list,
        libbitcoin::chain::transaction& output_tx);

    // creates a transaction from the selected unpent outputs, then
    // signs and broadcasts the transaction to the bitcoin network.
    bool create_and_broadcast_transaction(
        const UnspentList& unspent, uint64_t& amount,
        const libbitcoin::wallet::payment_address destination_address,
        const uint64_t target_fee_per_kb, const uint64_t change_amount,
        const libbitcoin::wallet::payment_address change_address,
        bool subtract_fee_from_amount);

    // selects unspent outputs required for this join amount at this
    // mix_depth.  passes back that list, the next available
    // change_address, and the change_amount (if any).  if the
    // specified amount is 0, all utxos will be used and the amount
    // will be set to the total amount of those unspent outputs.  if
    // an address list (excluded) is specifed, no utxos associated
    // with that address will be returned.
    bool retrieve_unspent_and_change_address(UnspentList& selected_unspent,
        libbitcoin::wallet::payment_address& change_address,
        uint64_t& change_amount, const uint32_t mix_depth,
        uint64_t& amount, std::vector<std::string>* excluded = nullptr);

    // sends a payment from the utxos in the specified mix_depth
    //
    // if the amount specified is 0, all available funds will be sent
    // (this is used for sweeping everything in the specified
    // mix_depth) and the amount will be returned in amount
    bool send_payment(const uint32_t mix_depth, uint64_t& amount,
        const libbitcoin::wallet::payment_address destination_address,
        const uint64_t target_fee_per_kb, bool subtract_fee_from_amount);

    // retrieves all utxos from this mix depth as well as the next
    // available change address for use
    libbitcoin::chain::output_info::list get_unspent_outputs_for_mix_depth(
        const uint32_t mix_depth, UnspentList& unspent_list,     
        libbitcoin::wallet::payment_address& change_address,
        std::vector<std::string>* excluded = nullptr);

    // constructs a coin join transaction in preparation for filling
    // various maker orders.  change_amount and change_address specify
    // our change amount and change address.  each maker's cut is
    // computed.  if amount is 0, the total of the mix_depth is used
    // and stored in amount.
    bool create_coin_join_transaction(
        libbitcoin::chain::transaction& out_tx, const uint64_t amount,
        const libbitcoin::wallet::payment_address& destination_address,
        const uint64_t change_amount,
        const libbitcoin::wallet::payment_address& change_address,
        joinparty::Wallet::UnspentList& unspent,
        std::vector<joinparty::OrderState>& order_states,
        const uint64_t estimated_fee, const bool subtract_fee);

    const libbitcoin::ec_secret get_key(
        uint32_t mix_depth, uint32_t for_change, uint32_t index) const;

    libbitcoin::ec_compressed get_address(
        uint32_t mix_depth, uint32_t for_change, uint32_t index);

    const libbitcoin::ec_secret get_key_from_address(
        std::string address) const;

    Wallet::AddressBalance get_address_balance(
        const libbitcoin::wallet::payment_address& address);

    const joinparty::wallet_utils::WalletMap& wallet_map() const;
    const libbitcoin::wallet::hd_private hd_private() const;
    const std::string encoded() const;
    const void set_list_all(bool list_all);
    const bool list_all() const;
    const bool initialized() const;
    const IndexList index_list() const;
    const uint32_t max_mix_depth() const;
    const uint32_t gap_limit() const;

    friend std::ostream& operator<<(std::ostream& out, Wallet& w);
    bool operator==(const Wallet& other) const;

    bool get_transaction_info(
        const hash_digest& tx_hash,
        libbitcoin::chain::transaction& output_tx_type);

    bool transaction_is_valid(
        const libbitcoin::chain::transaction& transaction);

    bool send_transaction(const libbitcoin::chain::transaction& transaction);

    // builds IndexList object from entries in wallet_map["index_cache"]
    void build_index_list_from_index_cache();

    size_t get_current_block_height();

  private:
    void get_wallet_seed(long_hash& seed);

    // connects to the specified libbitcoin server
    bool initialize_client_connection(const std::string server_address);

    // fetches information about the specified address
    bool fetch_address_info(
        libbitcoin::ec_compressed& point, const std::string& address,
        uint32_t mix_depth, uint32_t for_change, uint32_t index,
        AddressInfo& address_info);

    KeyPairList keys_;
    bool initialized_;
    bool list_all_;
    uint32_t gap_limit_;
    bool extend_mixdepth_;
    IndexList index_list_;
    uint32_t max_mix_depth_;
    const std::vector<std::string>& server_addresses_;
    AddressInfoMap addresses_;
    libbitcoin::wallet::hd_private m_0_;
    joinparty::wallet_utils::WalletMap& wallet_map_;
    libbitcoin::wallet::hd_private master_;
    libbitcoin::client::obelisk_client client_;
};

}; // namespace joinparty

#endif // __WALLET_HPP
