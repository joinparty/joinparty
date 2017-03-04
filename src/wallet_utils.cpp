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

#include "joinparty/wallet_utils.hpp"
#include "joinparty/utils.hpp"
#include "joinparty/json.hpp"

namespace joinparty
{

namespace wallet_utils
{
    void initialize_wallet_map(WalletMap& wallet_map)
    {
        static constexpr size_t max_creation_time_length = 32;
        const time_t now = time(NULL);
        struct tm* time_info = localtime(&now);
        static char buf[max_creation_time_length] = {0};
        strftime(buf, max_creation_time_length,
                 "%Y/%m/%d %H:%M:%S", time_info);

        wallet_map["checksum"] = {};
        wallet_map["encrypted_seed"] = {};
        wallet_map["creation_time"] = buf;
        wallet_map["network"] = joinparty::constants::bitcoin_network;
        wallet_map["index_cache"] = "0,0|0,0|0,0|0,0|0,0";
        wallet_map["creator"] =
            "joinparty " + joinparty::constants::joinparty_version;
    }

    void parse_wallet_file(
        std::string wallet_file, WalletMap& wallet_map)
    {
        std::ifstream wallet(wallet_file);
        if (!wallet.is_open())
        {
            throw std::runtime_error("Failed to open wallet file: " + wallet_file);
        }

        nlohmann::json json_data;
        wallet >> json_data;

        wallet_map["network"] = json_data["network"];
        wallet_map["creator"] = json_data["creator"];
        wallet_map["checksum"] = json_data["checksum"];
        wallet_map["index_cache"] = json_data["index_cache"];
        wallet_map["creation_time"] = json_data["creation_time"];
        wallet_map["encrypted_seed"] = json_data["encrypted_seed"];
    }

    void update_index_cache(WalletMap& wallet_map, uint32_t mix_depth,
                            uint32_t for_change, size_t increment)
    {
        auto index_cache_iter = wallet_map.find("index_cache");
        JP_ASSERT(index_cache_iter != wallet_map.end());
        std::vector<std::string> indices;
        boost::split(indices, index_cache_iter->second, boost::is_any_of("|"));
        if (mix_depth > indices.size())
        {
            throw std::runtime_error(
                "Requested update on mix_depth does not exist in cache");
        }

        const auto index_pair_str = indices[mix_depth];
        std::list<std::string> index_pair;
        boost::split(index_pair, index_pair_str, boost::is_any_of(","));

        const uint32_t external_index = atol(index_pair.front().c_str());
        const uint32_t internal_index = atol(index_pair.back().c_str());

        std::stringstream ss;
        const auto last_index = indices.size();
        for(auto i = 0; i < last_index; i++)
        {
            if (i == mix_depth)
            {
                ss << external_index + (for_change ? 0 : increment);
                ss << ",";
                ss << internal_index + (for_change ? increment : 0);
            }
            else
            {
                ss << indices[i];
            }

            if (i < (last_index - 1))
            {
                ss << "|";
            }
        }
        index_cache_iter->second = ss.str();
    }

    void write_wallet_map_to_wallet_file(
        std::string wallet_file, WalletMap& wallet_map)
    {
        std::ofstream wallet(wallet_file);
        if (!wallet.is_open())
        {
            throw std::runtime_error(
                "Failed to open wallet file: " + wallet_file);
        }

        nlohmann::json json_data;
        json_data["network"] = wallet_map["network"];
        json_data["creator"] = wallet_map["creator"];
        json_data["creation_time"] = wallet_map["creation_time"];
        json_data["encrypted_seed"] = wallet_map["encrypted_seed"];
        json_data["checksum"] = wallet_map["checksum"];
        json_data["index_cache"] = wallet_map["index_cache"];

        wallet << json_data << std::endl;

        wallet.flush();
        wallet.close();
    }

    bool initialize_wallet_from_mnemonic(
        libbitcoin::wallet::word_list& mnemonic,
        WalletMap& wallet_map, bool first_time)
    {
        hash_digest passphrase_hash;
        if (first_time)
        {
            std::string passphrase1 = "";
            std::string passphrase2 = "1";
            while(true)
            {
                std::cout << "\nEnter wallet encryption passphrase: ";
                joinparty::utils::get_passphrase(passphrase1);

                std::cout << "\nRe-enter wallet encryption passphrase: ";
                joinparty::utils::get_passphrase(passphrase2);
                std::cout << std::endl;

                if (passphrase1 == passphrase2)
                {
                    joinparty::utils::get_passphrase_key(passphrase_hash, passphrase1);
                    passphrase1.clear();
                    passphrase2.clear();
                    break;
                }
                std::cout << "Passphrases do not match!  Please try again"
                          << std::endl;
            }
        }
        else
        {
            std::cout << "\nEnter wallet encryption passphrase: ";
            std::string passphrase;
            joinparty::utils::get_passphrase(passphrase);
            joinparty::utils::get_passphrase_key(passphrase_hash, passphrase);
        }

        const auto& hash_start = reinterpret_cast<const char*>(&passphrase_hash);
        const auto passphrase_key = std::string(
            hash_start, hash_start + sizeof(passphrase_hash));

        auto seed = decode_mnemonic(mnemonic, passphrase_key);
        joinparty::utils::encrypt_data<decltype(seed)>(passphrase_hash, seed);

        // generate a checksum using encrypted seed and passphrase hash
        data_chunk extended(to_chunk(passphrase_hash));
        extend_data(extended, to_chunk(seed));
        const auto checksum = joinparty::utils::get_checksum(extended);

        initialize_wallet_map(wallet_map);
        wallet_map["encrypted_seed"] = encode_base16(seed);
        wallet_map["checksum"] = encode_base16(checksum);

        return true;
    }

    bool initialize_new_wallet(WalletMap& wallet_map)
    {
        static constexpr char recovery_warning[] =
            "\n*************************************************************\n"
            "  NOTE: It's *very* important that you write down this word\n"
            "  list in order to re-create your wallet in case it gets\n"
            "  corrupted or otherwise needs to be restored\n"
            "  (e.g. on another machine)\n"
            "*************************************************************\n";

        static constexpr auto entropy_length = 32;
        const auto entropy = joinparty::utils::generate_entropy(entropy_length);

        auto word_list = libbitcoin::wallet::create_mnemonic(
            entropy, libbitcoin::wallet::language::en);

        JP_ASSERT(libbitcoin::wallet::validate_mnemonic(
                      word_list, libbitcoin::wallet::language::en));

        std::cout << recovery_warning << std::endl;
        for(auto i = 0; i < word_list.size(); i++)
        {
            std::cout << "[" << std::setw(2) << i+1 <<  "] "
                      << word_list[i] << std::endl;
        }
        return initialize_wallet_from_mnemonic(word_list, wallet_map, true);
    }

    bool initialize_wallet(
        std::string wallet_file, WalletMap& wallet_map, bool create)
    {
        auto file_exists = joinparty::utils::file_exists(wallet_file);

        if (create)
        {
            if (file_exists)
            {
                std::cerr << "wallet file " << wallet_file
                          << " already exists." << std::endl;
                return false;
            }

            std::cout << "Generating a new wallet in " << wallet_file
                      << "..." << std::endl;

            WalletMap tmp_wallet_map;
            initialize_new_wallet(tmp_wallet_map);
            write_wallet_map_to_wallet_file(wallet_file, tmp_wallet_map);

            file_exists = joinparty::utils::file_exists(wallet_file);
        }

        if (!file_exists)
        {
            std::cerr << "wallet file " << wallet_file
                      << " does not exist." << std::endl;
            return false;
        }

        try
        {
            joinparty::wallet_utils::parse_wallet_file(wallet_file, wallet_map);
            return true;
        }
        catch(std::exception& e)
        {
            std::cerr << "initialize_wallet failed: " << e.what() << std::endl;
        }
        return false;
    }

    bool recover_wallet(std::string wallet_file)
    {
        if (joinparty::utils::file_exists(wallet_file))
            throw std::runtime_error(
                "Wallet file " + wallet_file + " already exists.  "
                "Cannot recover wallet to this location");

        word_list words;
        joinparty::utils::get_mnemonic_from_user_input(words);

        joinparty::wallet_utils::WalletMap wallet_map;
        if (joinparty::wallet_utils::initialize_wallet_from_mnemonic(
                words, wallet_map, false))
        {
            joinparty::wallet_utils::write_wallet_map_to_wallet_file(
                wallet_file, wallet_map);
        }
        return joinparty::utils::file_exists(wallet_file);
    }

    long_hash get_user_wallet_seed(joinparty::wallet_utils::WalletMap& wallet_map)
    {
        long_hash seed;

        std::cout << "\nEnter wallet encryption passphrase: ";
        std::string passphrase;
        joinparty::utils::get_passphrase(passphrase);

        hash_digest passphrase_hash;
        joinparty::utils::get_passphrase_key(passphrase_hash, passphrase);
        passphrase.clear();

        const auto encrypted_seed_iter = wallet_map.find("encrypted_seed");
        if (encrypted_seed_iter == wallet_map.end())
        {
            std::memset(&seed, 0, sizeof(seed));
            throw std::runtime_error(
                "Failed to retrieve encrypted seed from wallet_map");
        }
        decode_base16(seed, encrypted_seed_iter->second);

        const auto checksum_iter = wallet_map.find("checksum");
        if (checksum_iter == wallet_map.end())
        {
            std::memset(&seed, 0, sizeof(seed));
            throw std::runtime_error(
                "Failed to retrieve checksum from wallet_map");
        }
        data_chunk checksum;
        decode_base16(checksum, checksum_iter->second);

        // verify the checksum using encrypted seed and passphrase hash
        data_chunk extended(to_chunk(passphrase_hash));
        extend_data(extended, to_chunk(seed));

        if (!joinparty::utils::verify_checksum(checksum, extended))
        {
            std::memset(&seed, 0, sizeof(seed));
            throw std::runtime_error("Incorrect password entered");
        }

        decode_base16(seed, encrypted_seed_iter->second);
        joinparty::utils::decrypt_data<long_hash>(passphrase_hash, seed);

        std::memset(&passphrase_hash, 0, sizeof(passphrase_hash));
        return seed;
    }

}; // namespace wallet_utils

}; // namespace joinparty
