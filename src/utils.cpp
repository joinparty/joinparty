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

#include "joinparty/utils.hpp"

namespace joinparty
{

namespace utils
{

bool file_exists(std::string file)
{
    struct stat buffer;   
    return (stat(file.c_str(), &buffer) == 0);
}

void get_passphrase(std::string& passphrase)
{
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);

    tty.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);

    std::getline(std::cin, passphrase);

    tty.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);

    std::cout << std::endl;
}

void get_mnemonic_from_user_input(libbitcoin::wallet::word_list& words)
{
    static constexpr size_t word_multiple = 12;

    std::cout << "Enter all mnemonic words separated by spaces and then "
        "press enter" << std::endl;

    std::string line;
    std::getline(std::cin, line);

    boost::split(words, line, boost::is_any_of(" "));
    if ((words.size() % word_multiple) != 0)
    {
        throw std::runtime_error("incorrect word list retrieved. "
            "Number of words must be a multiple of 12");
    }
}

std::string bitcoin_address(const libbitcoin::ec_secret& secret)
{
    libbitcoin::ec_compressed point;
    libbitcoin::secret_to_public(point, secret);
    return bitcoin_address(point);
}

std::string bitcoin_address(const libbitcoin::ec_compressed& point)
{
    const libbitcoin::wallet::payment_address address(point);
    return address.encoded();
}

std::string bitcoin_address(const std::string hex_compressed)
{
    const auto pub = ec_public(hex_compressed);
    const auto address = libbitcoin::wallet::payment_address(pub);
    return address.encoded();
}

std::string bitcoin_address(const libbitcoin::chain::script& script)
{
    const auto script_address = payment_address::extract(script);
    return script_address.encoded();
}

void chunk_message(std::string message, size_t max_chunk_length,
    std::vector<std::string>& out_chunks)
{
    out_chunks.clear();

    const auto message_length = message.length();
    const auto num_chunks = (message_length / max_chunk_length) +
        ((message_length % max_chunk_length) ? 1 : 0);

    if (num_chunks)
    {
        out_chunks.reserve(num_chunks);

        auto start = message.begin();
        auto end = start + max_chunk_length;

        do
        {
            out_chunks.push_back(std::string(start, end));
            start = end;
            if (message.end() == end)
            {
                break;
            }
            else if ((message.end() - end) > max_chunk_length)
            {
                end += max_chunk_length;
            }
            else
            {
                end = message.end();
            }

        } while(end <= message.end());
    }
}

data_chunk uncompressed_public_from_private(
    const libbitcoin::ec_secret& secret)
{
    libbitcoin::wallet::ec_private private_key(secret, false);
    const auto public_key = private_key.to_public();

    libbitcoin::ec_uncompressed pub_key_data;
    public_key.to_uncompressed(pub_key_data);
    return to_chunk(pub_key_data);
}

data_chunk compressed_public_from_private(
    const libbitcoin::ec_secret& secret)
{
    libbitcoin::wallet::ec_private private_key(secret, true);
    const auto public_key = private_key.to_public();

    data_chunk pub_key_data;
    public_key.to_data(pub_key_data);
    return pub_key_data;
}

data_chunk public_from_private(
    const libbitcoin::ec_secret& secret, const bool compress)
{
    return (compress ? compressed_public_from_private(secret) :
        uncompressed_public_from_private(secret));
}

data_chunk generate_entropy(size_t num_bytes)
{
    data_chunk entropy(num_bytes);
    pseudo_random_fill(entropy);
    return entropy;
}

void get_passphrase_key(hash_digest& out_hash, const std::string& passphrase)
{
    const auto start = reinterpret_cast<const unsigned char*>(
        passphrase.c_str());
    const auto end = start + passphrase.length();
    out_hash = bitcoin_hash(array_slice<uint8_t>(start, end));
}

uint32_t get_random_number(uint32_t max)
{
    const auto rand_seed =
        std::chrono::system_clock::now().time_since_epoch().count();
    boost::random::mt19937 generator(rand_seed);
    return ((generator() + generator()) % max);
}

std::string generate_random_nickname(const size_t length)
{
    std::string nick;
    nick.reserve(length);

    static constexpr auto lower_case_start = 65;
    static constexpr auto upper_case_start = 97;

    const auto rand_seed =
        std::chrono::system_clock::now().time_since_epoch().count();
    boost::random::mt19937 generator(rand_seed);

    for(auto i = 0; i < length; i++)
    {
        auto increment = (((get_random_number(10)) > 5) ?
                          lower_case_start : upper_case_start);
        nick += static_cast<char>((get_random_number(26)) + increment);
    }
    return nick;
}

}; // namespace utils

}; // namespace joinparty
