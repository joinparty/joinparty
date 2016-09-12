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

#ifndef __ADDRESS_INFO_HPP
#define __ADDRESS_INFO_HPP

namespace joinparty
{

constexpr size_t num_confirmations = 6;
constexpr size_t unspent_height = 4294967295;
constexpr uint32_t unspent_index = 4294967295;

struct AddressInfo
{
    struct Transfer
    {
        Transfer(const chain::output_point& output_pt, const size_t o_height,
                 const chain::input_point& spend_pt, const size_t s_height,
                 const uint64_t val) :
        output(output_pt), output_height(o_height), spend(spend_pt),
            spend_height(s_height), value(val) {}

        chain::output_point output; // is_valid, hash, index
        size_t output_height;
        chain::input_point spend; // is_valid, hash, index
        size_t spend_height;
        uint64_t value;

        bool is_spent() const
        {
            return (spend.hash != null_hash);
        }

        bool confirmed(size_t height) const
        {
            return (height >= output_height + num_confirmations);
        }

        bool operator==(const Transfer &other) const
        {
            return (output_height == other.output_height &&
                    spend_height == other.spend_height &&
                    value == other.value &&
                    output == other.output &&
                    spend == other.spend);
        }
    };

    typedef std::vector<Transfer> TransferList;

    uint32_t mix_depth;
    uint32_t for_change;
    uint32_t index;
    uint64_t total_value;
    TransferList transfers;

    bool is_spent() const
    {
        auto ret = false, has_unspent = false;
        for(const auto& transfer : transfers)
        {
            ret = true;
            has_unspent = (transfer.spend.is_valid() &&
                           (transfer.spend.index == unspent_index) &&
                           (transfer.spend_height == unspent_height));
            if (has_unspent)
            {
                ret = false;
                break;
            }
        }
        return ret;
    }

    friend std::ostream& operator<<(std::ostream& out, const AddressInfo& ai)
    {
        out << "AddressInfo[" << ai.mix_depth << ", " << ai.for_change << ", "
            << ai.index << "] = " << ai.total_value << ", spent? "
            << (ai.is_spent() ? "true" : "false") << std::endl;
        return out;
    }

    bool operator==(const AddressInfo &other) const
    {
        auto ret = false;
        if (mix_depth == other.mix_depth &&
            for_change == other.for_change &&
            index == other.index &&
            total_value == other.total_value &&
            transfers.size() == other.transfers.size())
        {
            ret = true;

            size_t len = transfers.size();
            for(auto i = 0; i < len; i++)
            {
                if (!(transfers[i] == other.transfers[i]))
                {
                    ret = false;
                    break;
                }
            }
        }
        return ret;
    }
};

}; // namespace joinparty

#endif // __ADDRESS_INFO_HPP
