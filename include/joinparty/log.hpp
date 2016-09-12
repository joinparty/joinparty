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

#ifndef __LOG_HPP
#define __LOG_HPP

#include <time.h>
#include <ctime>
#include <array>
#include <fstream>
#include <iostream>

namespace joinparty
{

namespace log
{

static constexpr size_t time_size = 16;

class Log
{
  public:

    Log() : log_file_{}, verbose_(false), logging_initialized_(false)
    {
    }

    bool initialize(std::string log_name, bool verbose = false)
    {
        time_t cur_time;
        time(&cur_time);
        const auto time = localtime(&cur_time);
        std::array<char, time_size> timestamp{};
        std::strftime(timestamp.data(), time_size, "%F", time);

        log_file_.open(log_name);
        log_file_ << "# " << timestamp.data() << std::endl;
        logging_initialized_ = log_file_.is_open();
        verbose_ = verbose;

        return logging_initialized_;
    }

    template <typename T>
    void debug_continuation(T only)
    {
        if (logging_initialized_)
        {
            log_file_ << only << std::endl;
        }

        if (verbose_)
        {
            std::cout << only << std::endl;
        }
    }

    template <typename T, typename ... args>
    void debug_continuation(T current, args... next)
    {
        if (logging_initialized_)
        {
            log_file_ << current << " ";
        }

        if (verbose_)
        {
            std::cout << current << " ";
        }
        debug_continuation(next...);
    }

    template <typename T >
    void debug(T only)
    {
        time_t cur_time;
        time(&cur_time);
        const auto time = localtime(&cur_time);
        std::array<char, time_size> timestamp{};
        std::strftime(timestamp.data(), time_size, "%X", time);

        if (logging_initialized_)
        {
            log_file_ << "D:[" << timestamp.data() << "] " << only << std::endl;
        }

        if (verbose_)
        {
            std::cout << "D:[" << timestamp.data() << "] " << only << std::endl;
        }
    }

    template <typename T, typename ... args >
    void debug(T current, args... next)
    {
        time_t cur_time;
        time(&cur_time);
        const auto time = localtime(&cur_time);
        std::array<char, time_size> timestamp{};
        std::strftime(timestamp.data(), time_size, "%X", time);

        if (logging_initialized_)
        {
            log_file_ << "D:[" << timestamp.data() << "] " << current << " ";
        }

        if (verbose_)
        {
            std::cout << "D:[" << timestamp.data() << "] " << current << " ";
        }
        debug_continuation(next...);
    }

    template <typename T>
    void info_continuation(T only)
    {
        if (logging_initialized_)
        {
            log_file_ << only << std::endl;
        }
        std::cout << only << std::endl;
    }

    template <typename T, typename ... args>
    void info_continuation(T current, args... next)
    {
        if (logging_initialized_)
        {
            log_file_ << current << " ";
        }
        std::cout << current << " ";
        info_continuation(next...);
    }

    template <typename T >
    void info(T only)
    {
        time_t cur_time;
        time(&cur_time);
        const auto time = localtime(&cur_time);
        std::array<char, time_size> timestamp{};
        std::strftime(timestamp.data(), time_size, "%X", time);

        if (logging_initialized_)
        {
            log_file_ << "I:[" << timestamp.data() << "] " << only << std::endl;
        }
        std::cout << "I:[" << timestamp.data() << "] " << only << std::endl;
    }

    template <typename T, typename ... args >
    void info(T current, args... next)
    {
        time_t cur_time;
        time(&cur_time);
        const auto time = localtime(&cur_time);
        std::array<char, time_size> timestamp{};
        std::strftime(timestamp.data(), time_size, "%X", time);

        if (logging_initialized_)
        {
            log_file_ << "I:[" << timestamp.data() << "] " << current << " ";
        }
        std::cout << "I:[" << timestamp.data() << "] " << current << " ";
        info_continuation(next...);
    }

  private:

    std::ofstream log_file_;
    bool verbose_;
    bool logging_initialized_;
};

}; // namespace log

}; // namespace joinparty


#endif // __LOG_HPP
