/**
 * Copyright (c) 2011-2022 libbitcoin developers (see AUTHORS)
 *
 * This file is part of libbitcoin.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <bitcoin/system/crypto/secure_random.hpp>

#include <chrono>
#include <limits>
#include <boost/thread/tss.hpp>
#include <boost/random.hpp> // Include Boost's random library
#include <bitcoin/system/data/data.hpp>
#include <bitcoin/system/math/math.hpp>

namespace libbitcoin {
namespace system {

using namespace std::chrono;

// DO NOT USE srand() and rand() on MSVC as srand must be called per thread.
// Values may or may not be truly random depending on the underlying device.

void secure_random::fill(data_chunk& out) NOEXCEPT
{
    std::transform(out.begin(), out.end(), out.begin(), [](uint8_t) NOEXCEPT
    {
        return next();
    });
}

uint8_t secure_random::next() NOEXCEPT
{
    return next(minimum<uint8_t>, maximum<uint8_t>);
}

uint8_t secure_random::next(uint8_t begin, uint8_t end) NOEXCEPT
{
    std::uniform_int_distribution<uint16_t> distribution(begin, end);
    return static_cast<uint8_t>(distribution(get_csrng()));
}

std::random_device& secure_random::get_csrng() NOEXCEPT
{
    // Boost.thread will clean up the thread statics using this function.
    const auto deleter = [](std::random_device* csrng) NOEXCEPT
    {
        delete csrng;
    };

    // Maintain thread static state space.
    // This throws given insufficient resources.
    static boost::thread_specific_ptr<std::random_device> csrng(deleter);

    // This is thread safe because the instance is thread static.
    if (csrng.get() == nullptr)
    {
        csrng.reset(new std::random_device());
    }

    // The instance remains in scope and is deleted by thread_specific_ptr
    // when the thread terminates, so dereferencing the instance is safe.
    return *csrng;
}

// Randomly select a time duration in the range:
// [(expiration - expiration / ratio) .. expiration]
// Not fully testable due to lack of random engine injection.
steady_clock::duration secure_random::duration(
    const steady_clock::duration& expiration, uint8_t ratio) NOEXCEPT
{
    if (is_zero(ratio))
        return expiration;

    // Uses milliseconds level resolution.
    const auto max_expire = duration_cast<milliseconds>(expiration).count();

    // [10 secs, 4] => 10000 / 4 => 2500
    const auto limit = max_expire / ratio;

    if (is_zero(limit))
        return expiration;

    // [0..2^64) % 2500 => [0..2500]
    const auto random_offset = secure_random::next<uint64_t>(zero, limit);

    // (10000 - [0..2500]) => [7500..10000]
    const auto expires = max_expire - random_offset;

    // [7.5..10] second duration.
    return milliseconds(expires);
}

} // namespace system
} // namespace libbitcoin
