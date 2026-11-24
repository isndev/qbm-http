/**
 * @file qbm/http/tests/shared/watchdog.h
 * @brief A bound on a call that must return: past it the process ends, saying which call, so a test fails instead of
 *        hanging.
 *
 * A test of a blocking call made on the loop's own thread -- `run_sync()` from a callback -- cannot stop that call
 * from the same thread: the loop it pumps is the only thing running there. The watchdog is a thread that waits for the
 * call's end, up to its bound; past it, it writes one line to stderr and ends the process with `std::_Exit(3)`, which
 * ctest reads as the test's failure. Disarmed when it goes out of scope, it joins its thread.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

namespace qb::http::test {

/// Ends the process when the scope it guards has not ended within `bound`.
class watchdog {
public:
    watchdog(std::string what, std::chrono::milliseconds const bound)
        : _thread([this, what = std::move(what), bound] {
            std::unique_lock<std::mutex> lock(_mutex);
            if (!_ended.wait_for(lock, bound, [this] { return _disarmed; })) {
                std::fprintf(stderr, "watchdog: %s did not return within %lld ms\n", what.c_str(), static_cast<long long>(bound.count()));
                std::fflush(stderr);
                std::_Exit(3);
            }
        }) {}
    watchdog(watchdog const &)            = delete;
    watchdog &operator=(watchdog const &) = delete;
    ~watchdog() {
        {
            std::lock_guard<std::mutex> lock(_mutex);
            _disarmed = true;
        }
        _ended.notify_one();
        _thread.join();
    }

private:
    std::mutex              _mutex;
    std::condition_variable _ended;
    bool                    _disarmed = false;
    std::thread             _thread; ///< last: it starts once the members it reads exist
};

} // namespace qb::http::test
