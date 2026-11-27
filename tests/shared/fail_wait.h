/**
 * @file qbm/http/tests/shared/fail_wait.h
 * @brief A failure planted in the suite's wait helpers, off unless asked for: with `QBM_HTTP_TEST_FAIL_WAIT_AT=k` in
 *        the environment, the k-th wait of the process fails at once, as a wait that reached its deadline does, and
 *        the loop is turned after every case.
 *
 * What it is for. A case that fails must stay a failure of that case -- its `[  FAILED  ]` line, the rest of the
 * binary run. Since the HTTP clients answer from their destructor every callback they still hold (Huly QB-1246), a
 * case whose callbacks capture locals declared AFTER its client crashes when it fails: it returns early, those locals
 * die first, and the client's destructor writes into them -- under ASan a stack-use-after-scope that ends the binary
 * with no summary and no later case. Such a case passes as long as nothing fails, so no green run can see it.
 * `dev/agent/run-fail-wait.py` runs each case of a binary alone with k = 1, 2, ... until the case no longer reaches a
 * k-th wait, and requires every injected failure to end as one failed case.
 *
 * The three wait helpers call `fire()` before they wait: `ServerThread::pump_until` (loopback_server.h), the HTTP/3
 * loopback fixture's `pump()` and the HTTP/2 client cases' `loop_until()`. A wait that fires records one
 * `ADD_FAILURE()` and returns false, which is what the helper itself does at its deadline. After every case, once its
 * fixture is destroyed, a listener turns the calling thread's loop for `k_turn`: what the case left armed runs, as it
 * would under the next case of the binary, and the line it prints says how many waits the case reached.
 *
 * Unset, nothing changes: `fire()` reads a value computed once and returns false, no listener is installed and nothing
 * is printed. A value that is set but is not a positive number ends the process (exit 2) before the first case, saying
 * so -- a battery that misspelt its number must not read as one whose waits were never reached.
 *
 * Every line it prints starts with `[fail_wait] `, which is what the runner reads:
 *   - `[fail_wait] armed: wait <k> of this process fails` -- on stdout, before the first case: a death test's child
 *     runs the binary again, and the death test matches what that child writes to stderr;
 *   - `[fail_wait] injected: wait <k> (<helper>) fails, as at its deadline` -- the failure's message;
 *   - `[fail_wait] after <Suite.Case>: <n> waits reached, the loop turned for <ms> ms` -- on stderr, per case.
 *
 * It includes gtest and qb-io's `async.h`, and is included by the three helpers' files.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <atomic>
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstdlib>

#include <gtest/gtest.h>

#include <qb/io/async.h>

namespace qb::http::test::fail_wait {

/// The environment variable that arms the kit: the number of the wait, counted from 1 over the process, that fails.
inline constexpr char const *k_variable = "QBM_HTTP_TEST_FAIL_WAIT_AT";

/// How long the loop is turned after every case once the kit is armed.
inline constexpr std::chrono::milliseconds k_turn{300};

/// The wait that fails, 0 when the kit is off. A value that is set but is not a positive number ends the process.
inline int
target() noexcept {
    static int const k = [] {
        char const *const value = std::getenv(k_variable);
        if (value == nullptr)
            return 0;
        char      *end = nullptr;
        long const n   = std::strtol(value, &end, 10);
        if (end == value || *end != '\0' || n < 1 || n > INT_MAX) {
            std::fprintf(stderr, "[fail_wait] %s=\"%s\" is not a positive number: nothing runs\n", k_variable, value);
            std::fflush(stderr);
            std::_Exit(2);
        }
        return static_cast<int>(n);
    }();
    return k;
}

/// The waits the process reached so far, fired or not; counted only while the kit is armed.
inline std::atomic<int> &
reached() noexcept {
    static std::atomic<int> count{0};
    return count;
}

/// Called by a wait helper before it waits: true when this wait is the one that fails, its failure recorded.
inline bool
fire(char const *const helper) {
    int const k = target();
    if (k == 0)
        return false;
    if (reached().fetch_add(1, std::memory_order_relaxed) + 1 != k)
        return false;
    ADD_FAILURE() << "[fail_wait] injected: wait " << k << " (" << helper << ") fails, as at its deadline";
    return true;
}

/// Turns the loop after every case, once the case's fixture is gone, and says how many waits it reached.
class after_case final : public ::testing::EmptyTestEventListener {
public:
    void
    OnTestEnd(::testing::TestInfo const &info) override {
        for (auto const until = std::chrono::steady_clock::now() + k_turn; std::chrono::steady_clock::now() < until;)
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        std::fprintf(stderr, "[fail_wait] after %s.%s: %d waits reached, the loop turned for %lld ms\n", info.test_suite_name(), info.name(),
                     reached().load(std::memory_order_relaxed), static_cast<long long>(k_turn.count()));
        std::fflush(stderr);
    }
};

/// Installs the listener before the first case when the kit is armed; nothing at all otherwise.
inline bool const installed = [] {
    int const k = target();
    if (k == 0)
        return false;
    ::testing::UnitTest::GetInstance()->listeners().Append(new after_case);
    std::fprintf(stdout, "[fail_wait] armed: wait %d of this process fails\n", k);
    std::fflush(stdout);
    return true;
}();

} // namespace qb::http::test::fail_wait
