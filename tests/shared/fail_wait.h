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
 * Every deadline wait of the suite is one function of this header: `qb::http::test::wait_until()`, or
 * `expect_until()`, which also records a failure at its deadline. A test's own helpers (`ServerThread::pump_until`,
 * the HTTP/3 fixtures' `pump()`, the HTTP/2 cases' `loop_until()`, ...) call them and run no loop of their own, and
 * `dev/agent/run-fail-wait.py --lint` refuses a loop that turns the event loop until a condition or a deadline
 * anywhere else under qbm/http/tests -- a window, which always runs its whole span, is not a wait. The wait calls
 * `fire()` first: a wait that fires records one `ADD_FAILURE()` and returns false, which is what a wait that reached
 * its deadline returns. After every case, once its
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
 * It includes gtest and qb-io's `async.h`, and is included by every test file that waits.
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
#include <thread>

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

/// One non-blocking pass of the calling thread's loop: what a wait turns, by default, between two looks at its condition.
struct one_pass {
    void
    operator()() const {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
};

/// A pass that sleeps `idle` when it invoked nothing: the turn of a wait whose loop may have no watcher due.
struct pass_or_sleep {
    std::chrono::microseconds idle;

    void
    operator()() const {
        if (qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT) == 0)
            std::this_thread::sleep_for(idle);
    }
};

/// A pass, then a sleep of `idle` whatever it invoked: the turn of a wait that paces itself.
struct pass_then_sleep {
    std::chrono::microseconds idle;

    void
    operator()() const {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        std::this_thread::sleep_for(idle);
    }
};

/// The one deadline wait of the suite, which `wait_until()` and `expect_until()` are: looks at `done`, turns, until it
/// holds or `budget` has elapsed. Armed, its k-th call returns false at once, its failure recorded (`fire()`).
template <typename Done, typename Turn>
bool
wait(Done &done, std::chrono::milliseconds const budget, char const *const helper, Turn &turn, bool const fails_at_deadline) {
    if (fire(helper))
        return false;
    auto const until = std::chrono::steady_clock::now() + budget;
    while (!done()) {
        if (std::chrono::steady_clock::now() >= until) {
            if (done())
                return true;
            if (fails_at_deadline)
                ADD_FAILURE() << helper << ": predicate not satisfied within " << budget.count() << "ms";
            return false;
        }
        turn();
    }
    return true;
}

} // namespace qb::http::test::fail_wait

namespace qb::http::test {

/**
 * @brief Turns the calling thread's loop until @p done holds or @p budget elapses; whether @p done holds.
 *
 * The suite's deadline wait: a test that waits for something to happen on its loop calls this (or `expect_until()`),
 * never a loop of its own -- `dev/agent/run-fail-wait.py --lint` refuses one anywhere else under qbm/http/tests, so
 * that every wait is one the kit can make fail. It records nothing at its deadline: the caller's assertion names what
 * did not happen. @p helper names the wait in the kit's line; @p turn is one pass between two looks at @p done
 * (`fail_wait::one_pass` by default, `fail_wait::pass_or_sleep{1ms}` for a loop that may be idle, or the caller's own).
 */
template <typename Done, typename Turn = fail_wait::one_pass>
bool
wait_until(Done &&done, std::chrono::milliseconds const budget, char const *const helper = "wait_until", Turn &&turn = Turn{}) {
    return fail_wait::wait(done, budget, helper, turn, false);
}

/// `wait_until()` that records a non-fatal failure at its deadline, naming @p helper and @p budget.
template <typename Done, typename Turn = fail_wait::one_pass>
bool
expect_until(Done &&done, std::chrono::milliseconds const budget, char const *const helper = "expect_until", Turn &&turn = Turn{}) {
    return fail_wait::wait(done, budget, helper, turn, true);
}

/**
 * @brief Joins a worker thread that this thread's loop serves: turns the loop until @p ended, then joins.
 *
 * The net of a case whose worker needs this thread's loop to finish -- the server it talks to runs here. Once a wait of
 * the case has failed, a bare `join()` waits for a worker that waits for this loop: the case hangs, where it must fail.
 * The turns happen in a destructor, the case's teardown: it fails nothing, and the kit never fails it. Bounded by
 * @p budget, after which it joins anyway.
 */
class serving_join {
public:
    serving_join(std::thread &worker, std::atomic<bool> const &ended, std::chrono::milliseconds const budget) noexcept
        : _worker(worker)
        , _ended(ended)
        , _budget(budget) {}
    serving_join(serving_join const &)            = delete;
    serving_join &operator=(serving_join const &) = delete;

    ~serving_join() {
        auto const until = std::chrono::steady_clock::now() + _budget;
        while (!_ended.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < until)
            if (qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT) == 0)
                std::this_thread::sleep_for(std::chrono::microseconds(200));
        if (_worker.joinable())
            _worker.join();
    }

private:
    std::thread                    &_worker;
    std::atomic<bool> const        &_ended;
    std::chrono::milliseconds const _budget;
};

/// `serving_join`, here and now: @p worker is joined when this returns, this thread's loop turned until @p ended.
inline void
join_serving(std::thread &worker, std::atomic<bool> const &ended, std::chrono::milliseconds const budget = std::chrono::seconds(60)) {
    serving_join const joined{worker, ended, budget};
}

} // namespace qb::http::test
