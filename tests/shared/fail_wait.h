/**
 * @file qbm/http/tests/shared/fail_wait.h
 * @brief The suite's one wait, and a failure planted in it, off unless asked for: with `QBM_HTTP_TEST_FAIL_WAIT_AT=k` in
 *        the environment, the k-th `wait_until()` / `expect_until()` of the process fails at once, as a wait that
 *        reached its deadline does, and the loop is turned after every case.
 *
 * What it is for. A case that fails must stay a failure of that case -- its `[  FAILED  ]` line, the rest of the
 * binary run. Since the HTTP clients answer from their destructor every callback they still hold (Huly QB-1246), a
 * case whose callbacks capture locals declared AFTER its client crashes when it fails: it returns early, those locals
 * die first, and the client's destructor writes into them -- under ASan a stack-use-after-scope that ends the binary
 * with no summary and no later case. Such a case passes as long as nothing fails, so no green run can see it.
 * `dev/agent/run-fail-wait.py` runs each case of a binary alone with k = 1, 2, ... until the case no longer reaches a
 * k-th wait, and requires every injected failure to end as one failed case.
 *
 * What a wait is, and where the suite has one. A WAIT is a loop that passes time -- it turns the event loop, sleeps,
 * or compares the clock -- until a condition ends it. The suite has one such loop, `fail_wait::wait()` here, reached
 * three ways: `qb::http::test::wait_until()`; `expect_until()`, which also records a failure at its deadline; and
 * `peer_wait_until()`, for a scripted peer on a thread of its own, which the kit never fails. A test's own helpers
 * (`ServerThread::pump_until`, the fixtures' `pump()`, the raw clients' `read_until()` and `send()`, ...) call them and
 * run no loop of their own: `dev/agent/run-fail-wait.py --lint` refuses one anywhere else under qbm/http/tests, and a
 * second definition of one of the three names. Two loops are no waits: a WINDOW, whose only condition is its bound
 * (the time, or a count) and which nothing leaves early, always runs its whole span; a loop in a destructor is the net
 * of a case that has ended. So the kit can fail every `wait_until()` / `expect_until()` the lint counts -- not the
 * peers' waits, counted apart, and not what waits with no loop of its own (a condition variable's `wait_for`, a
 * blocking `run_sync()`), which the lint does not see.
 *
 * A failable wait calls `fire()` first: a wait that fires records one `ADD_FAILURE()` and returns false, which is what
 * a wait that reached its deadline returns. After every case, once its
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

/// A sleep of `idle`, then a pass: the turn of a wait whose caller made the first pass itself, before its first look.
struct sleep_then_pass {
    std::chrono::microseconds idle;

    void
    operator()() const {
        std::this_thread::sleep_for(idle);
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
};

/// A sleep of `idle` and no pass: the turn of a wait for what another thread does.
struct nap {
    std::chrono::microseconds idle{1000};

    void
    operator()() const {
        std::this_thread::sleep_for(idle);
    }
};

/// No turn at all: the wait's condition does the waiting itself (a read or a poll that blocks for a bounded time).
struct no_turn {
    void
    operator()() const noexcept {}
};

/// The bound of a wait that has none: a service loop, which ends when its condition says so.
inline constexpr std::chrono::steady_clock::time_point never = std::chrono::steady_clock::time_point::max();

/// The instant a wait gives up, from what its caller gave: that instant, or a budget from now.
inline std::chrono::steady_clock::time_point
deadline(std::chrono::steady_clock::time_point const until) noexcept {
    return until;
}
template <typename Rep, typename Period>
std::chrono::steady_clock::time_point
deadline(std::chrono::duration<Rep, Period> const budget) noexcept {
    return std::chrono::steady_clock::now() + budget;
}

/// The thread the cases run on: the one that initialised this, gtest's main thread.
inline std::thread::id const case_thread = std::this_thread::get_id();

/// The one wait of the suite, which `wait_until()`, `expect_until()` and `peer_wait_until()` are: looks at `done`,
/// turns, until it holds or `until` is reached. Injected and armed, its k-th call returns false at once, its failure
/// recorded (`fire()`).
template <typename Done, typename Turn>
bool
wait(Done &done, std::chrono::steady_clock::time_point const until, char const *const helper, Turn &turn, bool const fails_at_deadline,
     bool const injected) {
    if (injected && fire(helper))
        return false;
    auto const began = std::chrono::steady_clock::now();
    while (!done()) {
        if (until != never && std::chrono::steady_clock::now() >= until) { // a service loop reads no clock
            if (done())
                return true;
            if (fails_at_deadline)
                ADD_FAILURE() << helper << ": predicate not satisfied within "
                              << std::chrono::duration_cast<std::chrono::milliseconds>(until - began).count() << "ms";
            return false;
        }
        turn();
    }
    return true;
}

} // namespace qb::http::test::fail_wait

namespace qb::http::test {

/**
 * @brief Looks at @p done and turns until it holds or @p bound is reached; whether @p done holds.
 *
 * The suite's wait: a test that waits for something to happen calls this (or `expect_until()`), never a loop of its
 * own -- `dev/agent/run-fail-wait.py --lint` refuses, anywhere else under qbm/http/tests, a loop that passes time until
 * a condition ends it -- so that every such wait is one the kit can make fail. It records nothing at its deadline: the
 * caller's assertion names what did not happen. @p bound is a budget from now or a `steady_clock` instant; @p helper
 * names the wait in the kit's line; @p turn is what happens between two looks at @p done: one pass of this thread's
 * loop by default (`fail_wait::one_pass`), a pass and a sleep (`pass_or_sleep`, `pass_then_sleep`, `sleep_then_pass`),
 * a sleep alone for what another thread does (`nap`), nothing when @p done itself blocks (`no_turn`), or the caller's.
 */
template <typename Done, typename Bound, typename Turn = fail_wait::one_pass>
bool
wait_until(Done &&done, Bound const &bound, char const *const helper = "wait_until", Turn &&turn = Turn{}) {
    return fail_wait::wait(done, fail_wait::deadline(bound), helper, turn, false, true);
}

/// `wait_until()` that records a non-fatal failure at its deadline, naming @p helper and the time it waited.
template <typename Done, typename Bound, typename Turn = fail_wait::one_pass>
bool
expect_until(Done &&done, Bound const &bound, char const *const helper = "expect_until", Turn &&turn = Turn{}) {
    return fail_wait::wait(done, fail_wait::deadline(bound), helper, turn, true, true);
}

/**
 * @brief The wait of a scripted peer on a thread of its own: `wait_until()` that the kit never fails.
 *
 * A peer the case scripts -- a raw server or client run by a `std::thread` -- waits for its script's next step here.
 * Failing such a wait would not be a wait of the case reaching its deadline but a peer that misbehaves, so the kit
 * leaves it alone, and the lint counts these calls apart from the ones it can fail. It is for a thread of the peer's
 * own only: called on the thread the cases run on, it records a failure -- a case's wait is `wait_until()`. @p bound may
 * be `fail_wait::never` for a service loop; @p turn is a sleep of 1 ms by default.
 */
template <typename Done, typename Bound, typename Turn = fail_wait::nap>
bool
peer_wait_until(Done &&done, Bound const &bound, Turn &&turn = Turn{}) {
    if (std::this_thread::get_id() == fail_wait::case_thread)
        ADD_FAILURE() << "[fail_wait] peer_wait_until() on the thread the cases run on: a case's wait is wait_until()";
    return fail_wait::wait(done, fail_wait::deadline(bound), "peer_wait_until", turn, false, false);
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
