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
 * `dev/agent/run-fail-wait.py` runs each case of a binary alone, one wait failed a run, and requires every injected
 * failure to end as one failed case.
 *
 * What a wait is, and what holds that this is the one. A WAIT is a loop that passes time -- it turns the event loop,
 * sleeps, polls, compares the clock, or calls a function of the tests that does -- until a condition ends it. The kit's
 * is `fail_wait::wait()` here, reached three ways: `qb::http::test::wait_until()`; `expect_until()`, which also records
 * a failure at its deadline; and `peer_wait_until()`, for a scripted peer on a thread of its own, which the kit never
 * fails. A test's own helpers (`ServerThread::pump_until`, the fixtures' `pump()`, the raw clients' `read_until()` and
 * `send()`, ...) call them and run no loop of their own: `dev/agent/run-fail-wait.py --lint` refuses, anywhere else
 * under qbm/http/tests, every such loop it can read, an occurrence of one of the three names that is no call of the
 * kit's, a call of `fail_wait::wait()` itself, a `wait_until()` whose result is dropped, and a helper that reaches the
 * kit without naming its caller. Two loops are no waits: a WINDOW, whose only condition is its bound (the time, a
 * count, the items of a range), which nothing leaves early and whose passes no state decides, always runs its whole
 * span; a loop in a destructor is the net of a case that has ended. What the lint reads is text, and that is its
 * limit -- its docstring lists what it cannot see (a wait with no loop of its own, such as a condition variable's
 * `wait_for` or a blocking `run_sync()`; a pass behind a function defined outside the tests, a pointer or a macro; a
 * loop on a socket made blocking; recursion and `goto`). So the claim is the lint's: every wait it can read is this
 * one, and the kit can fail each `wait_until()` / `expect_until()` it counts -- not the peers' waits, counted apart.
 *
 * The wait itself is one look a turn: it looks at its condition, gives up if its deadline has passed, turns, and looks
 * again -- never twice with no turn between, so a condition that does something (reads a socket, accepts a
 * connection) does it once a turn, and not once more after the deadline. A failure the kit injects looks once too,
 * then fails: such a condition does what it does at a deadline, once.
 *
 * Where a wait is reached from. The kit names a wait by its PLACE: the line that called the kit, and before it the
 * line every helper on the way was called from -- `ServerThread::pump_until()` called at line 40 of a case is not the
 * same place as at line 60. A helper that reaches the kit takes `std::source_location const where =
 * std::source_location::current()` and holds a `fail_wait::called_from const caller{where};` as its first statement,
 * for as long as it runs; a helper it calls does the same, so the place is the whole path, outermost first (the
 * case's line, then each helper's, `>` between them). `--lint` refuses a helper that reaches the kit without it. A
 * gtest entry (the body of a case, `SetUp()`, `TearDown()`) and a function the framework calls (an `override`, a
 * destructor) take no caller: they are where a path starts.
 *
 * What a wait's result is for. `wait_until()` records nothing at its deadline and is `[[nodiscard]]`: its caller
 * asserts the result, returns it, or says why it reads none with `discard(wait_until(...), "why")` -- a window that
 * ends at its budget, a condition read again right after.
 *
 * Whose thread. `wait_until()` and `expect_until()` are the waits of the case, on the thread the cases run on: called on
 * another thread they record a failure, as `peer_wait_until()` does on the cases' thread -- a failure injected off the
 * cases' thread would be numbered by a race and recorded behind the case's back. A case whose body runs on a thread of
 * its own says so there, with a `fail_wait::case_on_this_thread` that lives as long as that body; while it lives, that
 * thread is the case's and no other is -- the thread the cases run on included -- and a second thread declaring it
 * records a failure.
 *
 * A failable wait calls `fire()` first: a wait that fires records one `ADD_FAILURE()` and returns false, which is what
 * a wait that reached its deadline returns. After every case, once its fixture is destroyed, a listener turns the
 * calling thread's loop for `k_turn`: what the case left armed runs, as it would under the next case of the binary,
 * and the lines it prints say which waits the case reached, and where.
 *
 * What the variable may say: `k`, the k-th failable wait of the process fails; `0`, none does -- the run a case gets
 * with the kit armed and nothing failed; `K+J`, past the K-th wait, the first wait of the J-th STRETCH fails -- a
 * stretch being consecutive waits at one place (one path to one `wait_until()` or `expect_until()` call, reached again
 * and again: a helper writing a thousand frames from one line of a case), which the runner fails once, at its first
 * wait, in a case that reaches more waits than it fails one by one. Each is digits alone -- no sign, no space, `J` at
 * least 1. Unset, nothing changes: `fire()` reads a value computed once and returns false, `called_from` keeps
 * nothing, no listener is installed and nothing is printed. Anything else ends the process (exit 2) before the first
 * case, saying so -- a battery that misspelt its number must not read as one whose waits were never reached.
 *
 * Every line it prints starts with `[fail_wait] `, which is what the runner reads:
 *   - `[fail_wait] armed: wait <k> of this process fails` (or `no wait of this process fails`, or `past wait <K>, the
 *     first wait of stretch <J> fails`) -- on stdout, before the first case: a death test's child runs the binary
 *     again, and the death test matches what that child writes to stderr;
 *   - `[fail_wait] injected: wait <k> (<helper>) at <place> fails, as at its deadline` -- the failure's message;
 *   - after a case, on stderr: `[fail_wait] site <place> (<helper>): <n> waits, the first wait <k>, stretch <j> past
 *     wait <K>` for every place a wait was reached from (the stretch its first wait opened, 0 when that wait is not
 *     past K: `K+j` names it again in a run whose stretches before it count the same), `[fail_wait] past wait <K>: <n>
 *     waits opened a stretch` under `K+J`, then `[fail_wait] after <Suite.Case>: <n> waits reached, the loop turned
 *     for <ms> ms`. A place is `<file>:<line>` steps joined by `>`, outermost first, with no space.
 *
 * It includes gtest and qb-io's `async.h`, and is included by every test file that waits.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <source_location>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <qb/io/async.h>

namespace qb::http::test::fail_wait {

/// The environment variable that arms the kit: `k`, `0` or `K+J` (see the file's header).
inline constexpr char const *k_variable = "QBM_HTTP_TEST_FAIL_WAIT_AT";

/// How long the loop is turned after every case once the kit is armed.
inline constexpr std::chrono::milliseconds k_turn{300};

/// What the variable asks for.
struct plan {
    bool armed   = false; ///< the variable is set: the listener is installed, the waits are counted
    int  at      = 0;     ///< `k`: the wait that fails, counted from 1 over the process; 0, none
    int  past    = 0;     ///< `K+J`: the wait past which stretches are counted
    int  stretch = 0;     ///< `K+J`: the stretch whose first wait fails, counted from 1 past `past`; 0 unless that form
};

/// Reads the digits at @p at into @p n, @p at moved past them: false when there are none, or more than an int holds.
inline bool
digits(char const *&at, long long &n) noexcept {
    if (*at < '0' || *at > '9')
        return false;
    for (n = 0; *at >= '0' && *at <= '9'; ++at)
        if ((n = n * 10 + (*at - '0')) > INT_MAX)
            return false;
    return true;
}

/// The variable, read once: `0`, `k` or `K+J`, digits alone. A value that is set and is none of them ends the process.
inline plan const &
asked() noexcept {
    static plan const said = [] {
        plan              out;
        char const *const value = std::getenv(k_variable);
        if (value == nullptr)
            return out;
        char const *at = value;
        long long   n  = 0;
        long long   j  = 0;
        bool        ok = digits(at, n);
        if (ok && *at == '+') {
            ++at;
            ok = digits(at, j) && j >= 1;
        }
        if (!ok || *at != '\0') {
            std::fprintf(stderr, "[fail_wait] %s=\"%s\" names no wait (k, 0 or K+J): nothing runs\n", k_variable, value);
            std::fflush(stderr);
            std::_Exit(2);
        }
        out.armed = true;
        if (j != 0) {
            out.past    = static_cast<int>(n);
            out.stretch = static_cast<int>(j);
        } else
            out.at = static_cast<int>(n);
        return out;
    }();
    return said;
}

/// A place a failable wait was reached from, and how often.
struct site {
    std::string place;  ///< `<file>:<line>` steps joined by `>`, outermost first
    char const *helper; ///< the name its first wait gave
    int         count;
    int         first;   ///< the number of its first wait
    int         stretch; ///< the stretch that wait opened, counted past `plan::past`; 0 when it is not past it
};

/// What the kit counts once armed: the waits reached, where from, and the stretches they make.
struct book {
    std::mutex        guard;
    int               reached   = 0; ///< failable waits reached so far, fired or not
    int               stretches = 0; ///< waits past `plan::past` whose place differs from the wait before them
    std::string       last;          ///< the place of the last wait reached
    std::vector<site> sites;
};

inline book &
kept() noexcept {
    static book *const one = new book; // never destroyed: a wait may be reached while the process ends
    return *one;
}

/// A source file's name without its directories.
inline char const *
leaf(char const *path) noexcept {
    char const *name = path;
    for (char const *c = path; *c != '\0'; ++c)
        if (*c == '/' || *c == '\\')
            name = c + 1;
    return name;
}

/// The callers of the helpers running on this thread, outermost first: what a `called_from` keeps while it lives.
inline std::vector<std::source_location> &
callers() noexcept {
    thread_local std::vector<std::source_location> kept;
    return kept;
}

/**
 * @brief The place a helper that reaches the kit was called from, kept for as long as the helper runs.
 *
 * A helper (`ServerThread::pump_until()`, a raw client's `write_all()`, a lambda a case calls from several lines)
 * takes `std::source_location const where = std::source_location::current()` and holds one of these first, so that
 * the waits it reaches are named by the line of its caller, not by its own line alone: two waits a case writes at two
 * lines through one helper are two places, and a case failed past `K` is failed at both. Unarmed, it keeps nothing.
 */
class called_from {
public:
    explicit called_from(std::source_location const where)
        : _kept(asked().armed) {
        if (_kept)
            callers().push_back(where);
    }
    called_from(called_from const &)            = delete;
    called_from &operator=(called_from const &) = delete;
    ~called_from() {
        if (_kept)
            callers().pop_back();
    }

private:
    bool const _kept;
};

/// The place of a wait whose kit call is at @p where: the callers kept on this thread, then @p where.
inline std::string
place_of(std::source_location const &where) {
    std::string out;
    for (std::source_location const &step : callers()) {
        out += leaf(step.file_name());
        out += ':';
        out += std::to_string(step.line());
        out += '>';
    }
    out += leaf(where.file_name());
    out += ':';
    out += std::to_string(where.line());
    return out;
}

/// Called by a failable wait before it waits: true when this wait is the one that fails, its failure recorded.
inline bool
fire(char const *const helper, std::source_location const &where) {
    plan const &said = asked();
    if (!said.armed)
        return false;
    std::string const     place = place_of(where);
    book                 &b     = kept();
    std::lock_guard const lock(b.guard);
    int const             k     = ++b.reached;
    bool const            opens = k == 1 || b.last != place;
    b.last                      = place;
    auto const known            = std::find_if(b.sites.begin(), b.sites.end(), [&](site const &s) { return s.place == place; });
    if (opens && k > said.past)
        ++b.stretches;
    if (known == b.sites.end())
        b.sites.push_back({place, helper, 1, k, k > said.past ? b.stretches : 0});
    else
        ++known->count;
    if (said.stretch != 0 ? !(opens && k > said.past && b.stretches == said.stretch) : k != said.at)
        return false;
    ADD_FAILURE() << "[fail_wait] injected: wait " << k << " (" << helper << ") at " << place << " fails, as at its deadline";
    return true;
}

/// Turns the loop after every case, once the case's fixture is gone, and says which waits it reached.
class after_case final : public ::testing::EmptyTestEventListener {
public:
    void
    OnTestEnd(::testing::TestInfo const &info) override {
        for (auto const until = std::chrono::steady_clock::now() + k_turn; std::chrono::steady_clock::now() < until;)
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        book                 &b = kept();
        std::lock_guard const lock(b.guard);
        for (site const &s : b.sites)
            std::fprintf(stderr, "[fail_wait] site %s (%s): %d waits, the first wait %d, stretch %d past wait %d\n", s.place.c_str(), s.helper,
                         s.count, s.first, s.stretch, asked().past);
        if (asked().stretch != 0)
            std::fprintf(stderr, "[fail_wait] past wait %d: %d waits opened a stretch\n", asked().past, b.stretches);
        std::fprintf(stderr, "[fail_wait] after %s.%s: %d waits reached, the loop turned for %lld ms\n", info.test_suite_name(), info.name(),
                     b.reached, static_cast<long long>(k_turn.count()));
        std::fflush(stderr);
    }
};

/// Installs the listener before the first case when the kit is armed; nothing at all otherwise.
inline bool const installed = [] {
    plan const &said = asked();
    if (!said.armed)
        return false;
    ::testing::UnitTest::GetInstance()->listeners().Append(new after_case);
    if (said.stretch != 0)
        std::fprintf(stdout, "[fail_wait] armed: past wait %d, the first wait of stretch %d fails\n", said.past, said.stretch);
    else if (said.at != 0)
        std::fprintf(stdout, "[fail_wait] armed: wait %d of this process fails\n", said.at);
    else
        std::fprintf(stdout, "[fail_wait] armed: no wait of this process fails\n");
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

/// The bound of a wait that has none: a peer's service loop, which ends when its condition says so. A type of its own,
/// which only `peer_wait_until()` takes: a wait the kit can fail always has a deadline.
struct never_t {
    explicit constexpr never_t() noexcept = default;
};
inline constexpr never_t never{};

/// The instant no wait reaches: what `never` is to the wait's loop, which then reads no clock.
inline constexpr std::chrono::steady_clock::time_point no_deadline = std::chrono::steady_clock::time_point::max();

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

/// The same for a peer's wait, which may have none.
inline std::chrono::steady_clock::time_point
peer_deadline(never_t) noexcept {
    return no_deadline;
}
template <typename Bound>
std::chrono::steady_clock::time_point
peer_deadline(Bound const &bound) noexcept {
    return deadline(bound);
}

/// The thread the cases run on: the one that initialised this, gtest's main thread.
inline std::thread::id const case_thread = std::this_thread::get_id();

/// The thread a `case_on_this_thread` declared the case's, while one lives: how many it holds, and whose.
struct declared_thread {
    std::mutex      guard;
    std::thread::id owner{};
    int             depth = 0;
};

inline declared_thread &
declared() noexcept {
    static declared_thread *const one = new declared_thread; // never destroyed: a wait may run while the process ends
    return *one;
}

/// Declares, for as long as it lives, that the body of the case runs on the calling thread -- a case that hands its
/// whole body to a `std::thread` and joins it. The case's waits are then that thread's, and no other thread's: a
/// `wait_until()` on the thread the cases run on records a failure meanwhile, as one on a second thread that declares
/// itself the case's does here.
class case_on_this_thread {
public:
    case_on_this_thread() {
        declared_thread      &d = declared();
        std::lock_guard const lock(d.guard);
        _second = d.depth > 0 && d.owner != std::this_thread::get_id();
        if (_second) {
            ADD_FAILURE() << "[fail_wait] case_on_this_thread on a second thread: the case's body runs on one thread at a time";
            return;
        }
        d.owner = std::this_thread::get_id();
        ++d.depth;
    }
    case_on_this_thread(case_on_this_thread const &)            = delete;
    case_on_this_thread &operator=(case_on_this_thread const &) = delete;
    ~case_on_this_thread() {
        if (_second)
            return;
        declared_thread      &d = declared();
        std::lock_guard const lock(d.guard);
        --d.depth;
    }

private:
    bool _second = false;
};

/// Whether the calling thread is the one the case's body runs on: the thread a `case_on_this_thread` declared while
/// one lives, the thread the cases run on otherwise.
inline bool
on_the_cases_thread() noexcept {
    declared_thread      &d = declared();
    std::lock_guard const lock(d.guard);
    return d.depth > 0 ? d.owner == std::this_thread::get_id() : std::this_thread::get_id() == case_thread;
}

/// The one wait of the suite, which `wait_until()`, `expect_until()` and `peer_wait_until()` are: one look at `done` a
/// turn -- a look, the deadline, a turn -- until it holds or `until` has passed. Injected and armed, the call the
/// variable names looks at `done` once and returns false, its failure recorded (`fire()`): what a wait whose deadline
/// has passed does, once.
template <typename Done, typename Turn>
bool
wait(Done &done, std::chrono::steady_clock::time_point const until, char const *const helper, Turn &turn, bool const fails_at_deadline,
     bool const injected, std::source_location const &where) {
    if (injected && fire(helper, where)) {
        static_cast<void>(done());
        return false;
    }
    auto const began = std::chrono::steady_clock::now();
    for (;;) {
        if (done())
            return true;
        if (until != no_deadline && std::chrono::steady_clock::now() >= until) { // a service loop reads no clock
            if (fails_at_deadline)
                ADD_FAILURE() << helper << ": predicate not satisfied within "
                              << std::chrono::round<std::chrono::milliseconds>(until - began).count() << "ms";
            return false;
        }
        turn();
    }
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
 * @p done is looked at once a turn. It is the case's wait: off the thread the cases run on it records a failure
 * (`fail_wait::case_on_this_thread`). @p where is the line of this call, which the kit's lines name after the places
 * of the helpers on the way (`fail_wait::called_from`). Its result is the caller's to read: asserted, returned, or
 * dropped through `discard()` with the reason.
 */
template <typename Done, typename Bound, typename Turn = fail_wait::one_pass>
[[nodiscard]] bool
wait_until(Done &&done, Bound const &bound, char const *const helper = "wait_until", Turn &&turn = Turn{},
           std::source_location const where = std::source_location::current()) {
    if (!fail_wait::on_the_cases_thread())
        ADD_FAILURE() << "[fail_wait] wait_until() off the thread the cases run on (" << helper << "): a peer's wait is peer_wait_until()";
    return fail_wait::wait(done, fail_wait::deadline(bound), helper, turn, false, true, where);
}

/// `wait_until()` that records a non-fatal failure at its deadline, naming @p helper and the time it waited.
template <typename Done, typename Bound, typename Turn = fail_wait::one_pass>
bool
expect_until(Done &&done, Bound const &bound, char const *const helper = "expect_until", Turn &&turn = Turn{},
             std::source_location const where = std::source_location::current()) {
    if (!fail_wait::on_the_cases_thread())
        ADD_FAILURE() << "[fail_wait] expect_until() off the thread the cases run on (" << helper << "): a peer's wait is peer_wait_until()";
    return fail_wait::wait(done, fail_wait::deadline(bound), helper, turn, true, true, where);
}

/// Drops the result of a `wait_until()` the caller reads no further, and says why: @p why names what makes it not
/// worth reading -- a window that ends at its budget, a condition the caller reads again right after. A wait dropped
/// this way records nothing at a real deadline; what @p why names must.
inline void
discard(bool const held, std::string_view const why) noexcept {
    static_cast<void>(held);
    static_cast<void>(why);
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
    if (fail_wait::on_the_cases_thread())
        ADD_FAILURE() << "[fail_wait] peer_wait_until() on the thread the cases run on: a case's wait is wait_until()";
    return fail_wait::wait(done, fail_wait::peer_deadline(bound), "peer_wait_until", turn, false, false, std::source_location::current());
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
