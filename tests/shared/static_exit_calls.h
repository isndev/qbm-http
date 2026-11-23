/**
 * @file qbm/http/tests/shared/static_exit_calls.h
 * @brief What the static-exit cases of the HTTP clients add to qb-io's `static_exit_support.h`: every outcome a case's
 *        callbacks hear is kept, and a push made while a client is being destroyed is seen answered inside the push.
 *
 * The judge of a case (`static_exit_support.h`) prints how many times the callbacks of what was in flight ran, and
 * the outcome of the LAST of them. Two things that line cannot say are said here, through the same line:
 *
 *   - a wrong status in the middle of a case -- a 502 between two 503 -- would be overwritten by the right one after
 *     it. `heard()` records a call as `called_with()` does, and from the first call whose outcome differs from the
 *     case's first one, the outcome the judge reads is `k_outcomes_differ`: every callback of a case hears the same;
 *   - a request pushed from a callback the destructor runs is answered INSIDE its push (Huly QB-1246), and a count of
 *     calls alone cannot tell that from an answer given later in the same destructor. `answered_inside()` runs a push
 *     and records a call of its own, `k_not_answered_inside`, when the push returned with no callback run.
 *
 * It includes qb-io's `static_exit_support.h` itself, and is included by a test of this module.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <utility>

#include "static_exit_support.h"

namespace qb::http::test::static_exit {

/// What the judge reads once two calls of a case heard different outcomes.
inline constexpr int k_outcomes_differ = -1;
/// The outcome of the call recorded for a push that returned before its callback ran.
inline constexpr int k_not_answered_inside = -2;

/// The outcome of the call recorded for a push made while its client is destroyed that did not go by the rule: the first a
/// callback of the destructor makes is answered inside the push, one made from inside that answer is refused by the
/// return value alone, its callback unheard (Huly QB-1246).
inline constexpr int k_not_as_the_rule = -3;

/// The callback of what a case left in flight ran, with `outcome`: `called_with()`, every outcome kept.
inline void
heard(int const outcome) noexcept {
    static int  first  = 0;
    static bool differ = false;
    if (qb::io::test::static_exit::g.calls == 0)
        first = outcome;
    differ = differ || outcome != first;
    qb::io::test::static_exit::called_with(differ ? k_outcomes_differ : outcome);
}

/// Runs `push` -- a request or a batch pushed while its client is being destroyed -- and sees it answered inside the
/// push: a callback ran before it returned.
template <typename Push>
void
answered_inside(Push &&push) {
    const int before = qb::io::test::static_exit::g.calls;
    std::forward<Push>(push)();
    if (qb::io::test::static_exit::g.calls == before)
        heard(k_not_answered_inside);
}

} // namespace qb::http::test::static_exit
