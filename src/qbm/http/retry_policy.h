/**
 * @file qbm/http/retry_policy.h
 * @brief The reconnection backoff policy shared by the qbm-http clients (Huly QB-103).
 *
 * The same shape as `qb::redis::RetryPolicy`, so a reader of one knows the other: attempt 1 is
 * immediate, attempt 2 waits `initial_delay`, every further attempt multiplies the wait by
 * `multiplier` up to `max_delay`, each wait jittered by up to a quarter either way when `jitter`
 * is on, `max_attempts` bounds the run (-1 = unlimited), and `on_retry(attempt, next_delay)` is
 * told, before each wait, how many attempts failed and how long the wait will be. The one field
 * the redis policy carries that this one does not is `connect_timeout`: an HTTP client already
 * owns that setting (`set_connect_timeout`), and it applies to every attempt.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <algorithm>
#include <chrono>
#include <functional>
#include <random>

#include <qb/system/time.h>

namespace qb::http {

/**
 * @struct RetryPolicy
 * @brief Exponential backoff with jitter and a cap on the run, for a client's automatic
 *        reconnection. Pure data plus one pure function, so a policy is testable on its own.
 */
struct RetryPolicy {
    int                                                       max_attempts = -1; ///< attempts per run, -1 = unlimited
    qb::duration                                              initial_delay{std::chrono::milliseconds(100)}; ///< the wait before attempt 2
    qb::duration                                              max_delay{std::chrono::seconds(30)};           ///< the wait never grows past this
    double                                                    multiplier = 2.0;  ///< growth factor between consecutive waits
    bool                                                      jitter     = true; ///< +-25 % on every wait
    std::function<void(int attempt, qb::duration next_delay)> on_retry;          ///< called before each wait

    /** @brief Set maximum number of attempts per run (-1 = unlimited) */
    RetryPolicy &
    with_max_attempts(int n) noexcept {
        max_attempts = n;
        return *this;
    }
    /** @brief Set the wait before the second attempt */
    RetryPolicy &
    with_initial_delay(qb::duration d) noexcept {
        initial_delay = d;
        return *this;
    }
    /** @brief Set the cap the wait never grows past */
    RetryPolicy &
    with_max_delay(qb::duration d) noexcept {
        max_delay = d;
        return *this;
    }
    /** @brief Set the exponential backoff multiplier (below 1 reads as 1: the wait never shrinks) */
    RetryPolicy &
    with_multiplier(double m) noexcept {
        multiplier = m;
        return *this;
    }
    /** @brief Enable/disable random jitter on the waits */
    RetryPolicy &
    with_jitter(bool j) noexcept {
        jitter = j;
        return *this;
    }
    /** @brief Set the callback invoked before each wait (attempts failed so far, next_delay) */
    RetryPolicy &
    with_on_retry(std::function<void(int, qb::duration)> cb) {
        on_retry = std::move(cb);
        return *this;
    }

    /**
     * @brief The wait after `attempt` failed attempts, before attempt `attempt + 1`.
     *
     * Zero for `attempt < 1` (the first attempt is immediate); `initial_delay` after one failure;
     * then `initial_delay * multiplier^(attempt - 1)`, each step capped at `max_delay` -- the same
     * integer-millisecond arithmetic `qb::redis::connect_with_retry` runs. With `jitter` on and an
     * `rng` given, a uniform +-25 % of the wait is added, and the result never drops below 1 ms
     * once the wait was positive: a policy whose waits are zero (an `initial_delay` of zero) stays
     * at zero, on purpose, since that is what was asked for.
     */
    [[nodiscard]] qb::duration
    next_delay(int attempt, std::mt19937 *rng = nullptr) const {
        using rep = std::chrono::milliseconds::rep;
        if (attempt < 1) {
            return qb::duration::zero();
        }
        const rep    max_ms   = std::max<rep>(0, std::chrono::duration_cast<std::chrono::milliseconds>(max_delay).count());
        rep          delay_ms = std::clamp<rep>(std::chrono::duration_cast<std::chrono::milliseconds>(initial_delay).count(), 0, max_ms);
        const double growth   = std::max(1.0, multiplier);
        for (int i = 1; i < attempt && delay_ms < max_ms; ++i) {
            const double next = static_cast<double>(delay_ms) * growth;
            delay_ms          = next >= static_cast<double>(max_ms) ? max_ms : static_cast<rep>(next);
        }
        if (jitter && rng != nullptr && delay_ms > 0) {
            const rep                          quarter = delay_ms / 4;
            std::uniform_int_distribution<rep> dist{-quarter, quarter};
            delay_ms = std::max<rep>(1, delay_ms + dist(*rng));
        }
        return qb::duration{std::chrono::milliseconds{delay_ms}};
    }
};

} // namespace qb::http
