/**
 * @file qbm/http/tests/unit/retry-policy/retry-policy.cpp
 * @brief Pure-logic unit tests for `qb::http::RetryPolicy` (retry_policy.h), the backoff the
 *        HTTP/2 client's automatic reconnection follows (Huly QB-103).
 *
 * The policy is data plus one pure function, `next_delay(attempt, rng)`: the wait after `attempt`
 * failed attempts. No loop, no socket, no client: every case calls it directly, with a seeded
 * generator where jitter is on, so the arithmetic the client relies on is pinned here and the
 * system suite only has to prove the client OBEYS it.
 *
 * What is pinned, and why each matters:
 *   - the first attempt is immediate (attempt 0 waits nothing);
 *   - the defaults are `qb::redis::RetryPolicy`'s (100 ms, x2, 30 s cap, jitter on, unlimited),
 *     so a reader of one module knows the other;
 *   - the growth is geometric, capped at `max_delay`, and STOPS at the cap: attempt 1000 with a
 *     multiplier of 10 is the cap, not an overflow;
 *   - jitter is +-25 % in integer milliseconds and never takes a positive wait below 1 ms, while a
 *     zero wait stays zero (an `initial_delay` of zero asks for immediate retries and gets them);
 *   - the pathological inputs read sanely: an initial delay above the cap is the cap, a multiplier
 *     below 1 is 1, a negative attempt is 0.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <chrono>
#include <random>

#include <qbm/http/retry_policy.h>

using namespace std::chrono_literals;

namespace {

[[nodiscard]] long long
ms(qb::duration d) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(d).count();
}

TEST(RetryPolicy, FirstAttemptIsImmediate) {
    qb::http::RetryPolicy policy;
    EXPECT_EQ(policy.next_delay(0), qb::duration::zero());
    EXPECT_EQ(policy.next_delay(-1), qb::duration::zero()) << "a negative attempt count reads as none";
    std::mt19937 rng{7};
    EXPECT_EQ(policy.next_delay(0, &rng), qb::duration::zero()) << "jitter has nothing to add to a zero wait";
}

TEST(RetryPolicy, DefaultsAreTheRedisOnes) {
    const qb::http::RetryPolicy policy;
    EXPECT_EQ(policy.max_attempts, -1);
    EXPECT_EQ(policy.initial_delay, 100ms);
    EXPECT_EQ(policy.max_delay, 30s);
    EXPECT_DOUBLE_EQ(policy.multiplier, 2.0);
    EXPECT_TRUE(policy.jitter);
    EXPECT_FALSE(policy.on_retry);
    // Without a generator the jitter is not applied, so the defaults read exactly.
    EXPECT_EQ(ms(policy.next_delay(1)), 100);
    EXPECT_EQ(ms(policy.next_delay(2)), 200);
    EXPECT_EQ(ms(policy.next_delay(3)), 400);
    EXPECT_EQ(ms(policy.next_delay(9)), 25600);
    EXPECT_EQ(ms(policy.next_delay(10)), 30000) << "100 ms * 2^9 = 51.2 s is past the 30 s cap";
}

TEST(RetryPolicy, GrowsGeometricallyAndStopsAtTheCap) {
    const auto policy = qb::http::RetryPolicy{}.with_initial_delay(30ms).with_multiplier(2.0).with_max_delay(500ms).with_jitter(false);
    EXPECT_EQ(ms(policy.next_delay(1)), 30);
    EXPECT_EQ(ms(policy.next_delay(2)), 60);
    EXPECT_EQ(ms(policy.next_delay(3)), 120);
    EXPECT_EQ(ms(policy.next_delay(4)), 240);
    EXPECT_EQ(ms(policy.next_delay(5)), 480);
    EXPECT_EQ(ms(policy.next_delay(6)), 500) << "960 would be past the cap";
    EXPECT_EQ(ms(policy.next_delay(7)), 500);
    EXPECT_EQ(ms(policy.next_delay(1000)), 500) << "the growth stops at the cap: no overflow, whatever the attempt";
}

TEST(RetryPolicy, HugeMultiplierAndAttemptDoNotOverflow) {
    const auto policy = qb::http::RetryPolicy{}.with_initial_delay(1ms).with_multiplier(1e9).with_max_delay(2s).with_jitter(false);
    EXPECT_EQ(ms(policy.next_delay(2)), 2000);
    EXPECT_EQ(ms(policy.next_delay(1000)), 2000);
}

TEST(RetryPolicy, NonIntegralMultiplierTruncatesInMilliseconds) {
    const auto policy = qb::http::RetryPolicy{}.with_initial_delay(100ms).with_multiplier(1.5).with_max_delay(10s).with_jitter(false);
    EXPECT_EQ(ms(policy.next_delay(1)), 100);
    EXPECT_EQ(ms(policy.next_delay(2)), 150);
    EXPECT_EQ(ms(policy.next_delay(3)), 225);
    EXPECT_EQ(ms(policy.next_delay(4)), 337) << "337.5 truncates, as the redis arithmetic does";
}

TEST(RetryPolicy, JitterStaysWithinAQuarterEitherWay) {
    const auto   policy = qb::http::RetryPolicy{}.with_initial_delay(100ms).with_jitter(true);
    std::mt19937 rng{20260909};
    long long    lo = 1'000'000, hi = 0;
    for (int i = 0; i < 2000; ++i) {
        const auto d = ms(policy.next_delay(1, &rng));
        lo           = std::min(lo, d);
        hi           = std::max(hi, d);
        ASSERT_GE(d, 75);
        ASSERT_LE(d, 125);
    }
    EXPECT_LT(lo, 85) << "2000 draws of a uniform +-25 must reach the low quarter";
    EXPECT_GT(hi, 115) << "and the high one";
    // The cap bounds the base, not the jittered result: a jittered wait may exceed max_delay by
    // the quarter, exactly as qb::redis::connect_with_retry's does.
    const auto capped = qb::http::RetryPolicy{}.with_initial_delay(1s).with_max_delay(1s).with_jitter(true);
    for (int i = 0; i < 200; ++i) {
        const auto d = ms(capped.next_delay(5, &rng));
        ASSERT_GE(d, 750);
        ASSERT_LE(d, 1250);
    }
}

TEST(RetryPolicy, JitterNeverTakesAPositiveWaitBelowOneMillisecond) {
    std::mt19937 rng{3};
    const auto   tiny = qb::http::RetryPolicy{}.with_initial_delay(1ms).with_jitter(true);
    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(ms(tiny.next_delay(1, &rng)), 1) << "a quarter of 1 ms is 0 ms: nothing to add, nothing to remove";
    }
    const auto four = qb::http::RetryPolicy{}.with_initial_delay(4ms).with_jitter(true);
    for (int i = 0; i < 200; ++i) {
        const auto d = ms(four.next_delay(1, &rng));
        ASSERT_GE(d, 3);
        ASSERT_LE(d, 5);
    }
}

TEST(RetryPolicy, ZeroInitialDelayStaysZeroEvenJittered) {
    std::mt19937 rng{11};
    const auto   policy = qb::http::RetryPolicy{}.with_initial_delay(0ms).with_jitter(true);
    EXPECT_EQ(policy.next_delay(1, &rng), qb::duration::zero());
    EXPECT_EQ(policy.next_delay(5, &rng), qb::duration::zero()) << "zero times any multiplier is zero: immediate retries were asked for";
}

TEST(RetryPolicy, InitialDelayAboveTheCapIsTheCap) {
    const auto policy = qb::http::RetryPolicy{}.with_initial_delay(5s).with_max_delay(1s).with_jitter(false);
    EXPECT_EQ(ms(policy.next_delay(1)), 1000);
    EXPECT_EQ(ms(policy.next_delay(3)), 1000);
}

TEST(RetryPolicy, MultiplierBelowOneReadsAsOne) {
    const auto shrinking = qb::http::RetryPolicy{}.with_initial_delay(200ms).with_multiplier(0.5).with_jitter(false);
    EXPECT_EQ(ms(shrinking.next_delay(1)), 200);
    EXPECT_EQ(ms(shrinking.next_delay(4)), 200) << "the wait never shrinks";
    const auto negative = qb::http::RetryPolicy{}.with_initial_delay(200ms).with_multiplier(-3.0).with_jitter(false);
    EXPECT_EQ(ms(negative.next_delay(3)), 200);
}

TEST(RetryPolicy, NegativeMaxDelayReadsAsZero) {
    const auto policy = qb::http::RetryPolicy{}.with_initial_delay(100ms).with_max_delay(-1s).with_jitter(false);
    EXPECT_EQ(policy.next_delay(1), qb::duration::zero());
    EXPECT_EQ(policy.next_delay(4), qb::duration::zero());
}

TEST(RetryPolicy, BuildersChainAndStoreEveryField) {
    int          seen_attempt = 0;
    qb::duration seen_delay{};
    auto         policy = qb::http::RetryPolicy{}
                              .with_max_attempts(3)
                              .with_initial_delay(10ms)
                              .with_max_delay(80ms)
                              .with_multiplier(3.0)
                              .with_jitter(false)
                              .with_on_retry([&](int attempt, qb::duration delay) {
                          seen_attempt = attempt;
                          seen_delay   = delay;
                              });
    EXPECT_EQ(policy.max_attempts, 3);
    EXPECT_EQ(policy.initial_delay, 10ms);
    EXPECT_EQ(policy.max_delay, 80ms);
    EXPECT_DOUBLE_EQ(policy.multiplier, 3.0);
    EXPECT_FALSE(policy.jitter);
    ASSERT_TRUE(policy.on_retry);
    policy.on_retry(2, policy.next_delay(2));
    EXPECT_EQ(seen_attempt, 2);
    EXPECT_EQ(ms(seen_delay), 30);
    EXPECT_EQ(ms(policy.next_delay(3)), 80) << "90 is past the cap";
}

} // namespace
