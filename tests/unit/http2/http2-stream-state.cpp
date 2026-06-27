/**
 * @file qbm/http/tests/unit/http2/http2-stream-state.cpp
 * @brief Pure-logic unit tests for the HTTP/2 stream state layer (stream.h / stream.cpp).
 *
 * The frame-layer and protocol tests drive the templated framer through a
 * socket-less harness, but the value-type building blocks declared in
 * `2/protocol/stream.h` — `FlowControlManager`, `Http2StreamBase` (state machine
 * + flow control + reset), and the `StreamManager<>` connection helper — have a
 * large surface that those higher-level tests only touch incidentally. This TU
 * exercises them DIRECTLY:
 *
 *   - FlowControlManager: window overflow, send-update threshold, threshold calc.
 *   - Http2StreamBase: is_closed / can_send_data / can_receive_data, touch /
 *     get_age / get_idle_time, process_received_data flow accounting,
 *     update_peer_window_size (SETTINGS delta, overflow, negative), the full
 *     transition_state END_STREAM matrix (send + receive), mark_reset,
 *     reset_window_update_tracking.
 *   - StreamManager: cleanup_streams (closed/reset/idle/age/total-limit eviction),
 *     get_statistics, are_all_relevant_streams_closed (server/client parity +
 *     GOAWAY boundary), get_active_stream_count, update_all_stream_windows,
 *     find_streams_needing_window_update.
 *
 * No socket, no FakeIO, no protocol instantiation: every assertion calls a
 * member or static helper on a value-type directly. Deterministic, parallel-safe.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <thread>

#include "../2/protocol/stream.h"

namespace h2 = qb::protocol::http2;

using h2::FlowControlManager;
using h2::Http2StreamBase;
using h2::Http2StreamConcreteState;
using h2::Http2ServerStream;
using State = h2::Http2StreamConcreteState;

// Default initial window per RFC 9113 — what the stream ctors get fed in tests.
static constexpr int64_t kInitWin = h2::DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE; // 65535

// ===========================================================================
// FlowControlManager — pure static helpers
// ===========================================================================

TEST(HTTP2FlowControl, UpdateWindowSafeAddsWithinBound) {
    // current 100, +50, max 1000 -> 150.
    EXPECT_EQ(FlowControlManager::update_window_safe(100, 50, 1000), 150);
    // Reaching exactly the max is allowed (not an overflow).
    EXPECT_EQ(FlowControlManager::update_window_safe(900, 100, 1000), 1000);
    // From zero.
    EXPECT_EQ(FlowControlManager::update_window_safe(0, 1, 1000), 1);
}

TEST(HTTP2FlowControl, UpdateWindowSafeReportsOverflowAsMinusOne) {
    // 1000 + 1 over a 1000 cap -> -1 sentinel.
    EXPECT_EQ(FlowControlManager::update_window_safe(1000, 1, 1000), -1);
    // The RFC limit boundary: 2^31-1 + 1 overflows.
    EXPECT_EQ(FlowControlManager::update_window_safe(h2::MAX_WINDOW_SIZE_LIMIT, 1, h2::MAX_WINDOW_SIZE_LIMIT), -1);
    // Exactly the limit survives.
    EXPECT_EQ(FlowControlManager::update_window_safe(0, h2::MAX_WINDOW_SIZE_LIMIT, h2::MAX_WINDOW_SIZE_LIMIT),
              static_cast<int64_t>(h2::MAX_WINDOW_SIZE_LIMIT));
}

TEST(HTTP2FlowControl, ShouldSendWindowUpdateThresholdRule) {
    // processed >= threshold (and threshold > 0) -> true.
    EXPECT_TRUE(FlowControlManager::should_send_window_update(10, 10));
    EXPECT_TRUE(FlowControlManager::should_send_window_update(11, 10));
    EXPECT_FALSE(FlowControlManager::should_send_window_update(9, 10));
    // threshold == 0 disables updates regardless of processed count.
    EXPECT_FALSE(FlowControlManager::should_send_window_update(100, 0));
    EXPECT_FALSE(FlowControlManager::should_send_window_update(0, 0));
}

TEST(HTTP2FlowControl, CalculateWindowThresholdHalvesAndFloorsAtOne) {
    // Default divisor 2.
    EXPECT_EQ(FlowControlManager::calculate_window_threshold(65535), 32767u);
    EXPECT_EQ(FlowControlManager::calculate_window_threshold(1000, 4), 250u);
    // A window/divisor that rounds to 0 is floored to 1 (never 0 = "disabled").
    EXPECT_EQ(FlowControlManager::calculate_window_threshold(1, 2), 1u);
    // Non-positive window or divisor -> 1.
    EXPECT_EQ(FlowControlManager::calculate_window_threshold(0, 2), 1u);
    EXPECT_EQ(FlowControlManager::calculate_window_threshold(-5, 2), 1u);
    EXPECT_EQ(FlowControlManager::calculate_window_threshold(1000, 0), 1u);
    EXPECT_EQ(FlowControlManager::calculate_window_threshold(1000, -1), 1u);
}

// ===========================================================================
// Http2StreamBase — predicates over the concrete state
// ===========================================================================

TEST(HTTP2StreamBase, IsClosedReflectsStateAndResetFlags) {
    Http2StreamBase s(1, kInitWin, kInitWin);
    s.state = State::OPEN;
    EXPECT_FALSE(s.is_closed());

    s.state = State::CLOSED;
    EXPECT_TRUE(s.is_closed());

    // A reset flag alone (state still OPEN) also reads as closed.
    Http2StreamBase r(3, kInitWin, kInitWin);
    r.state               = State::OPEN;
    r.rst_stream_received = true;
    EXPECT_TRUE(r.is_closed());

    Http2StreamBase rs(5, kInitWin, kInitWin);
    rs.state           = State::OPEN;
    rs.rst_stream_sent = true;
    EXPECT_TRUE(rs.is_closed());
}

TEST(HTTP2StreamBase, CanSendAndReceiveDataPerState) {
    Http2StreamBase s(1, kInitWin, kInitWin);

    // OPEN: both directions.
    s.state = State::OPEN;
    EXPECT_TRUE(s.can_send_data());
    EXPECT_TRUE(s.can_receive_data());

    // HALF_CLOSED_LOCAL: we sent END_STREAM -> can receive, cannot send.
    s.state = State::HALF_CLOSED_LOCAL;
    EXPECT_FALSE(s.can_send_data());
    EXPECT_TRUE(s.can_receive_data());

    // HALF_CLOSED_REMOTE: peer sent END_STREAM -> can send, cannot receive.
    s.state = State::HALF_CLOSED_REMOTE;
    EXPECT_TRUE(s.can_send_data());
    EXPECT_FALSE(s.can_receive_data());

    // IDLE / CLOSED: neither.
    s.state = State::IDLE;
    EXPECT_FALSE(s.can_send_data());
    EXPECT_FALSE(s.can_receive_data());
    s.state = State::CLOSED;
    EXPECT_FALSE(s.can_send_data());
    EXPECT_FALSE(s.can_receive_data());
}

TEST(HTTP2StreamBase, ConstructorSeedsWindowsAndThreshold) {
    Http2StreamBase s(7, /*peer=*/100, /*local=*/200);
    EXPECT_EQ(s.id, 7u);
    EXPECT_EQ(s.state, State::IDLE);
    EXPECT_EQ(s.peer_window_size, 100);
    EXPECT_EQ(s.local_window_size, 200);
    // threshold = local / 2 = 100.
    EXPECT_EQ(s.window_update_threshold, 100u);
    EXPECT_EQ(s.processed_bytes_for_window_update, 0u);
    EXPECT_EQ(s.error_code, h2::ErrorCode::NO_ERROR);
}

TEST(HTTP2StreamBase, AgeAndIdleTimeAdvanceWithWallClock) {
    Http2StreamBase s(1, kInitWin, kInitWin);
    // Age is monotonic and non-negative right after construction.
    EXPECT_GE(s.get_age().count(), 0);
    EXPECT_GE(s.get_idle_time().count(), 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    const auto age_after = s.get_age();
    EXPECT_GE(age_after.count(), 4);

    // touch() resets the idle clock but not the creation age.
    s.touch();
    EXPECT_LE(s.get_idle_time().count(), age_after.count());
    EXPECT_GE(s.get_age().count(), age_after.count());
}

// ===========================================================================
// Http2StreamBase::process_received_data — receive-side flow accounting
// ===========================================================================

TEST(HTTP2StreamBase, ProcessReceivedDataShrinksWindowAndSignalsThreshold) {
    // local window 100 -> threshold 50.
    Http2StreamBase s(1, kInitWin, /*local=*/100);
    ASSERT_EQ(s.window_update_threshold, 50u);

    // 40 bytes: below threshold, no update signalled.
    EXPECT_FALSE(s.process_received_data(40));
    EXPECT_EQ(s.local_window_size, 60);
    EXPECT_EQ(s.processed_bytes_for_window_update, 40u);

    // +20 more (total 60 >= 50): update is now due.
    EXPECT_TRUE(s.process_received_data(20));
    EXPECT_EQ(s.local_window_size, 40);
    EXPECT_EQ(s.processed_bytes_for_window_update, 60u);
}

TEST(HTTP2StreamBase, ResetWindowUpdateTrackingCreditsBackAndZeroesCounter) {
    Http2StreamBase s(1, kInitWin, /*local=*/100);
    (void) s.process_received_data(60);
    ASSERT_EQ(s.local_window_size, 40);
    ASSERT_EQ(s.processed_bytes_for_window_update, 60u);

    // Emitting a WINDOW_UPDATE of 60 credits the local window back and clears the counter.
    s.reset_window_update_tracking(60);
    EXPECT_EQ(s.local_window_size, 100);
    EXPECT_EQ(s.processed_bytes_for_window_update, 0u);
}

// ===========================================================================
// Http2StreamBase::update_peer_window_size — SETTINGS_INITIAL_WINDOW_SIZE delta
// ===========================================================================

TEST(HTTP2StreamBase, UpdatePeerWindowSizeAppliesPositiveDelta) {
    Http2StreamBase s(1, /*peer=*/1000, kInitWin);
    // New initial 1500, old 1000 -> +500.
    EXPECT_TRUE(s.update_peer_window_size(1500, 1000));
    EXPECT_EQ(s.peer_window_size, 1500);
}

TEST(HTTP2StreamBase, UpdatePeerWindowSizeAppliesNegativeDelta) {
    Http2StreamBase s(1, /*peer=*/1000, kInitWin);
    // New initial 600, old 1000 -> -400.
    EXPECT_TRUE(s.update_peer_window_size(600, 1000));
    EXPECT_EQ(s.peer_window_size, 600);
}

TEST(HTTP2StreamBase, UpdatePeerWindowSizeNegativeDeltaDrivingWindowBelowZeroFails) {
    // peer window only 100; shrinking the initial size by 400 drives it to -300,
    // which the function reports as a failure (return false) per RFC 6.9.2.
    Http2StreamBase s(1, /*peer=*/100, kInitWin);
    EXPECT_FALSE(s.update_peer_window_size(600, 1000));
    EXPECT_LT(s.peer_window_size, 0);
}

TEST(HTTP2StreamBase, UpdatePeerWindowSizePositiveDeltaOverflowFails) {
    // peer window already at the RFC max; any positive delta overflows.
    Http2StreamBase s(1, /*peer=*/h2::MAX_WINDOW_SIZE_LIMIT, kInitWin);
    EXPECT_FALSE(s.update_peer_window_size(/*new=*/1000, /*old=*/0));
    // On overflow the window is left unchanged (function returned before assigning).
    EXPECT_EQ(s.peer_window_size, static_cast<int64_t>(h2::MAX_WINDOW_SIZE_LIMIT));
}

// ===========================================================================
// Http2StreamBase::transition_state — END_STREAM matrix (stream.cpp)
// ===========================================================================

TEST(HTTP2StreamBase, TransitionStateNoOpWhenEndStreamFlagClear) {
    Http2StreamBase s(1, kInitWin, kInitWin);
    s.state = State::OPEN;
    s.transition_state(/*end_stream_flag=*/false, /*is_sending=*/true);
    EXPECT_EQ(s.state, State::OPEN);
    EXPECT_FALSE(s.end_stream_sent);
    EXPECT_FALSE(s.end_stream_received);
}

TEST(HTTP2StreamBase, TransitionStateSendingEndStream) {
    // OPEN + send END_STREAM -> HALF_CLOSED_LOCAL.
    Http2StreamBase a(1, kInitWin, kInitWin);
    a.state = State::OPEN;
    a.transition_state(true, /*is_sending=*/true);
    EXPECT_EQ(a.state, State::HALF_CLOSED_LOCAL);
    EXPECT_TRUE(a.end_stream_sent);

    // HALF_CLOSED_REMOTE + send END_STREAM -> CLOSED.
    Http2StreamBase b(3, kInitWin, kInitWin);
    b.state = State::HALF_CLOSED_REMOTE;
    b.transition_state(true, /*is_sending=*/true);
    EXPECT_EQ(b.state, State::CLOSED);
    EXPECT_TRUE(b.end_stream_sent);
}

TEST(HTTP2StreamBase, TransitionStateReceivingEndStream) {
    // OPEN + receive END_STREAM -> HALF_CLOSED_REMOTE.
    Http2StreamBase a(1, kInitWin, kInitWin);
    a.state = State::OPEN;
    a.transition_state(true, /*is_sending=*/false);
    EXPECT_EQ(a.state, State::HALF_CLOSED_REMOTE);
    EXPECT_TRUE(a.end_stream_received);

    // HALF_CLOSED_LOCAL + receive END_STREAM -> CLOSED.
    Http2StreamBase b(3, kInitWin, kInitWin);
    b.state = State::HALF_CLOSED_LOCAL;
    b.transition_state(true, /*is_sending=*/false);
    EXPECT_EQ(b.state, State::CLOSED);
    EXPECT_TRUE(b.end_stream_received);
}

TEST(HTTP2StreamBase, TransitionStateInvalidSourceStateLeavesStateButSetsFlag) {
    // Sending END_STREAM from IDLE is not a defined open->half-closed move; the
    // default arm leaves the state alone but still records the flag (and touches).
    Http2StreamBase s(1, kInitWin, kInitWin);
    s.state = State::IDLE;
    s.transition_state(true, /*is_sending=*/true);
    EXPECT_EQ(s.state, State::IDLE);
    EXPECT_TRUE(s.end_stream_sent);

    Http2StreamBase r(3, kInitWin, kInitWin);
    r.state = State::CLOSED;
    r.transition_state(true, /*is_sending=*/false);
    EXPECT_EQ(r.state, State::CLOSED);
    EXPECT_TRUE(r.end_stream_received);
}

// ===========================================================================
// Http2StreamBase::mark_reset (stream.cpp)
// ===========================================================================

TEST(HTTP2StreamBase, MarkResetSendingClosesAndFlagsSent) {
    Http2StreamBase s(1, kInitWin, kInitWin);
    s.state = State::OPEN;
    s.mark_reset(h2::ErrorCode::CANCEL, /*is_sending=*/true);
    EXPECT_EQ(s.state, State::CLOSED);
    EXPECT_EQ(s.error_code, h2::ErrorCode::CANCEL);
    EXPECT_TRUE(s.rst_stream_sent);
    EXPECT_FALSE(s.rst_stream_received);
    EXPECT_TRUE(s.is_closed());
}

TEST(HTTP2StreamBase, MarkResetReceivingClosesAndFlagsReceived) {
    Http2StreamBase s(1, kInitWin, kInitWin);
    s.state = State::OPEN;
    s.mark_reset(h2::ErrorCode::REFUSED_STREAM, /*is_sending=*/false);
    EXPECT_EQ(s.state, State::CLOSED);
    EXPECT_EQ(s.error_code, h2::ErrorCode::REFUSED_STREAM);
    EXPECT_TRUE(s.rst_stream_received);
    EXPECT_FALSE(s.rst_stream_sent);
}

// ===========================================================================
// StreamManager<Http2ServerStream> — connection-level stream bookkeeping
// ===========================================================================

namespace {

using ServerMap     = qb::unordered_map<uint32_t, Http2ServerStream>;
using ServerManager = h2::StreamManager<Http2ServerStream>;

// Emplace a server stream in `map` with the given id/state and return a ref.
// Mirrors server.h's own `emplace(id, std::move(stream))` move-construction.
Http2ServerStream &
add_stream(ServerMap &map, uint32_t id, State st) {
    Http2ServerStream stream(id, kInitWin, kInitWin);
    stream.state  = st;
    auto [it, ok] = map.emplace(id, std::move(stream));
    return it->second;
}

} // namespace

TEST(HTTP2StreamManager, CleanupRemovesClosedAndResetStreamsByDefault) {
    ServerMap map;
    add_stream(map, 1, State::OPEN);                       // kept
    add_stream(map, 3, State::CLOSED);                     // removed (closed)
    add_stream(map, 5, State::OPEN).rst_stream_sent = true; // removed (reset)
    ASSERT_EQ(map.size(), 3u);

    ServerManager mgr(map);
    ServerManager::CleanupCriteria criteria; // cleanup_closed + cleanup_reset default true
    const std::size_t removed = mgr.cleanup_streams(criteria);

    EXPECT_EQ(removed, 2u);
    EXPECT_EQ(map.size(), 1u);
    EXPECT_TRUE(map.count(1));
    EXPECT_FALSE(map.count(3));
    EXPECT_FALSE(map.count(5));
}

TEST(HTTP2StreamManager, CleanupCanBeRestrictedToNotTouchClosedStreams) {
    ServerMap map;
    add_stream(map, 1, State::CLOSED);
    add_stream(map, 3, State::OPEN);

    ServerManager mgr(map);
    ServerManager::CleanupCriteria criteria;
    criteria.cleanup_closed_streams = false;
    criteria.cleanup_reset_streams  = false;
    // With both disabled and no idle/age/total limits, nothing is removed.
    EXPECT_EQ(mgr.cleanup_streams(criteria), 0u);
    EXPECT_EQ(map.size(), 2u);
}

TEST(HTTP2StreamManager, CleanupEvictsByAge) {
    ServerMap map;
    add_stream(map, 1, State::OPEN);
    // Force this stream's creation time well into the past.
    map.at(1).created_at = std::chrono::steady_clock::now() - std::chrono::seconds(60);
    add_stream(map, 3, State::OPEN); // fresh, kept

    ServerManager mgr(map);
    ServerManager::CleanupCriteria criteria;
    criteria.cleanup_closed_streams = false;
    criteria.cleanup_reset_streams  = false;
    criteria.max_age                = std::chrono::seconds(10);

    EXPECT_EQ(mgr.cleanup_streams(criteria), 1u);
    EXPECT_FALSE(map.count(1));
    EXPECT_TRUE(map.count(3));
}

TEST(HTTP2StreamManager, CleanupEvictsByIdleTime) {
    ServerMap map;
    add_stream(map, 1, State::OPEN);
    map.at(1).last_activity = std::chrono::steady_clock::now() - std::chrono::seconds(60);
    add_stream(map, 3, State::OPEN); // recently active

    ServerManager mgr(map);
    ServerManager::CleanupCriteria criteria;
    criteria.cleanup_closed_streams = false;
    criteria.cleanup_reset_streams  = false;
    criteria.max_idle_time          = std::chrono::seconds(10);

    EXPECT_EQ(mgr.cleanup_streams(criteria), 1u);
    EXPECT_FALSE(map.count(1));
    EXPECT_TRUE(map.count(3));
}

TEST(HTTP2StreamManager, CleanupEnforcesMaxTotalStreamsByEvictingOldestClosed) {
    ServerMap map;
    // Three closed (eligible for total-limit eviction) + one open.
    auto &c1 = add_stream(map, 1, State::CLOSED);
    auto &c3 = add_stream(map, 3, State::CLOSED);
    auto &c5 = add_stream(map, 5, State::CLOSED);
    add_stream(map, 7, State::OPEN);
    // Stagger creation times so the oldest-first sort is deterministic.
    const auto now = std::chrono::steady_clock::now();
    c1.created_at  = now - std::chrono::seconds(30);
    c3.created_at  = now - std::chrono::seconds(20);
    c5.created_at  = now - std::chrono::seconds(10);

    ServerManager mgr(map);
    ServerManager::CleanupCriteria criteria;
    // Disable the regular closed/reset sweep so ONLY the max_total path runs.
    criteria.cleanup_closed_streams = false;
    criteria.cleanup_reset_streams  = false;
    criteria.max_total_streams      = 2; // keep at most 2 -> remove 2 oldest closed

    const std::size_t removed = mgr.cleanup_streams(criteria);
    EXPECT_EQ(removed, 2u);
    EXPECT_EQ(map.size(), 2u);
    // The two oldest closed (1, 3) go; the newest closed (5) and the open (7) stay.
    EXPECT_FALSE(map.count(1));
    EXPECT_FALSE(map.count(3));
    EXPECT_TRUE(map.count(5));
    EXPECT_TRUE(map.count(7));
}

TEST(HTTP2StreamManager, GetStatisticsCountsByCategory) {
    ServerMap map;
    add_stream(map, 1, State::OPEN);                            // active
    add_stream(map, 3, State::HALF_CLOSED_REMOTE);              // active (not yet CLOSED)
    add_stream(map, 5, State::CLOSED);                          // closed
    add_stream(map, 7, State::OPEN).rst_stream_received = true; // counted as CLOSED, see below
    add_stream(map, 9, State::IDLE);                            // idle

    ServerManager mgr(map);
    const auto    stats = mgr.get_statistics();
    EXPECT_EQ(stats.total_streams, 5u);
    EXPECT_EQ(stats.active_streams, 2u); // OPEN + HALF_CLOSED_REMOTE
    // is_closed() is `state==CLOSED || rst_received || rst_sent`, and get_statistics tests
    // is_closed() FIRST — so a reset stream is bucketed as closed, and reset_streams (checked
    // only in the subsequent else-if) is effectively always zero. This pins that real behavior.
    EXPECT_EQ(stats.closed_streams, 2u); // CLOSED + the rst_received stream
    EXPECT_EQ(stats.reset_streams, 0u);  // unreachable bucket (is_closed already caught it)
    EXPECT_EQ(stats.idle_streams, 1u);
    EXPECT_GE(stats.oldest_stream_age.count(), 0);
}

TEST(HTTP2StreamManager, GetStatisticsEmptyMapIsAllZero) {
    ServerMap     map;
    ServerManager mgr(map);
    const auto    stats = mgr.get_statistics();
    EXPECT_EQ(stats.total_streams, 0u);
    EXPECT_EQ(stats.active_streams, 0u);
    EXPECT_EQ(stats.oldest_stream_age.count(), 0);
    EXPECT_EQ(stats.average_stream_age.count(), 0);
}

TEST(HTTP2StreamManager, AreAllRelevantStreamsClosedNoGoawayChecksEveryStream) {
    ServerMap map;
    add_stream(map, 1, State::CLOSED);
    add_stream(map, 3, State::OPEN);

    ServerManager mgr(map);
    // last_processed_stream_id == 0 -> "no GOAWAY yet" path checks all streams;
    // an open one means not-all-closed.
    EXPECT_FALSE(mgr.are_all_relevant_streams_closed(0, /*is_server=*/true));

    map.at(3).state = State::CLOSED;
    EXPECT_TRUE(mgr.are_all_relevant_streams_closed(0, /*is_server=*/true));
}

TEST(HTTP2StreamManager, AreAllRelevantStreamsClosedServerOnlyChecksClientStreamsWithinBoundary) {
    ServerMap map;
    add_stream(map, 1, State::CLOSED); // client (odd), within boundary
    add_stream(map, 3, State::OPEN);   // client (odd), ABOVE boundary -> skipped
    add_stream(map, 2, State::OPEN);   // server (even) -> irrelevant for is_server

    ServerManager mgr(map);
    // GOAWAY boundary at last_stream_id 1: only client streams <= 1 are relevant.
    // Stream 3 (open) is above the boundary, stream 2 is even, so all *relevant*
    // streams are closed.
    EXPECT_TRUE(mgr.are_all_relevant_streams_closed(/*last=*/1, /*is_server=*/true));

    // Lower nothing but extend the boundary to 3 -> stream 3 (open) now counts.
    EXPECT_FALSE(mgr.are_all_relevant_streams_closed(/*last=*/3, /*is_server=*/true));
}

TEST(HTTP2StreamManager, AreAllRelevantStreamsClosedClientChecksEvenStreams) {
    ServerMap map;
    add_stream(map, 2, State::OPEN); // server-initiated (even), within boundary
    add_stream(map, 1, State::OPEN); // client (odd) -> irrelevant for is_server=false

    ServerManager mgr(map);
    // For a client, only even (server-initiated) streams within the boundary count.
    EXPECT_FALSE(mgr.are_all_relevant_streams_closed(/*last=*/2, /*is_server=*/false));
    map.at(2).state = State::CLOSED;
    EXPECT_TRUE(mgr.are_all_relevant_streams_closed(/*last=*/2, /*is_server=*/false));
}

TEST(HTTP2StreamManager, GetActiveStreamCount) {
    ServerMap map;
    add_stream(map, 1, State::OPEN);   // active client
    add_stream(map, 3, State::IDLE);   // idle, not active
    add_stream(map, 5, State::CLOSED); // closed, not active
    add_stream(map, 2, State::OPEN);   // active server (even)

    ServerManager mgr(map);
    // Count all non-closed, non-idle streams.
    EXPECT_EQ(mgr.get_active_stream_count(/*server_initiated_only=*/false), 2u);
    // Server-initiated only skips odd (client) ids -> only stream 2.
    EXPECT_EQ(mgr.get_active_stream_count(/*server_initiated_only=*/true), 1u);
}

TEST(HTTP2StreamManager, UpdateAllStreamWindowsAppliesDeltaAndCountsOverflows) {
    ServerMap map;
    // Stream A has a healthy peer window; B is already at the RFC max so a
    // positive delta overflows and gets reset to FLOW_CONTROL_ERROR.
    auto &a = add_stream(map, 1, State::OPEN);
    a.peer_window_size = 1000;
    auto &b = add_stream(map, 3, State::OPEN);
    b.peer_window_size = h2::MAX_WINDOW_SIZE_LIMIT;

    ServerManager mgr(map);
    // Raise the initial window by 1000 (new 1000, old 0).
    const std::size_t overflows = mgr.update_all_stream_windows(/*new=*/1000, /*old=*/0);
    EXPECT_EQ(overflows, 1u);
    EXPECT_EQ(map.at(1).peer_window_size, 2000); // +1000 applied
    EXPECT_TRUE(map.at(3).rst_stream_received);  // marked reset on overflow
    EXPECT_EQ(map.at(3).error_code, h2::ErrorCode::FLOW_CONTROL_ERROR);
}

TEST(HTTP2StreamManager, FindStreamsNeedingWindowUpdate) {
    ServerMap map;
    // Stream 1: processed >= threshold AND can receive -> needs update.
    auto &s1 = add_stream(map, 1, State::OPEN);
    s1.window_update_threshold           = 10;
    s1.processed_bytes_for_window_update = 20;
    // Stream 3: processed >= threshold but CLOSED -> cannot receive, excluded.
    auto &s3 = add_stream(map, 3, State::CLOSED);
    s3.window_update_threshold           = 10;
    s3.processed_bytes_for_window_update = 20;
    // Stream 5: below threshold -> excluded.
    auto &s5 = add_stream(map, 5, State::OPEN);
    s5.window_update_threshold           = 10;
    s5.processed_bytes_for_window_update = 5;

    ServerManager mgr(map);
    const auto ids = mgr.find_streams_needing_window_update();
    ASSERT_EQ(ids.size(), 1u);
    EXPECT_EQ(ids[0], 1u);
}
