/**
 * @file qbm/http/2/protocol/stream.cpp
 * @brief Out-of-line definitions for HTTP/2 stream state management
 *
 * Houses the substantial non-template member function bodies declared in
 * stream.h (flow-control window updates, stream state transitions, and reset
 * marking) to keep the header lean while preserving the public API.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./stream.h"

namespace qb::protocol::http2 {

bool
Http2StreamBase::update_peer_window_size(uint32_t new_initial_size, uint32_t old_initial_size) noexcept {
    // RFC 9113 §6.9.2: the window moves by the difference of the two initial sizes. A decrease
    // can leave it negative -- a debt the sender tracks and repays before it sends again -- and
    // is never an error; only a window pushed past 2^31-1 is (FLOW_CONTROL_ERROR), and then the
    // window is left as it was (Huly QB-532). All values fit int64_t: |delta| < 2^32.
    const int64_t delta      = static_cast<int64_t>(new_initial_size) - static_cast<int64_t>(old_initial_size);
    const int64_t new_window = peer_window_size + delta;
    if (new_window > static_cast<int64_t>(MAX_WINDOW_SIZE_LIMIT)) {
        return false; // Overflow
    }
    peer_window_size = new_window;
    return true;
}

void
Http2StreamBase::transition_state(bool end_stream_flag, bool is_sending) noexcept {
    if (!end_stream_flag)
        return;

    if (is_sending) {
        end_stream_sent = true;
        switch (state) {
            case Http2StreamConcreteState::OPEN:
                state = Http2StreamConcreteState::HALF_CLOSED_LOCAL;
                break;
            case Http2StreamConcreteState::HALF_CLOSED_REMOTE:
                state = Http2StreamConcreteState::CLOSED;
                break;
            default:
                // Invalid transition, but don't crash
                break;
        }
    } else {
        end_stream_received = true;
        switch (state) {
            case Http2StreamConcreteState::OPEN:
                state = Http2StreamConcreteState::HALF_CLOSED_REMOTE;
                break;
            case Http2StreamConcreteState::HALF_CLOSED_LOCAL:
                state = Http2StreamConcreteState::CLOSED;
                break;
            default:
                // Invalid transition, but don't crash
                break;
        }
    }
    touch();
}

void
Http2StreamBase::mark_reset(ErrorCode error_code_param, bool is_sending) noexcept {
    error_code = error_code_param;
    state      = Http2StreamConcreteState::CLOSED;

    if (is_sending) {
        rst_stream_sent = true;
    } else {
        rst_stream_received = true;
    }
    touch();
}

} // namespace qb::protocol::http2
