/**
 * @file qbm/http/tests/shared/http2_fake_io.h
 * @brief Shared socket-less HTTP/2 protocol harness for the qbm-http test suite.
 *
 * The HTTP/2 unit tests drive @c qb::protocol::http2::ServerHttp2Protocol and
 * @c ClientHttp2Protocol without a real socket. They do this through a "FakeIO"
 * harness: a plain struct that satisfies the protocol's IO concept (it owns an
 * input and an output @c qb::allocator::pipe<char>, exposes @c in()/@c out(),
 * an @c operator<< frame sink, and the application callbacks the protocol
 * invokes — @c on(Request&&,id), @c on(Response&&,id[,ErrorCode]) and the
 * stream-error / GOAWAY / PUSH_PROMISE event sinks). Tests then:
 *   - push raw wire bytes (preface + frames) into @c input via @ref push_frame,
 *     and drive the framer with @ref drive (getMessageSize / onMessage loop), or
 *   - construct typed @c Http2FrameData<T> via @ref make_headers_frame etc. and
 *     hand them straight to a protocol's @c on(...) overload, and
 *   - inspect what the protocol serialized into @c output via
 *     @ref parse_emitted_frames / @ref peek_frame_header / @ref find_frame_offset.
 *
 * This header reconciles the previously-duplicated inline harnesses into one
 * canonical, capability-superset version:
 *   - @ref Http2FakeIO            — server-facing sink (request + events), plus a
 *                                   captured @c last_request for field assertions.
 *   - @ref Http2ClientFakeIO      — client-facing sink (response + events), plus
 *                                   captured status/body/PUSH_PROMISE details.
 *   - @ref Http2PeerFakeIO        — minimal server peer for client round-trips.
 *   - wire builders / parsers     — @ref push_frame, @ref encode_hpack_headers,
 *                                   @ref make_headers_frame, @ref make_data_frame,
 *                                   @ref make_settings_frame,
 *                                   @ref make_window_update_frame,
 *                                   @ref parse_emitted_frames, @ref peek_frame_header,
 *                                   @ref find_frame_offset, @ref count_frames,
 *                                   @ref output_has_frame, @ref pump, @ref drive,
 *                                   @ref do_handshake, @ref default_request_headers.
 *
 * Reconciled from the inline copies that previously lived in:
 *   - tests/test-http2-header-validator.cpp   (Http2ProtocolHarness / encode_hpack_headers)
 *   - tests/unit/http2/http2-server-protocol.cpp
 *       (Http2ServerHarness, push_frame, drive, parse_emitted_frames,
 *        output_has_frame, count_output_frames, do_handshake, default_request_headers)
 *   - tests/unit/http2/http2-client-protocol.cpp
 *       (ClientHarness, ServerPeerHarness, make_headers_frame, make_data_frame,
 *        pump, peek_frame_header, find_frame_offset)
 *
 * No real socket is used; everything is header-only and inline so multiple test
 * TUs can include it without ODR hazards. Contains no TEST()/main().
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#ifndef QBM_HTTP_TESTS_SHARED_HTTP2_FAKE_IO_H
#define QBM_HTTP_TESTS_SHARED_HTTP2_FAKE_IO_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "../2/protocol/base.h"
#include "../2/protocol/client.h"
#include "../2/protocol/server.h"

namespace qb::http::test {

namespace h2 = qb::protocol::http2;

// ===========================================================================
// FakeIO harnesses
// ===========================================================================

/**
 * @brief Socket-less server-facing IO harness for @c ServerHttp2Protocol.
 *
 * Owns two pipes (input fed to the framer, output where the protocol writes
 * emitted frames), counts the application callbacks, and captures the last
 * request so individual tests can assert parsed fields. Satisfies the full
 * server IO contract (request sink + stream-error / GOAWAY / PUSH_PROMISE
 * event sinks).
 */
struct Http2FakeIO {
    using base_io_t = Http2FakeIO;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;

    int           request_count      = 0;
    int           stream_error_count = 0;
    int           goaway_count       = 0;
    int           push_promise_count = 0;
    h2::ErrorCode last_stream_error  = h2::ErrorCode::NO_ERROR;
    h2::ErrorCode last_goaway_error  = h2::ErrorCode::NO_ERROR;

    /// Last request seen by @c on(Request&&, stream_id), captured for assertions.
    std::optional<qb::http::Request> last_request;
    uint32_t                         last_request_stream_id = 0;

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }
    qb::allocator::pipe<char> &
    out() noexcept {
        return output;
    }

    template <typename Frame>
    Http2FakeIO &
    operator<<(const Frame &frame) {
        output.put(frame);
        return *this;
    }

    void
    on(qb::http::Request &&request, uint32_t stream_id) {
        ++request_count;
        last_request_stream_id = stream_id;
        last_request           = std::move(request);
    }

    void
    on(const h2::Http2StreamErrorEvent &event) {
        ++stream_error_count;
        last_stream_error = event.error_code;
    }

    void
    on(const h2::Http2GoAwayEvent &event) {
        ++goaway_count;
        last_goaway_error = event.error_code;
    }

    void
    on(const h2::Http2PushPromiseEvent & /*event*/) {
        ++push_promise_count;
    }
};

/**
 * @brief Socket-less client-facing IO harness for @c ClientHttp2Protocol.
 *
 * Supplies the client-facing response overloads — @c on(Response&&, app_id) and
 * @c on(Response&&, app_id, ErrorCode) — and the GOAWAY / PUSH_PROMISE event
 * sinks, while capturing status/body and the last PUSH_PROMISE association.
 */
struct Http2ClientFakeIO {
    using base_io_t = Http2ClientFakeIO;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;

    int           response_count      = 0;
    int           stream_error_count  = 0;
    int           goaway_count        = 0;
    int           push_promise_count  = 0;
    uint64_t      last_app_id         = 0;
    h2::ErrorCode last_response_error = h2::ErrorCode::NO_ERROR;
    h2::ErrorCode last_stream_error   = h2::ErrorCode::NO_ERROR;
    h2::ErrorCode last_goaway_error   = h2::ErrorCode::NO_ERROR;

    std::optional<int>         last_status;
    std::optional<std::string> last_body;

    uint32_t last_promised_stream_id   = 0;
    uint32_t last_associated_stream_id = 0;

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }
    qb::allocator::pipe<char> &
    out() noexcept {
        return output;
    }

    template <typename Frame>
    Http2ClientFakeIO &
    operator<<(const Frame &frame) {
        output.put(frame);
        return *this;
    }

    void
    capture(qb::http::Response &&response) {
        ++response_count;
        last_status = response.status().code();
        last_body   = response.body().template as<std::string>();
    }

    void
    on(qb::http::Response &&response, uint64_t app_id) {
        last_app_id         = app_id;
        last_response_error = h2::ErrorCode::NO_ERROR;
        capture(std::move(response));
    }

    void
    on(qb::http::Response &&response, uint64_t app_id, h2::ErrorCode ec) {
        last_app_id         = app_id;
        last_response_error = ec;
        capture(std::move(response));
    }

    void
    on(const h2::Http2StreamErrorEvent &event) {
        ++stream_error_count;
        last_stream_error = event.error_code;
    }

    void
    on(const h2::Http2GoAwayEvent &event) {
        ++goaway_count;
        last_goaway_error = event.error_code;
    }

    void
    on(const h2::Http2PushPromiseEvent &event) {
        ++push_promise_count;
        last_associated_stream_id = event.associated_stream_id;
        last_promised_stream_id   = event.promised_stream_id;
    }
};

/**
 * @brief Minimal server peer for client round-trip tests.
 *
 * Used when a client's emitted frames are fed into a real @c ServerHttp2Protocol
 * to confirm the client serialized a request faithfully. Captures the method,
 * path and body of the received request.
 */
struct Http2PeerFakeIO {
    using base_io_t = Http2PeerFakeIO;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;

    int                        request_count = 0;
    std::optional<std::string> last_method;
    std::optional<std::string> last_path;
    std::optional<std::string> last_body;

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }
    qb::allocator::pipe<char> &
    out() noexcept {
        return output;
    }

    template <typename Frame>
    Http2PeerFakeIO &
    operator<<(const Frame &frame) {
        output.put(frame);
        return *this;
    }

    void
    on(qb::http::Request &&request, uint32_t) {
        ++request_count;
        last_method = std::string(request.method());
        last_path   = std::string(request.uri().path());
        last_body   = request.body().template as<std::string>();
    }

    void
    on(const h2::Http2StreamErrorEvent &) {}
    void
    on(const h2::Http2GoAwayEvent &) {}
    void
    on(const h2::Http2PushPromiseEvent &) {}
};

// ===========================================================================
// HPACK helper
// ===========================================================================

/**
 * @brief HPACK-encode a header list into a header-block fragment.
 *
 * Uses a fresh @c Encoder per call (no shared dynamic-table state). Asserts the
 * encode succeeds so a malformed input fails the calling test rather than
 * silently producing empty output.
 */
[[nodiscard]] inline std::vector<uint8_t>
encode_hpack_headers(const std::vector<qb::protocol::hpack::HeaderField> &headers) {
    qb::protocol::hpack::Encoder encoder;
    std::vector<uint8_t>         encoded;
    EXPECT_TRUE(encoder.encode(headers, encoded));
    return encoded;
}

/// Standard valid request pseudo-header set (`:method`/`:scheme`/`:authority`/`:path`).
[[nodiscard]] inline std::vector<qb::protocol::hpack::HeaderField>
default_request_headers(const std::string &path = "/") {
    return {{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", path}};
}

// ===========================================================================
// Raw-wire helpers (input pipe)
// ===========================================================================

/// Append raw bytes to a harness input pipe.
template <typename FakeIO>
inline void
push_bytes(FakeIO &io, const void *p, std::size_t n) {
    std::memcpy(io.input.allocate_back(n), p, n);
}

/// Append the literal HTTP/2 client connection preface to the input pipe.
template <typename FakeIO>
inline void
push_preface(FakeIO &io) {
    push_bytes(io, HTTP2_CONNECTION_PREFACE.data(), HTTP2_CONNECTION_PREFACE.size());
}

/**
 * @brief Append a full frame (9-byte header + payload) to the input pipe.
 *
 * The 24-bit length field is computed from @p payload, so callers only supply
 * the type/flags/stream-id and body bytes.
 */
template <typename FakeIO>
inline void
push_frame(FakeIO &io, h2::FrameType type, uint8_t flags, uint32_t stream_id, const std::vector<uint8_t> &payload) {
    h2::FrameHeader fh{};
    fh.set_payload_length(static_cast<uint32_t>(payload.size()));
    fh.type  = static_cast<uint8_t>(type);
    fh.flags = flags;
    fh.set_stream_id(stream_id);
    push_bytes(io, &fh, sizeof(fh));
    if (!payload.empty()) {
        push_bytes(io, payload.data(), payload.size());
    }
}

/// Encode a SETTINGS payload body (id/value pairs, 6 octets each, big-endian).
[[nodiscard]] inline std::vector<uint8_t>
make_settings_payload(const std::vector<std::pair<uint16_t, uint32_t>> &settings) {
    std::vector<uint8_t> payload;
    payload.reserve(settings.size() * 6u);
    for (const auto &[id, val] : settings) {
        payload.push_back(static_cast<uint8_t>((id >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(id & 0xFF));
        payload.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
        payload.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
        payload.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(val & 0xFF));
    }
    return payload;
}

/// Encode a WINDOW_UPDATE payload body (4 octets, big-endian increment).
[[nodiscard]] inline std::vector<uint8_t>
make_window_update_payload(uint32_t increment) {
    return {
        static_cast<uint8_t>((increment >> 24) & 0xFF), static_cast<uint8_t>((increment >> 16) & 0xFF),
        static_cast<uint8_t>((increment >> 8) & 0xFF), static_cast<uint8_t>(increment & 0xFF)
    };
}

/// Push a SETTINGS frame (stream 0) carrying the given id/value pairs.
template <typename FakeIO>
inline void
make_settings_frame(FakeIO &io, const std::vector<std::pair<uint16_t, uint32_t>> &settings, uint8_t flags = 0) {
    push_frame(io, h2::FrameType::SETTINGS, flags, 0, make_settings_payload(settings));
}

/// Push a WINDOW_UPDATE frame on @p stream_id with the given increment.
template <typename FakeIO>
inline void
make_window_update_frame(FakeIO &io, uint32_t stream_id, uint32_t increment) {
    push_frame(io, h2::FrameType::WINDOW_UPDATE, 0, stream_id, make_window_update_payload(increment));
}

// ===========================================================================
// Typed-frame builders (for direct protocol.on(...) dispatch)
// ===========================================================================

/// Build a HEADERS @c Http2FrameData ready to hand to @c protocol.on(...).
[[nodiscard]] inline h2::Http2FrameData<h2::HeadersFrame>
make_headers_frame(uint32_t stream_id, uint8_t flags, const std::vector<qb::protocol::hpack::HeaderField> &headers) {
    h2::Http2FrameData<h2::HeadersFrame> frame;
    frame.header.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
    frame.header.flags = flags;
    frame.header.set_stream_id(stream_id);
    frame.payload.header_block_fragment = encode_hpack_headers(headers);
    return frame;
}

/// Build a DATA @c Http2FrameData carrying @p body, ready for @c protocol.on(...).
[[nodiscard]] inline h2::Http2FrameData<h2::DataFrame>
make_data_frame(uint32_t stream_id, uint8_t flags, const std::string &body) {
    h2::Http2FrameData<h2::DataFrame> frame;
    frame.header.type  = static_cast<uint8_t>(h2::FrameType::DATA);
    frame.header.flags = flags;
    frame.header.set_stream_id(stream_id);
    frame.payload.data_payload.assign(body.begin(), body.end());
    return frame;
}

// ===========================================================================
// Framer drive loops
// ===========================================================================

/**
 * @brief Drive the framer over a harness input pipe until it stalls or errors.
 *
 * Repeatedly calls @c getMessageSize() / @c onMessage() and frees the consumed
 * prefix, stopping as soon as the protocol reports @c !ok().
 */
template <typename Protocol, typename FakeIO>
inline void
drive(Protocol &protocol, FakeIO &io) {
    std::size_t sz = 0;
    while ((sz = protocol.getMessageSize()) > 0) {
        protocol.onMessage(sz);
        io.input.free_front(sz);
        if (!protocol.ok()) {
            break;
        }
    }
}

/**
 * @brief Move whatever is in @p from's output pipe into @p to's input pipe and
 *        drive @p protocol over it. Consumes @p from's output.
 *
 * Used for round-trip tests where one protocol's emitted frames feed the peer.
 */
template <typename Protocol, typename ToHarness, typename FromHarness>
inline void
pump(Protocol &protocol, ToHarness &to, FromHarness &from) {
    const std::size_t n = from.output.size();
    if (n > 0) {
        std::memcpy(to.input.allocate_back(n), from.output.cbegin(), n);
        from.output.reset();
    }
    drive(protocol, to);
}

/**
 * @brief Drive preface + an empty client SETTINGS through a server protocol.
 *
 * Leaves the server in a normal post-handshake state. Assertions live in the
 * calling test.
 */
template <typename Protocol, typename FakeIO>
inline void
do_handshake(Protocol &protocol, FakeIO &io) {
    push_preface(io);
    push_frame(io, h2::FrameType::SETTINGS, 0, 0, {});
    drive(protocol, io);
}

// ===========================================================================
// Emitted-frame parsing (output pipe)
// ===========================================================================

/// A parsed view of a single frame emitted into an output pipe.
struct EmittedFrame {
    h2::FrameType type;
    uint8_t       flags;
    uint32_t      stream_id;
    uint32_t      payload_length;
};

/**
 * @brief Walk an output pipe as a sequence of [FrameHeader][payload].
 *
 * Every frame serializer writes a 9-byte @c FrameHeader with the recomputed
 * payload length, so the output is self-describing.
 */
[[nodiscard]] inline std::vector<EmittedFrame>
parse_emitted_frames(const qb::allocator::pipe<char> &output) {
    std::vector<EmittedFrame> frames;
    const char               *data = output.cbegin();
    const std::size_t         size = output.size();
    std::size_t               off  = 0;
    while (off + h2::FRAME_HEADER_SIZE <= size) {
        h2::FrameHeader fh{};
        std::memcpy(&fh, data + off, h2::FRAME_HEADER_SIZE);
        const uint32_t plen = fh.get_payload_length();
        frames.push_back({fh.get_type(), fh.flags, fh.get_stream_id(), plen});
        off += h2::FRAME_HEADER_SIZE + plen;
    }
    return frames;
}

/// Parse the @c FrameHeader sitting at @p offset bytes into a pipe.
[[nodiscard]] inline h2::FrameHeader
peek_frame_header(const qb::allocator::pipe<char> &pipe, std::size_t offset) {
    h2::FrameHeader fh{};
    std::memcpy(&fh, pipe.cbegin() + offset, h2::FRAME_HEADER_SIZE);
    return fh;
}

/**
 * @brief Locate the byte offset of the first frame of @p type at or after
 *        @p start. Returns @c SIZE_MAX if none is found.
 */
[[nodiscard]] inline std::size_t
find_frame_offset(const qb::allocator::pipe<char> &pipe, h2::FrameType type, std::size_t start = 0) {
    std::size_t       offset = start;
    const std::size_t total  = pipe.size();
    while (offset + h2::FRAME_HEADER_SIZE <= total) {
        const auto fh      = peek_frame_header(pipe, offset);
        const auto payload = fh.get_payload_length();
        if (fh.get_type() == type) {
            return offset;
        }
        offset += h2::FRAME_HEADER_SIZE + payload;
    }
    return SIZE_MAX;
}

/// True if the output pipe contains at least one frame of @p type.
[[nodiscard]] inline bool
output_has_frame(const qb::allocator::pipe<char> &output, h2::FrameType type) {
    for (const auto &f : parse_emitted_frames(output)) {
        if (f.type == type) {
            return true;
        }
    }
    return false;
}

/// Count how many frames of @p type were emitted into the output pipe.
[[nodiscard]] inline std::size_t
count_frames(const qb::allocator::pipe<char> &output, h2::FrameType type) {
    std::size_t n = 0;
    for (const auto &f : parse_emitted_frames(output)) {
        if (f.type == type) {
            ++n;
        }
    }
    return n;
}

} // namespace qb::http::test

#endif // QBM_HTTP_TESTS_SHARED_HTTP2_FAKE_IO_H
