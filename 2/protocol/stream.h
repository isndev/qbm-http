/**
 * @file qbm/http/2/protocol/stream.h
 * @brief HTTP/2 stream state management for qb-io framework
 *
 * This file provides HTTP/2 stream state management and lifecycle handling
 * built for the qb-io asynchronous framework. It includes:
 *
 * - Complete HTTP/2 stream state machine implementation
 * - Flow control window management for both directions
 * - Stream lifecycle tracking with proper state transitions
 * - Header processing state management
 * - Trailer handling and expectation tracking
 * - Priority information storage and management
 * - Client and server stream specializations
 * - Event structures for stream and connection errors
 *
 * The stream management follows RFC 9113 specifications for proper
 * HTTP/2 stream state transitions and flow control.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http2
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <optional>
#include <vector> // Required by qb::http::Headers if it uses std::vector for multi-value headers
#include <unordered_set>

#include "../../request.h"
#include "../../response.h"
#include "./frames.h" // For Http2PriorityData, ErrorCode, frame constants, DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE

namespace qb::protocol::http2 {

/**
 * @brief Default divisor for stream window update threshold calculation
 */
constexpr uint32_t DEFAULT_STREAM_WINDOW_UPDATE_THRESHOLD_DIVISOR = 2;

/**
 * @brief HTTP/2 stream states as defined in RFC 9113 Section 5.1
 */
enum class Http2StreamConcreteState {
    IDLE,               ///< Stream not yet created
    OPEN,               ///< Stream is open for sending/receiving
    RESERVED_LOCAL,     ///< Stream reserved by local endpoint (push promise)
    RESERVED_REMOTE,    ///< Stream reserved by remote endpoint (push promise)
    HALF_CLOSED_LOCAL,  ///< Local endpoint has sent END_STREAM
    HALF_CLOSED_REMOTE, ///< Remote endpoint has sent END_STREAM
    CLOSED              ///< Stream is closed
};

// Forward declare HPACK decoder if it needs to be part of stream state
// namespace qb::protocol::hpack { class Decoder; }

/**
 * @brief Base stream state structure for HTTP/2 streams
 * 
 * Contains all the common state information needed to manage an HTTP/2 stream,
 * including flow control windows, lifecycle flags, and header processing state.
 */
struct Http2StreamState {
    uint32_t id = 0;                                              ///< Stream identifier
    Http2StreamConcreteState state = Http2StreamConcreteState::IDLE; ///< Current stream state
    
    // Flow control windows
    int64_t local_window_size;  ///< How much data we can receive from peer
    int64_t peer_window_size;   ///< How much data peer can receive from us

    uint32_t window_update_threshold;              ///< Threshold for sending WINDOW_UPDATE
    uint32_t processed_bytes_for_window_update = 0; ///< Bytes processed towards WINDOW_UPDATE

    // Stream lifecycle flags
    bool end_stream_received = false;    ///< Peer has indicated end of stream
    bool end_stream_sent = false;        ///< We have indicated end of stream
    bool rst_stream_received = false;    ///< Peer sent RST_STREAM
    bool rst_stream_sent = false;        ///< We sent RST_STREAM
    ErrorCode error_code = ErrorCode::NO_ERROR; ///< Error code if stream was reset

    // Header processing state
    bool headers_received_main = false;  ///< Main headers received and processed
    bool trailers_expected = false;      ///< Expecting trailers from peer
    bool trailers_received = false;      ///< Trailers received and processed
    bool expecting_continuation = false; ///< Expecting CONTINUATION frame

    std::optional<Http2PriorityData> priority_info; ///< Priority information for stream

    /**
     * @brief Construct a new stream state
     * @param stream_id Stream identifier
     * @param initial_peer_window Initial peer flow control window size
     * @param initial_local_window Initial local flow control window size
     */
    Http2StreamState(uint32_t stream_id, int64_t initial_peer_window, int64_t initial_local_window)
        : id(stream_id)
        , local_window_size(initial_local_window)
        , peer_window_size(initial_peer_window)
        , window_update_threshold(static_cast<uint32_t>(initial_local_window / DEFAULT_STREAM_WINDOW_UPDATE_THRESHOLD_DIVISOR)) {
        if (window_update_threshold == 0 && initial_local_window > 0) {
            window_update_threshold = 1;
        }
    }
    virtual ~Http2StreamState() = default;
};

/**
 * @brief Client-side HTTP/2 stream state
 * 
 * Extends the base stream state with client-specific information such as
 * the assembled response, request metadata, and push promise handling.
 */
struct Http2ClientStream : public Http2StreamState {
    qb::http::Response assembled_response;      ///< Response being assembled
    uint64_t application_request_id = 0;        ///< Application-level request ID
    uint32_t associated_stream_id = 0;          ///< For pushed streams (unused by client sending requests)
    std::string method;                         ///< HTTP method for this request (from original request)
    bool response_dispatched = false;           ///< Response has been dispatched
    bool client_will_send_trailers = false;     ///< Client intends to send trailers for the current request
    
    // For sending request body
    bool has_pending_data_to_send = false;      ///< True if original_request_to_send.body() has data remaining.
    qb::http::Request original_request_to_send; ///< Stores the original request if its body needs to be sent progressively.
    size_t send_buffer_offset = 0;              ///< Current offset in original_request_to_send.body().raw()
    std::vector<std::string> _expected_trailer_names; ///< Names of headers expected in the trailer part, parsed from "Trailer" header.

    std::vector<hpack::HeaderField> synthetic_request_headers; ///< For PUSH_PROMISE validation/info by app
    bool request_sent = false;                  ///< Initial HEADERS frame for the request has been sent

    /**
     * @brief Construct a new client stream
     * @param stream_id Stream identifier
     * @param initial_peer_window Initial peer flow control window size
     * @param initial_local_window Initial local flow control window size
     */
    explicit Http2ClientStream(uint32_t stream_id, int64_t initial_peer_window, int64_t initial_local_window)
        : Http2StreamState(stream_id, initial_peer_window, initial_local_window) {
    }
};

/**
 * @brief Server-side HTTP/2 stream state
 * 
 * Extends the base stream state with server-specific information such as
 * the assembled request, response handling state, and push promise support.
 */
struct Http2ServerStream : public Http2StreamState {
    // Application-specific members for server side
    qb::http::Request assembled_request;        ///< Request being assembled
    bool request_dispatched = false;            ///< Request has been dispatched
    bool response_sent = false;                 ///< Tracks if initial HEADERS frame for response was sent
    bool server_will_send_trailers = false;     ///< Server intends to send trailers - REVIEW if needed, might be covered by is_trailers
    std::string method;                         ///< HTTP method from request
    
    // Response sending state for the current response_to_send
    size_t send_buffer_offset = 0;              ///< Current offset in response_to_send.body().raw()
    qb::unordered_set<std::string> headers_sent_in_initial_frame; ///< Headers already sent in the first HEADERS frame for this response
    
    // Push promise support
    std::vector<uint32_t> associated_push_promises; ///< IDs of PUSH_PROMISE streams initiated *by this* server stream (if it's a client request stream)
    uint32_t parent_stream_id = 0;              ///< If *this* stream *is* a server-pushed stream, this is the ID of the client-initiated stream it's associated with.
    // uint32_t associated_stream_id = 0;       ///< REMOVED - Consolidate to parent_stream_id for clarity when this stream IS a pushed stream.

    // Fields for header processing (incoming request headers)
    std::vector<hpack::HeaderField> decoded_header_fields;         ///< Decoded HPACK fields for current header block
    std::vector<uint8_t> last_received_header_block_fragment;    ///< Raw bytes of last header block for PUSH_PROMISE validation
    FrameHeader last_received_frame_header;                      ///< Header of the frame that completed the last header block

    qb::io::uri request_uri;                                     ///< URI assembled from incoming request pseudo-headers
    uint64_t application_tracking_id = 0;                        ///< For app to track request/response pair

    // State for current outgoing response
    bool has_pending_data_to_send = false; ///< True if response_to_send.body() has data remaining or if trailers are pending after body.
    qb::http::Response response_to_send;   ///< The complete response object being sent (headers, body, trailers).
    bool is_trailers = false;              ///< True if response_to_send includes trailers that need to be sent after the body.

    /**
     * @brief Construct a new server stream
     * @param stream_id Stream identifier
     * @param initial_peer_window Initial peer flow control window size
     * @param initial_local_window Initial local flow control window size
     */
    explicit Http2ServerStream(uint32_t stream_id, int64_t initial_peer_window, int64_t initial_local_window)
        : Http2StreamState(stream_id, initial_peer_window, initial_local_window) {
         state = Http2StreamConcreteState::IDLE;
    }
};

/**
 * @brief Event for stream-specific errors
 */
struct Http2StreamErrorEvent {
    uint32_t stream_id;     ///< Stream identifier
    ErrorCode error_code;   ///< Error code
    std::string message;    ///< Error description

    /**
     * @brief Construct a stream error event
     * @param sid Stream identifier
     * @param ec Error code
     * @param msg Error message
     */
    Http2StreamErrorEvent(uint32_t sid, ErrorCode ec, std::string msg = "")
        : stream_id(sid), error_code(ec), message(std::move(msg)) {}
};

/**
 * @brief Event for GOAWAY frame reception
 */
struct Http2GoAwayEvent {
    ErrorCode error_code;       ///< Error code from GOAWAY
    uint32_t last_stream_id;    ///< Last stream ID processed by sender
    std::string debug_data;     ///< Additional debug information

    /**
     * @brief Construct a GOAWAY event
     * @param ec Error code
     * @param lsid Last stream ID
     * @param dbg Debug data
     */
    Http2GoAwayEvent(ErrorCode ec, uint32_t lsid, std::string dbg = "")
        : error_code(ec), last_stream_id(lsid), debug_data(std::move(dbg)) {}
};

/**
 * @brief Event for PUSH_PROMISE frame reception
 */
struct Http2PushPromiseEvent {
    uint32_t associated_stream_id;  ///< Client-initiated stream this push relates to
    uint32_t promised_stream_id;    ///< New stream ID for pushed content
    qb::http::Headers headers;      ///< Decoded request headers from PUSH_PROMISE

    /**
     * @brief Construct a push promise event
     * @param assoc_sid Associated stream ID
     * @param prom_sid Promised stream ID
     * @param h Request headers
     */
    Http2PushPromiseEvent(uint32_t assoc_sid, uint32_t prom_sid, qb::http::Headers h)
        : associated_stream_id(assoc_sid), promised_stream_id(prom_sid), headers(std::move(h)) {}
};

/**
 * @brief Event for connection-level errors
 */
struct Http2ConnectionErrorEvent {
    ErrorCode error_code;   ///< Error code
    std::string message;    ///< Error description
    bool fatal;            ///< If true, connection must be terminated

    /**
     * @brief Construct a connection error event
     * @param ec Error code
     * @param msg Error message
     * @param is_fatal Whether the error is fatal
     */
    Http2ConnectionErrorEvent(ErrorCode ec, std::string msg, bool is_fatal)
        : error_code(ec), message(std::move(msg)), fatal(is_fatal) {}
};

} // namespace qb::protocol::http2 