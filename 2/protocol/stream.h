/**
 * @file qbm/http/2/protocol/stream.h
 * @brief HTTP/2 stream management and state tracking
 *
 * This file provides stream state management classes for both client and server
 * sides of HTTP/2 connections. It includes:
 *
 * - Stream state machine implementation
 * - Flow control window management  
 * - Request/response data assembly
 * - Stream lifecycle tracking
 * - Priority and dependency management
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
#include <chrono>

#include "../../request.h"
#include "../../response.h"
#include "./frames.h" // For Http2PriorityData, ErrorCode, frame constants, DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE
#include "./hpack.h"  // For HeaderField

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
 * @brief Flow control management helper
 * 
 * Centralizes flow control logic to avoid duplication between client/server streams
 */
class FlowControlManager {
public:
    /**
     * @brief Update flow control window and check for overflow
     * @param current_window Current window size
     * @param increment Window increment value
     * @param max_window Maximum allowed window size
     * @return New window size, or -1 on overflow
     */
    static int64_t update_window_safe(int64_t current_window, uint32_t increment, int64_t max_window) {
        int64_t new_window = current_window + static_cast<int64_t>(increment);
        if (new_window > max_window) {
            return -1; // Overflow
        }
        return new_window;
    }

    /**
     * @brief Check if WINDOW_UPDATE should be sent
     * @param processed_bytes Bytes processed since last update
     * @param threshold Threshold for sending update
     * @return true if update should be sent
     */
    static bool should_send_window_update(uint32_t processed_bytes, uint32_t threshold) {
        return processed_bytes >= threshold && threshold > 0;
    }

    /**
     * @brief Calculate window update threshold
     * @param initial_window Initial window size
     * @param divisor Threshold divisor
     * @return Calculated threshold
     */
    static uint32_t calculate_window_threshold(int64_t initial_window, int divisor = 2) {
        if (initial_window <= 0 || divisor <= 0) return 1;
        uint32_t threshold = static_cast<uint32_t>(initial_window / divisor);
        return threshold == 0 ? 1 : threshold;
    }
};

/**
 * @brief Base class for HTTP/2 stream state management
 * 
 * Provides common functionality for both client and server streams including:
 * - Flow control window management
 * - Stream state tracking
 * - Header processing state
 * - Error handling
 */
class Http2StreamBase {
public:
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

    // Timing information
    std::chrono::steady_clock::time_point created_at; ///< Stream creation time
    std::chrono::steady_clock::time_point last_activity; ///< Last activity time

protected:
    static constexpr int DEFAULT_STREAM_WINDOW_UPDATE_THRESHOLD_DIVISOR = 2;

public:
    /**
     * @brief Construct a new stream state
     * @param stream_id Stream identifier
     * @param initial_peer_window Initial peer flow control window size
     * @param initial_local_window Initial local flow control window size
     */
    Http2StreamBase(uint32_t stream_id, int64_t initial_peer_window, int64_t initial_local_window)
        : id(stream_id)
        , local_window_size(initial_local_window)
        , peer_window_size(initial_peer_window)
        , window_update_threshold(FlowControlManager::calculate_window_threshold(initial_local_window))
        , created_at(std::chrono::steady_clock::now())
        , last_activity(created_at) {
    }

    virtual ~Http2StreamBase() = default;

    // Non-copyable, but movable for container usage
    Http2StreamBase(const Http2StreamBase&) = delete;
    Http2StreamBase& operator=(const Http2StreamBase&) = delete;
    Http2StreamBase(Http2StreamBase&&) = default;
    Http2StreamBase& operator=(Http2StreamBase&&) = default;

    /**
     * @brief Check if stream is in a closed state
     * @return true if stream is closed or reset
     */
    [[nodiscard]] bool is_closed() const noexcept {
        return state == Http2StreamConcreteState::CLOSED || rst_stream_received || rst_stream_sent;
    }

    /**
     * @brief Check if stream can send data
     * @return true if local endpoint can send data
     */
    [[nodiscard]] bool can_send_data() const noexcept {
        return state == Http2StreamConcreteState::OPEN || 
               state == Http2StreamConcreteState::HALF_CLOSED_REMOTE;
    }

    /**
     * @brief Check if stream can receive data
     * @return true if local endpoint can receive data
     */
    [[nodiscard]] bool can_receive_data() const noexcept {
        return state == Http2StreamConcreteState::OPEN || 
               state == Http2StreamConcreteState::HALF_CLOSED_LOCAL;
    }

    /**
     * @brief Update last activity timestamp
     */
    void touch() noexcept {
        last_activity = std::chrono::steady_clock::now();
    }

    /**
     * @brief Get stream age in milliseconds
     * @return Age in milliseconds
     */
    [[nodiscard]] std::chrono::milliseconds get_age() const noexcept {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - created_at);
    }

    /**
     * @brief Get time since last activity in milliseconds
     * @return Time since last activity in milliseconds
     */
    [[nodiscard]] std::chrono::milliseconds get_idle_time() const noexcept {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - last_activity);
    }

    /**
     * @brief Process received data and update flow control
     * @param data_size Size of received data
     * @return true if WINDOW_UPDATE should be sent
     */
    bool process_received_data(uint32_t data_size) noexcept {
        touch();
        local_window_size -= static_cast<int64_t>(data_size);
        processed_bytes_for_window_update += data_size;
        
        return FlowControlManager::should_send_window_update(
            processed_bytes_for_window_update, window_update_threshold);
    }

    /**
     * @brief Update peer window size safely
     * @param new_initial_size New initial window size
     * @param old_initial_size Old initial window size
     * @return true if update successful, false if overflow
     */
    bool update_peer_window_size(uint32_t new_initial_size, uint32_t old_initial_size) noexcept {
        int64_t delta = static_cast<int64_t>(new_initial_size) - static_cast<int64_t>(old_initial_size);
        int64_t new_window = FlowControlManager::update_window_safe(
            peer_window_size, static_cast<uint32_t>(std::abs(delta)), 
            static_cast<int64_t>(MAX_WINDOW_SIZE_LIMIT));
        
        if (new_window == -1) {
            return false; // Overflow
        }
        
        peer_window_size = delta >= 0 ? new_window : peer_window_size + delta;
        return peer_window_size >= 0;
    }

    /**
     * @brief Reset window update tracking after sending WINDOW_UPDATE
     * @param increment_sent The increment that was sent
     */
    void reset_window_update_tracking(uint32_t increment_sent) noexcept {
        local_window_size += static_cast<int64_t>(increment_sent);
        processed_bytes_for_window_update = 0;
    }

    /**
     * @brief Transition stream state based on events
     * @param end_stream_flag Whether END_STREAM flag was set
     * @param is_sending Whether we are sending (true) or receiving (false)
     */
    void transition_state(bool end_stream_flag, bool is_sending) noexcept {
        if (!end_stream_flag) return;

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

    /**
     * @brief Mark stream as reset
     * @param error_code_param Error code for reset
     * @param is_sending Whether we are sending (true) or receiving (false) the reset
     */
    void mark_reset(ErrorCode error_code_param, bool is_sending) noexcept {
        error_code = error_code_param;
        state = Http2StreamConcreteState::CLOSED;
        
        if (is_sending) {
            rst_stream_sent = true;
        } else {
            rst_stream_received = true;
        }
        touch();
    }
};

/**
 * @brief Client-side HTTP/2 stream state
 * 
 * Extends the base stream state with client-specific information such as
 * the assembled response, request metadata, and push promise handling.
 */
struct Http2ClientStream : public Http2StreamBase {
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

    std::vector<qb::protocol::hpack::HeaderField> synthetic_request_headers; ///< For PUSH_PROMISE validation/info by app
    bool request_sent = false;                  ///< Initial HEADERS frame for the request

    /**
     * @brief Construct a new client stream
     * @param stream_id Stream identifier
     * @param initial_peer_window Initial peer flow control window size
     * @param initial_local_window Initial local flow control window size
     */
    explicit Http2ClientStream(uint32_t stream_id, int64_t initial_peer_window, int64_t initial_local_window)
        : Http2StreamBase(stream_id, initial_peer_window, initial_local_window) {
    }

    // Delete copy operations but allow move operations for container usage
    Http2ClientStream(const Http2ClientStream&) = delete;
    Http2ClientStream& operator=(const Http2ClientStream&) = delete;
    Http2ClientStream(Http2ClientStream&&) = default;
    Http2ClientStream& operator=(Http2ClientStream&&) = default;
};

/**
 * @brief Server-side HTTP/2 stream state
 * 
 * Extends the base stream state with server-specific information such as
 * the assembled request, response handling state, and push promise support.
 */
struct Http2ServerStream : public Http2StreamBase {
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
    std::vector<qb::protocol::hpack::HeaderField> decoded_header_fields;         ///< Decoded HPACK fields for current header block
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
        : Http2StreamBase(stream_id, initial_peer_window, initial_local_window) {
         state = Http2StreamConcreteState::IDLE;
    }

    // Delete copy operations but allow move operations for container usage
    Http2ServerStream(const Http2ServerStream&) = delete;
    Http2ServerStream& operator=(const Http2ServerStream&) = delete;
    Http2ServerStream(Http2ServerStream&&) = default;
    Http2ServerStream& operator=(Http2ServerStream&&) = default;
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

/**
 * @brief Stream management helper for HTTP/2 connections
 * 
 * Centralizes common stream management operations to reduce duplication
 * between client and server implementations.
 */
template<typename StreamType>
class StreamManager {
public:
    using StreamMap = qb::unordered_map<uint32_t, StreamType>;
    
    /**
     * @brief Stream cleanup criteria
     */
    struct CleanupCriteria {
        std::chrono::milliseconds max_idle_time{0};    ///< Maximum idle time (0 = no limit)
        std::chrono::milliseconds max_age{0};          ///< Maximum stream age (0 = no limit)
        bool cleanup_closed_streams = true;            ///< Remove closed streams
        bool cleanup_reset_streams = true;             ///< Remove reset streams
        uint32_t max_total_streams = 0;                ///< Maximum total streams (0 = no limit)
    };

    /**
     * @brief Stream statistics
     */
    struct StreamStats {
        std::size_t total_streams = 0;
        std::size_t active_streams = 0;
        std::size_t closed_streams = 0;
        std::size_t reset_streams = 0;
        std::size_t idle_streams = 0;
        std::chrono::milliseconds oldest_stream_age{0};
        std::chrono::milliseconds average_stream_age{0};
    };

private:
    StreamMap& _streams;

public:
    /**
     * @brief Construct stream manager
     * @param streams Reference to the stream map
     */
    explicit StreamManager(StreamMap& streams) : _streams(streams) {}

    /**
     * @brief Clean up streams based on criteria
     * @param criteria Cleanup criteria
     * @return Number of streams removed
     */
    std::size_t cleanup_streams(const CleanupCriteria& criteria) {
        std::size_t removed_count = 0;
        auto now = std::chrono::steady_clock::now();
        
        for (auto it = _streams.begin(); it != _streams.end(); ) {
            const StreamType& stream = it->second;
            bool should_remove = false;
            
            // Check if stream is closed and should be cleaned up
            if (criteria.cleanup_closed_streams && stream.is_closed()) {
                should_remove = true;
            }
            
            // Check if stream is reset and should be cleaned up
            if (criteria.cleanup_reset_streams && 
                (stream.rst_stream_received || stream.rst_stream_sent)) {
                should_remove = true;
            }
            
            // Check idle time
            if (criteria.max_idle_time.count() > 0) {
                auto idle_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - stream.last_activity);
                if (idle_time > criteria.max_idle_time) {
                    should_remove = true;
                }
            }
            
            // Check age
            if (criteria.max_age.count() > 0) {
                auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - stream.created_at);
                if (age > criteria.max_age) {
                    should_remove = true;
                }
            }
            
            if (should_remove) {
                it = _streams.erase(it);
                removed_count++;
            } else {
                ++it;
            }
        }
        
        // Check total stream limit
        if (criteria.max_total_streams > 0 && _streams.size() > criteria.max_total_streams) {
            // Remove oldest closed streams first
            std::vector<typename StreamMap::iterator> candidates;
            for (auto it = _streams.begin(); it != _streams.end(); ++it) {
                if (it->second.is_closed()) {
                    candidates.push_back(it);
                }
            }
            
            // Sort by age (oldest first)
            std::sort(candidates.begin(), candidates.end(), 
                     [](const auto& a, const auto& b) {
                         return a->second.created_at < b->second.created_at;
                     });
            
            std::size_t to_remove = _streams.size() - criteria.max_total_streams;
            std::size_t can_remove = std::min(to_remove, candidates.size());
            
            for (std::size_t i = 0; i < can_remove; ++i) {
                _streams.erase(candidates[i]);
                removed_count++;
            }
        }
        
        return removed_count;
    }

    /**
     * @brief Get stream statistics
     * @return Stream statistics
     */
    [[nodiscard]] StreamStats get_statistics() const {
        StreamStats stats;
        stats.total_streams = _streams.size();
        
        if (_streams.empty()) {
            return stats;
        }
        
        auto now = std::chrono::steady_clock::now();
        std::chrono::milliseconds total_age{0};
        std::chrono::milliseconds oldest_age{0};
        
        for (const auto& [stream_id, stream] : _streams) {
            auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - stream.created_at);
            total_age += age;
            
            if (age > oldest_age) {
                oldest_age = age;
            }
            
            if (stream.is_closed()) {
                stats.closed_streams++;
            } else if (stream.rst_stream_received || stream.rst_stream_sent) {
                stats.reset_streams++;
            } else if (stream.state == Http2StreamConcreteState::IDLE) {
                stats.idle_streams++;
            } else {
                stats.active_streams++;
            }
        }
        
        stats.oldest_stream_age = oldest_age;
        stats.average_stream_age = std::chrono::milliseconds(total_age.count() / _streams.size());
        
        return stats;
    }

    /**
     * @brief Check if all streams are closed for graceful shutdown
     * @param last_processed_stream_id Last processed stream ID (for GOAWAY)
     * @param is_server Whether this is server-side (affects stream ID parity check)
     * @return true if all relevant streams are closed
     */
    [[nodiscard]] bool are_all_relevant_streams_closed(uint32_t last_processed_stream_id, 
                                                       bool is_server) const {
        for (const auto& [stream_id, stream] : _streams) {
            // Skip streams that are beyond the GOAWAY boundary
            if (last_processed_stream_id > 0) {
                // For server: only check client-initiated streams (odd IDs)
                // For client: only check server-initiated streams (even IDs) 
                bool is_relevant_stream = is_server ? (stream_id % 2 == 1) : (stream_id % 2 == 0);
                
                if (is_relevant_stream && stream_id <= last_processed_stream_id) {
                    if (!stream.is_closed()) {
                        return false;
                    }
                }
            } else {
                // No GOAWAY sent yet, check all streams
                if (!stream.is_closed()) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * @brief Get count of active streams by type
     * @param server_initiated_only Whether to count only server-initiated streams
     * @return Number of active streams
     */
    [[nodiscard]] std::size_t get_active_stream_count(bool server_initiated_only = false) const {
        std::size_t count = 0;
        
        for (const auto& [stream_id, stream] : _streams) {
            if (server_initiated_only && (stream_id % 2 == 1)) {
                continue; // Skip client-initiated streams
            }
            
            if (!stream.is_closed() && 
                stream.state != Http2StreamConcreteState::IDLE) {
                count++;
            }
        }
        
        return count;
    }

    /**
     * @brief Update flow control windows for all streams
     * @param new_initial_size New initial window size
     * @param old_initial_size Old initial window size
     * @return Number of streams that had overflow errors
     */
    std::size_t update_all_stream_windows(uint32_t new_initial_size, uint32_t old_initial_size) {
        std::size_t error_count = 0;
        
        for (auto& [stream_id, stream] : _streams) {
            if (!stream.update_peer_window_size(new_initial_size, old_initial_size)) {
                error_count++;
                // Mark stream for reset due to flow control error
                stream.mark_reset(ErrorCode::FLOW_CONTROL_ERROR, false);
            }
        }
        
        return error_count;
    }

    /**
     * @brief Find streams that need WINDOW_UPDATE
     * @return Vector of stream IDs that need updates
     */
    [[nodiscard]] std::vector<uint32_t> find_streams_needing_window_update() const {
        std::vector<uint32_t> stream_ids;
        
        for (const auto& [stream_id, stream] : _streams) {
            if (stream.processed_bytes_for_window_update >= stream.window_update_threshold &&
                stream.can_receive_data()) {
                stream_ids.push_back(stream_id);
            }
        }
        
        return stream_ids;
    }
};

} // namespace qb::protocol::http2 