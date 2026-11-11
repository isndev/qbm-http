/**
 * @file qbm/http/2/protocol/server.h
 * @brief HTTP/2 server protocol implementation for qb-io framework
 *
 * This file provides HTTP/2 server-side protocol handling built on top of
 * the qb-io asynchronous framework. It includes:
 *
 * - Complete HTTP/2 server protocol implementation
 * - HPACK header compression and decompression
 * - Stream multiplexing and flow control management
 * - Request processing and response generation
 * - Connection and stream lifecycle management
 * - Settings negotiation and window updates
 * - Error handling for protocol violations
 * - Integration with HTTP/1.1 request/response objects
 *
 * The server efficiently handles multiple concurrent streams per connection
 * with proper flow control and resource management.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <type_traits> // std::void_t, std::declval: the io's write-cap trait (Huly QB-86)
#include <memory>      // std::unique_ptr: a streamed response's buffer, allocated when it begins (Huly QB-86)
#include <utility>
#include <algorithm> // std::min over the windows, the frame size and the socket's room (Huly QB-86)
#include <cstring>   // std::memcpy: a streamed body's piece into its stream's buffer (Huly QB-86)
#include <concepts>  // std::convertible_to: counts_appended_output (Huly QB-1212)

#include "../../origin.h" // origin::authority, the :authority every protocol writes (Huly QB-1064); origin::request_uri
#include "./base.h"       // For qb::protocol::http2::Http2Protocol and frame types

namespace qb::http::well_known {
/// HTTP/2 ":method" request pseudo-header name.
constexpr std::string_view COLON_METHOD_SV = ":method";
/// HTTP/2 ":path" request pseudo-header name.
constexpr std::string_view COLON_PATH_SV = ":path";
/// HTTP/2 ":scheme" request pseudo-header name.
constexpr std::string_view COLON_SCHEME_SV = ":scheme";
/// HTTP/2 ":authority" request pseudo-header name.
constexpr std::string_view COLON_AUTHORITY_SV = ":authority";
/// "content-length" header name.
constexpr std::string_view CONTENT_LENGTH_SV = "content-length";
/// "transfer-encoding" header name (forbidden in HTTP/2).
constexpr std::string_view TRANSFER_ENCODING_SV = "transfer-encoding";
/// "trailer" header name.
constexpr std::string_view TRAILER_SV = "trailer";

/**
 * @brief Check if a header is hop-by-hop
 * @param header_name Header name to check (compared case-insensitively)
 * @return true if @p header_name names a hop-by-hop header that must not be
 *         forwarded across an HTTP/2 boundary, false otherwise
 */
inline bool
is_hop_by_hop(const std::string &header_name) {
    // Convert to lowercase for comparison
    std::string lower_name = header_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

    return lower_name == "connection" || lower_name == "keep-alive" || lower_name == "proxy-authenticate" || lower_name == "proxy-authorization"
           || lower_name == "te" || lower_name == "trailers" || lower_name == "transfer-encoding" || lower_name == "upgrade";
}
} // namespace qb::http::well_known

/// The head collection shared by send_response() and begin_streamed_response() is inlined into both, as it was when it
/// lived inside send_response() alone: a call with three out-parameters measured on a plain GET (Huly QB-86).
#if defined(_MSC_VER) && !defined(__clang__)
#define QB_HTTP2_FORCEINLINE __forceinline
#else
#define QB_HTTP2_FORCEINLINE [[gnu::always_inline]] inline
#endif

namespace qb::protocol::http2 {

/// An IO handler that counts every byte it ever appended to its output (`appended_total()`): the streamed responses
/// mark the end of each DATA frame on that count for their stall watch (Huly QB-1212); a handler without it, such as
/// the unit tests' fakes, leaves the mark at 0.
template <typename IO>
concept counts_appended_output = requires(IO const &io) {
    { io.appended_total() } -> std::convertible_to<std::uint64_t>;
};

namespace detail {
/// Whether the io exposes its write-buffer cap (`max_write_buffer_size()`): a test harness does, the real session's
/// is its transport's, a private base, so the protocol then reads qb-io's default (Huly QB-86). A trait, not a
/// requires-expression on the class's parameter: an access failure there is a hard error once instantiated.
template <typename IO, typename = void>
struct io_has_write_cap : std::false_type {};
template <typename IO>
struct io_has_write_cap<IO, std::void_t<decltype(std::declval<IO const &>().max_write_buffer_size())>> : std::true_type {};
} // namespace detail

/// HTTP/2 ":status" response pseudo-header name.
constexpr std::string_view STATUS_HEADER_NAME_SV = ":status";

/**
 * @brief HTTP/2 server protocol implementation
 *
 * This class implements the server-side HTTP/2 protocol handler. It processes
 * incoming HTTP/2 frames from clients, manages stream lifecycle, handles flow
 * control, and produces HTTP request objects for the application layer.
 *
 * @tparam IO_Handler Type that receives HTTP request objects and handles responses
 */
template <typename IO_Handler>
class ServerHttp2Protocol : public Http2Protocol<IO_Handler, ServerHttp2Protocol<IO_Handler>> {
public:
    using FramerBase = Http2Protocol<IO_Handler, ServerHttp2Protocol<IO_Handler>>;
    friend class qb::protocol::http2::Http2Protocol<IO_Handler, ServerHttp2Protocol<IO_Handler>>;

private:
    qb::unordered_map<uint32_t, Http2ServerStream> _server_streams;                      ///< Active stream contexts
    uint32_t                                       _last_client_initiated_stream_id = 0; ///< Last valid client stream ID
    uint32_t                                       _next_server_initiated_stream_id = 2; ///< Next server stream ID (for PUSH)
    std::uint32_t _rst_stream_count = 0, _client_streams_opened = 0; ///< Client resets, sent or provoked; streams opened (Rapid Reset)
    std::uint32_t _control_reply_count      = 0;                     ///< PONG+SETTINGS-ACK replies since real progress (flood guard)
    std::uint32_t _continuation_frame_count = 0;                     ///< CONTINUATION frames in the current header block (flood guard)

    std::vector<uint8_t> _current_header_block_fragment;    ///< Header block assembly buffer
    uint32_t             _current_header_stream_id = 0;     ///< Stream ID for header assembly
    bool                 _discarding_header_block  = false; ///< The block in assembly is refused: decode it, drop its fields
    /// The fields of the block in assembly, decoded: one vector a connection, read once the block is complete and
    /// cleared on every exit of its handler, so its capacity serves every stream and nothing of one stream reaches
    /// the next. A vector a stream grew 1 -> 2 -> 4 -> ... -> 32 fields for a browser's request -- six allocations,
    /// two of them past 1 KiB, the size from which glibc consolidates its fast bins before serving, after which the
    /// request's small allocations took the allocator's slow path (Huly QB-1215).
    std::vector<qb::protocol::hpack::HeaderField> _decoded_header_fields;
    /// The fields of the response being sent, the same way: one vector a connection, filled and encoded in
    /// send_response(), cleared on its every exit (Huly QB-1215).
    std::vector<qb::protocol::hpack::HeaderField> _response_header_fields;
    /// Clears a connection-level field vector when the scope that filled it ends, whatever the exit.
    struct ClearedOnExit {
        std::vector<qb::protocol::hpack::HeaderField> &fields;
        ~ClearedOnExit() {
            fields.clear();
        }
    };

    int64_t              _connection_send_window;            ///< Connection-level send window
    bool                 _streams_wait_for_socket   = false; ///< A streamed response's flush stopped at the socket's write cap (Huly QB-86)
    int64_t              _connection_receive_window = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE; ///< Connection-level receive window
    static constexpr int CONNECTION_WINDOW_THRESHOLD_DIVISOR = 2;

    // Peer (Client) Settings
    uint32_t _initial_peer_window_size    = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;    ///< Client's initial window size
    uint32_t _peer_max_concurrent_streams = DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS; ///< Max concurrent streams from client
    uint64_t _peer_max_header_list_size   = DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE;   ///< Max header list size client accepts
    bool     _peer_allows_push            = true;                                    ///< Whether client allows server push
    /// The largest stream the server has reserved with a PUSH_PROMISE: a promised stream exceeds it (RFC 9113 §5.1.1).
    uint32_t _last_promised_stream_id = 0;
    /// The promised streams whose response waits, kept in the stream, for room under the client's
    /// SETTINGS_MAX_CONCURRENT_STREAMS -- a reserved stream counts once its HEADERS open it (RFC 9113 §5.1.2) --, in
    /// the order they were answered: send_waiting_push_responses() sends them (Huly QB-1202).
    std::vector<uint32_t> _waiting_push_responses;
    bool                  _sending_waiting_push_responses = false;
    /// The promised stream send_waiting_push_responses() is sending: it alone passes the responses waiting behind it.
    uint32_t _push_response_leaving = 0;
    /// A GOAWAY received: no promised stream opens any more (RFC 9113 §6.8, Huly QB-1202).
    bool _peer_goaway_received = false;

    // Our Settings
    qb::unordered_map<Http2SettingIdentifier, uint32_t> _our_settings;                  ///< Server's HTTP/2 settings
    bool                                                _initial_settings_sent = false; ///< Whether initial SETTINGS sent

    bool _connection_active           = true;  ///< Connection active flag
    bool _graceful_shutdown_initiated = false; ///< Graceful shutdown flag

    /// A graceful shutdown this server began (RFC 9113 section 6.8, Huly QB-91): none; the notice sent -- a GOAWAY
    /// naming the largest stream id, and a PING whose ACK is the round trip it waits for; or the final GOAWAY sent.
    enum class shutdown_phase : std::uint8_t { none, notice, final_goaway };
    shutdown_phase _shutdown_phase = shutdown_phase::none;

    /// The opaque data of the notice's PING: an ACK carrying it ends the notice.
    static constexpr std::array<uint8_t, 8> SHUTDOWN_PING_DATA{'q', 'b', '-', 'd', 'r', 'a', 'i', 'n'};
    /// The largest stream id, which the notice's GOAWAY names: every stream the client opens is still served.
    static constexpr uint32_t SHUTDOWN_NOTICE_LAST_STREAM_ID = 0x7FFFFFFFu;
    /// The largest stream id there is (31 bits, RFC 9113 §5.1.1): a promised stream's id is at most this.
    static constexpr uint32_t MAX_STREAM_ID = 0x7FFFFFFFu;

    qb::protocol::hpack::Decoder _hpack_decoder; ///< HPACK decoder (F35 &mdash; owned by value)
    qb::protocol::hpack::Encoder _hpack_encoder; ///< HPACK encoder (F35 &mdash; owned by value)

    int64_t _connection_bytes_consumed_since_last_window_update = 0; ///< Bytes consumed for window update

    // Add as a private member to ServerHttp2Protocol class
    // private:
    //    bool _debug_send_padded_data = false; // Set to true to test sending padded DATA frames

public:
    /**
     * @brief Check whether a stream is closed or unknown
     * @param stream_id Stream identifier to query
     * @return true if the stream has no active context or its context is in the
     *         CLOSED state, false if it is still open/active
     */
    [[nodiscard]] bool
    is_stream_closed(uint32_t stream_id) const {
        auto it = _server_streams.find(stream_id);
        return it == _server_streams.end() || it->second.is_closed();
    }

    /**
     * @brief Validate HTTP/2 header name and value according to RFC 9113
     * @param name Header field name
     * @param value Header field value
     * @return true if valid, false if contains forbidden characters
     *
     * SECURITY FIX: Implements validation that was marked as TODO in the code.
     * According to RFC 9113:
     * - Header names must not contain uppercase letters (should be lowercase)
     * - Neither name nor value may contain NUL (0x00), CR (0x0D), or LF (0x0A)
     * - Values may contain TAB (0x09) but no other control characters (0x00-0x1F)
     * - Names must be valid token strings (no separators like : , ; etc.)
     */
    [[nodiscard]] static bool
    is_valid_header_field(const std::string &name, const std::string &value) noexcept {
        return HeaderValidator::is_valid_header_field(name, value);
    }
    /**
     * @brief Construct HTTP/2 server protocol handler
     * @param io_handler_ref Reference to IO handler that receives requests
     */
    explicit ServerHttp2Protocol(IO_Handler &io_handler_ref)
        : FramerBase(io_handler_ref) {
        LOG_HTTP_DEBUG("ServerHttp2Protocol: Constructing HTTP/2 server protocol handler");
        this->_our_max_frame_size = this->initialize_our_max_frame_size();
        _connection_send_window   = this->get_initial_window_size_from_settings();

        // Apply HPACK encoder settings based on _our_settings.
        auto it_table_size = _our_settings.find(Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE);
        if (it_table_size != _our_settings.end()) {
            _hpack_encoder.set_max_capacity(it_table_size->second);
            LOG_HTTP_DEBUG("ServerHttp2Protocol: HPACK encoder max capacity set to " << it_table_size->second);
        }

        this->reset();
        LOG_HTTP_INFO("ServerHttp2Protocol: HTTP/2 server protocol handler constructed successfully");
    }

    ~ServerHttp2Protocol() override = default;

    // Disable copy and move
    ServerHttp2Protocol(const ServerHttp2Protocol &)            = delete;
    ServerHttp2Protocol &operator=(const ServerHttp2Protocol &) = delete;
    ServerHttp2Protocol(ServerHttp2Protocol &&)                 = delete;
    ServerHttp2Protocol &operator=(ServerHttp2Protocol &&)      = delete;

    /**
     * @brief Reset protocol state to initial conditions
     */
    void
    reset() noexcept override {
        LOG_HTTP_DEBUG("ServerHttp2Protocol: Resetting protocol state to initial conditions");
        FramerBase::reset(); // Call base class reset first

        _server_streams.clear();
        _current_header_block_fragment.clear();
        _current_header_stream_id        = 0;
        _last_client_initiated_stream_id = 0;
        _next_server_initiated_stream_id = 2;
        _rst_stream_count = _client_streams_opened = 0;
        _control_reply_count                       = 0;
        _continuation_frame_count                  = 0;
        _connection_active                         = true;
        _graceful_shutdown_initiated               = false;
        _shutdown_phase                            = shutdown_phase::none;
        _initial_settings_sent                     = false;

        // Re-initialize our settings and derived values
        this->initialize_our_settings_map();

        _connection_send_window    = this->get_initial_window_size_from_settings();
        _connection_receive_window = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;

        _initial_peer_window_size = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;
        FramerBase::set_peer_max_frame_size(DEFAULT_SETTINGS_MAX_FRAME_SIZE);
        _peer_max_concurrent_streams = DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS;
        _peer_max_header_list_size   = DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE;
        _peer_allows_push            = true;
        _last_promised_stream_id = _highest_client_stream_id = _closed_stream_reply_count = _streams_opened_at_closed_reply = 0;
        _waiting_push_responses.clear();
        _push_response_leaving = 0;
        _peer_goaway_received  = false;

        _streams_opened_at_control_reply = 0; // the PING/SETTINGS budget forgiven from the first stream opened (Huly QB-1270)

        _hpack_decoder.reset();
        _hpack_encoder.reset();
        // Bound the DECODED header-list size we will accept. Without this the decoder
        // keeps its 4 GiB no-op default (HPACK_DEFAULT_MAX_HEADER_LIST_SIZE), so a peer
        // can expand a ≤1 MB encoded block into ~4 GiB of decoded HeaderFields via
        // repeated single-byte indexed references to a large dynamic-table entry (an
        // HPACK decompression bomb). The per-header enforcement in Decoder::decode is
        // already correct — it just needs a sane limit. The bound is advertised
        // (initialize_our_settings_map), and a list past it is decoded and discarded and
        // its request answered 431, up to HPACK_DISCARDED_LIST_FACTOR times it (Huly QB-1196).
        _hpack_decoder.set_max_header_list_size(::qb::http2::protocol_limits::MAX_HEADER_LIST_SIZE);
        auto it_table_size = _our_settings.find(Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE);
        if (it_table_size != _our_settings.end()) {
            _hpack_encoder.set_max_capacity(it_table_size->second);
        }
        LOG_HTTP_INFO("ServerHttp2Protocol: Protocol state reset completed");
    }

    /**
     * @brief Handle preface complete event
     * @param event Preface complete event
     */
    void
    on(qb::protocol::http2::PrefaceCompleteEvent /*event*/) {
        LOG_HTTP_DEBUG("ServerHttp2Protocol: Received preface complete event");
        if (!this->ok() || !_connection_active) {
            LOG_HTTP_WARN("ServerHttp2Protocol: Cannot process preface complete - protocol not OK or connection inactive");
            return;
        }

        send_initial_settings();
    }

    /**
     * @brief Begin a graceful shutdown of the connection (RFC 9113 section 6.8, Huly QB-91).
     *
     * Sends the notice: a GOAWAY naming the largest stream id with NO_ERROR -- the client stops opening streams,
     * and none it opened is lost -- then a PING. The streams that reach the server until that PING's ACK are
     * served as usual; the ACK, a round trip later, sends the final GOAWAY (complete_graceful_shutdown()). A
     * client that never answers the PING keeps the connection in the notice: its owner's deadline completes it.
     * The connection's SETTINGS go first when it had not sent them.
     * @return False, and nothing is sent, when the connection is closing or a shutdown of this server's began.
     */
    bool
    begin_graceful_shutdown() noexcept {
        if (!this->ok() || !_connection_active || _shutdown_phase != shutdown_phase::none)
            return false;
        send_initial_settings();
        _shutdown_phase = shutdown_phase::notice;
        send_graceful_goaway(SHUTDOWN_NOTICE_LAST_STREAM_ID, "graceful shutdown notice");
        Http2FrameData<PingFrame> ping;
        ping.header.type  = static_cast<uint8_t>(FrameType::PING);
        ping.header.flags = 0;
        ping.header.set_stream_id(0);
        ping.payload.opaque_data = SHUTDOWN_PING_DATA;
        this->_io << ping;
        LOG_HTTP_INFO("ServerHttp2Protocol: graceful shutdown notice sent (GOAWAY 2^31-1 + PING)");
        return true;
    }

    /**
     * @brief Send the final GOAWAY of a graceful shutdown (RFC 9113 section 6.8, Huly QB-91): the last stream id
     *        the client opened, NO_ERROR.
     *
     * A stream above it is refused (REFUSED_STREAM: the client may retry it elsewhere); the ones at or below it
     * are served, and the connection closes when the last of them ends -- at once when none is open. Called on the
     * ACK of the notice's PING, by a drain's deadline, or with no notice before for a connection that must serve
     * nothing: its last id is then 0. A no-op once the final GOAWAY is sent or the connection is closing.
     */
    void
    complete_graceful_shutdown() noexcept {
        if (!this->ok() || !_connection_active || _shutdown_phase == shutdown_phase::final_goaway)
            return;
        send_initial_settings();
        _shutdown_phase = shutdown_phase::final_goaway;
        send_graceful_goaway(_last_client_initiated_stream_id, "graceful shutdown");
        _graceful_shutdown_initiated = true;
        LOG_HTTP_INFO("ServerHttp2Protocol: final GOAWAY sent, last stream id " << _last_client_initiated_stream_id);
        if (this->are_all_relevant_streams_closed(_last_client_initiated_stream_id)) {
            _connection_active = false;
            this->not_ok(ErrorCode::NO_ERROR); // nothing left to serve: the connection closes once this is delivered
        }
    }

    /**
     * @brief Whether a graceful shutdown of this server's waits for the ACK of its notice's PING.
     */
    [[nodiscard]] bool
    graceful_shutdown_notice_pending() const noexcept {
        return _shutdown_phase == shutdown_phase::notice;
    }

    /**
     * @brief Handle DATA frame
     * @param data_event DATA frame event
     */
    void
    on(Http2FrameData<DataFrame> data_event) noexcept {
        if (!this->ok() || !_connection_active)
            return;

        const FrameHeader &header    = data_event.header;
        uint32_t           stream_id = header.get_stream_id();
        // RFC 9113 §6.1: the ENTIRE DATA frame payload — the Pad Length octet and the
        // Padding included — counts against connection and stream flow control, NOT just
        // the de-padded application bytes. Debit and replenish the full frame size; the
        // de-padded data is read from data_payload below for body assembly / content-length.
        std::size_t data_payload_size = data_event.payload.data_payload.size() + data_event.payload.padding_size;

        LOG_HTTP_TRACE_PA(stream_id, "Server: Received DATA frame, size: " << data_payload_size << ", flags: " << (int) header.flags);

        if (stream_id == 0) {
            LOG_HTTP_ERROR_PA(stream_id, "Server: DATA frame received on stream 0.");
            this->on_connection_error(ErrorCode::PROTOCOL_ERROR, "DATA frame received on stream 0.");
            return;
        }

        if (static_cast<int64_t>(data_payload_size) > this->_connection_receive_window
            && data_payload_size > 0) { // allow empty data frames if window is 0
            this->on_connection_error(ErrorCode::FLOW_CONTROL_ERROR, "Connection flow control window underflow on data frame.");
            return;
        }

        auto it = _server_streams.find(stream_id);
        if (it == _server_streams.end()) {
            if (stream_id > _highest_client_stream_id) {
                this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "DATA frame received on idle stream");
                return;
            }
            this->_connection_receive_window -= data_payload_size;
            this->send_closed_stream_rst(stream_id, ErrorCode::STREAM_CLOSED, "DATA frame received on closed stream");
            this->conditionally_send_connection_window_update();
            return;
        }

        Http2ServerStream &stream = it->second;

        if (stream.state == Http2StreamConcreteState::IDLE || stream.state == Http2StreamConcreteState::CLOSED || stream.rst_stream_sent
            || stream.rst_stream_received) {
            this->_connection_receive_window -= data_payload_size;
            this->conditionally_send_connection_window_update();
            if (stream.state == Http2StreamConcreteState::IDLE) {
                this->send_closed_stream_rst(stream_id, ErrorCode::STREAM_CLOSED, "DATA frame on IDLE stream.");
            }
            return;
        }
        if (stream.end_stream_received) {
            // Provoked by the client's frame: counted against the Rapid Reset ceiling (MadeYouReset, Huly QB-1244).
            this->send_provoked_rst_stream(stream_id, ErrorCode::STREAM_CLOSED, "DATA frame received after END_STREAM.");
            this->_connection_receive_window -= data_payload_size;
            this->conditionally_send_connection_window_update();
            return;
        }

        if (static_cast<int64_t>(data_payload_size) > stream.local_window_size && data_payload_size > 0) {
            this->send_provoked_rst_stream(stream_id, ErrorCode::FLOW_CONTROL_ERROR, "Stream flow control window exceeded.");
            this->_connection_receive_window -= data_payload_size;
            this->conditionally_send_connection_window_update();
            return;
        }

        this->_connection_receive_window -= data_payload_size;

        stream.local_window_size -= data_payload_size;

        auto &body_pipe = stream.assembled_request.body().raw();
        // A body past its declared content-length is malformed (RFC 9113 §8.1.1) whatever the body limit: judged first,
        // before the frame is appended. It was answered 413 when the overrun passed the limit too (Huly QB-1197).
        if (stream.expected_content_length && body_pipe.size() + data_event.payload.data_payload.size() > *stream.expected_content_length) {
            this->send_provoked_rst_stream(stream_id, ErrorCode::PROTOCOL_ERROR, "HTTP/2 request body exceeds content-length");
            this->conditionally_send_connection_window_update(); // its connection credit comes back, as on the 413 path
            return;
        }
        if (body_pipe.size() + data_event.payload.data_payload.size() > max_request_body_size()) [[unlikely]] {
            // Answered, not reset: 413 on the stream, then NO_ERROR (refuse_request, Huly QB-168), before the
            // frame is appended. Its bytes are dropped with the rest; its connection credit comes back as a
            // closed stream's does.
            this->refuse_request(stream_id, qb::http::status::PAYLOAD_TOO_LARGE, "HTTP/2 request body exceeds configured limit");
            this->conditionally_send_connection_window_update();
            return;
        }
        // Octets of a request body accepted are real progress: they forgive the PING/SETTINGS budget (CVE-2019-9512/9515),
        // past every rejection above. A frame that carries none -- empty, or padding alone -- moves no request forward
        // and forgave it, an empty DATA after every 999 PINGs holding the guard at zero (Huly QB-1270); the end of the
        // stream it may carry is progress once the request is dispatched (control_reply_over_budget()).
        if (!data_event.payload.data_payload.empty()) {
            _control_reply_count = 0;
        }
        body_pipe.put(reinterpret_cast<const char *>(data_event.payload.data_payload.data()), data_event.payload.data_payload.size());

        if (header.flags & FLAG_END_STREAM) {
            stream.end_stream_received = true;

            stream.processed_bytes_for_window_update += data_payload_size;
            if (stream.processed_bytes_for_window_update >= stream.window_update_threshold && stream.window_update_threshold > 0) {
                uint32_t increment = stream.processed_bytes_for_window_update;
                send_window_update(stream_id, increment);
                stream.local_window_size += increment;
                stream.processed_bytes_for_window_update = 0;
            }
            this->conditionally_send_connection_window_update();

            if (stream.headers_received_main) {
                if (stream.expected_content_length && stream.assembled_request.body().size() != *stream.expected_content_length) {
                    this->send_provoked_rst_stream(stream_id, ErrorCode::PROTOCOL_ERROR, "HTTP/2 request content-length mismatch");
                    return;
                }
                this->dispatch_complete_request(stream_id, stream);
            }
            // dispatch_complete_request() can synchronously send a response and
            // erase the stream. Reacquire before updating lifecycle state.
            auto after_dispatch = _server_streams.find(stream_id);
            if (after_dispatch != _server_streams.end()) {
                Http2ServerStream &current_stream = after_dispatch->second;
                // Answered, or reset -- a handler that threw: closed, its slot freed (it was rewritten half-closed, Huly QB-1270).
                if (current_stream.end_stream_sent || current_stream.rst_stream_sent || current_stream.rst_stream_received) {
                    current_stream.state = Http2StreamConcreteState::CLOSED;
                    this->try_close_stream_context(stream_id);
                } else {
                    current_stream.state = Http2StreamConcreteState::HALF_CLOSED_REMOTE;
                }
            }
            return;
        }

        // Send WINDOW_UPDATE for stream if necessary
        stream.processed_bytes_for_window_update += data_payload_size;
        if (stream.processed_bytes_for_window_update >= stream.window_update_threshold
            && stream.window_update_threshold > 0) { // only if threshold > 0
            uint32_t increment = stream.processed_bytes_for_window_update;
            send_window_update(stream_id, increment);
            stream.local_window_size += increment;
            stream.processed_bytes_for_window_update = 0;
        }

        // Send WINDOW_UPDATE for connection if necessary
        this->conditionally_send_connection_window_update();
    }

    /**
     * @brief Handle HEADERS frame
     * @param headers_event HEADERS frame event
     */
    void
    on(Http2FrameData<HeadersFrame> headers_event) noexcept {
        if (!this->ok() || !_connection_active)
            return;

        const FrameHeader &header      = headers_event.header;
        const uint32_t     stream_id   = header.get_stream_id();
        const bool         end_stream  = (header.flags & FLAG_END_STREAM) != 0;
        const bool         end_headers = (header.flags & FLAG_END_HEADERS) != 0;

        LOG_HTTP_TRACE_PA(stream_id, "Server: Received HEADERS frame, flags: " << (int) header.flags);

        if (stream_id == 0) {
            LOG_HTTP_ERROR_PA(stream_id, "Server: HEADERS frame on stream 0.");
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "HEADERS frame on stream 0");
            return;
        }
        if (stream_id % 2 == 0) {
            LOG_HTTP_ERROR_PA(stream_id, "Server: Client initiated HEADERS on even stream ID");
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "Client initiated HEADERS on an even stream ID");
            return;
        }

        Http2ServerStream *stream_ptr = nullptr;
        auto               it         = _server_streams.find(stream_id);

        if (it == _server_streams.end()) {
            if (stream_id <= _highest_client_stream_id) {
                this->send_closed_stream_rst(stream_id, ErrorCode::STREAM_CLOSED, "HEADERS for old/closed stream");
                this->begin_discarded_header_block(stream_id, headers_event.payload.header_block_fragment, end_headers);
                return;
            }
            if (_graceful_shutdown_initiated) {
                this->refuse_new_stream(stream_id, "New stream during graceful shutdown");
                this->begin_discarded_header_block(stream_id, headers_event.payload.header_block_fragment, end_headers);
                return;
            }
            uint32_t active_client_streams = 0;
            for (const auto &pair : _server_streams) {
                if (pair.first % 2 != 0) {
                    const auto &s = pair.second;
                    if (s.state == Http2StreamConcreteState::OPEN || s.state == Http2StreamConcreteState::HALF_CLOSED_LOCAL
                        || s.state == Http2StreamConcreteState::HALF_CLOSED_REMOTE) {
                        active_client_streams++;
                    }
                }
            }
            uint32_t max_concurrent_from_us = this->get_setting_value_or_default(Http2SettingIdentifier::SETTINGS_MAX_CONCURRENT_STREAMS,
                                                                                 DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS);
            if (active_client_streams >= max_concurrent_from_us) {
                LOG_HTTP_WARN_PA(stream_id, "Server: Refused new stream. Max concurrent streams limit reached: " << max_concurrent_from_us);
                this->refuse_new_stream(stream_id, "Exceeded MAX_CONCURRENT_STREAMS limit");
                this->begin_discarded_header_block(stream_id, headers_event.payload.header_block_fragment, end_headers);
                return;
            }

            LOG_HTTP_DEBUG_PA(stream_id, "Server: Creating new stream for client request");
            Http2ServerStream new_stream(stream_id, _initial_peer_window_size, this->get_initial_window_size_from_settings());
            auto              emp_res = _server_streams.emplace(stream_id, std::move(new_stream));
            stream_ptr                = &emp_res.first->second;
            _highest_client_stream_id = _last_client_initiated_stream_id = std::max(_highest_client_stream_id, stream_id);
        } else {
            stream_ptr = &it->second;
        }
        Http2ServerStream &stream = *stream_ptr;

        if (stream.expecting_continuation) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "New HEADERS frame received for stream " + std::to_string(stream_id)
                                                                       + " while previous header block for this stream was incomplete.");
            this->clear_header_assembly_state();
            return;
        }

        if (stream.state == Http2StreamConcreteState::CLOSED || stream.rst_stream_received || stream.rst_stream_sent) {
            this->begin_discarded_header_block(stream_id, headers_event.payload.header_block_fragment, end_headers);
            return;
        }
        if (stream.state == Http2StreamConcreteState::HALF_CLOSED_REMOTE) {
            // The client ended its side (END_STREAM): a trailer section would have had to come
            // before it, and nothing but WINDOW_UPDATE, PRIORITY or RST_STREAM may follow -- a
            // stream error of type STREAM_CLOSED (RFC 9113 §5.1). It used to be PROTOCOL_ERROR
            // (Huly QB-1058). Provoked: counted against the Rapid Reset ceiling (Huly QB-1244).
            this->send_provoked_rst_stream(stream_id, ErrorCode::STREAM_CLOSED, "HEADERS frame after the client ended the stream");
            this->begin_discarded_header_block(stream_id, headers_event.payload.header_block_fragment, end_headers);
            return;
        }

        // The HEADERS is now accepted onto a valid, active stream (a new request or a trailers block): a fresh
        // CONTINUATION budget for this header block starts HERE, past every rejection check above. It no longer
        // forgives the PING/SETTINGS budget: a block refused as malformed, or one that opens an upload never
        // dispatched, moves no request forward -- the request it begins does, once dispatched (Huly QB-1270).
        _continuation_frame_count = 0;

        bool is_current_block_trailers = stream.headers_received_main;

        if (_current_header_stream_id != 0 && _current_header_stream_id != stream_id) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "Interleaved HEADERS/CONTINUATION frames for different streams");
            return;
        }
        _current_header_stream_id = stream_id;

        _current_header_block_fragment.insert(_current_header_block_fragment.end(), headers_event.payload.header_block_fragment.begin(),
                                              headers_event.payload.header_block_fragment.end());
        if (_current_header_block_fragment.size() > qb::http2::protocol_limits::MAX_HEADER_BLOCK_SIZE) {
            this->send_goaway_and_close(ErrorCode::ENHANCE_YOUR_CALM, "HTTP/2 header block exceeds configured limit");
            return;
        }

        if (stream.state == Http2StreamConcreteState::IDLE) {
            stream.state = Http2StreamConcreteState::OPEN;
        }

        if (end_stream) {
            stream.end_stream_received = true;
            if (end_headers) {
                if (stream.state == Http2StreamConcreteState::OPEN) {
                    stream.state = Http2StreamConcreteState::HALF_CLOSED_REMOTE;
                } else if (stream.state == Http2StreamConcreteState::HALF_CLOSED_LOCAL) {
                    stream.state = Http2StreamConcreteState::CLOSED;
                }
            }
        }

        if (end_headers) { // Uses the correctly initialized local const boolean
            stream.expecting_continuation = false;
            if (!this->process_complete_header_block(stream, is_current_block_trailers)) {
                // Error handled
            } else {
                // process_complete_header_block() may synchronously dispatch to
                // the application, which may send a response and erase the
                // stream. Never touch the old reference after that call.
                auto after_process = _server_streams.find(stream_id);
                if (after_process != _server_streams.end() && after_process->second.state == Http2StreamConcreteState::CLOSED) {
                    this->try_close_stream_context(stream_id);
                }
            }
            this->clear_header_assembly_state();
        } else {
            stream.expecting_continuation = true;
        }
    }

    /**
     * @brief Handle CONTINUATION frame
     * @param continuation_event CONTINUATION frame event
     */
    void
    on(Http2FrameData<ContinuationFrame> continuation_event) noexcept {
        if (!this->ok() || !_connection_active)
            return;

        const FrameHeader &header      = continuation_event.header;
        const uint32_t     stream_id   = header.get_stream_id();
        const bool         end_headers = header.flags & FLAG_END_HEADERS;

        if (stream_id == 0 || _current_header_stream_id == 0 || stream_id != _current_header_stream_id) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "CONTINUATION frame error (no prior HEADERS or wrong stream_id)");
            this->clear_header_assembly_state(); // Clear any partial state
            return;
        }

        if (_discarding_header_block) {
            // The rest of a refused block: decoded for the HPACK table, never routed.
            if (++_continuation_frame_count > qb::http2::protocol_limits::MAX_CONTINUATION_FRAMES) {
                this->send_goaway_and_close(ErrorCode::ENHANCE_YOUR_CALM, "Excessive CONTINUATION frames in header block");
                this->clear_header_assembly_state();
                return;
            }
            this->append_discarded_header_fragment(continuation_event.payload.header_block_fragment, end_headers);
            return;
        }

        auto it = _server_streams.find(stream_id);
        if (it == _server_streams.end()) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR,
                                        "CONTINUATION for unknown stream (internal state error or stream closed mid-sequence)");
            this->clear_header_assembly_state();
            return;
        }
        Http2ServerStream &stream = it->second;

        if (!stream.expecting_continuation) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "Unexpected CONTINUATION frame");
            this->clear_header_assembly_state();
            return;
        }

        // Bound the CONTINUATION count per header block. The 1 MB byte cap below does NOT bound
        // a stream of ZERO-length CONTINUATION frames (each adds 0 bytes yet keeps END_HEADERS
        // pending), which would otherwise be processed forever (CVE-2024-27316 variant).
        if (++_continuation_frame_count > qb::http2::protocol_limits::MAX_CONTINUATION_FRAMES) {
            this->send_goaway_and_close(ErrorCode::ENHANCE_YOUR_CALM, "Excessive CONTINUATION frames in header block");
            this->clear_header_assembly_state();
            return;
        }

        _current_header_block_fragment.insert(_current_header_block_fragment.end(), continuation_event.payload.header_block_fragment.begin(),
                                              continuation_event.payload.header_block_fragment.end());
        if (_current_header_block_fragment.size() > qb::http2::protocol_limits::MAX_HEADER_BLOCK_SIZE) {
            this->send_goaway_and_close(ErrorCode::ENHANCE_YOUR_CALM, "HTTP/2 header block exceeds configured limit");
            this->clear_header_assembly_state();
            return;
        }

        if (end_headers) {
            stream.expecting_continuation  = false;
            bool is_current_block_trailers = stream.headers_received_main;

            if (!this->process_complete_header_block(stream, is_current_block_trailers)) {
                // Error handled by process_complete_header_block
            } else {
                // process_complete_header_block() can dispatch synchronously and
                // the application can close/erase this stream while we are still
                // in the frame handler. Reacquire before touching stream state.
                auto after_process = _server_streams.find(stream_id);
                if (after_process != _server_streams.end()) {
                    Http2ServerStream &current_stream = after_process->second;

                    if (is_current_block_trailers) {
                        current_stream.trailers_received = true;
                        current_stream.trailers_expected = false;
                    }
                    // current_stream.headers_received_main would have been set by initial HEADERS.

                    // State change depends on END_STREAM from the original HEADERS frame.
                    if (current_stream.end_stream_received) {
                        if (current_stream.state == Http2StreamConcreteState::OPEN) {
                            current_stream.state = Http2StreamConcreteState::HALF_CLOSED_REMOTE;
                        } else if (current_stream.state == Http2StreamConcreteState::HALF_CLOSED_LOCAL) {
                            current_stream.state = Http2StreamConcreteState::CLOSED;
                        }
                    }

                    if (current_stream.state == Http2StreamConcreteState::CLOSED) {
                        this->dispatch_complete_request(stream_id, current_stream);
                        this->try_close_stream_context(stream_id);
                    }
                }
            }
            this->clear_header_assembly_state();
        } else {
            stream.expecting_continuation = true; // Still expecting more CONTINUATION frames
        }
    }

    /**
     * @brief Handle SETTINGS frame
     * @param settings_event SETTINGS frame event
     */
    void
    on(Http2FrameData<SettingsFrame> settings_event) noexcept {
        if (!this->ok() || !_connection_active)
            return;

        const FrameHeader &header = settings_event.header;

        LOG_HTTP_TRACE_PA(header.get_stream_id(), "Server: Received SETTINGS frame, flags: " << (int) header.flags);
        if (header.get_stream_id() != 0) {
            LOG_HTTP_ERROR_PA(header.get_stream_id(), "Server: SETTINGS frame on non-zero stream_id.");
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "SETTINGS frame on non-zero stream_id");
            return;
        }

        if (header.flags & FLAG_ACK) {
            if (!settings_event.payload.entries.empty()) {
                LOG_HTTP_ERROR_PA(0, "Server: SETTINGS ACK frame with payload.");
                this->send_goaway_and_close(ErrorCode::FRAME_SIZE_ERROR, "SETTINGS ACK frame with payload");
                return; // Return after GOAWAY
            }
            LOG_HTTP_DEBUG_PA(0, "Server: Received SETTINGS ACK from client.");
            return;
        }

        // SETTINGS frame from client (not an ACK) - validate and process each setting
        for (const auto &setting_entry : settings_event.payload.entries) {
            Http2SettingIdentifier id    = setting_entry.identifier;
            uint32_t               value = setting_entry.value;

            // Validate setting using centralized helper
            auto validation_result = SettingsHelper::validate_setting(id, value, true); // true = from client
            if (!validation_result.is_valid) {
                this->send_goaway_and_close(validation_result.error_code, validation_result.error_message);
                return;
            }

            // Apply validated setting
            switch (id) {
                case Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE:
                    // Client informs us the max table size its decoder supports for headers we send.
                    // Our encoder must respect this.
                    _hpack_encoder.set_peer_max_dynamic_table_size(value);
                    break;

                case Http2SettingIdentifier::SETTINGS_ENABLE_PUSH:
                    // Client tells us if it allows server push.
                    _peer_allows_push = (value == 1);
                    break;

                case Http2SettingIdentifier::SETTINGS_MAX_CONCURRENT_STREAMS:
                    // Client tells us max concurrent streams it will allow *us* to PUSH.
                    _peer_max_concurrent_streams = value;
                    break;

                case Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE:
                    this->update_initial_peer_window_size(value);
                    break;

                case Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE:
                    FramerBase::set_peer_max_frame_size(value);
                    break;

                case Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE:
                    _peer_max_header_list_size = value;
                    break;

                case Http2SettingIdentifier::SETTINGS_ENABLE_CONNECT_PROTOCOL:
                    // Implementation specific - store for extended CONNECT support
                    // For now, just accept the value (already validated)
                    break;

                default:
                    // Unknown setting identifiers MUST be ignored by recipient.
                    LOG_HTTP_TRACE_PA(0, "Server: Ignoring unknown setting ID " << static_cast<uint16_t>(id) << " from client.");
                    break;
            }
        }

        // Bound SETTINGS-ACK amplification (CVE-2019-9515): like PONGs, ACKs are exempt from
        // flow control, so a flood of empty SETTINGS frames grows the output pipe without limit.
        // Same counter/reset discipline as the PING guard.
        if (this->control_reply_over_budget()) {
            this->send_goaway_and_close(ErrorCode::ENHANCE_YOUR_CALM, "Excessive SETTINGS control frames (flood)");
            return;
        }
        // Send SETTINGS ACK using centralized frame sending
        Http2FrameData<SettingsFrame> ack_frame;
        ack_frame.header.type  = static_cast<uint8_t>(FrameType::SETTINGS);
        ack_frame.header.flags = FLAG_ACK;
        ack_frame.header.set_stream_id(0);
        this->_io << ack_frame;
        LOG_HTTP_DEBUG_PA(0, "Server: Processed SETTINGS frame from client. Sending ACK.");
        // A SETTINGS_MAX_CONCURRENT_STREAMS raised makes room for a promised response that waits (Huly QB-1202).
        if (!_waiting_push_responses.empty()) [[unlikely]] {
            send_waiting_push_responses();
        }
    }

    /**
     * @brief Handle RST_STREAM frame
     * @param rst_event RST_STREAM frame event
     */
    void
    on(Http2FrameData<RstStreamFrame> rst_event) noexcept {
        if (!this->ok() || !_connection_active)
            return;

        const uint32_t  stream_id  = rst_event.header.get_stream_id();
        const ErrorCode error_code = rst_event.payload.error_code;

        if (stream_id == 0) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "RST_STREAM frame on stream 0");
            return;
        }

        // Rapid Reset (CVE-2023-44487): HEADERS(+END_STREAM) then an immediate RST_STREAM dispatches the request yet frees the
        // concurrency slot before it counts -- unbounded CPU amplification. Count the reset for ANY non-idle stream (id at or
        // below the highest client id) WHETHER OR NOT it is resident: a synchronous server erases the stream in the HEADERS
        // handler before the RST arrives. Weigh the resets against the streams the client OPENED -- a request dispatched, or one
        // it cancelled before it was complete -- never its highest id: ids may be skipped (RFC 9113 §5.1.1), and a client that
        // opened 2^30+1 first, or whose every other stream the server refused itself (413, 414, 431, malformed), was never
        // tripped (Huly QB-1244). Idle streams (id > highest opened) are a protocol error handled further down. A pushed (even)
        // stream is the server's work, not the client's: its resets are no Rapid Reset, and one at or below the largest
        // promised is closed, not idle (RFC 9113 §5.1.1) -- it was judged against the client's ids, and a reset or a
        // window update crossing the end of a push closed the connection (Huly QB-1239).
        const bool pushed = (stream_id & 1u) == 0u;
        if (!pushed && stream_id <= _highest_client_stream_id) {
            ++_rst_stream_count;
            // Cancelled before its request was complete -- an upload, say: opened, never dispatched.
            if (const auto held = _server_streams.find(stream_id); held != _server_streams.end() && !held->second.request_dispatched)
                ++_client_streams_opened;
            if (_rst_stream_count > ::qb::http2::protocol_limits::MAX_RAPID_RESETS && _rst_stream_count * 2u > _client_streams_opened) {
                this->send_goaway_and_close(ErrorCode::ENHANCE_YOUR_CALM, "Excessive stream resets (HTTP/2 Rapid Reset)");
                return;
            }
        }

        auto it = _server_streams.find(stream_id);
        if (it != _server_streams.end()) {
            Http2ServerStream &stream  = it->second;
            stream.rst_stream_received = true;
            stream.error_code          = error_code;
            stream.state               = Http2StreamConcreteState::CLOSED;

            // Notify application if request wasn't dispatched or response wasn't fully sent by us yet.
            if (!stream.request_dispatched || !stream.end_stream_sent) {
                auto &io_handler = this->_io;
                try {
                    if (error_code != ErrorCode::NO_ERROR) {
                        Http2StreamErrorEvent stream_error_event{stream_id, error_code, "RST_STREAM received from client"};
                        io_handler.on(stream_error_event);
                    } else if constexpr (requires(IO_Handler &io) { io.on_peer_stream_reset(stream_id); }) {
                        io_handler.on_peer_stream_reset(stream_id);
                    }
                } catch (...) {
                    // Application observers cannot escape this noexcept frame
                    // handler. The native reset still closes the stream below.
                }
                if constexpr (requires(IO_Handler &io, ServerHttp2Protocol *active) { io.protocol() == active; }) {
                    if (io_handler.protocol() != this)
                        return;
                }
            }
            // The observer may have erased the stream. Reclaim by fresh lookup
            // and never use the preceding stream reference after user code.
            this->try_close_stream_context(stream_id);
        } else if (stream_id > (pushed ? _last_promised_stream_id : _highest_client_stream_id)) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "RST_STREAM frame received on idle stream");
        }
        // If stream not found (already closed), the reset was still counted above.
    }

    /**
     * @brief Handle PUSH_PROMISE frame (error case for server)
     * @param pp_event PUSH_PROMISE frame event
     */
    void
    on(Http2FrameData<PushPromiseFrame> /*pp_event*/) noexcept {
        // Server should not receive PUSH_PROMISE from client.
        this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "Server received PUSH_PROMISE frame from client");
    }

    /**
     * @brief Handle GOAWAY frame
     * @param goaway_event GOAWAY frame event
     */
    void
    on(Http2FrameData<GoAwayFrame> goaway_event) noexcept {
        if (!this->ok() && _graceful_shutdown_initiated)
            return; // Already processing a GOAWAY or shutting down

        const std::string debug_data_str(goaway_event.payload.additional_debug_data.begin(), goaway_event.payload.additional_debug_data.end());
        LOG_HTTP_WARN_PA(0, "Server: Received GOAWAY frame from client. Last Stream ID: " << goaway_event.payload.last_stream_id << ", Error: "
                                                                                          << static_cast<int>(goaway_event.payload.error_code)
                                                                                          << ", Debug: " << debug_data_str);

        // RFC 9113 §6.8: the last-stream-id of a GOAWAY a CLIENT sends is the highest
        // SERVER-initiated stream -- a push -- it processed or might process. It says nothing
        // about the client's own requests: their sender still expects their responses. A NO_ERROR
        // GOAWAY therefore closes the pushes above that bound (never processed) and stops new
        // streams, and every request already accepted is answered; the connection closes when
        // the last stream has finished (try_close_stream_context). An error GOAWAY ends the
        // connection and every stream with it. This used to apply the bound to the CLIENT's
        // requests, closing the ones above it -- every request, for last-stream-id 0 -- and the
        // connection before their responses (Huly QB-530). A promised stream still reserved is
        // cancelled under the bound too: its HEADERS would open it, and "Receivers of a GOAWAY
        // frame MUST NOT open additional streams" -- a response that waited went out (Huly QB-1202).
        _graceful_shutdown_initiated         = true;
        const uint32_t last_pushed_stream_id = goaway_event.payload.last_stream_id;
        FramerBase::set_last_peer_initiated_stream_id_processed_in_goaway(last_pushed_stream_id);
        const ErrorCode error_code = goaway_event.payload.error_code;
        _waiting_push_responses.clear();
        _peer_goaway_received = true; // before any observer runs: send_response() opens no promised stream now

        Http2GoAwayEvent event_to_dispatch{error_code, last_pushed_stream_id, debug_data_str};
        if constexpr (qb::has_on<IO_Handler, Http2GoAwayEvent>) {
            this->get_io_handler().on(event_to_dispatch);
        }

        // Collect first, then close each by fresh lookup: the application observer may act on
        // the protocol (respond, reset) while we notify it.
        std::vector<uint32_t> ids_to_close;
        for (const auto &[sid, stream] : _server_streams) {
            if (stream.state == Http2StreamConcreteState::IDLE || stream.state == Http2StreamConcreteState::CLOSED) {
                continue;
            }
            const bool pushed = (sid % 2) == 0;
            if (error_code != ErrorCode::NO_ERROR
                || (pushed && (sid > last_pushed_stream_id || stream.state == Http2StreamConcreteState::RESERVED_LOCAL))) {
                ids_to_close.push_back(sid);
            }
        }
        for (const uint32_t sid : ids_to_close) {
            auto it = _server_streams.find(sid);
            if (it == _server_streams.end() || it->second.state == Http2StreamConcreteState::CLOSED) {
                continue;
            }
            const bool      pushed       = (sid % 2) == 0;
            const bool      cancelled    = error_code == ErrorCode::NO_ERROR && sid <= last_pushed_stream_id; // reserved, never opened
            const ErrorCode stream_error = error_code != ErrorCode::NO_ERROR ? error_code : ErrorCode::CANCEL;
            // Erased before the observer runs, so nothing it does can reach a dangling stream.
            _server_streams.erase(it);
            if (cancelled) {
                this->send_rst_stream(sid, ErrorCode::CANCEL, "Promised stream cancelled by the client's GOAWAY"); // the frame alone
            }
            Http2StreamErrorEvent stream_event{
                sid, stream_error,
                cancelled ? "Promised stream cancelled by the client's GOAWAY"
                : pushed  ? "Pushed stream not processed by the client (GOAWAY)"
                          : "Stream closed by the client's GOAWAY"
            };
            if constexpr (qb::has_on<IO_Handler, Http2StreamErrorEvent>) {
                this->get_io_handler().on(stream_event);
            }
        }

        if (error_code != ErrorCode::NO_ERROR) {
            _connection_active = false;
            this->not_ok(error_code); // Signal specific error
            return;
        }
        if (_connection_active && this->are_all_relevant_streams_closed(last_pushed_stream_id)) {
            // Nothing left to finish: the graceful shutdown is complete at once.
            _connection_active = false;
            this->not_ok(ErrorCode::NO_ERROR);
        }
    }

    /**
     * @brief Handle WINDOW_UPDATE frame
     * @param wu_event WINDOW_UPDATE frame event
     */
    void
    on(Http2FrameData<WindowUpdateFrame> wu_event) noexcept {
        const FrameHeader &header           = wu_event.header;
        uint32_t           stream_id        = header.get_stream_id();
        uint32_t           window_increment = wu_event.payload.window_size_increment;

        LOG_HTTP_TRACE_PA(stream_id, "Server: Received WINDOW_UPDATE frame with increment " << window_increment);

        if (window_increment == 0) { // a guard: the frame layer ends both first (on_stream_frame_error, report_frame_error)
            if (stream_id == 0) {
                this->on_connection_error(ErrorCode::PROTOCOL_ERROR, "Received WINDOW_UPDATE with 0 increment on stream 0.");
            } else {
                this->send_provoked_rst_stream(stream_id, ErrorCode::PROTOCOL_ERROR, "Received WINDOW_UPDATE with 0 increment.");
            }
            return;
        }

        if (stream_id == 0) {
            if (this->_connection_send_window > (static_cast<int64_t>(MAX_WINDOW_SIZE_LIMIT) - window_increment)) {
                this->on_connection_error(ErrorCode::FLOW_CONTROL_ERROR,
                                          "Connection WINDOW_UPDATE causes flow control window to exceed maximum.");
                return;
            }
            this->_connection_send_window += window_increment;
            // Snapshot candidate stream ids first: try_send_pending_data_for_stream
            // may flush a stream to CLOSED and erase it from _server_streams, which
            // would invalidate a live iterator into the map mid-loop (UAF).
            std::vector<uint32_t> pending_ids;
            pending_ids.reserve(_server_streams.size());
            for (auto &pair : _server_streams) {
                if (pair.second.has_pending_data_to_send)
                    pending_ids.push_back(pair.first);
            }
            for (uint32_t pending_id : pending_ids) {
                auto it = _server_streams.find(pending_id);
                if (it == _server_streams.end())
                    continue; // erased by an earlier flush in this loop
                if (it->second.has_pending_data_to_send) {
                    try_send_pending_data_for_stream(it->first, it->second);
                    if (!this->_connection_active)
                        break;
                }
            }

        } else {
            auto it = _server_streams.find(stream_id);
            if (it == _server_streams.end()) {
                // A pushed stream at or below the largest promised has closed: its window update is ignored (RFC 9113
                // §6.9, Huly QB-1239).
                if (stream_id > ((stream_id & 1u) == 0u ? _last_promised_stream_id : _highest_client_stream_id)) {
                    this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "WINDOW_UPDATE frame received on idle stream");
                }
                return;
            }
            Http2ServerStream &stream = it->second;
            if (stream.state == Http2StreamConcreteState::IDLE || stream.state == Http2StreamConcreteState::CLOSED) {
                // Per RFC 9113, 6.9.1: WINDOW_UPDATE on IDLE or CLOSED (after RST or normal closure) is a PROTOCOL_ERROR if it causes window >
                // 2^31-1. Otherwise, it can be ignored for closed/rst streams if it doesn't cause overflow. Simpler to just check for overflow
                // if closed, or treat any WU on IDLE as error.
                if (stream.state == Http2StreamConcreteState::IDLE) {
                    this->send_closed_stream_rst(stream_id, ErrorCode::PROTOCOL_ERROR, "WINDOW_UPDATE on IDLE stream.");
                    return;
                }
                if (stream.peer_window_size > (static_cast<int64_t>(MAX_WINDOW_SIZE_LIMIT) - window_increment)) {
                    this->send_closed_stream_rst(stream_id, ErrorCode::FLOW_CONTROL_ERROR,
                                                 "WINDOW_UPDATE on closed stream causes flow control window to exceed maximum.");
                }
                return; // Otherwise ignore for CLOSED stream if no overflow
            }

            if (stream.peer_window_size > (static_cast<int64_t>(MAX_WINDOW_SIZE_LIMIT) - window_increment)) {
                this->send_provoked_rst_stream(stream_id, ErrorCode::FLOW_CONTROL_ERROR,
                                               "Stream WINDOW_UPDATE causes flow control window to exceed maximum.");
                return;
            }

            stream.peer_window_size += window_increment;
            stream.progressed_since_idle_sweep = true; // the client is reading this stream

            if (stream.has_pending_data_to_send) {
                // QB_LOG_TRACE_PA(this->getName(), "Server: Stream " << stream_id << " has pending data. Attempting to send.");
                try_send_pending_data_for_stream(stream_id, stream);
            }
        }
    }

    /**
     * @brief Handle PING frame
     * @param ping_event PING frame event
     */
    void
    on(Http2FrameData<PingFrame> ping_event) noexcept {
        if (!this->ok() || !_connection_active)
            return;

        const FrameHeader &header = ping_event.header;

        LOG_HTTP_TRACE_PA(header.get_stream_id(), "Server: Received PING frame, flags: " << (int) header.flags);

        if (header.get_stream_id() != 0) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "PING frame on non-zero stream_id");
            return;
        }

        if (header.flags & FLAG_ACK) {
            // The ACK of a shutdown notice's PING is the round trip RFC 9113 section 6.8 waits for: every stream the
            // client opened before it saw the notice has reached us, and the final GOAWAY can name the last one
            // (Huly QB-91). Any other ACK answers no PING of ours and is ignored.
            if (_shutdown_phase == shutdown_phase::notice && ping_event.payload.opaque_data == SHUTDOWN_PING_DATA)
                complete_graceful_shutdown();
        } else {
            // This is a PING from client, send PONG (PING with ACK).
            // Bound PONG amplification (CVE-2019-9512): control frames are exempt from HTTP/2
            // flow control, so a peer flooding PINGs while stalling its own reads makes the
            // output pipe grow without limit. The budget is forgiven whenever the peer makes real
            // request progress (control_reply_over_budget()); if control replies pile up past the
            // cap without any, treat it as a flood and close.
            if (this->control_reply_over_budget()) {
                this->send_goaway_and_close(ErrorCode::ENHANCE_YOUR_CALM, "Excessive PING control frames (flood)");
                return;
            }
            Http2FrameData<PingFrame> pong_frame;
            pong_frame.header.type  = static_cast<uint8_t>(FrameType::PING);
            pong_frame.header.flags = FLAG_ACK;
            pong_frame.header.set_stream_id(0);
            // pong_frame.header.set_payload_length(HTTP2_PING_PAYLOAD_SIZE); // Length is implicit from PingFrame
            pong_frame.payload.opaque_data = ping_event.payload.opaque_data; // Echo opaque data

            this->_io << pong_frame;
        }
    }

    /**
     * @brief Handle PRIORITY frame
     * @param priority_event PRIORITY frame event
     */
    void
    on(Http2FrameData<PriorityFrame> priority_event) noexcept {
        if (!this->ok() || !_connection_active)
            return;

        const FrameHeader &header    = priority_event.header;
        uint32_t           stream_id = header.get_stream_id();

        if (stream_id == 0) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "PRIORITY frame on stream 0 from client");
            return;
        }
        // Any stream state (RFC 9113 §6.3); a self-dependency is ignored: RFC 9113 deprecates priority signals (§5.3.2).
        // Store it in stream context if stream exists.
        auto it = _server_streams.find(stream_id);
        if (it != _server_streams.end()) {
            it->second.priority_info = priority_event.payload.priority_data;
            // TODO: Application/IO_Handler could be notified to adjust response sending priorities
            // based on this explicit PRIORITY frame. This is an application integration point.
        } else {
            // PRIORITY for an unknown/closed stream. If it's for a stream ID we *could* create (new client stream),
            // one could create a placeholder. For now, ignore if stream not found.
        }
    }

    /**
     * @brief Send HTTP response to client
     *
     * Sends response headers and body data for the specified stream. Handles
     * HPACK encoding, flow control, and proper stream state transitions.
     *
     * @param stream_id Stream identifier for the response
     * @param http_response HTTP response object containing status, headers, and body
     * @return true if response sent successfully, false on error
     */
    bool
    send_response(uint32_t stream_id, qb::http::Response const &http_response) {
        LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Attempting to send response");
        auto it = _server_streams.find(stream_id);
        if (it == _server_streams.end()) {
            LOG_HTTP_WARN_PA(stream_id, "ServerHttp2Protocol: Attempt to send response on non-existent stream");
            return false; // Or send RST_STREAM(STREAM_CLOSED) if appropriate
        }
        Http2ServerStream &stream = it->second;

        if (stream.state == Http2StreamConcreteState::IDLE) {
            LOG_HTTP_WARN_PA(stream_id, "ServerHttp2Protocol: Attempt to send response on stream in IDLE state");
            this->on_stream_error(stream_id, ErrorCode::PROTOCOL_ERROR, "Sending response on stream in invalid state for response.");
            return false;
        }
        if (stream.state == Http2StreamConcreteState::RESERVED_LOCAL) {
            if (std::find(_waiting_push_responses.begin(), _waiting_push_responses.end(), stream_id) != _waiting_push_responses.end()) {
                return false; // answered already, the response waiting
            }
            if (_peer_goaway_received) [[unlikely]] {
                // Its HEADERS would open it after the client's GOAWAY (RFC 9113 §6.8): one answered from an observer of
                // the GOAWAY, before the handler reached it, is refused and left to the handler, which cancels it with
                // the others, as the GOAWAY's code and last-stream-id say.
                return false;
            }
        }
        // A response that waited is sent from the one its stream keeps (send_waiting_push_responses): nothing below reads
        // it once the stream may be gone.
        if (&http_response != &stream.response_to_send) {
            stream.response_to_send = http_response;
        }
        stream.send_buffer_offset = 0;

        if (stream.state == Http2StreamConcreteState::CLOSED || stream.state == Http2StreamConcreteState::HALF_CLOSED_LOCAL) {
            LOG_HTTP_INFO_PA(stream_id, "ServerHttp2Protocol: Attempt to send response on already closed/half-closed(local) stream");
            return false; // Stream is already closed or we've already sent END_STREAM
        }

        LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Building response headers with status " << http_response.status().code());
        // The fields go to the connection's vector, cleared on every exit of this function: its capacity serves every
        // response, where a fresh vector grew with each (Huly QB-1215).
        std::vector<qb::protocol::hpack::HeaderField> &hf_vector = _response_header_fields;
        const ClearedOnExit                            response_fields_cleared{hf_vector};
        std::optional<std::uint64_t>                   declared_content_length;
        bool                                           trailed = false;
        if (!collect_response_head(stream_id, http_response, hf_vector, declared_content_length, trailed)) {
            return false; // refused, and the stream reset: a forbidden or invalid field, a malformed length, a forbidden trailer
        }

        const auto &body_pipe        = http_response.body().raw();
        const auto  status_code      = http_response.status().code();
        const bool  response_to_head = stream.assembled_request.method() == qb::http::method::HEAD;
        const bool  body_length_must_match =
            !response_to_head && !((status_code >= 100 && status_code < 200) || status_code == 204 || status_code == 304);
        if (declared_content_length && body_length_must_match && body_pipe.size() != *declared_content_length) {
            this->on_stream_error(stream_id, ErrorCode::INTERNAL_ERROR, "HTTP/2 response content-length mismatch");
            return false;
        }
        if (body_pipe.size() > qb::http::protocol_limits::MAX_BODY_SIZE) {
            this->on_stream_error(stream_id, ErrorCode::INTERNAL_ERROR, "HTTP/2 response body exceeds configured limit");
            return false;
        }

        // The client's SETTINGS_MAX_HEADER_LIST_SIZE, counted as RFC 9113 §6.5.2 counts it -- each name and value, and
        // 32 octets -- and judged before the block is encoded: the encoder indexes fields as it encodes, so a block
        // encoded then dropped left this table ahead of the client's, and the next block that referenced an entry it
        // added could not be decoded -- COMPRESSION_ERROR, every stream with it (RFC 9113 §4.3). The ENCODED size was
        // compared, after encoding (Huly QB-1235).
        if (!this->fits_peer_header_list(stream_id, hf_vector)) { // counts as §6.5.2 does, logs what it refuses
            send_rst_stream(stream_id, ErrorCode::INTERNAL_ERROR);
            return false;
        }
        // The trailer section, a field section of its own, is held to the same bound here, before anything is sent, and
        // again when it leaves, by the bound then in force (try_send_pending_data_for_stream); it was sent past the bound
        // (Huly QB-1240). Its size is counted from its plan, no field copied. A response to HEAD sends none.
        if (trailed && !response_to_head && _peer_max_header_list_size < DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE
            && !this->fits_peer_list_size(stream_id, trailer_section_size(http_response))) {
            send_rst_stream(stream_id, ErrorCode::INTERNAL_ERROR);
            return false;
        }

        if (stream.state == Http2StreamConcreteState::RESERVED_LOCAL) {
            // A promised stream (send_push_promise) is answered here, its documented next step:
            // sending its HEADERS moves it to half-closed (remote) -- the client never sends on a
            // pushed stream -- and the response's END_STREAM closes it (RFC 9113 §5.1, §8.4; Huly
            // QB-529). Those HEADERS open a stream the client's SETTINGS_MAX_CONCURRENT_STREAMS
            // counts, which a server MUST NOT exceed (§5.1.2): without room the response waits,
            // judged first as any response is, kept, and leaves once a pushed stream ends or the
            // client raises its limit -- or is cancelled as an idle stream is (cleanup_idle_streams).
            // It left at once, past a limit the client had lowered (Huly QB-1202).
            if (get_active_stream_count(true) >= _peer_max_concurrent_streams || waits_behind_a_promised_response(stream_id)) {
                _waiting_push_responses.push_back(stream_id);
                return true;
            }
            stream.state               = Http2StreamConcreteState::HALF_CLOSED_REMOTE;
            stream.end_stream_received = true;
        }

        std::vector<uint8_t> encoded_headers;
        if (!_hpack_encoder.encode(hf_vector, encoded_headers)) {
            LOG_HTTP_ERROR_PA(stream_id, "ServerHttp2Protocol: HPACK encoding failed for response headers");
            this->on_connection_error(ErrorCode::COMPRESSION_ERROR, "HPACK encoder failed for response headers.");
            return false;
        }
        uint8_t header_flags = 0;

        // A response to HEAD carries the representation's metadata -- content-length included --
        // and no content (RFC 9110 §9.3.2): its HEADERS end the stream even when the handler filled
        // the body to compute that metadata, as the HTTP/1.1 and HTTP/3 paths do (Huly QB-527).
        // A trailer section follows the body, an empty one included: those HEADERS end the stream
        // then, never the leading ones -- with an empty body they did, and the trailer fields were
        // lost (Huly QB-1073).
        stream.is_trailers = trailed && !response_to_head;
        bool has_body      = (!body_pipe.empty() || stream.is_trailers) && !response_to_head;

        if (!has_body) {
            header_flags |= FLAG_END_STREAM; // No body, HEADERS ends the stream
            LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Response has no body, setting END_STREAM flag");
        } else {
            LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Response has body of size " << body_pipe.size());
        }

        if (!this->send_headers_with_continuation(stream_id, header_flags, std::move(encoded_headers))) {
            LOG_HTTP_ERROR_PA(stream_id, "ServerHttp2Protocol: Failed to send response HEADERS");
            return false;
        }
        stream.progressed_since_idle_sweep = true;

        // Update stream state AFTER successful send of HEADERS frame
        if (header_flags & FLAG_END_STREAM) {
            stream.end_stream_sent = true;
            if (stream.state == Http2StreamConcreteState::OPEN) {
                stream.state = Http2StreamConcreteState::HALF_CLOSED_LOCAL;
            } else if (stream.state == Http2StreamConcreteState::HALF_CLOSED_REMOTE) {
                stream.state = Http2StreamConcreteState::CLOSED;
            }
            LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Response headers sent with END_STREAM");
        }

        if (has_body) {
            if (!send_response_body(stream, http_response)) {
                LOG_HTTP_ERROR_PA(stream_id, "ServerHttp2Protocol: Failed to send response body");
                return false;
            }
            auto after_body = _server_streams.find(stream_id);
            if (after_body == _server_streams.end()) {
                LOG_HTTP_INFO_PA(stream_id, "ServerHttp2Protocol: Response sent successfully");
                return this->ok();
            }
            Http2ServerStream &current_stream = after_body->second;
            if (current_stream.state == Http2StreamConcreteState::CLOSED) {
                this->try_close_stream_context(stream_id); // Corrected call
            }
        } else { // No body
            if (stream.state == Http2StreamConcreteState::CLOSED) {
                this->try_close_stream_context(stream_id); // Corrected call
            }
        }

        LOG_HTTP_INFO_PA(stream_id, "ServerHttp2Protocol: Response sent successfully");
        return this->ok();
    }

    /**
     * @brief Whether `stream_id` can take a streamed response now (Huly QB-86): a dispatched request on a stream open
     *        to a response (OPEN or half-closed remote), neither reset nor answered, no stream begun on it. A promised
     *        (pushed) stream cannot: its response goes whole, through send_response().
     */
    [[nodiscard]] bool
    can_begin_streamed_response(uint32_t stream_id) const noexcept {
        const auto it = _server_streams.find(stream_id);
        return it != _server_streams.end() && can_begin_streamed_response(it->second);
    }

    /**
     * @brief Begin a streamed response (Huly QB-86): the HEADERS of `http_response` leave now -- without END_STREAM, or
     *        with it when `head_only` (a HEAD's response is whole at its head) -- and the body follows piece by piece
     *        through write_streamed_body(): each piece goes as DATA frames within the stream's and the connection's
     *        send windows and the peer's frame size, the rest waits in the stream for a WINDOW_UPDATE
     *        (try_send_pending_data_for_stream), and end_streamed_response() sends END_STREAM, after the response's
     *        trailer section when it has one. The head is judged as send_response() judges one -- a field HTTP/2
     *        forbids, an invalid field, a malformed `content-length`, a trailer field a section must not carry refuse
     *        it (RST_STREAM INTERNAL_ERROR, Huly QB-1273), a block past the peer's SETTINGS_MAX_HEADER_LIST_SIZE too,
     *        nothing sent -- except that a `content-length` is compared to no body: the stream counts the pieces
     *        against it. The body of `http_response` is not read.
     * @return `true` when the HEADERS left; `false` when the stream cannot take a streamed response
     *         (can_begin_streamed_response()) or the head was refused, the stream then reset.
     */
    [[nodiscard]] bool
    begin_streamed_response(uint32_t stream_id, qb::http::Response const &http_response, bool head_only) {
        auto it = _server_streams.find(stream_id);
        if (it == _server_streams.end() || !can_begin_streamed_response(it->second)) {
            LOG_HTTP_WARN_PA(stream_id, "ServerHttp2Protocol: Attempt to begin a streamed response on a stream that cannot take one");
            return false;
        }
        Http2ServerStream                             &stream    = it->second;
        std::vector<qb::protocol::hpack::HeaderField> &hf_vector = _response_header_fields;
        const ClearedOnExit                            response_fields_cleared{hf_vector};
        std::optional<std::uint64_t>                   declared_content_length;
        bool                                           trailed = false;
        if (!collect_response_head(stream_id, http_response, hf_vector, declared_content_length, trailed)) {
            return false;
        }
        // The client's SETTINGS_MAX_HEADER_LIST_SIZE, judged before the block is encoded, as send_response() judges it
        // (Huly QB-1235), through the helper every field section the server encodes goes through (Huly QB-1240).
        if (!this->fits_peer_header_list(stream_id, hf_vector)) { // counts as §6.5.2 does, logs what it refuses
            send_rst_stream(stream_id, ErrorCode::INTERNAL_ERROR);
            return false;
        }
        std::vector<uint8_t> encoded_headers;
        if (!_hpack_encoder.encode(hf_vector, encoded_headers)) {
            LOG_HTTP_ERROR_PA(stream_id, "ServerHttp2Protocol: HPACK encoding failed for streamed response headers");
            this->on_connection_error(ErrorCode::COMPRESSION_ERROR, "HPACK encoder failed for response headers.");
            return false;
        }
        // The head's fields are kept for the trailer section (end_streamed_response reads the announcement there); the
        // body stays empty: the pieces live in `streamed->buffer`.
        stream.response_to_send    = http_response;
        stream.send_buffer_offset  = 0;
        const uint8_t header_flags = head_only ? FLAG_END_STREAM : 0;
        if (!this->send_headers_with_continuation(stream_id, header_flags, std::move(encoded_headers))) {
            LOG_HTTP_ERROR_PA(stream_id, "ServerHttp2Protocol: Failed to send streamed response HEADERS");
            return false;
        }
        stream.progressed_since_idle_sweep = true;
        stream.response_sent               = true;
        if (head_only) {
            // The response to HEAD carries no content (RFC 9110 §9.3.2): its HEADERS end the stream (Huly QB-527).
            stream.end_stream_sent = true;
            if (stream.state == Http2StreamConcreteState::OPEN) {
                stream.state = Http2StreamConcreteState::HALF_CLOSED_LOCAL;
            } else if (stream.state == Http2StreamConcreteState::HALF_CLOSED_REMOTE) {
                stream.state = Http2StreamConcreteState::CLOSED;
                this->try_close_stream_context(stream_id); // `stream` dangles past it
            }
            return this->ok();
        }
        stream.streamed     = std::make_unique<Http2StreamedBody>(); // the one allocation a streamed response adds: not a HEAD's
        stream.streaming    = true;
        stream.stream_ended = false;
        stream.is_trailers  = trailed;
        LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: streamed response begun");
        return this->ok();
    }

    /**
     * @brief Append a piece of a streamed body (Huly QB-86): what the stream's and the connection's send windows allow
     *        leaves now as DATA frames of at most the peer's frame size, the rest waits in the stream until a
     *        WINDOW_UPDATE lets it go. An empty piece changes nothing.
     * @return `false` when the stream takes no piece: not a streamed response, ended, or closed.
     */
    bool
    write_streamed_body(uint32_t stream_id, std::string_view bytes) {
        auto it = _server_streams.find(stream_id);
        if (it == _server_streams.end() || !it->second.streaming || it->second.stream_ended || it->second.is_closed() || !this->ok()
            || !_connection_active) {
            return false; // a connection that is closing takes nothing more: the producer reads `closed`
        }
        Http2ServerStream &stream = it->second;
        if (!bytes.empty()) {
            std::memcpy(stream.streamed->buffer.allocate_back(bytes.size()), bytes.data(), bytes.size());
        }
        flush_streamed_response(stream_id, stream); // `stream` may dangle past it: a last piece can close the stream
        return true;
    }

    /**
     * @brief The last piece of a streamed body was written (Huly QB-86): END_STREAM follows the pieces still waiting
     *        -- on an empty DATA frame when none is left -- after the trailer section when there is one: the fields
     *        `final_response` carries at the end (its `trailers()`, and the fields its `trailer` header announces),
     *        as HTTP/2 sends a trailer section (outgoing_trailer_fields); a section the head announced and the end
     *        leaves empty is sent empty. A trailer field a section must not carry, or a section past the client's
     *        SETTINGS_MAX_HEADER_LIST_SIZE (Huly QB-1240), aborts the stream (RST_STREAM INTERNAL_ERROR): the message
     *        cannot be completed as the producer asked.
     * @param final_response The response as it stands at the end, for its trailers; `nullptr` sends the head's.
     * @return `false` when the stream has no streamed response to end (not streaming, ended already, closed).
     */
    bool
    end_streamed_response(uint32_t stream_id, qb::http::Response const *final_response) {
        auto it = _server_streams.find(stream_id);
        if (it == _server_streams.end() || !it->second.streaming || it->second.stream_ended || it->second.is_closed()) {
            return false;
        }
        Http2ServerStream        &stream = it->second;
        qb::http::Response const &source = final_response ? *final_response : stream.response_to_send;
        if (source.has_trailers() || source.has_header(qb::http::well_known::TRAILER_SV)) {
            const auto plan = qb::http::detail::plan_outgoing_trailers(source, source.has_trailers() ? &source.trailers() : nullptr);
            if (!plan.forbidden.empty()) {
                LOG_HTTP_WARN_PA(stream_id, "ServerHttp2Protocol: a streamed response's trailers() carries a field a trailer section must not: "
                                                << plan.forbidden);
                stream.streamed.reset();
                stream.streaming = false;
                send_rst_stream(stream_id, ErrorCode::INTERNAL_ERROR, "streamed response trailers refused");
                return false;
            }
            // Held to the client's SETTINGS_MAX_HEADER_LIST_SIZE as send_response() holds a buffered response's section
            // (Huly QB-1240): by the bound in force at the end, counted from the plan, and again when it leaves
            // (flush_streamed_response), by the bound then in force -- nothing past it is encoded, so the HPACK table
            // stays in step with the client's.
            if (_peer_max_header_list_size < DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE
                && !this->fits_peer_list_size(stream_id, trailer_section_size(source))) {
                stream.streamed.reset();
                stream.streaming = false;
                send_rst_stream(stream_id, ErrorCode::INTERNAL_ERROR, "streamed response trailer section past the client's bound");
                return false;
            }
            stream.streamed->trailer_fields = outgoing_trailer_fields(source);
            stream.is_trailers              = true;
        }
        stream.stream_ended = true;
        flush_streamed_response(stream_id, stream); // `stream` may dangle past it
        return true;
    }

    /**
     * @brief Give up a streamed response that cannot be completed (Huly QB-86; the producer aborted it, the context was
     *        cancelled): the pieces still waiting are dropped and the stream is reset, RST_STREAM INTERNAL_ERROR --
     *        the stream alone, the connection serves on. Nothing happens on a stream that is not streaming, has sent
     *        its END_STREAM or is closed already (a peer's reset reached it first).
     * @return Whether a RST_STREAM was sent.
     */
    bool
    abandon_streamed_response(uint32_t stream_id) noexcept {
        auto it = _server_streams.find(stream_id);
        if (it == _server_streams.end() || !it->second.streaming || it->second.end_stream_sent || it->second.is_closed()) {
            return false;
        }
        Http2ServerStream &stream = it->second;
        stream.streamed.reset();
        stream.streaming                = false;
        stream.has_pending_data_to_send = false;
        send_rst_stream(stream_id, ErrorCode::INTERNAL_ERROR, "streamed response aborted");
        return true;
    }

    /// The bytes of a streamed body the stream still holds for the windows (Huly QB-86); 0 for any other stream.
    [[nodiscard]] std::size_t
    streamed_body_pending(uint32_t stream_id) const noexcept {
        const auto it = _server_streams.find(stream_id);
        return it != _server_streams.end() && it->second.streaming ? it->second.streamed->buffer.size() : 0;
    }

    /// What of this stream's streamed body the socket has not taken, as far as the connection can tell (Huly QB-1212):
    /// the pieces its windows hold back, and the distance of its last DATA frame from leaving the connection's output
    /// -- shared with every other stream, drained in order: `drained_total` is what the socket took of it, ever, and
    /// the frame's end was marked on the same count. A FIFO bound that falls at every drain, whichever stream's frames
    /// sit around it, and reaches 0 once the frame has left. 0 for any other stream.
    [[nodiscard]] std::size_t
    streamed_body_waiting(uint32_t stream_id, std::uint64_t drained_total) const noexcept {
        const auto it = _server_streams.find(stream_id);
        if (it == _server_streams.end() || !it->second.streaming)
            return 0;
        auto const &body = *it->second.streamed;
        return body.buffer.size() + static_cast<std::size_t>(body.end_pos > drained_total ? body.end_pos - drained_total : 0);
    }

    /**
     * @brief Whether a streamed response holds pieces back for the SOCKET: its flush stopped at the io's write-buffer
     *        cap (`max_write_buffer_size()`, which `publish()` enforces by disconnecting), not at a window. The session
     *        calls resume_streamed_responses() on its next write pass when this is true (Huly QB-86).
     */
    [[nodiscard]] bool
    streams_wait_for_socket() const noexcept {
        return _streams_wait_for_socket;
    }

    /// What a streamed flush keeps free under the io's write-buffer cap: the connection's own frames -- a PING or
    /// SETTINGS ACK, another stream's HEADERS or RST_STREAM -- must still find room there, since `publish()`
    /// disconnects at the cap and a flush that filled it exactly would make the next frame the one that kills the
    /// connection (Huly QB-86).
    static constexpr std::size_t streamed_socket_headroom = 64 * 1024;

    /**
     * @brief Flush again every streamed response that waited for the socket's room: called by the session from its
     *        write pass once bytes left the socket. Snapshots the ids first (a flush can close and erase a stream).
     */
    void
    resume_streamed_responses() noexcept {
        if (!_streams_wait_for_socket || !this->ok() || !_connection_active) {
            return;
        }
        _streams_wait_for_socket = false;
        std::vector<uint32_t> ids;
        for (const auto &[stream_id, stream] : _server_streams) {
            if (stream.streaming && stream.has_pending_data_to_send && !stream.is_closed()) {
                ids.push_back(stream_id);
            }
        }
        for (const uint32_t stream_id : ids) {
            const auto it = _server_streams.find(stream_id);
            if (it != _server_streams.end() && it->second.streaming && it->second.has_pending_data_to_send && !it->second.is_closed()) {
                flush_streamed_response(stream_id, it->second); // `it` may be erased past it
            }
        }
    }

    /// Whether `stream_id` carries a streamed response whose END_STREAM has not left (Huly QB-86).
    [[nodiscard]] bool
    is_streaming_response(uint32_t stream_id) const noexcept {
        const auto it = _server_streams.find(stream_id);
        return it != _server_streams.end() && it->second.streaming && !it->second.end_stream_sent;
    }

    /**
     * @brief Send PUSH_PROMISE to client
     *
     * Initiates a server push by sending a PUSH_PROMISE frame; the promised stream is answered by send_response().
     *
     * @param associated_stream_id Stream ID of the client request triggering this push
     * @param promised_stream_id Stream ID for the promised response (must be even)
     * @param promised_request The promised request: a GET or a HEAD without content or trailer section (RFC 9113 §8.4),
     *        its URI the scheme, authority and path promised; its fields are sent as a client's request sends them
     *        (append_sent_request_fields, Huly QB-1191).
     * @return std::nullopt once the PUSH_PROMISE is sent, else why it was not: INVALID_PROMISED_STREAM for a promised
     *         stream id that is zero, odd, past 2^31-1 or not above every one promised (RFC 9113 §5.1.1),
     *         INVALID_ASSOCIATED_STREAM for one the client did not open or that is not open (§8.4),
     *         INVALID_PROMISED_REQUEST for a request §8.4 does not allow, PEER_HEADER_LIST_SIZE_EXCEEDED for one past
     *         the client's SETTINGS_MAX_HEADER_LIST_SIZE (§6.5.2, Huly QB-1240), CONNECTION_INACTIVE once a GOAWAY was
     *         received (§6.8) or sent, the shutdown notice included -- each a refusal a retry cannot change, judged
     *         first -- and last PEER_CONCURRENCY_LIMIT_REACHED, which only has to wait: the pushed streams the client's
     *         SETTINGS_MAX_CONCURRENT_STREAMS counts -- those a response opened, not those reserved (§5.1.2) -- fill it
     *         (Huly QB-1202). A promise made under it reserves its stream; its response (send_response()) waits for
     *         room while the limit has none.
     */
    [[nodiscard]] std::optional<PushPromiseFailureReason>
    send_push_promise(uint32_t associated_stream_id, uint32_t promised_stream_id, qb::http::Request promised_request) {
        LOG_HTTP_DEBUG_PA(associated_stream_id, "Server: Attempting to send PUSH_PROMISE for promised_stream_id " << promised_stream_id);
        // A GOAWAY received forbids a new stream (RFC 9113 §6.8); once one is sent -- the notice included -- this server
        // starts no push either, a policy of its own. Both were open to a push (Huly QB-1191).
        if (!this->ok() || !_connection_active || _graceful_shutdown_initiated || _shutdown_phase != shutdown_phase::none) {
            LOG_HTTP_WARN_PA(associated_stream_id, "Server: Cannot send PUSH_PROMISE. Protocol not OK or connection inactive.");
            return PushPromiseFailureReason::CONNECTION_INACTIVE;
        }
        if (!_peer_allows_push) {
            LOG_HTTP_INFO_PA(associated_stream_id,
                             "Server: Client has disabled PUSH_PROMISE (SETTINGS_ENABLE_PUSH = 0). Cannot send push for promised_stream_id "
                                 << promised_stream_id);
            return PushPromiseFailureReason::PEER_PUSH_DISABLED;
        }
        if (promised_stream_id == 0 || (promised_stream_id & 1u) != 0u || promised_stream_id > MAX_STREAM_ID
            || promised_stream_id <= _last_promised_stream_id) {
            LOG_HTTP_WARN_PA(associated_stream_id, "Server: Invalid promised stream id " << promised_stream_id << " for PUSH_PROMISE.");
            return PushPromiseFailureReason::INVALID_PROMISED_STREAM;
        }
        // A PUSH_PROMISE goes on a stream the client opened (RFC 9113 §8.4): a pushed stream was accepted (Huly QB-1191).
        auto it_assoc_stream = (associated_stream_id & 1u) != 0u ? _server_streams.find(associated_stream_id) : _server_streams.end();
        if (it_assoc_stream == _server_streams.end()) {
            // QB_LOG_WARN_PA(this->getName(), "Server: PUSH_PROMISE for non-existent associated stream " << associated_stream_id);
            return PushPromiseFailureReason::INVALID_ASSOCIATED_STREAM;
        }

        if (it_assoc_stream->second.state != Http2StreamConcreteState::OPEN
            && it_assoc_stream->second.state != Http2StreamConcreteState::HALF_CLOSED_REMOTE) {
            // QB_LOG_WARN_PA(this->getName(), "Server: PUSH_PROMISE on associated stream " << associated_stream_id << " not in valid state.");
            return PushPromiseFailureReason::INVALID_ASSOCIATED_STREAM;
        }

        // The promised request, judged before anything is reserved. It is safe and cacheable -- a GET or a HEAD -- and
        // has no content and no trailer section (RFC 9113 §8.4): a client treats any other as a stream error of type
        // PROTOCOL_ERROR (Huly QB-1191; any method was promised, a body silently dropped).
        const auto &promised_uri    = promised_request.uri();
        const auto  promised_method = promised_request.method();
        // The authority every protocol writes for a URI (qb::http::origin::authority, Huly QB-1064).
        std::string promised_authority = qb::http::origin::authority(promised_uri);
        std::string promised_path      = promised_uri.path().empty() ? std::string{"/"} : std::string(promised_uri.path());
        if (!promised_uri.encoded_queries().empty()) {
            promised_path.push_back('?');
            promised_path += promised_uri.encoded_queries();
        }
        if ((promised_method != qb::http::method::GET && promised_method != qb::http::method::HEAD) || promised_uri.scheme().empty()
            || promised_authority.empty() || !promised_request.body().empty() || promised_request.has_trailers()
            || promised_request.has_header("trailer")) {
            return PushPromiseFailureReason::INVALID_PROMISED_REQUEST;
        }
        // :method, :scheme, :authority and :path, then the promised request's fields under the rules a client's request
        // is sent by (append_sent_request_fields): no connection-specific field (RFC 9113 §8.2.2), nor one its
        // `connection` header names, no `host` (`:authority` names the authority, §8.3.1), no `content-length`, no field
        // HTTP/2 cannot carry; the names are lowercase already (§8.2.1), the headers map storing them folded. They were
        // copied as they were: `host`, `connection` or `transfer-encoding` made a promise the client must treat as
        // malformed, and a value with a CR failed the whole promise in the HPACK encoder (Huly QB-1191).
        std::vector<hpack::HeaderField> hf_vector;
        hf_vector.push_back({std::string(qb::http::well_known::COLON_METHOD_SV), std::string(promised_method)});
        hf_vector.push_back({std::string(qb::http::well_known::COLON_SCHEME_SV), std::string(promised_uri.scheme())});
        hf_vector.push_back({std::string(qb::http::well_known::COLON_AUTHORITY_SV), std::move(promised_authority)});
        hf_vector.push_back({std::string(qb::http::well_known::COLON_PATH_SV), std::move(promised_path)});
        append_sent_request_fields(promised_request, hf_vector);
        // The list is held to the client's SETTINGS_MAX_HEADER_LIST_SIZE (RFC 9113 §6.5.2) before anything is reserved or
        // encoded: a promise past it was sent (Huly QB-1240). The one refusal that only has to wait comes last: before the
        // stream and the request were judged, a caller that retried on it retried a promise that could never be made (Huly
        // QB-1202). A reserved stream does not count (§5.1.2): a second promise was refused under a limit of one.
        if (!this->fits_peer_header_list(associated_stream_id, hf_vector)) {
            return PushPromiseFailureReason::PEER_HEADER_LIST_SIZE_EXCEEDED;
        }
        if (get_active_stream_count(true) >= _peer_max_concurrent_streams) {
            LOG_HTTP_WARN_PA(associated_stream_id,
                             "Server: push " << promised_stream_id << " refused: MAX_CONCURRENT_STREAMS " << _peer_max_concurrent_streams);
            return PushPromiseFailureReason::PEER_CONCURRENCY_LIMIT_REACHED;
        }
        // Create a new stream context for the promised stream
        Http2ServerStream promised_stream(promised_stream_id, _initial_peer_window_size, this->get_initial_window_size_from_settings());
        promised_stream.state            = Http2StreamConcreteState::RESERVED_LOCAL;
        promised_stream.parent_stream_id = associated_stream_id;
        // The promised request's method: send_response() reads it (a pushed HEAD gets no body).
        promised_stream.assembled_request.method() = promised_method;

        // Emplace the stream
        auto emp_res = _server_streams.emplace(promised_stream_id, std::move(promised_stream));
        if (!emp_res.second) {
            // QB_LOG_ERROR_PA(this->getName(), "Server: Failed to emplace promised stream " << promised_stream_id << " context.");
            return PushPromiseFailureReason::INTERNAL_ERROR;
        }

        std::vector<uint8_t> encoded_headers;
        if (!_hpack_encoder.encode(hf_vector, encoded_headers)) {
            LOG_HTTP_ERROR_PA(associated_stream_id,
                              "Server: HPACK encoding failed for PUSH_PROMISE on promised_stream_id " << promised_stream_id);
            _server_streams.erase(promised_stream_id);
            return PushPromiseFailureReason::INTERNAL_HPACK_ERROR;
        }

        // The promised request's header block, split over CONTINUATION frames past the peer's
        // SETTINGS_MAX_FRAME_SIZE like every other header block (Huly QB-522).
        if (!this->send_push_promise_with_continuation(associated_stream_id, promised_stream_id, std::move(encoded_headers))
            || !this->ok()) {                          // Check if the send operation itself failed (e.g. underlying transport error)
            _server_streams.erase(promised_stream_id); // Clean up if send failed
            // The not_ok() might have been set by the transport, leading to CONNECTION_INACTIVE on next attempt
            return PushPromiseFailureReason::CONNECTION_INACTIVE; // Or a more generic send error
        }
        _last_promised_stream_id = promised_stream_id;
        LOG_HTTP_INFO_PA(associated_stream_id, "Server: Sending PUSH_PROMISE for promised_stream_id " << promised_stream_id);
        return std::nullopt; // Success
    }

    /**
     * @brief Cleanup idle streams to prevent DDoS attacks
     *
     * Removes streams that have been idle for too long or incomplete for too long.
     * This prevents resource exhaustion from malicious clients opening many streams.
     *
     * A stream's idle time runs from its last real progress -- response HEADERS or DATA sent, a
     * stream WINDOW_UPDATE received -- as seen by the sweep that observed it (the frame path only
     * marks the stream, the sweep stamps the time): a response still progressing is not idle
     * (Huly QB-531). A request not yet complete is also bounded by its age since the stream
     * opened, whatever happened on it, so a slow upload cannot hold a stream indefinitely.
     *
     * @param max_idle Maximum idle time before cleanup (default: 30s)
     * @param max_incomplete Maximum age of a stream whose request is not complete (default: 10s)
     * @return Number of streams cleaned up
     */
    uint32_t
    cleanup_idle_streams(qb::duration max_idle = std::chrono::seconds(30), qb::duration max_incomplete = std::chrono::seconds(10)) noexcept {
        uint32_t   cleaned_count = 0;
        const auto now           = std::chrono::steady_clock::now();

        // The ids first, each found again: a stream reset below closes, and its close can send a promised response that
        // waits (send_waiting_push_responses), whose stream may end and be erased at once -- the stream an iterator held
        // past the reset pointed to (Huly QB-1202); the reset's observer may act on the protocol too.
        std::vector<uint32_t> stream_ids;
        stream_ids.reserve(_server_streams.size());
        for (const auto &pair : _server_streams)
            stream_ids.push_back(pair.first);
        for (const uint32_t stream_id : stream_ids) {
            const auto it = _server_streams.find(stream_id);
            // Skip already closed streams
            if (it == _server_streams.end() || it->second.state == Http2StreamConcreteState::CLOSED)
                continue;
            auto &stream = it->second;

            if (stream.progressed_since_idle_sweep) {
                stream.progressed_since_idle_sweep = false;
                stream.last_activity               = now;
            }
            const auto idle_time         = now - stream.last_activity;
            const auto idle_time_seconds = std::chrono::duration_cast<std::chrono::seconds>(idle_time).count();

            // Check for incomplete streams (not dispatched yet)
            bool is_incomplete = !stream.request_dispatched
                                 && (stream.state == Http2StreamConcreteState::IDLE || stream.state == Http2StreamConcreteState::OPEN);

            // Check for idle timeout
            bool should_cleanup = false;
            if (is_incomplete && now - stream.created_at > max_incomplete) {
                LOG_HTTP_WARN_PA(stream_id, "ServerHttp2Protocol: Cleaning up incomplete stream (idle for " << idle_time_seconds << "s)");
                should_cleanup = true;
            } else if (idle_time > max_idle) {
                LOG_HTTP_WARN_PA(stream_id, "ServerHttp2Protocol: Cleaning up idle stream (idle for " << idle_time_seconds << "s)");
                should_cleanup = true;
            }

            if (should_cleanup) {
                // send_rst_stream() (close_context defaults to true) closes and ERASES this
                // stream's context: `stream` dangles past it.
                this->send_rst_stream(stream_id, ErrorCode::CANCEL, "Stream idle timeout (" + std::to_string(idle_time_seconds) + "s)");
                _server_streams.erase(stream_id); // idempotent safety net (reclaims if send_rst_stream didn't, e.g. !ok())
                cleaned_count++;
            }
        }

        if (cleaned_count > 0) {
            LOG_HTTP_INFO("ServerHttp2Protocol: Cleaned up " << cleaned_count << " idle/incomplete streams");
        }

        return cleaned_count;
    }

    /**
     * @brief Send RST_STREAM frame
     *
     * Sends a stream reset frame and marks the stream as closed.
     * This method is public to allow the session layer to send RST_STREAM
     * when routing fails or other application-level errors occur.
     *
     * @param stream_id Stream identifier
     * @param error_code Error code for the reset
     * @param context_msg Debug context message
     */
    void
    send_rst_stream(uint32_t stream_id, ErrorCode error_code, const std::string &context_msg = "", bool close_context = true) noexcept {
        if (!_connection_active
            && error_code != ErrorCode::CANCEL) { // CANCEL can be sent on closed connection by app // Removed .load(std::memory_order_relaxed)
            LOG_HTTP_WARN_PA(stream_id, "ServerHttp2Protocol: Tried to send RST_STREAM but connection is not active");
            return;
        }
        LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Sending RST_STREAM with error code " << static_cast<uint32_t>(error_code)
                                                                                                << ". Context: " << context_msg);

        Http2FrameData<RstStreamFrame> rst_frame_data;
        rst_frame_data.payload.error_code = error_code;

        FrameHeader header;
        header.type  = static_cast<uint8_t>(FrameType::RST_STREAM);
        header.flags = 0;
        header.set_stream_id(stream_id);

        rst_frame_data.header = header;
        this->_io << rst_frame_data;

        auto it = _server_streams.find(stream_id);
        if (it != _server_streams.end()) {
            it->second.state           = Http2StreamConcreteState::CLOSED; // RST_STREAM immediately closes the stream
            it->second.rst_stream_sent = true;
            it->second.error_code      = error_code;
            LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Stream marked as CLOSED due to sent RST_STREAM");

            // Notify IO_Handler if request wasn't dispatched or response wasn't fully sent
            if ((!it->second.request_dispatched || !it->second.end_stream_sent) && error_code != ErrorCode::NO_ERROR) {
                Http2StreamErrorEvent stream_error_event{stream_id, error_code, "RST_STREAM sent by server: " + context_msg};
                if constexpr (qb::has_on<IO_Handler, Http2StreamErrorEvent>) {
                    this->get_io_handler().on(stream_error_event);
                }
            }
            // close_context is false when RST is sent from deep inside a frame
            // handler that still holds a reference to this stream: erasing the
            // context now would dangle that reference. The caller reclaims it.
            if (close_context) {
                this->try_close_stream_context(stream_id); // Attempt to clean up if conditions met
            }
        }
        LOG_HTTP_INFO_PA(stream_id, "ServerHttp2Protocol: RST_STREAM sent successfully");
    }

private:
    /**
     * @brief The request limits in force: the server's `request_limits()` (`set_request_limits`, Huly QB-94), read
     *        through the io when it has the hook, the defaults otherwise -- normalized, each 0 ("none") read as
     *        the largest size.
     */
    [[nodiscard]] qb::http::request_limits
    request_limits_in_force() noexcept {
        if constexpr (requires(IO_Handler &io) { io.http_request_limits(); }) {
            return this->_io.http_request_limits().normalized();
        } else {
            return qb::http::request_limits{}.normalized();
        }
    }

    /**
     * @brief The request body limit alone (`set_max_body_size`, Huly QB-168), read on every DATA frame: the largest
     *        size when it is 0, which means none.
     */
    [[nodiscard]] std::size_t
    max_request_body_size() noexcept {
        if constexpr (requires(IO_Handler &io) { io.http_request_limits(); }) {
            const std::size_t cap = this->_io.http_request_limits().max_body_size;
            return cap == 0 ? std::numeric_limits<std::size_t>::max() : cap;
        } else {
            return qb::http::protocol_limits::MAX_BODY_SIZE;
        }
    }

    /**
     * @brief Answer a request refused for a limit on its own stream (Huly QB-168, QB-94): @p status with an
     *        empty body and END_STREAM, then RST_STREAM(NO_ERROR), which asks the client to stop sending
     *        what is left of the request without an error -- a complete response sent before the request
     *        is (RFC 9113 §8.1). The request is never routed; the connection and its other streams go on.
     *        A response that cannot be sent falls back to the stream error it replaces.
     * @param stream_id The refused stream.
     * @param status    The answer.
     * @param reason    For the log.
     */
    void
    refuse_request(uint32_t stream_id, qb::http::Status status, char const *reason) noexcept {
        auto it = _server_streams.find(stream_id);
        if (it == _server_streams.end())
            return;
        // Its reset is one the client solicits on a stream it never opened: budgeted as a reset before dispatch is (Huly
        // QB-1270). Past the budget the connection is closed, nothing answered.
        if (!this->admit_solicited_reset("Excessive requests refused (HTTP/2 reset flood)"))
            return;
        LOG_HTTP_WARN_PA(stream_id, "ServerHttp2Protocol: request refused with " << status.code() << ": " << reason);
        it->second.assembled_request.body().clear(); // what was received of the refused body
        bool sent = false;
        try {
            sent = send_response(stream_id, qb::http::Response{status});
        } catch (...) {
            sent = false;
        }
        if (!sent) {
            if (_server_streams.find(stream_id) != _server_streams.end())
                this->on_stream_error(stream_id, ErrorCode::ENHANCE_YOUR_CALM, reason);
            return;
        }
        if (_server_streams.find(stream_id) != _server_streams.end())
            this->send_rst_stream(stream_id, ErrorCode::NO_ERROR, reason);
    }

    /**
     * @brief Initialize server's HTTP/2 settings to defaults
     */
    void
    initialize_our_settings_map() noexcept {
        _our_settings.clear();
        _our_settings[Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE] = hpack::HPACK_DEFAULT_MAX_TABLE_SIZE;
        _our_settings[Http2SettingIdentifier::SETTINGS_ENABLE_PUSH]       = 0; // Server disables push by default
        // Use lower default for DDoS protection (can be increased if needed)
        _our_settings[Http2SettingIdentifier::SETTINGS_MAX_CONCURRENT_STREAMS] = 50; // Max streams we allow client to open (reduced from 100)
        _our_settings[Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE]    = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;
        _our_settings[Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE]         = DEFAULT_SETTINGS_MAX_FRAME_SIZE;
        // The bound the decoder enforces (set in reset()), advertised: the default, unlimited, told clients a list of
        // any size was read, and one past 1 MiB closed the connection (Huly QB-1196). Past it a request is answered 431.
        _our_settings[Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE] =
            static_cast<uint32_t>(::qb::http2::protocol_limits::MAX_HEADER_LIST_SIZE);
    }

    /**
     * @brief Calculate and validate max frame size from settings
     * @return Valid max frame size for initialization
     */
    uint32_t
    initialize_our_max_frame_size() {
        this->initialize_our_settings_map();
        uint32_t calculated_max_frame_size =
            this->get_setting_value_or_default(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, DEFAULT_SETTINGS_MAX_FRAME_SIZE);
        if (calculated_max_frame_size < DEFAULT_SETTINGS_MAX_FRAME_SIZE || calculated_max_frame_size > MAX_FRAME_SIZE_LIMIT) {
            calculated_max_frame_size = DEFAULT_SETTINGS_MAX_FRAME_SIZE;
        }
        return calculated_max_frame_size;
    }

    /**
     * @brief Get initial window size from settings
     * @return Initial window size value
     */
    uint32_t
    get_initial_window_size_from_settings() const noexcept {
        return this->get_setting_value_or_default(Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE);
    }

    /**
     * @brief Get setting value or default if not found
     * @param id Setting identifier
     * @param default_val Default value if setting not found
     * @return Setting value or default
     */
    uint32_t
    get_setting_value_or_default(Http2SettingIdentifier id, uint32_t default_val) const noexcept {
        auto it = _our_settings.find(id);
        if (it != _our_settings.end()) {
            return it->second;
        }
        return default_val;
    }

    /**
     * @brief Clear header assembly state between header blocks
     */
    void
    clear_header_assembly_state() noexcept {
        _current_header_block_fragment.clear();
        _current_header_stream_id = 0;
        _discarding_header_block  = false;
    }

    /**
     * @brief Start a header block the server refuses: it is decoded, and its fields dropped.
     * @details HPACK is one compression context per connection: the client's encoder indexed
     *          this block's fields whether or not the request is admitted, and its later blocks
     *          reference them. A refused HEADERS -- over the concurrency cap, during shutdown, on
     *          a closed or reset stream, after END_STREAM -- is therefore assembled across its
     *          CONTINUATION frames under the same size and count limits and decoded like any
     *          other (RFC 9113 §4.3, Huly QB-534). Nothing is routed. A block that does not
     *          decode is a connection COMPRESSION_ERROR.
     */
    void
    begin_discarded_header_block(uint32_t stream_id, const std::vector<uint8_t> &fragment, bool end_headers) noexcept {
        if (!this->ok() || !_connection_active) {
            return; // the connection is going away: its compression state no longer matters
        }
        _current_header_block_fragment.clear();
        _current_header_stream_id = stream_id;
        _discarding_header_block  = true;
        _continuation_frame_count = 0;
        this->append_discarded_header_fragment(fragment, end_headers);
    }

    /**
     * @brief Add a fragment to the refused block in assembly; at END_HEADERS decode it through
     *        the connection's decoder and drop the fields.
     */
    void
    append_discarded_header_fragment(const std::vector<uint8_t> &fragment, bool end_headers) noexcept {
        _current_header_block_fragment.insert(_current_header_block_fragment.end(), fragment.begin(), fragment.end());
        if (_current_header_block_fragment.size() > qb::http2::protocol_limits::MAX_HEADER_BLOCK_SIZE) {
            this->send_goaway_and_close(ErrorCode::ENHANCE_YOUR_CALM, "HTTP/2 header block exceeds configured limit");
            this->clear_header_assembly_state();
            return;
        }
        if (!end_headers) {
            return;
        }
        bool       incomplete = false;
        bool       over_list  = false; // dropped all the same
        const bool decoded =
            _hpack_decoder.decode(_current_header_block_fragment, _decoded_header_fields, incomplete, over_list) && !incomplete;
        _decoded_header_fields.clear(); // dropped
        this->clear_header_assembly_state();
        if (!decoded) {
            this->on_connection_error(ErrorCode::COMPRESSION_ERROR, "HPACK decoding failed");
        }
    }

    /**
     * @brief Process a complete header block (headers or trailers)
     *
     * Decodes HPACK data, validates pseudo-headers, and updates stream state.
     * Handles both initial headers and trailing headers.
     *
     * @param stream Stream context
     * @param is_trailers_block Whether this is a trailers block
     * @return true if processing succeeded, false on error
     */
    bool
    process_complete_header_block(Http2ServerStream &stream, bool is_trailers_block) {
        // Debug: Log raw HPACK bytes (removed in production)

        // QB_LOG_TRACE_PA(this->getName(), "Stream " << stream.id << ": Processing complete header block (is_trailers=" << is_trailers_block <<
        // ")");
        qb::http::Headers current_headers_decoded; // Decoded headers for this block
        bool              possibly_incomplete_hpack = false;
        bool              over_header_list_size     = false;

        // A block that does not decode leaves the decoder's dynamic table wherever the failure
        // stopped it -- possibly after entries the fields ahead of it added -- so the connection's
        // compression context is no longer the client's: a connection error of type
        // COMPRESSION_ERROR (RFC 9113 §4.3, Huly QB-533), never a stream reset that would let
        // decoding go on. A field that decodes but is invalid stays a stream error below. A list
        // past the bound SETTINGS_MAX_HEADER_LIST_SIZE advertises is decoded to its end and its
        // fields past the bound dropped: the request is answered 431 below, once the fields kept
        // say it is well-formed, its stream alone -- the connection was closed (Huly QB-1196).
        // The fields land in the connection's vector (_decoded_header_fields), read once below and cleared on every
        // exit, success or stream error: its capacity is the next block's, and a stream that dies mid-block leaves
        // nothing for the next (Huly QB-1215).
        const ClearedOnExit decoded_fields_cleared{_decoded_header_fields};
        if (!_hpack_decoder.decode(_current_header_block_fragment, _decoded_header_fields, possibly_incomplete_hpack, over_header_list_size)
            || possibly_incomplete_hpack) {
            this->on_connection_error(ErrorCode::COMPRESSION_ERROR, "HPACK decoding failed");
            return false;
        }

        // Convert the decoded fields into stream.assembled_request: its header fields for the main
        // block (pseudo-headers validated), its trailers() for a trailer block.

        _current_header_block_fragment.clear(); // Clear for next use
        stream.expecting_continuation = false;

        // The server's request limits (Huly QB-94), read once per block: a field name, a field value or a field
        // count over them is answered 431, a `:path` over its own 414 -- once the block is known well-formed, a
        // malformed one staying the stream error it is.
        const qb::http::request_limits limits             = request_limits_in_force();
        std::size_t                    fields             = 0;
        bool                           fields_over_limits = over_header_list_size;

        if (!is_trailers_block) { // Main headers (request)
            stream.headers_received_main = true;
            // Validate pseudo-headers and convert to qb::http::Request components
            std::optional<std::string_view> method_sv, scheme_sv, path_sv, authority_sv, host_sv;
            bool                            pseudo_headers_finished = false;

            std::string temp_method_str; // Temporary for method conversion

            for (auto &hf : _decoded_header_fields) {
                std::string &name  = hf.name;  // name and value move into the request below: the field vector is read once
                std::string &value = hf.value; // (the value since QB-1215, the name since QB-1216 gave convert() an rvalue overload)

                if (name.empty()) {
                    this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Empty header field name received.");
                    return false;
                }
                if (name[0] == ':') { // Pseudo-header
                    if (pseudo_headers_finished) {
                        this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Pseudo-header received after regular header.");
                        return false;
                    }
                    if (!HeaderValidator::is_valid_header_value(value)) {
                        this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Invalid pseudo-header value format.");
                        return false;
                    }
                    // Process pseudo-headers
                    if (name == ":method") {
                        if (method_sv) {
                            this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Duplicate :method pseudo-header.");
                            return false;
                        }
                        method_sv       = value;
                        temp_method_str = value; // Store for later conversion
                    } else if (name == ":scheme") {
                        if (scheme_sv) {
                            this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Duplicate :scheme pseudo-header.");
                            return false;
                        }
                        scheme_sv = value;
                    } else if (name == ":path") {
                        if (path_sv) {
                            this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Duplicate :path pseudo-header.");
                            return false;
                        }
                        path_sv = value;
                    } else if (name == ":authority") {
                        if (authority_sv) {
                            this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Duplicate :authority pseudo-header.");
                            return false;
                        }
                        authority_sv = value;
                    } else {
                        this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Unknown pseudo-header in request: " + name);
                        return false;
                    }
                } else { // Regular header
                    pseudo_headers_finished = true;
                    // SECURITY FIX: Validate header name/value format per RFC 9113
                    if (!is_valid_header_field(name, value)) {
                        this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR,
                                                       "Invalid header field name or value format (contains forbidden characters).");
                        return false;
                    }
                    if (HeaderValidator::is_forbidden_header(name) || (name == "te" && !HeaderValidator::is_valid_request_te_value(value))) {
                        this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR,
                                                       "Forbidden connection-specific header in request: " + name);
                        return false;
                    }
                    // A `host` field names the authority too: one field, as RFC 9112 §3.2 has it, naming :authority's
                    // (RFC 9113 §8.3.1) -- HTTP/3's check (Huly QB-1189) -- or, without :authority, the request's
                    // authority: §8.3.1 sets Host aside only when :authority is present (Huly QB-1195).
                    if (name == "host") [[unlikely]] {
                        if (host_sv || (authority_sv && !qb::http::utility::iequals(value, *authority_sv))) {
                            this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR,
                                                           "A second host header field, or one not naming the :authority before it.");
                            return false;
                        }
                        host_sv = value;
                    }
                    // `content-length` too is judged before the limits, over them or not: a malformed or conflicting
                    // value is a malformed request, and the body it declares is judged below (Huly QB-1197).
                    if (name == "content-length") {
                        auto parsed = HeaderValidator::parse_content_length(value);
                        if (!parsed) {
                            this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR,
                                                           "Invalid content-length header in HTTP/2 request");
                            return false;
                        }
                        if (stream.expected_content_length && *stream.expected_content_length != *parsed) {
                            this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR,
                                                           "Conflicting content-length headers in HTTP/2 request");
                            return false;
                        }
                        stream.expected_content_length = *parsed; // judged against the body cap once the block is valid
                    }
                    if (name.size() > limits.max_header_name_length || value.size() > limits.max_header_value_length
                        || ++fields > limits.max_headers_count) [[unlikely]] {
                        fields_over_limits = true; // answered 431 once the block is known well-formed
                        continue;
                    }
                    // The name and the value move: their buffers become the request's instead of being copied and freed
                    // with the field (Huly QB-1215, QB-1216). A `host` value is copied -- host_sv names it after the loop.
                    if (host_sv && host_sv->data() == value.data()) [[unlikely]] {
                        stream.assembled_request.add_header(std::move(name), value);
                    } else {
                        stream.assembled_request.add_header(std::move(name), std::move(value));
                    }
                }
            }

            if (!method_sv || !scheme_sv || !path_sv) {
                this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR,
                                               "Missing mandatory pseudo-header (:method, :scheme, or :path).");
                return false;
            }
            if (path_sv.value().empty()) {
                this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, ":path pseudo-header cannot be empty.");
                return false;
            }
            // The request's authority: :authority, else its `host` field, which RFC 9113 §8.3.1 sets aside only when
            // :authority is present -- one of the two, as HTTP/3 asks (RFC 9114 §4.3.1; Huly QB-1195). No URI is
            // composed without one, whatever the scheme; an empty one is no authority, below.
            const auto request_authority = authority_sv ? authority_sv : host_sv;
            if (!request_authority) {
                this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Missing :authority and host header field.");
                return false;
            }

            qb::http::Method method_from_string_view(temp_method_str);
            if (method_from_string_view == qb::http::Method::Value::UNINITIALIZED) {
                this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Invalid :method value");
                return false;
            }
            // CONNECT names a tunnel by :authority alone (RFC 9113 §8.5): a CONNECT carrying :scheme and :path is
            // malformed, and one without them asks for a tunnel this server does not open -- refused above, as it
            // misses them. Both are a stream error, as on HTTP/3; the malformed one reached the router as a CONNECT on
            // an ordinary path (Huly QB-1177). HTTP/1.1 routes an authority-form CONNECT.
            if (method_from_string_view == qb::http::method::CONNECT) [[unlikely]] {
                this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR,
                                               "CONNECT with :scheme and :path is malformed (RFC 9113 §8.5)");
                return false;
            }
            stream.assembled_request.method() = method_from_string_view;

            // The URI the three fields name, its authority the request's: a :path that is no absolute path, a
            // userinfo or a text the URI parser refuses is a malformed request (Huly QB-1177), a `host` that names
            // the authority read as :authority is (QB-1195).
            auto uri = qb::http::origin::request_uri(scheme_sv.value(), *request_authority, path_sv.value(),
                                                     method_from_string_view == qb::http::method::OPTIONS);
            if (!uri) {
                this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Malformed :scheme, :authority, host or :path field.");
                return false;
            }
            stream.assembled_request.uri() = std::move(*uri);

            // A block that ends the stream ends the request with no body: a `content-length` that declares one makes it
            // malformed (RFC 9113 §8.1.1), whatever the limits -- this check came after the answers below, and such a
            // request beside a field or a :path over them was answered 431 or 414 (Huly QB-1197).
            if (stream.end_stream_received && stream.expected_content_length
                && stream.assembled_request.body().size() != *stream.expected_content_length) {
                this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "HTTP/2 request content-length mismatch");
                return false;
            }

            // Over the limits, the request is answered once it is known well-formed -- its method and its URI
            // included, as HTTP/3 answers it: a malformed :scheme, :path, :authority or `host` stays a stream error (QB-1195).
            if (path_sv.value().size() > limits.max_url_length) [[unlikely]] {
                this->refuse_request(stream.id, qb::http::status::URI_TOO_LONG, "HTTP/2 :path exceeds configured size limit");
                return false;
            }
            if (fields_over_limits) [[unlikely]] {
                this->refuse_request(stream.id, qb::http::status::REQUEST_HEADER_FIELDS_TOO_LARGE,
                                     "HTTP/2 request header fields exceed configured limits");
                return false;
            }

            if (stream.end_stream_received) { // end_stream_received would have been set by on(HeadersFrame) if END_STREAM was on the header
                this->dispatch_complete_request(stream.id, stream);
            } else if (stream.expected_content_length && *stream.expected_content_length > max_request_body_size()) [[unlikely]] {
                // A declared body over the cap is answered before a byte of it is read, like HTTP/1.1's
                // (Huly QB-168): 413 on the stream, then NO_ERROR. A block that also ends the stream is a
                // content-length mismatch above, malformed before it is too large.
                this->refuse_request(stream.id, qb::http::status::PAYLOAD_TOO_LARGE, "HTTP/2 request content-length exceeds configured limit");
                return false;
            }

        } else { // Trailers block
            stream.trailers_received = true;
            for (const auto &hf : _decoded_header_fields) {
                const std::string &name  = hf.name;
                const std::string &value = hf.value;
                if (name.empty() || name[0] == ':') {
                    this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR,
                                                   "Invalid header field name in trailers (empty or pseudo-header).");
                    return false;
                }
                if (!is_valid_header_field(name, value)) {
                    this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Invalid trailer header field name or value format.");
                    return false;
                }
                if (qb::http::detail::is_forbidden_trailer_field(name)) {
                    this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Forbidden header in trailers: " + name);
                    return false;
                }
                if (name.size() > limits.max_header_name_length || value.size() > limits.max_header_value_length
                    || ++fields > limits.max_headers_count) [[unlikely]] {
                    fields_over_limits = true; // answered 431 once the section is known well-formed
                    continue;
                }
                // To the request's trailers(), and its header fields for 3.x (Huly QB-1073).
                qb::http::detail::store_received_trailer(stream.assembled_request, name, value);
            }

            // As per RFC 9113, a trailer section's final frame MUST contain END_STREAM.
            // stream.end_stream_received should have been set by the on(HeadersFrame/ContinuationFrame) that had END_HEADERS and END_STREAM.
            if (!stream.end_stream_received) {
                this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Trailers HEADERS block did not end the stream.");
                return false;
            }
            if (stream.expected_content_length && stream.assembled_request.body().size() != *stream.expected_content_length) {
                this->send_provoked_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "HTTP/2 request content-length mismatch");
                return false;
            }
            if (fields_over_limits) [[unlikely]] {
                this->refuse_request(stream.id, qb::http::status::REQUEST_HEADER_FIELDS_TOO_LARGE,
                                     "HTTP/2 request trailer fields exceed configured limits");
                return false;
            }

            // If the request headers and body (if any) were already processed and dispatched,
            // these trailers are supplementary. The application might need a way to access them post-dispatch.
            // If not yet dispatched (e.g. END_STREAM came only with trailers), dispatch now.
            if (stream.request_dispatched == false && stream.end_stream_received) {
                this->dispatch_complete_request(stream.id, stream);
            }
        }
        return true;
    }

    /**
     * @brief Send response body data
     *
     * Handles sending body data frames with flow control, buffering when
     * window is exhausted, and trailer frames if present.
     *
     * @param stream Stream context
     * @param http_response Response containing body data
     * @return true if body sent/buffered successfully, false on error
     */
    bool
    send_response_body(Http2ServerStream &stream, const qb::http::Response &http_response) {
        // This function is called after initial HEADERS are sent.
        // stream.response_to_send should already be populated by the calling send_response function.
        // stream.send_buffer_offset should be 0 if this is the first attempt for this body.
        const uint32_t stream_id = stream.id;

        const auto &body_pipe     = http_response.body().raw(); // Use http_response passed in, which should be same as stream.response_to_send
        std::size_t body_size     = body_pipe.size();
        const char *body_data_ptr = body_pipe.data();

        // send_buffer_offset tracks progress within stream.response_to_send.body(), which is http_response.body()
        // uint32_t sent_bytes_this_function_call = 0; // Tracks what this specific call achieves

        // stream.is_trailers was set by send_response(): the response has a trailer section.

        while (stream.send_buffer_offset < body_size) {
            if (stream.peer_window_size <= 0 || _connection_send_window <= 0) {
                stream.has_pending_data_to_send = true; // Mark that body data remains unsent
                // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream.id << ": Send body blocked by flow control. Offset: " <<
                // stream.send_buffer_offset);
                return true; // Successfully buffered/marked pending, not a protocol error
            }

            uint32_t max_can_send_on_stream =
                static_cast<uint32_t>(std::min(this->FramerBase::get_peer_max_frame_size(), static_cast<uint32_t>(stream.peer_window_size)));
            uint32_t max_can_send_on_conn =
                static_cast<uint32_t>(std::min(this->FramerBase::get_peer_max_frame_size(), static_cast<uint32_t>(_connection_send_window)));
            uint32_t chunk_size = std::min(
                {static_cast<uint32_t>(body_size - stream.send_buffer_offset), max_can_send_on_stream, max_can_send_on_conn,
                 this->FramerBase::get_peer_max_frame_size()});

            if (chunk_size == 0 && (body_size - stream.send_buffer_offset) > 0) {
                stream.has_pending_data_to_send = true;
                // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream.id << ": Send body blocked by zero chunk_size. Offset: " <<
                // stream.send_buffer_offset);
                return true;
            }
            if (chunk_size == 0 && body_size == 0 && stream.send_buffer_offset == 0) { // Empty body case
                break;                                                                 // Nothing to send for body
            }
            if (chunk_size == 0 && stream.send_buffer_offset == body_size) { // All body already processed
                break;
            }

            Http2FrameData<DataFrame> data_frame_data;
            data_frame_data.payload.data_payload.assign(body_data_ptr + stream.send_buffer_offset,
                                                        body_data_ptr + stream.send_buffer_offset + chunk_size);

            FrameHeader header_to_send;
            header_to_send.type  = static_cast<uint8_t>(FrameType::DATA);
            header_to_send.flags = 0;
            header_to_send.set_stream_id(stream.id);

            stream.send_buffer_offset += chunk_size;
            // sent_bytes_this_function_call += chunk_size; // Not strictly needed here anymore

            stream.peer_window_size -= chunk_size;
            _connection_send_window -= chunk_size;

            if (stream.send_buffer_offset == body_size && !stream.is_trailers) {
                header_to_send.flags |= FLAG_END_STREAM;
                // stream.end_stream_sent will be set after successful send
            }

            data_frame_data.header = header_to_send;
            this->_io << data_frame_data;

            if (!this->ok()) {
                // QB_LOG_ERROR_PA(this->getName(), "Server Stream " << stream.id << ": Send failed for DATA frame during send_response_body.
                // Reverting offset.");
                stream.send_buffer_offset -= chunk_size; // Revert offset for this failed chunk
                stream.peer_window_size += chunk_size;   // Revert window consumption
                _connection_send_window += chunk_size;   // Revert window consumption
                stream.has_pending_data_to_send = true;  // Mark as pending because send failed
                return false;                            // Indicate send failure
            }

            stream.progressed_since_idle_sweep = true;
            if (header_to_send.flags & FLAG_END_STREAM) {
                stream.end_stream_sent = true;
                stream.state           = Http2StreamConcreteState::HALF_CLOSED_LOCAL;
                // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream.id << ": END_STREAM sent with DATA in send_response_body.");
            }

            if (stream.end_stream_sent && !stream.is_trailers) {
                break; // All body sent, no trailers, we are done with body sending.
            }
        }

        // After loop: if all body is sent (offset == size) and there are trailers, trailers will be handled by try_send_pending_data or a
        // dedicated trailer send call. If not all body is sent, has_pending_data_to_send is already true.
        if (stream.send_buffer_offset == body_size) {
            stream.has_pending_data_to_send = false; // All *body* data processed by this function or was empty.
                                                     // If trailers are present, `is_trailers` will trigger next step.
        } else {
            stream.has_pending_data_to_send = true; // Still more body data to send later.
        }

        // If trailers are expected and all body data has been sent by this function.
        // The actual sending of trailers is usually handled by try_send_pending_data_for_stream or a subsequent call.
        if (stream.send_buffer_offset == body_size && stream.is_trailers && !stream.end_stream_sent) {
            // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream_id_param << ": Body fully processed in send_response_body, trailers
            // are pending."); At this point, try_send_pending_data_for_stream will pick up trailer sending.
            try_send_pending_data_for_stream(stream_id, stream);
            auto after_trailers = _server_streams.find(stream_id);
            if (after_trailers == _server_streams.end()) {
                return true;
            }
            Http2ServerStream &current_stream = after_trailers->second;
            if (current_stream.end_stream_sent && current_stream.end_stream_received) {
                current_stream.state = Http2StreamConcreteState::CLOSED;
            }
            return true;
        }

        if (stream.end_stream_sent && stream.end_stream_received) {
            stream.state = Http2StreamConcreteState::CLOSED;
            // this->try_close_stream_context(stream.id); // Let send_response or try_send_pending handle final close context
        }
        return true; // Successfully sent what it could or marked pending
    }

    /**
     * @brief Dispatch complete request to IO handler
     *
     * Validates the assembled request and forwards it to the application
     * layer for processing.
     *
     * @param stream_id Stream identifier
     * @param stream Stream context with assembled request
     */
    void
    dispatch_complete_request(uint32_t stream_id, Http2ServerStream &stream) {
        if (stream.request_dispatched || stream.rst_stream_sent || stream.rst_stream_received) {
            LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Skipping request dispatch - already dispatched or stream reset");
            return;
        }

        if (this->ok() && this->_connection_active) {
            LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Dispatching complete request to application layer");
            // Assemble qb::http::Request from stream.assembled_request
            // The pseudo-headers should have already populated method and URI components.
            // Body should be in stream.assembled_request.body()
            // Trailers in stream.assembled_request.trailers() (and its header fields, Huly QB-1073)
            // Create a final qb::http::Request object.
            // For simplicity, let's assume stream.assembled_request is already mostly a qb::http::Request.
            // If it's a different intermediate struct, copy/move to qb::http::Request here.

            // Ensure mandatory fields are present if not checked earlier during header processing
            if (stream.assembled_request.method() == qb::http::Method::Value::UNINITIALIZED || stream.assembled_request.uri().path().empty()) {
                LOG_HTTP_ERROR_PA(stream_id, "ServerHttp2Protocol: Attempt to dispatch incomplete request (missing method/path)");
                this->send_rst_stream(stream_id, ErrorCode::INTERNAL_ERROR, "Attempt to dispatch incomplete request (missing method/path)");
                return;
            }
            stream.assembled_request.major_version = 2;
            stream.assembled_request.minor_version = 0;
            // A Cookie header over max_cookie_header_size, its lines joined -- the one refusal left, a malformed pair is
            // dropped -- throws: caught here, the request is served without cookies, as on HTTP/1.1. Uncaught, it
            // reached the noexcept frame handlers and terminated the process (Huly QB-1174).
            try {
                stream.assembled_request.parse_cookie_header();
            } catch (const std::exception &e) {
                LOG_HTTP_WARN_PA(stream_id, "Failed to parse Cookie header: " << e.what());
            } catch (...) {
                LOG_HTTP_WARN_PA(stream_id, "Failed to parse Cookie header: unknown exception");
            }

            // CRITICAL: dispatched BEFORE _io.on(), which may answer and close the stream, the reference dying with it.
            stream.request_dispatched = true;
            ++_client_streams_opened; // a request the application serves, which the Rapid Reset guard weighs (Huly QB-1244)

            // _io.on() runs the application layer (router, middleware, sync
            // handlers) synchronously. It is reached from the noexcept frame
            // handlers, so an exception escaping it would call std::terminate.
            // Contain it: reset the offending stream and keep the connection.
            try {
                this->_io.on(std::move(stream.assembled_request), stream_id); // Pass stream_id as context/correlation
            } catch (const std::exception &e) {
                LOG_HTTP_ERROR_PA(stream_id, "HTTP/2 request handler threw: " << e.what());
                // Do NOT erase the stream context here: this runs deep inside
                // on(HeadersFrame/DataFrame/ContinuationFrame), which still hold a
                // reference to the stream. Mark it reset + send RST_STREAM; the
                // caller's normal cleanup reclaims the context once it is done.
                this->send_rst_stream(stream_id, ErrorCode::INTERNAL_ERROR, "Request handler threw an exception", /*close_context=*/false);
                return;
            } catch (...) {
                LOG_HTTP_ERROR_PA(stream_id, "HTTP/2 request handler threw an unknown exception");
                this->send_rst_stream(stream_id, ErrorCode::INTERNAL_ERROR, "Request handler threw an exception", /*close_context=*/false);
                return;
            }

            // After _io.on(), the stream might have been closed and erased. We need to check if it still exists.
            auto it = _server_streams.find(stream_id);
            if (it != _server_streams.end()) {
                LOG_HTTP_INFO_PA(stream_id, "ServerHttp2Protocol: Request successfully dispatched to application");
                // Check stream state only if stream still exists
                if (it->second.state == Http2StreamConcreteState::CLOSED) {
                    this->try_close_stream_context(stream_id);
                }
            } else {
                // Stream was already closed and cleaned up during the dispatch
                LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Stream was closed during request dispatch");
            }
        } else {
            LOG_HTTP_WARN_PA(stream_id, "ServerHttp2Protocol: Cannot dispatch request - protocol not OK or connection inactive");
        }
    }

    /**
     * @brief Attempt to clean up stream context
     *
     * Removes stream from active streams if it's closed or reset.
     * Handles graceful shutdown completion checking.
     *
     * @param stream_id Stream identifier
     */
    void
    try_close_stream_context(uint32_t stream_id) noexcept {
        auto it = _server_streams.find(stream_id);
        if (it != _server_streams.end()) {
            Http2ServerStream &stream = it->second;

            bool can_cleanup = (stream.state == Http2StreamConcreteState::CLOSED) || stream.rst_stream_sent || stream.rst_stream_received;

            if (can_cleanup) {
                LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Cleaning up stream context");
                // If an error occurred that wasn't dispatched because request/response cycle was aborted by RST
                if ((!stream.request_dispatched || !stream.end_stream_sent) && (stream.rst_stream_sent || stream.rst_stream_received)
                    && stream.error_code != ErrorCode::NO_ERROR) {
                    // Stream was reset before full lifecycle completion by app. Error already dispatched by RST handler.
                }
                _server_streams.erase(it);
                LOG_HTTP_INFO_PA(stream_id, "ServerHttp2Protocol: Stream context cleaned up successfully");
                // A pushed stream ended: room for a promised response that waits, and one waiting no more (Huly QB-1202).
                if (!_waiting_push_responses.empty() && (stream_id & 1u) == 0u) [[unlikely]] {
                    std::erase(_waiting_push_responses, stream_id);
                    send_waiting_push_responses();
                }

                // The drain a client's NO_ERROR GOAWAY started completes with the last stream it
                // left us, whatever its id (our own GOAWAY deactivated the connection when sent).
                if (_graceful_shutdown_initiated && _connection_active
                    && this->are_all_relevant_streams_closed(FramerBase::get_last_peer_initiated_stream_id_processed_in_goaway())) {
                    _connection_active = false;
                    LOG_HTTP_INFO("ServerHttp2Protocol: Graceful shutdown complete - all streams closed");
                    this->not_ok(ErrorCode::NO_ERROR); // Graceful shutdown complete
                }
            } else {
                LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Stream not ready for cleanup yet");
            }
        } else {
            LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Stream context not found for cleanup");
        }
    }

    /**
     * @brief Send the connection's SETTINGS -- the server preface -- unless they were sent.
     */
    void
    send_initial_settings() noexcept {
        if (_initial_settings_sent)
            return;
        LOG_HTTP_DEBUG("Server: Sending initial SETTINGS frame");
        Http2FrameData<SettingsFrame> settings_frame_data;
        settings_frame_data.header.type  = static_cast<uint8_t>(FrameType::SETTINGS);
        settings_frame_data.header.flags = 0;
        settings_frame_data.header.set_stream_id(0);

        for (const auto &setting_pair : _our_settings) {
            settings_frame_data.payload.entries.push_back({setting_pair.first, setting_pair.second});
        }

        this->_io << settings_frame_data;
        _initial_settings_sent = true;
        LOG_HTTP_DEBUG("Server: Initial SETTINGS frame sent successfully");
    }

    /**
     * @brief Send a GOAWAY of a graceful shutdown: NO_ERROR, the connection kept (Huly QB-91).
     * @param last_stream_id The last client stream the server may process.
     * @param debug_message  Its debug data.
     */
    void
    send_graceful_goaway(uint32_t last_stream_id, std::string_view debug_message) noexcept {
        Http2FrameData<GoAwayFrame> goaway;
        goaway.header.type  = static_cast<uint8_t>(FrameType::GOAWAY);
        goaway.header.flags = 0;
        goaway.header.set_stream_id(0);
        goaway.payload.last_stream_id = last_stream_id;
        goaway.payload.error_code     = ErrorCode::NO_ERROR;
        goaway.payload.additional_debug_data.assign(debug_message.begin(), debug_message.end());
        this->_io << goaway;
    }

    /**
     * @brief Send GOAWAY frame and close connection
     *
     * Initiates connection shutdown by sending GOAWAY with the specified
     * error code and debug information.
     *
     * @param error_code Error code for GOAWAY
     * @param debug_message Debug information
     */
    void
    send_goaway_and_close(ErrorCode error_code, const std::string &debug_message) noexcept {
        if (!_connection_active) { // Removed .load(std::memory_order_relaxed)
            LOG_HTTP_DEBUG("ServerHttp2Protocol: Avoiding GOAWAY send - connection already inactive");
            return; // Avoid sending if already inactive.
        }

        LOG_HTTP_WARN("ServerHttp2Protocol: Sending GOAWAY frame. Error: " << static_cast<int>(error_code) << ", Message: " << debug_message);

        Http2FrameData<GoAwayFrame> goaway_frame_data;
        goaway_frame_data.payload.last_stream_id =
            _last_client_initiated_stream_id; // Report last stream ID client successfully initiated with us
        goaway_frame_data.payload.error_code = error_code;
        if (!debug_message.empty()) {
            goaway_frame_data.payload.additional_debug_data.assign(debug_message.begin(), debug_message.end());
        }

        FrameHeader header;
        header.type  = static_cast<uint8_t>(FrameType::GOAWAY);
        header.flags = 0;
        header.set_stream_id(0); // GOAWAY is on stream 0

        goaway_frame_data.header = header;
        this->_io << goaway_frame_data;

        _graceful_shutdown_initiated = true;
        _connection_active           = false; // Connection is being shut down

        // Notify IO_Handler about sending GOAWAY
        if constexpr (qb::has_on<IO_Handler, Http2GoAwayEvent>) {
            Http2GoAwayEvent goaway_event_to_dispatch{error_code, _last_client_initiated_stream_id, "GOAWAY sent by server: " + debug_message};
            this->get_io_handler().on(goaway_event_to_dispatch);
        }

        LOG_HTTP_INFO("ServerHttp2Protocol: GOAWAY sent. Connection will be closed");
        this->FramerBase::not_ok(error_code); // Request underlying transport to close.
    }

    /**
     * @brief Send WINDOW_UPDATE frame
     *
     * @param stream_id Stream ID (0 for connection-level)
     * @param increment Window size increment
     */
    void
    send_window_update(uint32_t stream_id, uint32_t increment) noexcept {
        if (!this->ok() || increment == 0) {
            return;
        }

        Http2FrameData<WindowUpdateFrame> wu_frame_data;
        wu_frame_data.header.type  = static_cast<uint8_t>(FrameType::WINDOW_UPDATE);
        wu_frame_data.header.flags = 0;
        wu_frame_data.header.set_stream_id(stream_id);
        wu_frame_data.payload.window_size_increment = increment;

        this->_io << wu_frame_data;
    }

    /**
     * @brief Conditionally send connection-level WINDOW_UPDATE
     *
     * Sends WINDOW_UPDATE for the connection if the receive window
     * falls below the threshold.
     */
    void
    conditionally_send_connection_window_update() noexcept {
        const int64_t connection_window_update_thresh =
            static_cast<int64_t>(DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE) / CONNECTION_WINDOW_THRESHOLD_DIVISOR;
        int64_t current_conn_recv_window = this->_connection_receive_window;

        if (current_conn_recv_window < connection_window_update_thresh) {
            uint32_t increment = static_cast<uint32_t>(DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE - current_conn_recv_window);
            if (increment > 0) {
                this->send_window_update(0, increment);
                this->_connection_receive_window += increment;
            }
        }
    }

    /**
     * @brief Update peer's initial window size
     *
     * Updates window sizes for all streams based on new SETTINGS_INITIAL_WINDOW_SIZE
     * received from peer.
     *
     * @param new_size New initial window size
     */
    void
    update_initial_peer_window_size(uint32_t new_size) noexcept {
        // This `new_size` is client's SETTINGS_INITIAL_WINDOW_SIZE
        // It affects how much data *we* (server) can send on *new* streams initiated by client
        // or on PUSH_PROMISE streams we initiate.
        const uint32_t old_size   = _initial_peer_window_size;
        _initial_peer_window_size = new_size;

        // Snapshot stream ids first: try_send_pending_data_for_stream may flush a
        // stream to CLOSED and erase it from _server_streams, invalidating a live
        // iterator into the map mid-loop (UAF). Re-find each id before use.
        std::vector<uint32_t> stream_ids;
        stream_ids.reserve(_server_streams.size());
        for (auto &pair : _server_streams)
            stream_ids.push_back(pair.first);

        for (uint32_t sid : stream_ids) {
            auto it = _server_streams.find(sid);
            if (it == _server_streams.end())
                continue; // erased by an earlier flush in this loop
            Http2ServerStream &stream = it->second;
            // RFC 9113 §6.9.2 adjusts EVERY stream window the endpoint maintains, and the one that
            // matters most is the stream answering a request that has already ended:
            // HALF_CLOSED_REMOTE, the state of nearly every response. It used to be skipped, so a
            // response waiting for credit stayed stuck until a stream WINDOW_UPDATE the client had
            // no reason to send (Huly QB-528). Only a closed or reset stream sends nothing more.
            if (stream.state != Http2StreamConcreteState::CLOSED && !stream.rst_stream_sent && !stream.rst_stream_received) {
                const int64_t old_stream_peer_window = stream.peer_window_size;

                if (!stream.update_peer_window_size(new_size, old_size)) {
                    this->send_rst_stream(stream.id, ErrorCode::FLOW_CONTROL_ERROR,
                                          "Stream window overflow (server side) due to client SETTINGS_INITIAL_WINDOW_SIZE change");
                    this->send_goaway_and_close(ErrorCode::FLOW_CONTROL_ERROR,
                                                "Client SETTINGS_INITIAL_WINDOW_SIZE change caused stream window overflow (conn error)");
                    return;
                }
                // A NEGATIVE window is legal and MUST NOT be an error. RFC 9113 §6.9.2: "A change to
                // SETTINGS_INITIAL_WINDOW_SIZE can cause the available space in a flow-control
                // window to become negative. A sender MUST track the negative flow-control window
                // and MUST NOT send new flow-controlled frames until it receives WINDOW_UPDATE
                // frames that cause the flow-control window to become positive." — the RFC even
                // works the example through (60 KB sent, initial size lowered to 16 KB, window
                // becomes -44 KB). Only EXCEEDING the maximum is a connection error, and that is
                // handled above.
                //
                // This used to RST the stream and GOAWAY the connection, so any peer that lowered
                // its initial window size after data had flowed — ordinary adaptive flow control —
                // had its connection killed, and a peer could trigger it deliberately with one
                // SETTINGS frame. Tracking it needs no new machinery: the send path already
                // declines while `peer_window_size <= 0`, and the resume below already fires when a
                // WINDOW_UPDATE brings it back positive. The client side (client.h) has always got
                // this right; this brings the server in line with it and with the RFC.
                if (old_stream_peer_window <= 0 && stream.peer_window_size > 0 && stream.has_pending_data_to_send) {
                    this->try_send_pending_data_for_stream(stream.id, stream);
                }
            }
        }
    }

    /**
     * @brief Try to send pending data for a specific stream
     *
     * Attempts to send buffered data when flow control window permits.
     * Handles both body data and trailers.
     *
     * @param stream_id_param Stream identifier
     * @param stream Stream context with pending data
     */
    void
    try_send_pending_data_for_stream(uint32_t stream_id_param, Http2ServerStream &stream) noexcept {
        if (!this->ok() || !_connection_active) {
            // QB_LOG_WARN_PA(this->getName(), "Server Stream " << stream_id_param << ": Connection not OK or inactive in
            // try_send_pending_data.");
            return;
        }

        if (stream.state != Http2StreamConcreteState::OPEN && stream.state != Http2StreamConcreteState::HALF_CLOSED_REMOTE) {
            // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream_id_param << ": Attempt to send pending data but stream not in OPEN or
            // HALF_CLOSED_LOCAL state. Current state: " << static_cast<int>(stream.state));
            return;
        }

        if (stream.streaming) {
            flush_streamed_response(stream_id_param, stream); // a streamed response: its pieces, then END_STREAM once ended (Huly QB-86)
            return;
        }

        bool body_fully_sent_or_empty = (stream.send_buffer_offset == stream.response_to_send.body().size());

        // Part 1: Try to send remaining body data if any
        if (stream.has_pending_data_to_send && !body_fully_sent_or_empty) {
            const auto &body_pipe       = std::as_const(stream.response_to_send).body().raw(); // a read: creates no pipe
            std::size_t total_body_size = body_pipe.size();
            const char *body_data_ptr   = body_pipe.data();

            while (stream.send_buffer_offset < total_body_size) {
                if (stream.peer_window_size <= 0 || this->_connection_send_window <= 0) {
                    // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream_id_param << ": Send pending body blocked by flow control.
                    // PeerWin: " << stream.peer_window_size << " ConnWin: " << this->_connection_send_window);
                    stream.has_pending_data_to_send = true; // Ensure it's still marked
                    return;                                 // Blocked, will retry later
                }

                uint32_t max_chunk_size = std::min(
                    {static_cast<uint32_t>(stream.peer_window_size), static_cast<uint32_t>(this->_connection_send_window),
                     this->FramerBase::get_peer_max_frame_size()});
                if (max_chunk_size == 0) {
                    // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream_id_param << ": Max chunk size is 0 for pending body, cannot
                    // send.");
                    stream.has_pending_data_to_send = true; // Still effectively blocked
                    return;
                }

                uint32_t remaining_body_to_send = static_cast<uint32_t>(total_body_size - stream.send_buffer_offset);
                uint32_t current_chunk_size     = std::min(remaining_body_to_send, max_chunk_size);

                if (current_chunk_size == 0 && remaining_body_to_send > 0) { // Should not happen if max_chunk_size > 0
                    stream.has_pending_data_to_send = true;
                    return;
                }
                if (current_chunk_size == 0 && remaining_body_to_send == 0)
                    break; // All body sent

                // START PADDING LOGIC MODIFICATION FOR SERVER DATA FRAMES
                uint8_t pad_length_s  = 0;
                bool    add_padding_s = false; // Use the debug flag

                if (add_padding_s && current_chunk_size > 0) {
                    uint32_t max_payload_without_pad_field_s = this->FramerBase::get_peer_max_frame_size() - 1;
                    if (current_chunk_size >= max_payload_without_pad_field_s) {
                        add_padding_s = false;
                    } else {
                        uint32_t available_for_padding_s = max_payload_without_pad_field_s - current_chunk_size;
                        pad_length_s                     = static_cast<uint8_t>(std::min((uint32_t) 15, available_for_padding_s));
                        if (current_chunk_size + pad_length_s > max_payload_without_pad_field_s) {
                            pad_length_s = static_cast<uint8_t>(max_payload_without_pad_field_s - current_chunk_size);
                        }
                    }
                } else {
                    add_padding_s = false;
                }

                Http2FrameData<DataFrame> data_frame_event;
                data_frame_event.header.type  = static_cast<uint8_t>(FrameType::DATA);
                data_frame_event.header.flags = 0; // No PADDED flag by default
                data_frame_event.header.set_stream_id(stream_id_param);

                // Populate payload directly with data chunk
                data_frame_event.payload.data_payload.assign(body_data_ptr + stream.send_buffer_offset,
                                                             body_data_ptr + stream.send_buffer_offset + current_chunk_size);
                // END PADDING LOGIC MODIFICATION FOR SERVER DATA FRAMES

                stream.send_buffer_offset += current_chunk_size;
                body_fully_sent_or_empty = (stream.send_buffer_offset == total_body_size);

                if (body_fully_sent_or_empty && !stream.is_trailers && !stream.end_stream_sent) {
                    data_frame_event.header.flags |= FLAG_END_STREAM;
                }

                this->_io << data_frame_event;

                if (!this->ok()) {
                    stream.send_buffer_offset -= current_chunk_size;
                    stream.has_pending_data_to_send = true;
                    return;
                }

                // Decrement flow control windows by actual data chunk size
                stream.peer_window_size -= current_chunk_size;
                this->_connection_send_window -= current_chunk_size;
                stream.progressed_since_idle_sweep = true;
                // REVERTED PADDING LOGIC (flow control decrement)

                if (data_frame_event.header.flags & FLAG_END_STREAM) {
                    stream.state                    = Http2StreamConcreteState::HALF_CLOSED_LOCAL;
                    stream.end_stream_sent          = true;
                    stream.has_pending_data_to_send = false;
                    break;
                }
            } // end while for sending body data

            if (stream.send_buffer_offset == total_body_size) {
                stream.has_pending_data_to_send = false; // All body data has been processed for sending.
            }
        } // end if has_pending_data_to_send (for body)

        // Part 2: Handle trailers if all body data is sent, trailers are expected, and END_STREAM not yet sent
        if (body_fully_sent_or_empty && stream.is_trailers && !stream.end_stream_sent) {
            // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream_id_param << ": All body sent, proceeding to send trailers.");

            // Exactly the fields the `trailer` header announces, which send_response() kept out of
            // the leading HEADERS (Huly QB-1058), then the response's trailers() (Huly QB-1073).
            std::vector<qb::protocol::hpack::HeaderField> hf_vector_trailers = outgoing_trailer_fields(stream.response_to_send);
            // Held to the client's SETTINGS_MAX_HEADER_LIST_SIZE as the leading block is, by the bound in force, before it is
            // encoded: one past it was sent (Huly QB-1240). Trailers end the stream, split over CONTINUATION frames (Huly QB-522).
            std::vector<uint8_t> encoded_trailers;
            if (!this->fits_peer_header_list(stream_id_param, hf_vector_trailers)
                || (!hf_vector_trailers.empty() && !_hpack_encoder.encode(hf_vector_trailers, encoded_trailers))) {
                send_rst_stream(stream_id_param, ErrorCode::INTERNAL_ERROR, "Trailer section past the client's bound, or not encoded");
                return; // Stop processing for this stream
            }

            if (this->send_headers_with_continuation(stream_id_param, FLAG_END_STREAM, std::move(encoded_trailers))) {
                stream.state           = Http2StreamConcreteState::HALF_CLOSED_LOCAL;
                stream.end_stream_sent = true;
                stream.is_trailers     = false; // Trailers have been handled
                // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream_id_param << ": Trailers sent with END_STREAM.");
            } else {
                // QB_LOG_ERROR_PA(this->getName(), "Server Stream " << stream_id_param << ": Send failed for trailers frame.");
                // If send failed, stream.end_stream_sent remains false, stream.is_trailers remains true.
                // The stream will be re-attempted or errored out by other mechanisms.
                return;
            }
        }

        // Final check for stream closure
        if (stream.end_stream_sent) {
            // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream_id_param << ": END_STREAM is sent. Current state: " <<
            // static_cast<int>(stream.state) << ", end_stream_received: " << stream.end_stream_received);
            if (stream.state == Http2StreamConcreteState::HALF_CLOSED_LOCAL && stream.end_stream_received) {
                stream.state = Http2StreamConcreteState::CLOSED;
                // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream_id_param << ": State changed to CLOSED.");
            }
            try_close_stream_context(stream_id_param);
        }
    }

    /// can_begin_streamed_response(), on the stream itself.
    [[nodiscard]] static bool
    can_begin_streamed_response(Http2ServerStream const &stream) noexcept {
        return stream.request_dispatched && !stream.rst_stream_sent && !stream.rst_stream_received && !stream.end_stream_sent
               && !stream.streaming && !stream.response_sent
               && (stream.state == Http2StreamConcreteState::OPEN || stream.state == Http2StreamConcreteState::HALF_CLOSED_REMOTE);
    }

    /**
     * @brief The leading header block of a response as `http_response`'s fields give it, for send_response() and
     *        begin_streamed_response(): `:status` first, then every field -- a name is lowercase already, the headers
     *        map stores it folded (Huly QB-1191) -- each validated, one `content-length` at most, parsed into
     *        `declared_content_length`; then, for a response with a trailer section (`trailed`: a `trailer` header, or
     *        `trailers()`), the fields the section takes leave the block and `trailers()` is announced
     *        (prepare_trailed_header_block, Huly QB-1058, QB-1073). The trailer section itself leaves after the body
     *        (try_send_pending_data_for_stream), the same contract as HTTP/1.1 and HTTP/3.
     * @return `false` when the response is refused -- a field HTTP/2 forbids or cannot carry, a malformed or a
     *         conflicting `content-length`, a trailer field a section must not carry -- the stream then reset
     *         (on_stream_error, INTERNAL_ERROR: the application's response is the fault, not the peer, Huly QB-1273)
     *         and nothing sent.
     */
    [[nodiscard]] QB_HTTP2_FORCEINLINE bool
    collect_response_head(uint32_t stream_id, qb::http::Response const &http_response, std::vector<qb::protocol::hpack::HeaderField> &hf_vector,
                          std::optional<std::uint64_t> &declared_content_length, bool &trailed) {
        hf_vector.emplace_back(":status", std::to_string(http_response.status().code()));
        bool announces_trailers = false;
        for (const auto &header_item : http_response.headers()) {
            const std::string &name_lower = header_item.first;
            if (name_lower.empty() || name_lower[0] == ':' || HeaderValidator::is_forbidden_response_header(name_lower)) {
                this->on_stream_error(stream_id, ErrorCode::INTERNAL_ERROR,
                                      "Forbidden or invalid HTTP/2 response header: " + header_item.first);
                return false;
            }
            for (const auto &value :
                 header_item.second) { // Assuming header_item.second is iterable (e.g. vector of strings for multi-value headers)
                if (!HeaderValidator::is_valid_header_field(name_lower, value)) {
                    this->on_stream_error(stream_id, ErrorCode::INTERNAL_ERROR, "Invalid HTTP/2 response header field: " + header_item.first);
                    return false;
                }
                if (name_lower == "content-length") {
                    const auto parsed = HeaderValidator::parse_content_length(value);
                    if (!parsed) {
                        this->on_stream_error(stream_id, ErrorCode::INTERNAL_ERROR, "Invalid HTTP/2 response content-length");
                        return false;
                    }
                    if (declared_content_length && *declared_content_length != *parsed) {
                        this->on_stream_error(stream_id, ErrorCode::INTERNAL_ERROR, "Conflicting HTTP/2 response content-length headers");
                        return false;
                    }
                    declared_content_length = *parsed;
                }
                hf_vector.emplace_back(name_lower, value);
            }
            announces_trailers = announces_trailers || name_lower == qb::http::well_known::TRAILER_SV;
        }
        trailed = announces_trailers || http_response.has_trailers();
        if (trailed) {
            if (const char *refused = prepare_trailed_header_block(hf_vector, http_response)) {
                this->on_stream_error(stream_id, ErrorCode::INTERNAL_ERROR, refused);
                return false;
            }
        }
        return true;
    }

    /// The room the socket has left for a frame: the io's write-buffer cap (`max_write_buffer_size()` when the io has
    /// one, qb-io's default otherwise; SIZE_MAX means no cap) less the bytes it already queues (Huly QB-86).
    [[nodiscard]] std::size_t
    streamed_socket_room() const noexcept {
        std::size_t cap = QB_MAX_WRITE_BUFFER_SIZE;
        if constexpr (detail::io_has_write_cap<IO_Handler>::value) {
            cap = static_cast<std::size_t>(this->_io.max_write_buffer_size());
        }
        if (cap == static_cast<std::size_t>(-1)) {
            return cap;
        }
        const std::size_t queued = this->_io.out().size() + std::min(streamed_socket_headroom, cap / 4); // a small cap keeps a quarter
        return cap > queued ? cap - queued : 0;
    }

    /**
     * @brief Send what a streamed response can send now (Huly QB-86): the pieces `streamed->buffer` holds, as DATA frames
     *        of at most the peer's frame size, as far as the stream's and the connection's send windows go -- the rest
     *        waits for a WINDOW_UPDATE, which calls again through try_send_pending_data_for_stream() -- then, once
     *        end_streamed_response() ran and the last piece left, END_STREAM: on the last DATA frame, or on an empty
     *        one, or on the trailer section's HEADERS when the response has one (split over CONTINUATION frames past
     *        the peer's frame size, Huly QB-522). `stream` may be erased by the time this returns (a closed stream is
     *        reclaimed): callers read nothing through it afterwards.
     */
    void
    flush_streamed_response(uint32_t stream_id, Http2ServerStream &stream) noexcept {
        auto &buffer = stream.streamed->buffer; // begin_streamed_response() allocated it: `streaming` says so
        while (buffer.size() > 0) {
            if (stream.peer_window_size <= 0 || _connection_send_window <= 0) {
                stream.has_pending_data_to_send = true; // the next WINDOW_UPDATE comes back here
                return;
            }
            // The socket's room: the io's write-buffer cap less what the socket already queues. A stream's own write()
            // is admitted against that cap with its own held pieces alone; the pieces every stream held back for a
            // window would flush together past it on one WINDOW_UPDATE, and publish() disconnects past the cap.
            const std::size_t socket_room = streamed_socket_room();
            if (socket_room <= FRAME_HEADER_SIZE) {
                stream.has_pending_data_to_send = true; // the next write pass comes back here (resume_streamed_responses)
                _streams_wait_for_socket        = true;
                return;
            }
            const auto     window = std::min<int64_t>(stream.peer_window_size, _connection_send_window);
            const uint32_t room   = std::min<uint32_t>(
                {static_cast<uint32_t>(std::min<int64_t>(window, 0x7FFFFFFF)), this->FramerBase::get_peer_max_frame_size(),
                 static_cast<uint32_t>(std::min<std::size_t>(socket_room - FRAME_HEADER_SIZE, 0x7FFFFFFF))});
            const uint32_t chunk = static_cast<uint32_t>(std::min<std::size_t>(buffer.size(), room));
            if (chunk == 0) {
                stream.has_pending_data_to_send = true;
                return;
            }
            const bool                last = stream.stream_ended && chunk == buffer.size() && !stream.is_trailers;
            Http2FrameData<DataFrame> frame;
            frame.header.type  = static_cast<uint8_t>(FrameType::DATA);
            frame.header.flags = last ? FLAG_END_STREAM : 0;
            frame.header.set_stream_id(stream_id);
            frame.payload.data_payload.assign(buffer.begin(), buffer.begin() + chunk);
            this->_io << frame;
            if (!this->ok()) {
                stream.has_pending_data_to_send = true;
                return;
            }
            if constexpr (counts_appended_output<IO_Handler>)
                stream.streamed->end_pos = this->_io.appended_total(); // the stall watch's FIFO mark (Huly QB-1212)
            buffer.free_front(chunk);
            stream.peer_window_size -= chunk;
            _connection_send_window -= chunk;
            stream.progressed_since_idle_sweep = true;
            if (last) {
                buffer.reset();
                stream.has_pending_data_to_send = false;
                stream.end_stream_sent          = true;
                stream.streaming                = false;
                stream.state = stream.end_stream_received ? Http2StreamConcreteState::CLOSED : Http2StreamConcreteState::HALF_CLOSED_LOCAL;
                try_close_stream_context(stream_id); // `stream` dangles past it
                return;
            }
        }
        buffer.reset(); // every piece left: the pipe's room is kept, its cursor returns to the front
        stream.has_pending_data_to_send = false;
        if (!stream.stream_ended || stream.end_stream_sent) {
            return; // more pieces may come, or the end left already
        }
        if (stream.is_trailers) {
            // The room first, on a bound of the section's encoded size: encoding advances the HPACK encoder's dynamic
            // table, so a block encoded and then held back would leave the peer's table behind on the retry. A field's
            // literal form is under its name, its value and 32 octets (HPACK's own size of an entry); a frame header per
            // frame of the peer's size, one more for the remainder.
            std::size_t bound = 0;
            for (const auto &field : stream.streamed->trailer_fields) {
                bound += field.name.size() + field.value.size() + 32;
            }
            const std::size_t frames = bound / std::max<std::size_t>(this->FramerBase::get_peer_max_frame_size(), 1) + 1;
            if (streamed_socket_room() <= bound + frames * FRAME_HEADER_SIZE) {
                stream.has_pending_data_to_send = true; // the trailer section waits for the socket's room, unencoded
                _streams_wait_for_socket        = true;
                return;
            }
            if (!this->fits_peer_header_list(stream_id, stream.streamed->trailer_fields)) { // the bound then in force (Huly QB-1240)
                send_rst_stream(stream_id, ErrorCode::INTERNAL_ERROR, "streamed response trailer section past the client's bound");
                return;
            }
            std::vector<uint8_t> encoded_trailers;
            if (!stream.streamed->trailer_fields.empty() && !_hpack_encoder.encode(stream.streamed->trailer_fields, encoded_trailers)) {
                send_rst_stream(stream_id, ErrorCode::INTERNAL_ERROR, "HPACK trailer encoding error");
                return;
            }
            if (!this->send_headers_with_continuation(stream_id, FLAG_END_STREAM, std::move(encoded_trailers))) {
                stream.has_pending_data_to_send = true; // tried again at the next write pass
                return;
            }
            stream.is_trailers = false;
        } else {
            if (streamed_socket_room() <= FRAME_HEADER_SIZE) {
                stream.has_pending_data_to_send = true; // the empty END_STREAM frame waits for the socket's room
                _streams_wait_for_socket        = true;
                return;
            }
            Http2FrameData<DataFrame> frame;
            frame.header.type  = static_cast<uint8_t>(FrameType::DATA);
            frame.header.flags = FLAG_END_STREAM;
            frame.header.set_stream_id(stream_id);
            this->_io << frame;
            if (!this->ok()) {
                stream.has_pending_data_to_send = true;
                return;
            }
        }
        stream.progressed_since_idle_sweep = true;
        stream.end_stream_sent             = true;
        stream.streaming                   = false;
        stream.state = stream.end_stream_received ? Http2StreamConcreteState::CLOSED : Http2StreamConcreteState::HALF_CLOSED_LOCAL;
        try_close_stream_context(stream_id); // `stream` dangles past it
    }

    /**
     * @brief Handle errors detected by the framer
     *
     * Called by base class when frame parsing errors occur.
     *
     * @param reason Error code
     * @param message Error description
     * @param stream_id_context Stream ID if error is stream-specific, 0 for connection errors
     */
    void
    handle_framer_detected_error(ErrorCode reason, const std::string &message, uint32_t stream_id_context) noexcept {
        if (stream_id_context != 0) {
            // Error is specific to a stream - send RST_STREAM
            this->send_rst_stream(stream_id_context, reason, message);
        } else {
            // Error affects the entire connection
            this->on_connection_error(reason, message);
        }
    }

    /**
     * @brief Handle stream-level error
     *
     * Override from base class to handle stream errors properly
     *
     * @param stream_id Stream ID
     * @param error_code Error code
     * @param debug_message Error description
     */
    void
    on_stream_error(uint32_t stream_id, ErrorCode error_code, const std::string &debug_message) noexcept {
        LOG_HTTP_ERROR_PA(stream_id, "ServerHttp2Protocol: Stream error detected - " << debug_message
                                                                                     << " (code: " << static_cast<int>(error_code) << ")");
        // Send RST_STREAM for the specific stream
        this->send_rst_stream(stream_id, error_code, debug_message);
    }

    /**
     * @brief Handle connection-level error
     *
     * Override from base class to handle connection errors properly
     *
     * @param error_code Error code
     * @param debug_message Error description
     */
    void
    on_connection_error(ErrorCode error_code, const std::string &debug_message) noexcept {
        LOG_HTTP_ERROR("ServerHttp2Protocol: Connection error detected - " << debug_message << " (code: " << static_cast<int>(error_code)
                                                                           << ")");
        // Send GOAWAY and close the connection
        this->send_goaway_and_close(error_code, debug_message);
    }

    /**
     * @brief Check if all relevant streams are closed
     *
     * Server-specific implementation to check if graceful shutdown can complete.
     *
     * @param last_known_stream_id Last stream ID from GOAWAY
     * @return true if all relevant streams are closed
     */
    [[nodiscard]] bool
    are_all_relevant_streams_closed(uint32_t /*last_known_stream_id*/) const noexcept {
        // During the drain a client's NO_ERROR GOAWAY starts, everything still open must finish:
        // the client's requests whatever their id -- the GOAWAY's last-stream-id bounds the
        // server's own streams, not them -- and the pushes at or below that bound, the ones above
        // it having been closed on receipt (Huly QB-530).
        if (_graceful_shutdown_initiated) {
            for (const auto &pair : _server_streams) {
                const Http2ServerStream &stream = pair.second;
                if (stream.state != Http2StreamConcreteState::CLOSED && stream.state != Http2StreamConcreteState::IDLE
                    && // IDLE might be considered effectively closed for new work
                    !stream.rst_stream_sent && !stream.rst_stream_received) {
                    return false; // A stream is still to finish.
                }
            }
            return true;
        }
        return false; // Not in graceful shutdown or no streams to check in that context
    }

    /**
     * @brief Get existing stream or create new stream context
     *
     * @param stream_id Stream identifier
     * @param is_client_initiated Whether stream was initiated by client (unused, inferred from ID)
     * @return Reference to stream context
     */
    Http2ServerStream &
    get_or_create_stream_context(uint32_t stream_id, bool /*is_client_initiated -- inferred from stream_id */) {
        auto it = _server_streams.find(stream_id);
        if (it == _server_streams.end()) {
            // Create new stream context
            // For server, is_client_initiated is true if stream_id is odd.
            // bool client_init = (stream_id % 2 != 0);
            Http2ServerStream new_stream(stream_id, _initial_peer_window_size, this->get_initial_window_size_from_settings());
            // new_stream.is_client_initiated = client_init; // is_client_initiated is not a member of Http2ServerStream
            // The count of active client streams is handled elsewhere, e.g. on HEADERS receipt.
            auto result = _server_streams.emplace(stream_id, std::move(new_stream));
            it          = result.first;
        }
        return it->second;
    }

    /**
     * @brief Get reference to I/O handler (application layer).
     * @return Reference to I/O handler.
     */
    [[nodiscard]] IO_Handler &
    get_io_handler() noexcept {
        return this->_io;
    }

    /**
     * @brief Get reference to I/O handler (application layer), const version.
     * @return Const reference to I/O handler.
     */
    [[nodiscard]] const IO_Handler &
    get_io_handler() const noexcept {
        return this->_io;
    }

    /**
     * @brief Send the promised responses that wait for room under the client's SETTINGS_MAX_CONCURRENT_STREAMS, in the
     *        order they were answered, as long as it has room (RFC 9113 §5.1.2, Huly QB-1202). A stream reset or
     *        reclaimed meanwhile is skipped. Re-entered from a response it sends -- one that ends its stream at once --
     *        it returns: the loop below goes on.
     */
    void
    send_waiting_push_responses() noexcept {
        if (_sending_waiting_push_responses) {
            return;
        }
        _sending_waiting_push_responses = true;
        while (!_waiting_push_responses.empty() && this->ok() && get_active_stream_count(true) < _peer_max_concurrent_streams) {
            const uint32_t stream_id = _waiting_push_responses.front();
            _waiting_push_responses.erase(_waiting_push_responses.begin());
            const auto it = _server_streams.find(stream_id);
            if (it == _server_streams.end() || it->second.state != Http2StreamConcreteState::RESERVED_LOCAL || it->second.rst_stream_sent
                || it->second.rst_stream_received) {
                continue;
            }
            _push_response_leaving = stream_id;
            (void) send_response(stream_id, it->second.response_to_send);
            _push_response_leaving = 0;
        }
        _sending_waiting_push_responses = false;
    }

    /**
     * @brief Whether a response given for @p stream_id has a promised response still waiting before it (Huly QB-1202):
     *        given from an observer of the stream whose close makes room, before the drain runs, it went out first. The
     *        response the drain is sending passes; a stream the list names that was reset or reclaimed holds none.
     */
    [[nodiscard]] bool
    waits_behind_a_promised_response(uint32_t stream_id) const noexcept {
        if (stream_id == _push_response_leaving) {
            return false;
        }
        for (const uint32_t waiting : _waiting_push_responses) {
            const auto it = _server_streams.find(waiting);
            if (it != _server_streams.end() && it->second.state == Http2StreamConcreteState::RESERVED_LOCAL && !it->second.rst_stream_sent
                && !it->second.rst_stream_received) {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Get the count of active streams: open or half-closed, those a peer's SETTINGS_MAX_CONCURRENT_STREAMS
     *        counts -- a reserved stream is not (RFC 9113 §5.1.2), and a promised one was (Huly QB-1202).
     * @param server_initiated_check If true, counts even-numbered (server-pushed) streams.
     *                               If false, counts odd-numbered (client-initiated) request streams.
     * @return Number of active streams matching the criteria.
     */
    [[nodiscard]] uint32_t
    get_active_stream_count(bool server_initiated_check) const noexcept {
        uint32_t count = 0;
        for (const auto &[stream_id, stream_obj] : _server_streams) {
            if (stream_obj.state != Http2StreamConcreteState::IDLE && stream_obj.state != Http2StreamConcreteState::CLOSED
                && stream_obj.state != Http2StreamConcreteState::RESERVED_LOCAL && !stream_obj.rst_stream_sent
                && !stream_obj.rst_stream_received) {
                if (server_initiated_check) { // Count server-initiated/pushed (even) streams
                    if (stream_id % 2 == 0) {
                        count++;
                    }
                } else { // Count client-initiated/request (odd) streams
                    if (stream_id % 2 != 0) {
                        count++;
                    }
                }
            }
        }
        return count;
    }

    /**
     * @brief Reset a stream because the client's own frame provoked it (MadeYouReset, CVE-2025-8671; Huly QB-1244): DATA
     *        or HEADERS after its END_STREAM, a WINDOW_UPDATE past 2^31-1 on a request in flight -- dispatched, unanswered,
     *        reset by neither side -- free its slot as a client RST_STREAM would while the application's work may go on,
     *        so the reset counts against the same Rapid Reset ceiling (on(RstStreamFrame)). A WINDOW_UPDATE of 0 or a
     *        short PRIORITY on a request in flight comes here too (on_stream_frame_error). A reset provoked BEFORE
     *        dispatch -- a malformed request or trailer section, DATA over the window, a body against its content-length,
     *        trailers without END_STREAM, a stream error on an upload -- frees no application work, and the client gets one
     *        per new stream id: the published form of the reset flood (CVE-2019-9514). It counts against the closed-stream
     *        budget (admit_solicited_reset()); past it the connection is closed and the reset is not sent (Huly QB-1270). A
     *        stream the server reset itself is not counted again (a handler that threw: closed). A client RST_STREAM on an
     *        id whose reset it provoked counts once more (on(RstStreamFrame) counts any closed odd id), toward the ceiling
     *        only.
     */
    void
    send_provoked_rst_stream(uint32_t stream_id, ErrorCode error_code, const std::string &context_msg) noexcept {
        bool past_ceiling = false;
        if (const auto it = _server_streams.find(stream_id); it != _server_streams.end() && _connection_active) {
            const Http2ServerStream &stream = it->second;
            if (!stream.rst_stream_sent && !stream.rst_stream_received) {
                if (stream.request_dispatched) {
                    past_ceiling = !stream.end_stream_sent && ++_rst_stream_count > ::qb::http2::protocol_limits::MAX_RAPID_RESETS
                                   && _rst_stream_count * 2u > _client_streams_opened;
                } else if (!this->admit_solicited_reset("Excessive stream resets before dispatch (HTTP/2 reset flood)")) {
                    return;
                }
            }
        }
        this->send_rst_stream(stream_id, error_code, context_msg);
        if (past_ceiling) {
            this->send_goaway_and_close(ErrorCode::ENHANCE_YOUR_CALM, "Excessive stream resets provoked (HTTP/2 MadeYouReset)");
        }
    }

    /**
     * @brief Whether a field section fits the client's SETTINGS_MAX_HEADER_LIST_SIZE, counted as RFC 9113 §6.5.2 counts
     *        it -- each name and value, and 32 octets. A promised request and a trailer section are judged by it before
     *        they are encoded, as a response's header list is (Huly QB-1235): both were sent past it (Huly QB-1240).
     * @param stream_id The stream the section belongs to, for the log.
     * @param fields The section, as it would be encoded.
     */
    [[nodiscard]] bool
    fits_peer_header_list(uint32_t stream_id, const std::vector<qb::protocol::hpack::HeaderField> &fields) const {
        if (_peer_max_header_list_size >= DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE) {
            return true;
        }
        std::uint64_t list_size = 0;
        for (const auto &field : fields) {
            list_size += field.hpack_size();
        }
        return fits_peer_list_size(stream_id, list_size);
    }

    /// @brief Whether a field section of @p list_size octets, counted as RFC 9113 §6.5.2 counts it, fits the client's
    ///        SETTINGS_MAX_HEADER_LIST_SIZE; one that does not is logged (Huly QB-1240).
    [[nodiscard]] bool
    fits_peer_list_size(uint32_t stream_id, std::uint64_t list_size) const {
        if (list_size <= _peer_max_header_list_size) {
            return true;
        }
        LOG_HTTP_WARN_PA(stream_id, "ServerHttp2Protocol: field section " << list_size << " exceeds peer's MAX_HEADER_LIST_SIZE "
                                                                          << _peer_max_header_list_size);
        return false;
    }

    /**
     * @brief The size RFC 9113 §6.5.2 counts of the trailer section a response sends, from its plan, no field copied:
     *        the fields outgoing_trailer_fields() keeps, and a `connection`-nominated one a streamed end() may still
     *        hold (the head refused the header; counting it only refuses more) -- each name and value, and 32 octets (Huly QB-1240).
     */
    [[nodiscard]] static std::uint64_t
    trailer_section_size(const qb::http::Response &response) {
        const auto    plan = qb::http::detail::plan_outgoing_trailers(response, response.has_trailers() ? &response.trailers() : nullptr);
        std::uint64_t size = 0;
        for (const auto &[name, value] : plan.fields) {
            if (HeaderValidator::is_valid_header_field(name, value)) {
                size += name.size() + value.size() + ::qb::protocol::hpack::HPACK_ENTRY_OVERHEAD;
            }
        }
        return size;
    }

    /**
     * @brief Answer a frame on a closed stream with RST_STREAM, at most MAX_QUEUED_CONTROL_REPLIES of them between two
     *        streams the client opens -- a request dispatched, or one it cancelled, which the Rapid Reset guard weighs --
     *        never forgiven by a frame it can send for nothing, such as an empty DATA (admit_solicited_reset(), the budget
     *        a stream refused and a request reset before its dispatch share): past them the connection is closed with
     *        GOAWAY(ENHANCE_YOUR_CALM). Each such frame drew a reset, without a bound (the reset flood of CVE-2019-9514;
     *        Huly QB-1270).
     */
    void
    send_closed_stream_rst(uint32_t stream_id, ErrorCode error_code, const std::string &context_msg) noexcept {
        if (this->admit_solicited_reset("Excessive frames on closed streams (HTTP/2 reset flood)")) {
            this->send_rst_stream(stream_id, error_code, context_msg);
        }
    }

    /**
     * @brief Count one RST_STREAM the client solicits on a stream it never opened -- a frame on a closed stream, a stream
     *        refused, a request reset or refused before its dispatch -- against the closed-stream budget: at most
     *        MAX_QUEUED_CONTROL_REPLIES between two streams the client opens (_client_streams_opened, what the Rapid Reset
     *        guard weighs: a request dispatched, or one it cancels), which no frame it sends for nothing forgives. Past it
     *        the connection is closed with GOAWAY(ENHANCE_YOUR_CALM), @p flood its debug data (Huly QB-1270).
     * @return Whether the reset may be sent.
     */
    [[nodiscard]] bool
    admit_solicited_reset(char const *flood) noexcept {
        if (_client_streams_opened != _streams_opened_at_closed_reply) { // a stream opened since: the budget is forgiven
            _streams_opened_at_closed_reply = _client_streams_opened;
            _closed_stream_reply_count      = 0;
        }
        if (++_closed_stream_reply_count > ::qb::http2::protocol_limits::MAX_QUEUED_CONTROL_REPLIES) {
            this->send_goaway_and_close(ErrorCode::ENHANCE_YOUR_CALM, flood);
            return false;
        }
        return true;
    }

    /**
     * @brief Count one PONG or SETTINGS ACK the client solicits against the PING/SETTINGS budget (CVE-2019-9512/9515): at
     *        most MAX_QUEUED_CONTROL_REPLIES between two units of real request progress -- a stream the client opens (a
     *        request dispatched, or one it cancels: _client_streams_opened, read here) or octets of a request body accepted
     *        (on(DataFrame) forgives them there). A frame that moves no request forward forgave it: an empty DATA, a DATA of
     *        padding alone, a HEADERS refused as malformed or opening an upload never dispatched (Huly QB-1270).
     * @return Whether the reply is past the budget: the caller closes the connection with GOAWAY(ENHANCE_YOUR_CALM).
     */
    [[nodiscard]] bool
    control_reply_over_budget() noexcept {
        if (_client_streams_opened != _streams_opened_at_control_reply) { // a stream opened since: the budget is forgiven
            _streams_opened_at_control_reply = _client_streams_opened;
            _control_reply_count             = 0;
        }
        return ++_control_reply_count > ::qb::http2::protocol_limits::MAX_QUEUED_CONTROL_REPLIES;
    }

    /**
     * @brief Refuse a new client stream with REFUSED_STREAM (RFC 9113 §8.7): opened by its HEADERS and closed at once, its id
     *        is no longer idle (§5.1.1) -- a frame the client sent on it before it saw the refusal is one on a closed stream
     *        -- while the last stream accepted, which a GOAWAY names, does not move. The id stayed idle: a DATA, WINDOW_UPDATE or
     *        RST_STREAM on it closed the connection with GOAWAY(PROTOCOL_ERROR), a HEADERS was refused again or served anew. The
     *        refusal, a reset the client solicits, is budgeted as those on a closed stream are (Huly QB-1270).
     */
    void
    refuse_new_stream(uint32_t stream_id, const std::string &context_msg) noexcept {
        _highest_client_stream_id = std::max(_highest_client_stream_id, stream_id);
        this->send_closed_stream_rst(stream_id, ErrorCode::REFUSED_STREAM, context_msg);
    }

public:
    /**
     * @brief A frame error RFC 9113 makes a STREAM error -- a WINDOW_UPDATE of 0 (§6.9), a PRIORITY that is not 5 octets
     *        (§6.3) -- for which the frame layer ended the connection, without a GOAWAY (Huly QB-1270): the stream is reset
     *        and the connection serves on. A request in flight counts its reset against the Rapid Reset ceiling, an upload
     *        not yet dispatched against the closed-stream budget (send_provoked_rst_stream), a closed stream against that
     *        budget too (send_closed_stream_rst); an idle stream, which no RST_STREAM may name (§6.4), or stream 0 makes it
     *        a connection error, with its GOAWAY (§5.4.1).
     */
    void
    on_stream_frame_error(ErrorCode error_code, const std::string &message, uint32_t stream_id) noexcept {
        if (stream_id == 0 || stream_id > ((stream_id & 1u) == 0u ? _last_promised_stream_id : _highest_client_stream_id)) {
            this->send_goaway_and_close(error_code, message);
            return;
        }
        const auto it = _server_streams.find(stream_id);
        if (it == _server_streams.end() || it->second.state == Http2StreamConcreteState::CLOSED || it->second.rst_stream_sent
            || it->second.rst_stream_received) {
            this->send_closed_stream_rst(stream_id, error_code, message);
            return;
        }
        this->send_provoked_rst_stream(stream_id, error_code, message);
    }

private:
    /// The highest id the client used, a refused stream's too: above it a client stream is idle (RFC 9113 §5.1.1), at or
    /// below it closed or open; the last stream accepted -- the id a GOAWAY names -- is _last_client_initiated_stream_id.
    uint32_t _highest_client_stream_id = 0;
    /// The resets admit_solicited_reset() let go since the client last opened a stream (_client_streams_opened, as it was).
    std::uint32_t _closed_stream_reply_count = 0, _streams_opened_at_closed_reply = 0;
    /// _client_streams_opened when control_reply_over_budget() last forgave the PING/SETTINGS budget (Huly QB-1270).
    std::uint32_t _streams_opened_at_control_reply = 0;

}; // class ServerHttp2Protocol

} // namespace qb::protocol::http2
