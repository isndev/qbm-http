/**
 * @file client.h
 * @brief HTTP/2 client protocol implementation for qb-io framework
 * @copyright Copyright (c) 2024 isndev. All rights reserved.
 * @license This software is licensed under the terms specified in the LICENSE file
 *          located in the root directory of the project.
 */

#pragma once

#include <memory>
#include <optional>
#include <algorithm>
#include <string_view>
#include <array>

#include <qb/io/async/protocol.h>
#include <qb/system/container/unordered_map.h>

#include "../../request.h"
#include "../../response.h"
#include "./base.h"
#include "./hpack.h"
#include "./stream.h"
#include "./frames.h"
#include "../../logger.h" // Added logger include

namespace qb::protocol::http2 {

/**
 * @brief Type alias for PING frame opaque data
 */
using OpaqueDataArray = std::array<uint8_t, 8>;

/**
 * @brief Constants for header field names and values
 */
constexpr std::string_view TE_TRAILERS_VALUE = "trailers";
constexpr std::string_view HOST_HEADER_NAME_SV = "Host";
constexpr std::string_view TE_HEADER_NAME_SV = "TE";

/**
 * @brief HTTP/2 client protocol implementation
 * @tparam IO_Handler The I/O handler type from qb-io framework
 * 
 * This class implements the HTTP/2 client-side protocol handling according to RFC 9113.
 * It manages:
 * - Client-initiated streams (odd numbered)
 * - Server push streams (even numbered)
 * - HPACK compression/decompression
 * - Flow control (connection and stream level)
 * - Settings negotiation
 * - Request/response processing
 * 
 * The client supports:
 * - Multiple concurrent streams
 * - Request body streaming with flow control
 * - Trailer headers
 * - Server push (PUSH_PROMISE)
 * - Graceful shutdown via GOAWAY
 * - Priority hints (deprecated but supported)
 */
template<typename IO_Handler>
class ClientHttp2Protocol :
    public qb::protocol::http2::Http2Protocol<IO_Handler, ClientHttp2Protocol<IO_Handler>>
{
public:
    using FramerBase = qb::protocol::http2::Http2Protocol<IO_Handler, ClientHttp2Protocol<IO_Handler>>;
    friend class qb::protocol::http2::Http2Protocol<IO_Handler, ClientHttp2Protocol<IO_Handler>>;

private:
    // Stream management
    qb::unordered_map<uint32_t, Http2ClientStream> _client_streams; 
    uint32_t _next_client_stream_id = 1; 
    uint32_t _last_initiated_stream_id = 0;

    // Header block assembly
    std::vector<uint8_t> _current_header_block_fragment;
    uint32_t _current_header_stream_id = 0;

    // Flow control
    int64_t _connection_send_window;
    int64_t _connection_receive_window = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;
    static constexpr int CONNECTION_WINDOW_THRESHOLD_DIVISOR = 2;

    // Peer settings
    uint32_t _initial_peer_window_size = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;
    uint32_t _peer_max_frame_size = DEFAULT_SETTINGS_MAX_FRAME_SIZE;
    uint32_t _peer_max_concurrent_streams = DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS;
    uint64_t _peer_max_header_list_size = DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE;
    bool _peer_allows_push = true;

    // Our settings
    // Our Settings
    qb::unordered_map<Http2SettingIdentifier, uint32_t> _our_settings;
    bool _initial_settings_sent = false;
    uint32_t _our_max_frame_size; // Set from _our_settings in constructor

    bool _connection_active = true; // Removed std::atomic
    bool _graceful_shutdown_initiated = false; // Removed std::atomic // True if we sent or received GOAWAY(NO_ERROR)

    // HPACK
    std::unique_ptr<hpack::Decoder> _hpack_decoder;
    std::unique_ptr<hpack::Encoder> _hpack_encoder;

    // For sending a single request
    bool _single_request_mode = false;
    const qb::http::Request* _original_single_request = nullptr;

    bool _received_goaway = false;
    ErrorCode _goaway_error_code = ErrorCode::NO_ERROR;

    uint32_t _connection_processed_bytes_for_window_update = 0;

    qb::unordered_map<uint32_t, Http2ClientStream> _pending_pushed_streams;

    uint32_t _active_header_block_stream_id = 0;

    bool _initial_settings_ack_received_placeholder = false; // Placeholder for actual ACK tracking.

    std::optional<OpaqueDataArray> _outstanding_ping_data;

    // Add as a private member to ClientHttp2Protocol class
    // private:
    //    bool _debug_send_padded_data = false; // Set to true to test sending padded DATA frames

public:
    /**
     * @brief Construct HTTP/2 client protocol handler
     * @param io_handler_ref Reference to IO handler
     * @param single_request_to_send Optional single request for simple mode
     */
    explicit ClientHttp2Protocol(IO_Handler& io_handler_ref, const qb::http::Request* single_request_to_send = nullptr)
        : FramerBase(io_handler_ref), // ✅ Remove the problematic call from here
          _single_request_mode(single_request_to_send != nullptr),
          _original_single_request(single_request_to_send)
    {
        LOG_HTTP_DEBUG_PA(0, "Client: Constructing HTTP/2 client protocol");
        
        // ✅ Initialize settings and derived values in constructor body (like server does)
        this->_our_max_frame_size = this->initialize_our_max_frame_size();
        _connection_send_window = this->get_initial_window_size_from_settings();
        
        LOG_HTTP_DEBUG_PA(0, "Client: Initializing HPACK encoder/decoder");
        _hpack_decoder = std::make_unique<hpack::HpackDecoderImpl>();
        _hpack_encoder = std::make_unique<hpack::HpackEncoderImpl>();
        
        // Apply HPACK encoder settings based on _our_settings
        auto it_table_size = _our_settings.find(Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE);
        if (it_table_size != _our_settings.end() && _hpack_encoder) {
            _hpack_encoder->set_max_capacity(it_table_size->second);
            LOG_HTTP_DEBUG_PA(0, "Client: Set HPACK encoder table size to " << it_table_size->second);
        }
        
        this->reset();
        
        LOG_HTTP_DEBUG_PA(0, "Client: HTTP/2 client protocol construction complete");
        
        // ✅ Framework will send HTTP/2 connection preface automatically
        send_connection_preface();
    }

    ~ClientHttp2Protocol() override = default;

    ClientHttp2Protocol(const ClientHttp2Protocol&) = delete;
    ClientHttp2Protocol& operator=(const ClientHttp2Protocol&) = delete;
    ClientHttp2Protocol(ClientHttp2Protocol&&) = delete;
    ClientHttp2Protocol& operator=(ClientHttp2Protocol&&) = delete;

    void reset() noexcept override {
        FramerBase::reset(); // Call base class reset first

        // Clear stream-specific data
        _client_streams.clear();
        _current_header_block_fragment.clear();
        _current_header_stream_id = 0;
        _last_initiated_stream_id = 0;
        _connection_active = true;
        _graceful_shutdown_initiated = false;
        _initial_settings_sent = false;

        // Reset our settings and derived values
        this->initialize_our_settings_map();
        _our_max_frame_size = this->get_setting_value_or_default(
            Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 
            DEFAULT_SETTINGS_MAX_FRAME_SIZE);

        // Reset connection flow control windows based on our settings
        _connection_send_window = this->get_initial_window_size_from_settings();
        _connection_receive_window = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE; // We are prepared to receive this much initially

        // Reset peer settings to defaults
        _initial_peer_window_size = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;
        _peer_max_frame_size = DEFAULT_SETTINGS_MAX_FRAME_SIZE;
        _peer_max_concurrent_streams = DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS;
        _peer_max_header_list_size = DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE;
        _peer_allows_push = true; // Default for server

        // Reset HPACK state
        if (_hpack_decoder) _hpack_decoder->reset();
        if (_hpack_encoder) {
            _hpack_encoder->reset();
            // Apply our SETTINGS_HEADER_TABLE_SIZE to the encoder
            auto it_table_size = _our_settings.find(Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE);
            if (it_table_size != _our_settings.end()) {
                _hpack_encoder->set_max_capacity(it_table_size->second);
            }
        }
    }

    // Called by FramerBase (Http2Protocol)
    void on(qb::protocol::http2::PrefaceCompleteEvent /*event*/) noexcept {
        LOG_HTTP_INFO_PA(0, "Client: HTTP/2 preface complete event received");
        
        if (!this->ok() || !_connection_active) {
            LOG_HTTP_WARN_PA(0, "Client: Preface complete but protocol not OK or connection inactive. OK: " 
                             << this->ok() << ", Active: " << _connection_active);
            return;
        }

        if (!_initial_settings_sent) {
            LOG_HTTP_DEBUG_PA(0, "Client: Sending initial SETTINGS frame");
            Http2FrameData<SettingsFrame> settings_frame_data;
            settings_frame_data.header.type = static_cast<uint8_t>(FrameType::SETTINGS);
            settings_frame_data.header.flags = 0;
            settings_frame_data.header.set_stream_id(0);

            LOG_HTTP_DEBUG_PA(0, "Client: Adding " << _our_settings.size() << " settings to SETTINGS frame");
            for(const auto& setting_pair : _our_settings) {
                settings_frame_data.payload.entries.push_back({setting_pair.first, setting_pair.second});
                LOG_HTTP_TRACE_PA(0, "Client: Setting " << static_cast<uint16_t>(setting_pair.first) 
                                 << " = " << setting_pair.second);
            }
            // No need to call calculate_length, it's implicit in Http2FrameData serialization

            this->_io << settings_frame_data; // Send SETTINGS frame with our settings
            _initial_settings_sent = true;
            LOG_HTTP_DEBUG_PA(0, "Client: Initial SETTINGS frame sent successfully");
            // HPACK encoder max table size is already set based on _our_settings in constructor/reset
        } else {
            LOG_HTTP_DEBUG_PA(0, "Client: Initial SETTINGS already sent, skipping");
        }

        // If initial settings were just sent (or already sent) and we are in single request mode
        if (_initial_settings_sent && _single_request_mode && _original_single_request) {
            LOG_HTTP_DEBUG_PA(0, "Client: Preface complete, sending single request automatically");
            // Attempt to send the request. The send_request method handles stream creation, etc.
            // The app_request_id from the async::session is not directly available here.
            // If it were needed, the async::session would have to pass it to the protocol,
            // perhaps via a dedicated method or during construction if a single request ID is known then.
            // For now, using default app_request_id = 0.
            if (!this->send_request(*_original_single_request, 0 /* app_request_id */)) {
                LOG_HTTP_ERROR_PA(0, "Client: Failed to send single request automatically");
                // send_request logs its own errors and calls not_ok or GOAWAY on failure.
                // If it was a recoverable issue like flow control, it would return true
                // and set has_pending_data_to_send on the stream.
                // If it returns false, it's generally a more severe issue like HPACK encoding failure
                // or peer limit exceeded before anything could be sent.
                // The connection might be already marked not_ok by send_request.
            } else {
                LOG_HTTP_DEBUG_PA(0, "Client: Single request sent successfully");
            }
            // It's important that this request is only sent once through this mechanism.
            // Subsequent calls to send_request should come from the IO_Handler explicitly if it's a multi-request client.
            // For a true single-shot client, the session might close after this one request/response cycle.
            // We don't clear _single_request_mode or _original_single_request here,
            // as the protocol might be reused if the IO_Handler has such logic,
            // but this automatic send on preface complete should only happen once.
            // The send_request method itself is designed to be callable multiple times for different requests.
        } else {
            LOG_HTTP_DEBUG_PA(0, "Client: Not in single request mode or no request to send. Single mode: " 
                             << _single_request_mode << ", Has request: " << (_original_single_request != nullptr));
        }
    }

    // Called by FramerBase (Http2Protocol)
    void on(Http2FrameData<DataFrame> data_event) noexcept {
        if (!this->FramerBase::ok()) return;
        const auto stream_id = data_event.header.get_stream_id(); // Corrected

        auto* stream_ptr = get_stream_by_id(stream_id);

        if (!stream_ptr) {
            handle_data_for_unknown_stream(stream_id, data_event.header.get_payload_length()); // Corrected
            return;
        }
        Http2ClientStream& stream = *stream_ptr;

        if (stream.state == Http2StreamConcreteState::CLOSED || stream.rst_stream_sent || stream.rst_stream_received) {
            handle_data_for_closed_stream(stream, data_event.header.get_payload_length()); // Corrected
            return;
        }

        if (stream.state != Http2StreamConcreteState::OPEN && stream.state != Http2StreamConcreteState::HALF_CLOSED_LOCAL) {
            send_rst_stream(stream_id, ErrorCode::STREAM_CLOSED, "DATA in invalid state");
            try_close_stream_context_by_id(stream.id, ErrorCode::STREAM_CLOSED, "DATA in invalid state for stream."); // Pass stream.id
            return;
        }

        const auto& data_payload = data_event.payload.data_payload;
        const uint32_t payload_size = data_payload.size();

        if (stream.local_window_size < payload_size) {
            send_rst_stream(stream_id, ErrorCode::FLOW_CONTROL_ERROR, "Stream flow control violation");
            try_close_stream_context_by_id(stream.id, ErrorCode::FLOW_CONTROL_ERROR, "Stream flow control violation on receive."); // Pass stream.id
            // As per RFC 9113 Section 5.2.2, this is also a connection error.
            this->send_goaway_and_close(ErrorCode::FLOW_CONTROL_ERROR, "Stream flow control violation by peer.");
            return;
        }
        stream.local_window_size -= payload_size;
        stream.processed_bytes_for_window_update += payload_size;

        if (_connection_receive_window < payload_size) {
            this->send_goaway_and_close(ErrorCode::FLOW_CONTROL_ERROR, "Connection flow control violation by peer.");
            return;
        }
        _connection_receive_window -= payload_size;
        _connection_processed_bytes_for_window_update += payload_size;

        if (!data_payload.empty()) {
            stream.assembled_response.body().raw().write(reinterpret_cast<const char*>(data_payload.data()), data_payload.size());
        }

        if (data_event.header.flags & FLAG_END_STREAM) {
            stream.end_stream_received = true;
            if (stream.state == Http2StreamConcreteState::OPEN) {
                stream.state = Http2StreamConcreteState::HALF_CLOSED_REMOTE;
            } else if (stream.state == Http2StreamConcreteState::HALF_CLOSED_LOCAL) {
                stream.state = Http2StreamConcreteState::CLOSED;
            }
            if (!stream.trailers_expected) { // Only process if not expecting trailers
                process_complete_response_if_ready(stream);
            }
        }

        if (stream.processed_bytes_for_window_update >= stream.window_update_threshold && stream.window_update_threshold > 0) {
            uint32_t increment = stream.processed_bytes_for_window_update; // Send update for all processed bytes
            send_window_update(stream_id, increment);
            stream.local_window_size += increment; // Increment our local window size as we're telling peer they can send more
            stream.processed_bytes_for_window_update = 0;
        }

        conditionally_send_connection_window_update(); // Check for connection-level WINDOW_UPDATE

        if (stream.state == Http2StreamConcreteState::CLOSED) {
            // LOG_DEBUG_PA("ClientHttp2Protocol\\", \\"[HTTP/2 Client] Stream \\" << stream_id << \\" closed after DATA with END_STREAM and no trailers expected (or already half-closed local).\\");
            try_close_stream_context_by_id(stream.id, ErrorCode::NO_ERROR);
        }
    }

    /**
     * @brief Handle HEADERS frame
     * @param headers_event HEADERS frame event
     */
    void on(Http2FrameData<HeadersFrame> headers_event) noexcept {
        LOG_HTTP_DEBUG_PA(headers_event.header.get_stream_id(), "Client: Received HEADERS frame");
        
        auto* stream_ptr = get_stream_by_id(headers_event.header.get_stream_id());

        if (!stream_ptr) {
            // Check if it's a pushed stream
            auto it = _pending_pushed_streams.find(headers_event.header.get_stream_id());
            if (it != _pending_pushed_streams.end()) {
                LOG_HTTP_DEBUG_PA(headers_event.header.get_stream_id(), "Client: Processing HEADERS for pushed stream");
                Http2ClientStream& pushed_stream = it->second;
                process_incoming_headers(pushed_stream, headers_event);
                return;
            }

            // Unknown stream - send RST_STREAM
            LOG_HTTP_WARN_PA(headers_event.header.get_stream_id(), "Client: Received HEADERS for unknown/closed stream. Sending RST_STREAM.");
            this->send_rst_stream(headers_event.header.get_stream_id(), 
                                ErrorCode::STREAM_CLOSED, 
                                "HEADERS on unknown/closed stream");
            return;
        }
        Http2ClientStream& stream = *stream_ptr;
        LOG_HTTP_DEBUG_PA(stream.id, "Client: Processing HEADERS for known stream");
        process_incoming_headers(stream, headers_event);
    }

    /**
     * @brief Handle CONTINUATION frame
     * @param continuation_event CONTINUATION frame event
     */
    void on(Http2FrameData<ContinuationFrame> continuation_event) noexcept {
        if (_active_header_block_stream_id == 0 || 
            _active_header_block_stream_id != continuation_event.header.get_stream_id()) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, 
                                       "CONTINUATION for unexpected stream.");
            return;
        }

        auto* stream_ptr = get_stream_by_id(_active_header_block_stream_id);
        if (!stream_ptr) {
            this->send_goaway_and_close(ErrorCode::INTERNAL_ERROR, 
                                       "CONTINUATION for internally inconsistent stream state.");
            clear_header_assembly_state();
            return;
        }
        Http2ClientStream& stream = *stream_ptr;

        if (!stream.expecting_continuation) {
            send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Unexpected CONTINUATION");
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "Unexpected CONTINUATION frame."); // Connection error
            clear_header_assembly_state();
            return;
        }

        _current_header_block_fragment.insert(_current_header_block_fragment.end(), 
                                             continuation_event.payload.header_block_fragment.begin(), 
                                             continuation_event.payload.header_block_fragment.end());
        // LOG_DEBUG_PA("ClientHttp2Protocol", "[HTTP/2 Client] CONTINUATION for stream " << stream.id << " added "
        //           << continuation_event.payload.header_block_fragment.size() << " bytes to assembly buffer. END_HEADERS: "
        //           << ((continuation_event.header.flags & FLAG_END_HEADERS) ? "yes" : "no"));


        if (continuation_event.header.flags & FLAG_END_HEADERS) {
            // LOG_DEBUG_PA("ClientHttp2Protocol", "[HTTP/2 Client] END_HEADERS received in CONTINUATION frame for stream " << stream.id << ". Decoding...");
            stream.expecting_continuation = false; // No more CONTINUATIONs for this block
            std::vector<hpack::HeaderField> decoded_fields;
            bool hpack_incomplete = false;

            if (!_hpack_decoder->decode(_current_header_block_fragment, decoded_fields, hpack_incomplete)) {
                // LOG_ERROR_PA("ClientHttp2Protocol", "[HTTP/2 Client] HPACK decoding failed for CONTINUATION on stream " << stream.id);
                send_rst_stream(stream.id, ErrorCode::COMPRESSION_ERROR, "HPACK decoding failed (CONTINUATION)");
                this->send_goaway_and_close(ErrorCode::COMPRESSION_ERROR, "HPACK decoding error.");
                clear_header_assembly_state();
                return;
            }
             if (hpack_incomplete){
                // LOG_WARN_PA("ClientHttp2Protocol", "[HTTP/2 Client] HPACK decoding possibly incomplete for stream " << stream.id << " (CONTINUATION)");
                send_rst_stream(stream.id, ErrorCode::COMPRESSION_ERROR, "HPACK incomplete decoding (CONTINUATION)");
                this->send_goaway_and_close(ErrorCode::COMPRESSION_ERROR, "HPACK incomplete decoding.");
                clear_header_assembly_state();
                return;
            }
            clear_header_assembly_state(); // Also resets _active_header_block_stream_id

            bool is_trailers_block = stream.headers_received_main;
            if (!parse_and_validate_headers_into_response(stream, decoded_fields, is_trailers_block)) {
                 // Error handled by parse_and_validate_headers_into_response
                return;
            }

            if (is_trailers_block) {
                stream.trailers_received = true;
                // LOG_DEBUG_PA("ClientHttp2Protocol", "[HTTP/2 Client] Trailers (via CONTINUATION) processed for stream " << stream.id);
            } else {
                stream.headers_received_main = true;
                // LOG_DEBUG_PA("ClientHttp2Protocol", "[HTTP/2 Client] Main headers (via CONTINUATION) processed for stream " << stream.id);
                 // Check for "Trailer" header
                if (!(stream.end_stream_received)) { // Only expect trailers if stream not already ended by this HEADERS/CONTINUATION block
                    for(const auto& hf : decoded_fields) {
                        if (hf.name == "trailer" || hf.name == "Trailer") {
                            stream.trailers_expected = true;
                            // LOG_DEBUG_PA("ClientHttp2Protocol", "[HTTP/2 Client] 'Trailer' header found on stream " << stream.id << " (via CONTINUATION). Expecting trailers.");
                            break;
                        }
                    }
                }
            }
             // State transitions for OPEN/HALF_CLOSED_REMOTE if applicable (e.g. if PUSH_PROMISE HEADERS was split)
            if (stream.state == Http2StreamConcreteState::IDLE && stream.id != 0) {
                stream.state = Http2StreamConcreteState::OPEN;
            } else if (stream.state == Http2StreamConcreteState::RESERVED_REMOTE) {
                stream.state = Http2StreamConcreteState::OPEN;
            }
        }
        // Note: CONTINUATION frames do not carry END_STREAM flag. That flag is on the initial HEADERS.
        // So, we don't check for stream.end_stream_received updates here directly from CONTINUATION flags.
        // The original HEADERS frame's END_STREAM flag determines that.
        
        // Check if the response is now complete and can be dispatched
        // This is important if END_STREAM was on the *initial* HEADERS frame, and this CONTINUATION
        // with END_HEADERS just completed the header block for that.
        process_complete_response_if_ready(stream);
    }

    // Called by FramerBase (Http2Protocol)
    void on(Http2FrameData<SettingsFrame> settings_event) noexcept {
        LOG_HTTP_DEBUG_PA(0, "Client: Received SETTINGS frame");
        
        if (!this->ok() || !_connection_active) {
            LOG_HTTP_WARN_PA(0, "Client: Ignoring SETTINGS frame - protocol not OK or connection inactive");
            return;
        }

        const FrameHeader& header = settings_event.header;
        if (header.get_stream_id() != 0) {
            LOG_HTTP_ERROR_PA(0, "Client: SETTINGS frame on non-zero stream_id: " << header.get_stream_id());
            send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "SETTINGS frame on non-zero stream_id");
            return;
        }

        if (header.flags & FLAG_ACK) {
            if (!settings_event.payload.entries.empty()) {
                LOG_HTTP_ERROR_PA(0, "Client: SETTINGS ACK frame with payload");
                send_goaway_and_close(ErrorCode::FRAME_SIZE_ERROR, "SETTINGS ACK frame with payload");
                return; // Return after sending GOAWAY
            }
            // ACK received. Can apply any local setting changes that were pending ACK if any.
            LOG_HTTP_DEBUG_PA(0, "Client: Received SETTINGS ACK from server");
            _initial_settings_ack_received_placeholder = true; // Mark that we got an ACK
            return;
        }

        //SETTINGS frame from server (not an ACK)
        LOG_HTTP_DEBUG_PA(0, "Client: Processing " << settings_event.payload.entries.size() << " settings from server");
        
        for (const auto& setting_entry : settings_event.payload.entries) {
            Http2SettingIdentifier id = setting_entry.identifier;
            uint32_t value = setting_entry.value;

            LOG_HTTP_TRACE_PA(0, "Client: Received setting ID " << static_cast<uint16_t>(id) << " with value " << value);

            // bool known_setting = false; // Not strictly needed if we only act on known ones
            switch(id) {
                case Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE:
                    // No specific validation on value range in RFC for receiver, 
                    // but decoder will cap it internally if it exceeds its own limits.
                    if (_hpack_encoder) {
                        _hpack_encoder->set_peer_max_dynamic_table_size(value);
                        LOG_HTTP_DEBUG_PA(0, "Client: Updated HPACK encoder peer table size to " << value);
                    }
                    break;
                case Http2SettingIdentifier::SETTINGS_ENABLE_PUSH:
                    if (value > 1) { // MUST be 0 or 1
                        LOG_HTTP_ERROR_PA(0, "Client: Invalid SETTINGS_ENABLE_PUSH value: " << value);
                        send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "Invalid SETTINGS_ENABLE_PUSH value from server: " + std::to_string(value));
                        return;
                    }
                    _peer_allows_push = (value == 1); 
                    LOG_HTTP_DEBUG_PA(0, "Client: Server push " << (_peer_allows_push ? "enabled" : "disabled"));
                    break;
                case Http2SettingIdentifier::SETTINGS_MAX_CONCURRENT_STREAMS:
                    // No specific upper bound mentioned for receiver to validate against, beyond practical limits.
                    _peer_max_concurrent_streams = value;
                    LOG_HTTP_DEBUG_PA(0, "Client: Server max concurrent streams: " << value);
                    break;
                case Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE:
                    if (value > MAX_WINDOW_SIZE_LIMIT) { // Cannot exceed 2^31-1
                        LOG_HTTP_ERROR_PA(0, "Client: SETTINGS_INITIAL_WINDOW_SIZE too large: " << value);
                        send_goaway_and_close(ErrorCode::FLOW_CONTROL_ERROR, "SETTINGS_INITIAL_WINDOW_SIZE too large from server: " + std::to_string(value)); // Changed to FLOW_CONTROL_ERROR
                        return;
                    }
                    LOG_HTTP_DEBUG_PA(0, "Client: Updating initial window size from " << _initial_peer_window_size << " to " << value);
                    update_initial_peer_window_size(value);
                    break;
                case Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE:
                    if (value < MIN_MAX_FRAME_SIZE || value > MAX_FRAME_SIZE_LIMIT) { // Must be between 16,384 and 2^24-1
                        LOG_HTTP_ERROR_PA(0, "Client: Invalid SETTINGS_MAX_FRAME_SIZE value: " << value);
                        send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "Invalid SETTINGS_MAX_FRAME_SIZE value from server: " + std::to_string(value));
                        return;
                    }
                    // this->_peer_max_frame_size = value; // This is handled by FramerBase::set_peer_max_frame_size
                    LOG_HTTP_DEBUG_PA(0, "Client: Updating peer max frame size to " << value);
                    FramerBase::set_peer_max_frame_size(value);
                    break;
                case Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE:
                    // No specific upper bound mentioned for receiver to validate against.
                    _peer_max_header_list_size = value;
                    LOG_HTTP_DEBUG_PA(0, "Client: Server max header list size: " << value);
                    break;
                // Case for SETTINGS_ENABLE_CONNECT_PROTOCOL (0x8) could be added if needed.
                // RFC 9113: "An endpoint that receives a SETTINGS frame with any unknown or unsupported identifier MUST ignore that setting."
                default:
                    // Unknown setting identifiers MUST be ignored by recipient.
                    LOG_HTTP_TRACE_PA(0, "Client: Ignoring unknown setting ID " << static_cast<uint16_t>(id) << " from server");
                    break;
            }
        }

        // Send SETTINGS ACK
        LOG_HTTP_DEBUG_PA(0, "Client: Sending SETTINGS ACK to server");
        Http2FrameData<SettingsFrame> ack_frame;
        ack_frame.header.type = static_cast<uint8_t>(FrameType::SETTINGS);
        ack_frame.header.flags = FLAG_ACK;
        ack_frame.header.set_stream_id(0);
        // ack_frame.header.set_payload_length(0); // Payload is empty, length is 0 (implicit in struct)
        this->_io << ack_frame;
        LOG_HTTP_DEBUG_PA(0, "Client: SETTINGS ACK sent to server");
    }
    
    // Called by FramerBase (Http2Protocol)
    void on(Http2FrameData<RstStreamFrame> rst_event) noexcept {
        if (!this->ok() || !_connection_active) return;

        const uint32_t stream_id = rst_event.header.get_stream_id();
        const ErrorCode error_code = rst_event.payload.error_code;

        if (stream_id == 0) {
            send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "RST_STREAM frame on stream 0");
            return; 
        }

        auto it = _client_streams.find(stream_id);
        if (it != _client_streams.end()) {
            Http2ClientStream& stream = it->second;
            stream.rst_stream_received = true;
            stream.error_code = error_code;
            stream.state = Http2StreamConcreteState::CLOSED;

            if (!stream.response_dispatched) { // Only dispatch error if no response was/will be sent
                Http2StreamErrorEvent stream_error_event{stream_id, error_code, "RST_STREAM received from peer"};
                this->_io.on(stream_error_event);
            }
            try_close_stream_context_by_id(stream.id, ErrorCode::STREAM_CLOSED, "RST_STREAM received from peer"); // Pass stream.id
        }
        // If stream not found, RST is for an unknown/already closed stream. Can be ignored.
    }

    // Called by FramerBase (Http2Protocol)
    void on(Http2FrameData<PushPromiseFrame> pp_event) noexcept {
        if (!this->ok() || !_connection_active) return;

        uint32_t associated_stream_id = pp_event.header.get_stream_id();
        uint32_t promised_stream_id = pp_event.payload.promised_stream_id;

        if (promised_stream_id == 0 || (promised_stream_id % 2 != 0)) {
            // Per RFC 9113, Section 6.6: "Promised stream identifiers MUST be
            // even-numbered integers." and "A PUSH_PROMISE frame that promises an
            // odd-numbered stream identifier MUST be treated as a connection error
            // (Section 5.4.1) of type PROTOCOL_ERROR."
            send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "PUSH_PROMISE with invalid promised_stream_id (0 or odd)");
            return;
        }

        // Check if this client instance is configured to accept pushes generally.
        // This is based on the SETTINGS_ENABLE_PUSH value *we* would send to the server.
        bool client_allows_push_globally = this->get_setting_value_or_default(Http2SettingIdentifier::SETTINGS_ENABLE_PUSH, 1) == 1;
        if (!client_allows_push_globally) {
            // We have push disabled, so we must refuse the stream.
            // Server should not have sent it if we set SETTINGS_ENABLE_PUSH to 0.
            // If it did, it's a protocol error on server side, but we still RST.
            send_rst_stream(promised_stream_id, ErrorCode::REFUSED_STREAM, "Client has SETTINGS_ENABLE_PUSH disabled");
            return;
        }

        // Server also has a SETTINGS_ENABLE_PUSH. While _peer_allows_push stores what server advertised, 
        // for receiving a PUSH_PROMISE, our setting is primary for refusal.
        // If server sends PUSH_PROMISE when _peer_allows_push was false from server's SETTINGS, that's an issue with server.

        auto assoc_it = _client_streams.find(associated_stream_id);
        if (assoc_it == _client_streams.end() || 
            !(assoc_it->second.state == Http2StreamConcreteState::OPEN || assoc_it->second.state == Http2StreamConcreteState::HALF_CLOSED_REMOTE)) {
            // Associated stream must be open or half-closed (remote) for PUSH_PROMISE to be valid.
            send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "PUSH_PROMISE on an invalid or non-existent associated stream");
            return;
        }
        
        if (_client_streams.count(promised_stream_id)) { // Check only active streams, pending_pushed_streams is for server
             send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "PUSH_PROMISE for already existing client stream ID");
             return;
        }

        // Check against our SETTINGS_MAX_CONCURRENT_STREAMS that we would advertise to the server.
        // This limits how many concurrent streams the server can push to us.
        uint32_t our_advertised_max_concurrent_server_initiated_streams = get_setting_value_or_default(Http2SettingIdentifier::SETTINGS_MAX_CONCURRENT_STREAMS, DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS);
        if (get_active_stream_count(true) >= our_advertised_max_concurrent_server_initiated_streams) { // true for server-initiated (even) streams
             send_rst_stream(promised_stream_id, ErrorCode::REFUSED_STREAM, "Client refusing PUSH_PROMISE due to its own MAX_CONCURRENT_STREAMS limit for incoming pushes");
             return;
        }

        // Decode headers from PUSH_PROMISE payload
        std::vector<hpack::HeaderField> temp_decoded_hpack_fields; 
        bool is_incomplete_dummy = false; 
        if (!_hpack_decoder || !_hpack_decoder->decode(pp_event.payload.header_block_fragment, temp_decoded_hpack_fields, is_incomplete_dummy)) { 
            LOG_HTTP_ERROR_PA(associated_stream_id, "Client: HPACK decode failed for PUSH_PROMISE headers.");
            send_goaway_and_close(ErrorCode::COMPRESSION_ERROR, "HPACK decode failed for PUSH_PROMISE headers");
            return;
        }
        if (is_incomplete_dummy) {
             LOG_HTTP_ERROR_PA(associated_stream_id, "Client: HPACK decode incomplete for PUSH_PROMISE headers.");
             send_goaway_and_close(ErrorCode::COMPRESSION_ERROR, "HPACK decode incomplete for PUSH_PROMISE headers");
            return;
        }

        // Create and store the new stream in RESERVED_REMOTE state
        Http2ClientStream pushed_stream_obj(promised_stream_id, 
                                          this->get_setting_value_or_default(Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE), // Our receive window for this pushed stream
                                          _initial_peer_window_size); // Server's send window for this pushed stream (based on their settings)
        pushed_stream_obj.state = Http2StreamConcreteState::RESERVED_REMOTE; 
        pushed_stream_obj.associated_stream_id = associated_stream_id;
        pushed_stream_obj.synthetic_request_headers = temp_decoded_hpack_fields; // Store for the app

        auto [inserted_it, success] = _client_streams.emplace(promised_stream_id, std::move(pushed_stream_obj));
        if (!success) {
            // Should not happen if count check above was correct, but as a safeguard.
            send_goaway_and_close(ErrorCode::INTERNAL_ERROR, "Failed to emplace new pushed stream context");
            return;
        }
                
        // Convert hpack::HeaderField to qb::http::Headers for the event
        qb::http::headers event_pseudo_headers_for_app;
        for (const auto& hf : temp_decoded_hpack_fields) {
            event_pseudo_headers_for_app.add_header(std::string(hf.name), std::string(hf.value));
        }

        Http2PushPromiseEvent event_to_dispatch{ 
            associated_stream_id,
            promised_stream_id,
            std::move(event_pseudo_headers_for_app) 
        };

        if constexpr (has_method_on<IO_Handler, void, Http2PushPromiseEvent>::value) {
            this->get_io_handler().on(event_to_dispatch);
            // IO_Handler is now responsible for calling application_reject_push if it wants to reject.
            // If it doesn't call reject, the stream remains RESERVED_REMOTE until server sends HEADERS/DATA for it.
        } else {
            // If IO_Handler cannot handle the event, reject the push by default.
            application_reject_push(promised_stream_id); 
        }
    }

    // Public method for application to reject a push explicitly
    void application_reject_push(uint32_t promised_stream_id) {
        if (!this->ok() || !_connection_active) return;

        auto it = _client_streams.find(promised_stream_id);
        if (it != _client_streams.end()) {
            Http2ClientStream& stream_to_reject = it->second;
            // Only reject if still in RESERVED_REMOTE. If server already sent HEADERS, it's too late to reject this way.
            if (stream_to_reject.state == Http2StreamConcreteState::RESERVED_REMOTE) { 
                 send_rst_stream(promised_stream_id, ErrorCode::REFUSED_STREAM, "Push rejected by application");
                 // Update stream state immediately after sending RST
                 stream_to_reject.rst_stream_sent = true;
                 stream_to_reject.error_code = ErrorCode::REFUSED_STREAM;
                 stream_to_reject.state = Http2StreamConcreteState::CLOSED;
                 try_close_stream_context_by_id(stream_to_reject.id, ErrorCode::REFUSED_STREAM, "Push rejected by application"); // Attempt cleanup now
            } else {
                // QB_LOG_WARN_PA(this->getName(), "Application tried to reject push for stream " << promised_stream_id 
                //              << " but it was not in RESERVED_REMOTE state. Current state: " << static_cast<int>(it->second.state));
            }
        } else {
            // QB_LOG_WARN_PA(this->getName(), "Application tried to reject push for unknown/already cleaned stream ID: " << promised_stream_id);
        }
    }


    // Called by FramerBase (Http2Protocol)
    void on(Http2FrameData<GoAwayFrame> goaway_event) noexcept {
        const std::string debug_data_str(goaway_event.payload.additional_debug_data.begin(), goaway_event.payload.additional_debug_data.end());
        LOG_HTTP_WARN_PA(0, "Client: Received GOAWAY frame. Last Stream ID: "
            << goaway_event.payload.last_stream_id << ", Error: " << static_cast<int>(goaway_event.payload.error_code)
            << ", Debug: " << debug_data_str);

        this->set_last_peer_initiated_stream_id_processed_in_goaway(goaway_event.payload.last_stream_id);
        _received_goaway = true;
        _goaway_error_code = goaway_event.payload.error_code;

        // Mark streams with IDs greater than last_stream_id as effectively closed or failed.
        // Iterate over _client_streams and _pending_pushed_streams.
        for (auto it = _client_streams.begin(); it != _client_streams.end(); ) {
            if (it->first > goaway_event.payload.last_stream_id && it->second.id % 2 != 0) { // Client-initiated
                // LOG_WARN_PA("ClientHttp2Protocol", "[HTTP/2 Client] Stream " << it->first << " was active but is now implicitly closed by GOAWAY.");
                it->second.error_code = goaway_event.payload.error_code; // Or a more specific "closed_by_goaway"
                it->second.rst_stream_received = true; // Simulate RST for purpose of closure and error reporting
                it->second.state = Http2StreamConcreteState::CLOSED; // Mark as closed
                process_complete_response_if_ready(it->second); // Dispatch whatever we have with an error
                it = _client_streams.erase(it); // Or use try_close_stream_context if events needed for each
            } else {
                ++it;
            }
        }
        for (auto it = _pending_pushed_streams.begin(); it != _pending_pushed_streams.end(); ) {
            if (it->first > goaway_event.payload.last_stream_id) {
                // LOG_WARN_PA("ClientHttp2Protocol", "[HTTP/2 Client] Pending PUSH stream " << it->first << " cancelled by GOAWAY.");
                // These streams were never fully "opened" to the app, so just remove.
                // No response to dispatch.
                it = _pending_pushed_streams.erase(it);
            } else {
                ++it;
            }
        }
        
        // Dispatch a general GOAWAY event to the IO_Handler
        if constexpr (has_method_on<IO_Handler, void, Http2GoAwayEvent>::value) {
            this->get_io_handler().on(Http2GoAwayEvent{goaway_event.payload.error_code, goaway_event.payload.last_stream_id, debug_data_str});
        }

        // The FramerBase::not_ok() should be called to signal the qb-io transport to close.
        // The GOAWAY itself implies the connection will close.
        // If error code is NO_ERROR, it's a graceful shutdown.
        if (goaway_event.payload.error_code != ErrorCode::NO_ERROR) {
            this->FramerBase::not_ok(goaway_event.payload.error_code);
        } else {
            // For graceful shutdown, we might wait for active streams to complete or set a timer.
            // For now, if graceful, just mark that we received it. The IO layer might have its own logic.
            // If no streams are active that are <= last_stream_id, we can close.
            if (are_all_relevant_streams_closed(goaway_event.payload.last_stream_id)) {
                // LOG_INFO_PA("ClientHttp2Protocol", "[HTTP/2 Client] Graceful GOAWAY received and all relevant streams are closed. Signaling connection closure.");
                this->FramerBase::not_ok(ErrorCode::NO_ERROR); // Signal a clean shutdown to the transport
            } else {
                 // LOG_INFO_PA("ClientHttp2Protocol", "[HTTP/2 Client] Graceful GOAWAY received, but some streams <= last_stream_id are still active. Waiting for them to complete.");
                _graceful_shutdown_initiated = true; // Protocol will check this later
            }
        }
    }

    // Called by FramerBase (Http2Protocol)
    void on(Http2FrameData<WindowUpdateFrame> wu_event) noexcept {
        LOG_HTTP_TRACE_PA(wu_event.header.get_stream_id(), "Client: Received WINDOW_UPDATE frame with increment " << wu_event.payload.window_size_increment);
        // LOG_DEBUG_PA("ClientHttp2Protocol", "[HTTP/2 Client] Received WINDOW_UPDATE frame on stream " << wu_event.header.get_stream_id()
        //           << " with increment " << wu_event.payload.window_size_increment);

        if (wu_event.payload.window_size_increment == 0) {
            LOG_HTTP_ERROR_PA(wu_event.header.get_stream_id(), "Client: WINDOW_UPDATE with 0 increment");
            if (wu_event.header.get_stream_id() == 0) {
                this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "WINDOW_UPDATE with 0 increment for connection.");
            } else {
                send_rst_stream(wu_event.header.get_stream_id(), ErrorCode::PROTOCOL_ERROR, "WINDOW_UPDATE with 0 increment for stream.");
            }
            return;
        }

        if (wu_event.header.get_stream_id() == 0) { // Connection-level window update
            if (_connection_send_window > MAX_WINDOW_SIZE_LIMIT - wu_event.payload.window_size_increment) {
                LOG_HTTP_ERROR_PA(0, "Client: Connection flow control window overflow. Current: " << _connection_send_window
                          << ", Increment: " << wu_event.payload.window_size_increment);
                this->send_goaway_and_close(ErrorCode::FLOW_CONTROL_ERROR, "Connection flow control window overflow.");
                return;
            }
            _connection_send_window += wu_event.payload.window_size_increment;
            // LOG_DEBUG_PA("ClientHttp2Protocol", "[HTTP/2 Client] Connection send window updated to " << _connection_send_window);

            // Try to send pending data on any stream that might have been blocked
            for (auto& pair : _client_streams) {
                if (pair.second.has_pending_data_to_send) {
                    try_send_pending_data_for_stream(pair.first, pair.second);
                }
            }
        } else { // Stream-level window update
            auto* stream_ptr = get_stream_by_id(wu_event.header.get_stream_id());
            if (!stream_ptr) {
                // LOG_WARN_PA("ClientHttp2Protocol", "[HTTP/2 Client] WINDOW_UPDATE for unknown or closed stream " << wu_event.header.get_stream_id());
                // As per RFC 9113, Section 6.9: WINDOW_UPDATE can be received for a stream in the "closed" state,
                // as frames might cross paths. It SHOULD NOT be considered an error.
                // For "half-closed (remote)" or "closed" state, it's fine.
                // If truly unknown (never existed or hard-closed long ago), it might be an issue, but spec says be tolerant.
                     return; 
                }
            Http2ClientStream& stream = *stream_ptr;

            if (stream.state == Http2StreamConcreteState::IDLE) {
                 // LOG_ERROR_PA("ClientHttp2Protocol", "[HTTP/2 Client] WINDOW_UPDATE for stream " << stream.id << " in IDLE state.");
                 // This is a connection error according to RFC 9113 Sec 6.9
                 this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "WINDOW_UPDATE for idle stream");
                    return;
                }
            
            if (stream.peer_window_size > MAX_WINDOW_SIZE_LIMIT - wu_event.payload.window_size_increment) {
                LOG_HTTP_ERROR_PA(stream.id, "Client: Stream flow control window overflow. Current: " << stream.peer_window_size
                          << ", Increment: " << wu_event.payload.window_size_increment);
                send_rst_stream(stream.id, ErrorCode::FLOW_CONTROL_ERROR, "Stream flow control window overflow");
                this->send_goaway_and_close(ErrorCode::FLOW_CONTROL_ERROR, "Stream window overflow lead to GOAWAY."); // Connection error
                return;
            }
            stream.peer_window_size += wu_event.payload.window_size_increment;
            // LOG_DEBUG_PA("ClientHttp2Protocol", "[HTTP/2 Client] Stream " << stream.id << " peer window updated to " << stream.peer_window_size);

            if (stream.has_pending_data_to_send) {
                try_send_pending_data_for_stream(stream.id, stream);
            }
        }
    }

    // Called by FramerBase (Http2Protocol)
    void on(Http2FrameData<PriorityFrame> priority_event) noexcept {
        if (!this->ok()) return;

        if (priority_event.header.get_stream_id() == 0) {
            send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "PRIORITY frame on stream 0");
                return;
            }
        // PRIORITY frames can be received for any stream state.
        // Store it in stream context if stream exists.
        auto it = _client_streams.find(priority_event.header.get_stream_id());
        if (it != _client_streams.end()) {
            it->second.priority_info = priority_event.payload.priority_data;
        }
        // No other action required by client for basic compliance. Actual reprioritization is optional.
    }

    /**
     * @brief Send an HTTP/2 request
     * @param http_request The HTTP request to send
     * @param app_request_id Application-specific request ID
     * @return true if request was successfully initiated, false on error
     */
    [[nodiscard]] bool send_request(qb::http::Request http_request, uint64_t app_request_id = 0) noexcept {
        LOG_HTTP_DEBUG_PA(0, "Client: send_request called for app_id " << app_request_id);
        
        if (!this->ok() || !_connection_active || _received_goaway) {
            LOG_HTTP_WARN_PA(0, "Client: Cannot send request. Protocol OK: " << this->ok() 
                             << ", Connection active: " << _connection_active 
                             << ", GOAWAY received: " << _received_goaway);
            return false;
        }

        if (get_active_stream_count(false) >= _peer_max_concurrent_streams) { 
            LOG_HTTP_WARN_PA(0, "Client: Cannot send request. Active streams: " << get_active_stream_count(false)
                             << ", Peer max: " << _peer_max_concurrent_streams);
            return false; 
        }

        uint32_t stream_id = _next_client_stream_id;
        _next_client_stream_id += 2;
        _last_initiated_stream_id = stream_id;
        
        LOG_HTTP_DEBUG_PA(stream_id, "Client: Initiating new request. Method: " << http_request.method() 
                          << ", URI: " << http_request.uri().source());

        // Create stream object first, but don't emplace it until after HEADERS are successfully sent.
        Http2ClientStream stream_obj(stream_id, 
                                   _initial_peer_window_size, 
                                   get_initial_window_size_from_settings());
        stream_obj.application_request_id = app_request_id;
        stream_obj.state = Http2StreamConcreteState::IDLE;

        std::vector<hpack::HeaderField> hf_vector;
        // Pass by const ref to prepare_request_headers as http_request will be moved later if needed.
        prepare_request_headers(http_request, hf_vector, stream_obj); 
        // stream_obj.client_will_send_trailers is set by prepare_request_headers

        LOG_HTTP_DEBUG_PA(stream_id, "Client: Prepared " << hf_vector.size() << " headers for encoding");

        std::vector<uint8_t> encoded_header_block;
        if (!_hpack_encoder || !_hpack_encoder->encode(hf_vector, encoded_header_block)) {
            LOG_HTTP_ERROR_PA(stream_id, "Client: HPACK encoding failed for new request headers");
            send_goaway_and_close(ErrorCode::INTERNAL_ERROR, "HPACK encoding failed for new request headers");
            return false;
        }

        LOG_HTTP_DEBUG_PA(stream_id, "Client: HPACK encoded " << hf_vector.size() 
                          << " headers into " << encoded_header_block.size() << " bytes");

        Http2FrameData<HeadersFrame> headers_frame_data; // Changed name
        headers_frame_data.header.type = static_cast<uint8_t>(FrameType::HEADERS);
        headers_frame_data.header.flags = FLAG_END_HEADERS;
        headers_frame_data.header.set_stream_id(stream_id);
        headers_frame_data.payload.header_block_fragment = std::move(encoded_header_block);

        const bool has_body = !http_request.body().empty();
        LOG_HTTP_DEBUG_PA(stream_id, "Client: Request has body: " << has_body 
                          << ", Will send trailers: " << stream_obj.client_will_send_trailers);

        if (!has_body && !stream_obj.client_will_send_trailers) {
            headers_frame_data.header.flags |= FLAG_END_STREAM;
            LOG_HTTP_DEBUG_PA(stream_id, "Client: Adding END_STREAM flag to HEADERS");
        }

        LOG_HTTP_DEBUG_PA(stream_id, "Client: Sending HEADERS frame");
        this->_io << headers_frame_data;
        if (!this->ok()) { 
            LOG_HTTP_ERROR_PA(stream_id, "Client: Failed to send HEADERS frame - protocol not OK");
            return false;
        }
        
        LOG_HTTP_DEBUG_PA(stream_id, "Client: HEADERS frame sent successfully");
        
        // HEADERS sent successfully, now update stream state and emplace it.
        stream_obj.request_sent = true; 
        stream_obj.state = Http2StreamConcreteState::OPEN;
        if (headers_frame_data.header.flags & FLAG_END_STREAM) {
            stream_obj.end_stream_sent = true;
            stream_obj.state = Http2StreamConcreteState::HALF_CLOSED_LOCAL;
            LOG_HTTP_DEBUG_PA(stream_id, "Client: Stream state set to HALF_CLOSED_LOCAL");
        } else {
            LOG_HTTP_DEBUG_PA(stream_id, "Client: Stream state set to OPEN");
        }

        // Store the original request if it has a body or if trailers will be sent.
        // The body will be consumed from stream_obj.original_request_to_send.
        if (has_body || stream_obj.client_will_send_trailers) {
            stream_obj.original_request_to_send = std::move(http_request); // Move the input request now
            stream_obj.send_buffer_offset = 0;
            stream_obj.has_pending_data_to_send = has_body;
            LOG_HTTP_DEBUG_PA(stream_id, "Client: Stored request for body/trailers sending");
        } else {
            stream_obj.has_pending_data_to_send = false;
            LOG_HTTP_DEBUG_PA(stream_id, "Client: No body or trailers to send");
            // http_request goes out of scope if not moved, its body potentially cleaned up.
        }
        
        auto [iter, emplaced] = _client_streams.emplace(stream_id, std::move(stream_obj));
        if (!emplaced) {
            // This should ideally not happen if stream ID generation is correct
            // QB_LOG_ERROR_PA(this->getName(), "Client: Failed to emplace stream context for new stream " << stream_id);
            LOG_HTTP_CRIT_PA(stream_id, "Client: Failed to emplace stream context for new stream after sending HEADERS.");
            send_rst_stream(stream_id, ErrorCode::INTERNAL_ERROR, "Stream context emplacement failed after sending HEADERS");
            return false;
        }
        Http2ClientStream& active_stream_ref = iter->second;

        // If there's a body to send, make the first attempt now.
        if (active_stream_ref.has_pending_data_to_send) { 
            if (!_send_request_body_data_internal(active_stream_ref)) {
                // Error occurred during initial body send (e.g., connection broke). 
                // _send_request_body_data_internal would have set has_pending_data_to_send if appropriate.
                // No need to remove stream from _client_streams here, error handling in on(IO) or subsequent calls will handle it.
                LOG_HTTP_ERROR_PA(active_stream_ref.id, "Client: _send_request_body_data_internal failed during initial send.");
                return false; 
            }
        }
        
        if (active_stream_ref.state == Http2StreamConcreteState::CLOSED) {
            try_close_stream_context_by_id(active_stream_ref.id, ErrorCode::NO_ERROR);
        }
        return true;
    }

    /**
     * @brief Send trailer headers for a request
     * @param stream_id Stream ID
     * @param trailers Trailer headers to send
     * @return true if trailers were sent, false on error
     */
    [[nodiscard]] bool send_request_trailers(uint32_t stream_id, const qb::http::headers& trailers) {
        auto* stream_ptr = get_stream_by_id(stream_id);
        if (!stream_ptr || stream_ptr->end_stream_sent) {
            return false;
        }
        Http2ClientStream& stream = *stream_ptr;

        if (!stream.client_will_send_trailers) {
            send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Trailers not announced");
            return false;
        }

        // Validate trailers
        std::vector<hpack::HeaderField> trailer_fields;
        for (const auto& header_item : trailers.headers()) {
            if (header_item.first.empty() || header_item.first[0] == ':') {
                send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Invalid trailer field name");
                return false;
            }
            
            // Check for forbidden headers in trailers
            std::string name_lower = header_item.first;
            std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
            
            static const std::array<std::string_view, 7> forbidden_headers = {
                "host", "content-length", "transfer-encoding", "connection", 
                "proxy-connection", "keep-alive", "upgrade"
            };
            
            bool is_forbidden = false;
            for (const auto& forbidden : forbidden_headers) {
                if (name_lower == forbidden) {
                    is_forbidden = true;
                    break;
                }
            }
            
            if (is_forbidden) {
                send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, 
                              "Forbidden header in trailers: " + header_item.first);
                return false;
            }
            
            trailer_fields.emplace_back(header_item.first, header_item.second);
        }

        // Encode trailers
        std::vector<uint8_t> encoded_trailers;
        if (!_hpack_encoder->encode(trailer_fields, encoded_trailers)) {
            send_rst_stream(stream.id, ErrorCode::COMPRESSION_ERROR, "HPACK encoding failed for trailers");
            return false;
        }

        // Send trailers as HEADERS frame with END_STREAM
        Http2FrameData<HeadersFrame> trailers_frame;
        trailers_frame.header.type = static_cast<uint8_t>(FrameType::HEADERS);
        trailers_frame.header.flags = FLAG_END_HEADERS | FLAG_END_STREAM;
        trailers_frame.header.set_stream_id(stream_id);
        trailers_frame.payload.header_block_fragment = std::move(encoded_trailers);

        this->_io << trailers_frame;
        stream.end_stream_sent = true;

        // Update stream state
        if (stream.state == Http2StreamConcreteState::OPEN) {
            stream.state = Http2StreamConcreteState::HALF_CLOSED_LOCAL;
        } else if (stream.state == Http2StreamConcreteState::HALF_CLOSED_REMOTE) {
            stream.state = Http2StreamConcreteState::CLOSED;
        }

        if (stream.state == Http2StreamConcreteState::CLOSED) {
            try_close_stream_context_by_id(stream.id, ErrorCode::NO_ERROR);
        }

        return true;
    }

    /**
     * @brief Get reference to I/O handler
     * @return Reference to I/O handler
     */
    [[nodiscard]] IO_Handler& get_io_handler() noexcept {
        return this->_io;
    }

    /**
     * @brief Get reference to I/O handler (const version)
     * @return Const reference to I/O handler
     */
    [[nodiscard]] const IO_Handler& get_io_handler() const noexcept {
        return this->_io;
    }

    /**
     * @brief Send HTTP/2 connection preface
     * 
     * The client must send the HTTP/2 connection preface immediately after
     * the TLS handshake completes and before sending any HTTP/2 frames.
     * The preface is: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
     */
    void send_connection_preface() noexcept {
        LOG_HTTP_DEBUG_PA(0, "Client: Sending HTTP/2 connection preface");
        
        // Send the raw preface bytes directly to the transport
        this->_io.out() << HTTP2_CONNECTION_PREFACE;
        
        LOG_HTTP_DEBUG_PA(0, "Client: HTTP/2 connection preface sent (" << HTTP2_CONNECTION_PREFACE.size() << " bytes)");

        // After sending its own preface, the client expects to receive frames from the server (e.g., SETTINGS).
        // Transition the parser state to expect a frame header.
        this->_current_state = FramerBase::ParserState::EXPECTING_FRAME_HEADER;
        LOG_HTTP_DEBUG_PA(0, "Client: State transitioned to EXPECTING_FRAME_HEADER after sending own preface.");

        // Manually trigger the logic that should occur after the client's preface has been sent.
        // This includes sending our initial SETTINGS frame and, if in single request mode, the request itself.
        // This effectively replaces the base class's mechanism of calling on(PrefaceCompleteEvent)
        // which was based on the client *receiving* a preface (which it doesn't).
        this->on(qb::protocol::http2::PrefaceCompleteEvent{});
    }

private:
    /**
     * @brief Initialize our max frame size setting
     * @return Max frame size value
     */
    [[nodiscard]] uint32_t initialize_our_max_frame_size() {
        this->initialize_our_settings_map();
        return this->get_setting_value_or_default(
            Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 
            DEFAULT_SETTINGS_MAX_FRAME_SIZE);
    }

    /**
     * @brief Initialize our settings map with default values
     */
    void initialize_our_settings_map() {
        _our_settings[Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE] = 4096;
        _our_settings[Http2SettingIdentifier::SETTINGS_ENABLE_PUSH] = 0;
        _our_settings[Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE] = 65535;
        _our_settings[Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE] = 16384;
    }

    /**
     * @brief Get initial window size from settings
     * @return Initial window size
     */
    [[nodiscard]] uint32_t get_initial_window_size_from_settings() const noexcept {
        return get_setting_value_or_default(
            Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 
            DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE);
    }

    /**
     * @brief Get setting value or default
     * @param id Setting identifier
     * @param default_val Default value if setting not found
     * @return Setting value
     */
    [[nodiscard]] uint32_t get_setting_value_or_default(Http2SettingIdentifier id, 
                                                       uint32_t default_val) const noexcept {
        auto it = _our_settings.find(id);
        if (it != _our_settings.end()) {
            return it->second;
        }
        return default_val;
    }

    /**
     * @brief Clear header assembly state
     */
    void clear_header_assembly_state() noexcept {
        _current_header_block_fragment.clear();
        _active_header_block_stream_id = 0;
    }

    /**
     * @brief Check if all relevant streams are closed
     * @param last_peer_stream_id Last peer stream ID
     * @return true if all streams are closed
     */
    [[nodiscard]] bool are_all_relevant_streams_closed(uint32_t last_peer_stream_id) const noexcept {
        for (const auto& [stream_id, stream] : _client_streams) {
            if (stream_id % 2 == 0 && stream_id <= last_peer_stream_id) {
                if (stream.state != Http2StreamConcreteState::CLOSED && 
                    !stream.rst_stream_sent && !stream.rst_stream_received) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * @brief Try to close stream context
     * @param stream_ref Stream reference
     * @param reason Error code
     * @param message Optional error message
     */
    void try_close_stream_context(Http2ClientStream& stream_ref, 
                                ErrorCode reason = ErrorCode::NO_ERROR, 
                                const std::string& message = "") {
        auto it = _client_streams.find(stream_ref.id);
        if (it != _client_streams.end() && 
            (it->second.state == Http2StreamConcreteState::CLOSED || 
             it->second.rst_stream_sent || it->second.rst_stream_received)) {
            _client_streams.erase(it);
        }
    }

    /**
     * @brief Try to close stream context by ID
     * @param stream_id_param Stream ID
     * @param reason Error code
     * @param message Optional error message
     */
    void try_close_stream_context_by_id(uint32_t stream_id_param, 
                                ErrorCode reason = ErrorCode::NO_ERROR, 
                                const std::string& message = "") {
        auto* stream_ptr = get_stream_by_id(stream_id_param);
        if (stream_ptr) {
            try_close_stream_context(*stream_ptr, reason, message);
        }
    }

    /**
     * @brief Handle DATA frame for unknown stream
     * @param stream_id Stream ID
     * @param data_payload_size Data payload size
     */
    void handle_data_for_unknown_stream(uint32_t stream_id, uint32_t data_payload_size) {
        if (stream_id % 2 == 0) {
            // Even stream ID - could be server push
            auto it = _pending_pushed_streams.find(stream_id);
            if (it != _pending_pushed_streams.end()) {
                send_rst_stream(stream_id, ErrorCode::PROTOCOL_ERROR, 
                              "DATA before HEADERS on pushed stream");
                _pending_pushed_streams.erase(it);
            } else {
                send_rst_stream(stream_id, ErrorCode::STREAM_CLOSED, 
                              "DATA for unknown pushed stream");
            }
        } else {
            // Odd stream ID - client-initiated
            send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, 
                                "DATA for unknown client stream");
        }

        // Update connection window
        _connection_receive_window -= data_payload_size;
        _connection_processed_bytes_for_window_update += data_payload_size;
        conditionally_send_connection_window_update();
    }

    /**
     * @brief Handle DATA frame for closed stream
     * @param stream Stream reference
     * @param data_payload_size Data payload size
     */
    void handle_data_for_closed_stream(Http2ClientStream& stream, uint32_t data_payload_size) {
        if (stream.id > 0 && stream.id <= _last_initiated_stream_id) {
            send_goaway_and_close(ErrorCode::STREAM_CLOSED, 
                                "DATA for closed stream");
        } else {
            // Ignore DATA for streams we haven't initiated yet
        }

        // Update windows
        _connection_receive_window -= data_payload_size;
        _connection_processed_bytes_for_window_update += data_payload_size;
        stream.local_window_size -= data_payload_size;
        stream.processed_bytes_for_window_update += data_payload_size;

        if (stream.processed_bytes_for_window_update >= stream.window_update_threshold && 
            stream.window_update_threshold > 0) {
            uint32_t increment = stream.processed_bytes_for_window_update;
            send_window_update(stream.id, increment);
            stream.local_window_size += increment;
            stream.processed_bytes_for_window_update = 0;
        }

        conditionally_send_connection_window_update();
    }

    /**
     * @brief Prepare request headers for HPACK encoding
     * @param http_request The HTTP request
     * @param out_hf_vector Output vector for header fields
     * @param stream_context Stream context
     */
    void prepare_request_headers(const qb::http::Request& http_request, 
                               std::vector<hpack::HeaderField>& out_hf_vector, 
                               Http2ClientStream& stream_context) {
        // Add pseudo-headers first (required order)
        out_hf_vector.emplace_back(":method", http_request.method());
        
        // Determine scheme
        std::string scheme = "https"; // Default
        const auto& uri = http_request.uri();
        if (!uri.scheme().empty()) {
            scheme = std::string(uri.scheme());
        }
        out_hf_vector.emplace_back(":scheme", scheme);
        
        // Add :authority header
        std::string authority;
        if (!uri.host().empty()) {
            authority = std::string(uri.host());
            if (!uri.port().empty()) {
                authority += ":" + std::string(uri.port());
            }
        } else if (http_request.has_header("host")) {
            authority = http_request.header("host");
        }
        
        if (!authority.empty()) {
            out_hf_vector.emplace_back(":authority", authority);
        }
        
        // Add :path header
        std::string path = "/"; // Default
        if (!uri.path().empty()) {
            path = std::string(uri.path());
        }
        if (!uri.encoded_queries().empty()) {
            path += "?" + std::string(uri.encoded_queries());
        }
        out_hf_vector.emplace_back(":path", path);
        
        // Add regular headers
        for (const auto& header : http_request.headers()) {
            const std::string& name = header.first;
            for (const auto& value : header.second) {
            
            // Skip connection-specific headers
            std::string name_lower = name;
            std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
            
            static const std::array<std::string_view, 8> forbidden_headers = {
                "connection", "proxy-connection", "keep-alive", "transfer-encoding", 
                "upgrade", "host", "te", "content-length"
            };
            
            bool skip = false;
            for (const auto& forbidden : forbidden_headers) {
                if (name_lower == forbidden) {
                    if (name_lower == "te" && value == TE_TRAILERS_VALUE) {
                        // TE: trailers is allowed
                    } else if (name_lower == "host") {
                        // Host header is converted to :authority
                        skip = true;
                    } else {
                        skip = true;
                    }
                    break;
                }
            }
            
            if (!skip) {
                out_hf_vector.emplace_back(name, value);
            }
            
            // Check for trailer announcement
            if (name_lower == "trailer") {
                stream_context.client_will_send_trailers = true;
                // Parse the value of the "Trailer" header to get the names of the expected trailer fields
                // The "Trailer" header value is a comma-separated list of field names.
                std::string trailer_header_value_str;
                if (!value.empty()) { // value is std::string from http_request.headers() iter
                    trailer_header_value_str = value;
                }
                // qb::http::utility::split_and_trim_header_list expects std::string_view
                auto trailer_names = qb::http::utility::split_and_trim_header_list(std::string_view(trailer_header_value_str), ',');
                for (const auto& trailer_name : trailer_names) {
                    if (!trailer_name.empty()) { // Ensure no empty names from parsing
                        stream_context._expected_trailer_names.push_back(trailer_name);
                    }
                }
            }
            }
        }
        
        // Add content-length if body is present and not using trailers
        if (!http_request.body().empty() && !stream_context.client_will_send_trailers) {
            out_hf_vector.emplace_back("content-length", 
                                     std::to_string(http_request.body().raw().size()));
        }
    }

    bool _send_request_body_data_internal(Http2ClientStream& active_stream) noexcept { 
        // Check if there is actually a body to send from the stored original request
        if (!active_stream.has_pending_data_to_send || active_stream.original_request_to_send.body().empty()) {
            active_stream.has_pending_data_to_send = false; 
            return true; // Nothing to send, or body is empty
        }

        const auto& body_pipe = active_stream.original_request_to_send.body().raw();
        size_t body_size = body_pipe.size();
        const char* body_data_ptr = body_pipe.data();

        // active_stream.send_buffer_offset tracks progress within body_pipe

        while(active_stream.send_buffer_offset < body_size) {
            if (!this->ok() || !_connection_active) { 
                // Connection issue, data remains pending, offset is preserved.
                active_stream.has_pending_data_to_send = (active_stream.send_buffer_offset < body_size);
                return false; // Indicate connection/protocol error
            }

            int64_t connection_can_send = _connection_send_window; 
            int64_t stream_can_send = active_stream.peer_window_size; 

            if (connection_can_send <= 0 || stream_can_send <= 0) {
                // Flow control blocked, data remains pending, offset is preserved.
                active_stream.has_pending_data_to_send = (active_stream.send_buffer_offset < body_size);
                return true; // Indicate flow control block, not a protocol error from this function's perspective
            }

            size_t max_frame_payload_size = this->get_peer_max_frame_size(); 
            size_t remaining_body_to_send = body_size - active_stream.send_buffer_offset;
            
            size_t chunk_size = std::min({
                remaining_body_to_send, 
                max_frame_payload_size, 
                static_cast<size_t>(connection_can_send), 
                static_cast<size_t>(stream_can_send)
            });

            if (chunk_size == 0 && remaining_body_to_send > 0) { 
                // Still effectively blocked by calculated chunk_size being zero.
                active_stream.has_pending_data_to_send = true;
                return true; 
            }
            if (chunk_size == 0 && remaining_body_to_send == 0) { // Should imply offset == body_size
                 break; // All body data sent
            }

            Http2FrameData<DataFrame> data_frame;
            data_frame.header.type = static_cast<uint8_t>(FrameType::DATA); 
            data_frame.header.flags = 0; // No PADDED flag by default
            data_frame.header.set_stream_id(active_stream.id); 

            // Populate payload directly with data chunk
            data_frame.payload.data_payload.assign(body_data_ptr + active_stream.send_buffer_offset, 
                                                     body_data_ptr + active_stream.send_buffer_offset + chunk_size);
            
            active_stream.send_buffer_offset += chunk_size; 

            if (active_stream.send_buffer_offset == body_size && !active_stream.client_will_send_trailers) { 
                data_frame.header.flags |= FLAG_END_STREAM;
            }
            
            this->_io << data_frame;
            if (!this->ok()) { 
                active_stream.send_buffer_offset -= chunk_size; 
                active_stream.has_pending_data_to_send = true;
                return false; 
            }

            // Decrement flow control windows by actual data chunk size
            _connection_send_window -= chunk_size; 
            active_stream.peer_window_size -= chunk_size; 
            
            if (data_frame.header.flags & FLAG_END_STREAM) {
                active_stream.end_stream_sent = true;
                if (active_stream.state == Http2StreamConcreteState::OPEN) {
                     active_stream.state = Http2StreamConcreteState::HALF_CLOSED_LOCAL;
                } else if (active_stream.state == Http2StreamConcreteState::HALF_CLOSED_REMOTE) {
                    active_stream.state = Http2StreamConcreteState::CLOSED;
                }
            }
        } // end while loop for sending data

        // After the loop, update has_pending_data_to_send based on whether all data was processed.
        active_stream.has_pending_data_to_send = (active_stream.send_buffer_offset < body_size);
        return true; // Return true if operations were successful or gracefully blocked by flow control
    }

    // Returns true if processed successfully, false if an error occurred and was handled (RST/GOAWAY)
    bool process_complete_header_block(Http2ClientStream& stream, bool is_trailers_block) {
        if (!this->ok()) return false;

        std::vector<hpack::HeaderField> decoded_fields;
        bool is_hpack_incomplete = false; 

        if (!_hpack_decoder || !_hpack_decoder->decode(_current_header_block_fragment, decoded_fields, is_hpack_incomplete)) {
            send_rst_stream(stream.id, ErrorCode::COMPRESSION_ERROR, "HPACK decode failed for response headers/trailers");
            return false;
        }

        if (is_hpack_incomplete) {
            send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Incomplete HPACK block despite END_HEADERS");
            return false;
        }

        std::optional<std::string> status_str_opt;
        qb::http::THeaders<std::string> temp_headers_for_validation; // Used for validation logic before modifying response

        for (const auto& hf : decoded_fields) {
            const std::string& name = hf.name;
            const std::string& value = hf.value;

            if (name.empty()) {
                send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Empty header field name received");
                return false;
            }

            if (is_trailers_block) {
                if (name[0] == ':') {
                    send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Pseudo-header received in trailers"); return false;
                }
            } else { // Main response headers
                if (name == ":status") {
                    if (status_str_opt) { 
                        send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Duplicate :status pseudo-header"); return false;
                    }
                    status_str_opt = value;
                } else if (name.length() > 0 && name[0] == ':') { 
                    if (name == ":method" || name == ":scheme" || name == ":path" || name == ":authority") {
                        send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Invalid request pseudo-header in response"); return false;
                    }
                }
            }
            
            static const std::array<std::string_view, 5> forbidden_h = {"connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade"};
            std::string name_lower = name;
            std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
            for(const auto& forbidden_header_sv : forbidden_h) {
                if (name_lower == forbidden_header_sv) {
                    send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Forbidden connection-specific header: " + name); return false;
                }
            }
            temp_headers_for_validation.add_header(name, value); // Add to temp THeaders for validation consistency if needed by THeaders itself
        }

        if (!is_trailers_block) {
            if (!status_str_opt) {
                send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Missing :status in response headers"); return false;
            }
            int status_code_val = 0;
            try {
                status_code_val = std::stoi(status_str_opt.value());
            } catch (const std::exception&) {
                send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Invalid :status value in response"); return false;
            }
            
            if (status_code_val >= 100 && status_code_val < 200) {
                if (status_code_val == 101) { 
                     send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "101 Switching Protocols not supported mid-HTTP/2 stream"); return false;
                }
                if (stream.end_stream_received) { 
                    send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "1xx response with END_STREAM on HEADERS"); return false;
                }
            }
            {
                qb::http::Body current_body = std::move(stream.assembled_response.body()); 
                stream.assembled_response.reset(); 
                stream.assembled_response.status() = status_code_val;
                for (const auto& hf : decoded_fields) { // Iterate original decoded fields directly
                    if (hf.name == ":status" && !is_trailers_block) continue; // :status is set via setStatus, not as a regular header
                    stream.assembled_response.add_header(hf.name, hf.value);
                }
                stream.assembled_response.body() = std::move(current_body); 
            }
        } else { // Trailers
             for (const auto& hf : decoded_fields) {
                stream.assembled_response.add_header(hf.name, hf.value); 
            }
        }
        return true;
    }

    void dispatch_complete_response(uint32_t stream_id, Http2ClientStream& stream) {
        if (stream.response_dispatched || stream.rst_stream_sent || stream.rst_stream_received) {
            return; // Already dispatched, or stream was reset (error already dispatched or will be).
        }

        if (this->ok() && _connection_active) {
            // Ensure response status is not 0 unless it's an informational one (which this path shouldn't hit for final dispatch)
            if (stream.assembled_response.status().code() == 0 && !(stream.assembled_response.status().code() >=100 && stream.assembled_response.status().code() < 200) ) {
                // This would be an internal logic error, trying to dispatch an uninitialized response.
                // Or server sent invalid response not caught earlier.
                send_rst_stream(stream_id, ErrorCode::INTERNAL_ERROR, "Attempt to dispatch incomplete response");
            return;
        }

            // Final check for HEAD method: ensure body is empty if we auto-stripped it.
            // The qb::http::Response itself should handle body constraints for HEAD if it was set.
            // Here, we just dispatch what we assembled.
            stream.assembled_response.parse_set_cookie_headers();
            this->_io.on(std::move(stream.assembled_response), stream.application_request_id);
            stream.response_dispatched = true;
        }

        // If stream is now fully closed, try to clean up its context.
        // This might be redundant if try_close_stream_context is called from state transition points.
        if (stream.state == Http2StreamConcreteState::CLOSED) {
            try_close_stream_context_by_id(stream.id, ErrorCode::NO_ERROR);
        }
    }

    void try_close_stream_context(uint32_t stream_id) noexcept {
        auto it = _client_streams.find(stream_id);
        if (it == _client_streams.end()) {
            return; // Already removed or never existed
        }

            Http2ClientStream& stream = it->second;
            
        // More robust check for stream closure based on HTTP/2 state transitions
        bool can_close = false;
        if (stream.state == Http2StreamConcreteState::CLOSED) {
            can_close = true;
        } else if (stream.rst_stream_sent || stream.rst_stream_received) {
            can_close = true;
        } else if (stream.end_stream_sent && stream.end_stream_received) {
            // Both sides have finished sending
            can_close = true;
        }


        if (can_close) {
            // LOG_DEBUG_PA("ClientHttp2Protocol", "[HTTP/2 Client] Closing stream context for stream ID: " << stream_id);
            // Notify IO_Handler about stream closure before erasing.
            // This allows the application to clean up its own state related to the stream.
            if constexpr (has_method_on<IO_Handler, void, Http2StreamErrorEvent>::value) {
                // Re-evaluate if Http2StreamErrorEvent is the right event for graceful closure.
                // Perhaps a new event like Http2StreamClosedEvent. For now, using existing.
                // If rst_stream_sent or rst_stream_received, stream.error_code would be set.
                // If not, NO_ERROR is appropriate for graceful closure.
                ErrorCode final_error_code = stream.error_code;
                if (stream.rst_stream_sent && stream.error_code == ErrorCode::NO_ERROR) {
                     final_error_code = ErrorCode::CANCEL; // Example if we sent RST due to local cancellation
                } else if (stream.rst_stream_received && stream.error_code == ErrorCode::NO_ERROR) {
                    // If peer sent RST, it should have included an error code.
                    // If error_code is still NO_ERROR, it might be a bug or a very specific scenario.
                    // For now, assume stream.error_code is correctly populated from RST_STREAM frame.
                }

                this->get_io_handler().on(Http2StreamErrorEvent{stream_id, final_error_code, "Stream closed"});
            }
            _client_streams.erase(it);
            // LOG_DEBUG_PA("ClientHttp2Protocol", "[HTTP/2 Client] Stream " << stream_id << " context erased. Count: " << _client_streams.size());
        } else {
            // LOG_DEBUG_PA("ClientHttp2Protocol", "[HTTP/2 Client] Stream " << stream_id << " not yet fully closed. State: "
            // << static_cast<int>(stream.state) << ", end_sent: " << stream.end_stream_sent
            // << ", end_recv: " << stream.end_stream_received
            // << ", rst_sent: " << stream.rst_stream_sent
            // << ", rst_recv: " << stream.rst_stream_received);
        }
    }

    /**
     * @brief Send RST_STREAM frame
     * @param stream_id Stream ID
     * @param error_code Error code
     * @param debug_message Optional debug message
     */
    void send_rst_stream(uint32_t stream_id, ErrorCode error_code, 
                        const std::string& debug_message = "") noexcept {
        if (!this->ok() || stream_id == 0) return;

        Http2FrameData<RstStreamFrame> rst_frame;
        rst_frame.header.type = static_cast<uint8_t>(FrameType::RST_STREAM);
        rst_frame.header.flags = 0;
        rst_frame.header.set_stream_id(stream_id);
        rst_frame.payload.error_code = error_code;

        this->_io << rst_frame;

        // Mark stream as RST sent
        auto it = _client_streams.find(stream_id);
        if (it != _client_streams.end()) {
            it->second.rst_stream_sent = true;
            it->second.error_code = error_code;
            // Notify IO_Handler if response wasn't already dispatched
            if (!it->second.response_dispatched) {
                Http2StreamErrorEvent stream_error_event{stream_id, error_code, "RST_STREAM sent by client: " + debug_message};
                // Check if IO_Handler has the 'on' method for this event type
                if constexpr (has_method_on<IO_Handler, void, Http2StreamErrorEvent>::value) {
                    this->get_io_handler().on(stream_error_event);
                }
            }
            // Attempt to close stream context after marking RST and potentially notifying
            try_close_stream_context(it->second, error_code);
        }
    }

    /**
     * @brief Send GOAWAY frame and close connection
     * @param error_code Error code
     * @param debug_message Debug message
     */
    void send_goaway_and_close(ErrorCode error_code, const std::string& debug_message) noexcept {
        if (!this->ok()) return; // Don't send if protocol already not ok

        LOG_HTTP_WARN_PA(0, "Client: Sending GOAWAY frame. Error: " << static_cast<int>(error_code) << ", Message: " << debug_message);

        uint32_t last_stream_id_to_report = 0; // Default to 0 if no streams
        // Determine the maximum stream ID initiated by this client that might have been processed by the server.
        // If we are initiating GOAWAY, it usually means we won't process further *new* incoming streams.
        // The last_stream_id in GOAWAY indicates the highest stream ID for which this endpoint *might* have taken action.
        // For client sending GOAWAY, it's often the highest stream ID it has *initiated*.
        if (!_client_streams.empty()) {
             last_stream_id_to_report = _last_initiated_stream_id;
        }


        Http2FrameData<GoAwayFrame> goaway_frame;
        goaway_frame.header.type = static_cast<uint8_t>(FrameType::GOAWAY);
        goaway_frame.header.flags = 0;
        goaway_frame.header.set_stream_id(0);
        goaway_frame.payload.last_stream_id = last_stream_id_to_report;
        goaway_frame.payload.error_code = error_code;
        
        if (!debug_message.empty()) {
            goaway_frame.payload.additional_debug_data.assign(
                debug_message.begin(), debug_message.end());
        }

        this->_io << goaway_frame;
        
        _connection_active = false; // Connection is being shut down
        _graceful_shutdown_initiated = true; // Mark that we've started shutdown

        // Notify IO_Handler about sending GOAWAY
        if constexpr (has_method_on<IO_Handler, void, Http2GoAwayEvent>::value) {
            Http2GoAwayEvent goaway_event_to_dispatch{error_code, last_stream_id_to_report, "GOAWAY sent by client: " + debug_message};
            this->get_io_handler().on(goaway_event_to_dispatch);
        }
        
        this->FramerBase::not_ok(error_code); // Signal base protocol and underlying transport to close
    }

    /**
     * @brief Send WINDOW_UPDATE frame
     * @param stream_id Stream ID (0 for connection)
     * @param increment Window increment
     */
    void send_window_update(uint32_t stream_id, uint32_t increment) noexcept {
        if (!this->ok() || increment == 0 || increment > 0x7FFFFFFF) return;

        Http2FrameData<WindowUpdateFrame> wu_frame;
        wu_frame.header.type = static_cast<uint8_t>(FrameType::WINDOW_UPDATE);
        wu_frame.header.flags = 0;
        wu_frame.header.set_stream_id(stream_id);
        wu_frame.payload.window_size_increment = increment;

        this->_io << wu_frame;
    }

    /**
     * @brief Conditionally send connection-level WINDOW_UPDATE
     */
    void conditionally_send_connection_window_update() noexcept {
        const int64_t threshold = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE / CONNECTION_WINDOW_THRESHOLD_DIVISOR;
        
        if (_connection_processed_bytes_for_window_update >= threshold) {
            uint32_t increment = static_cast<uint32_t>(_connection_processed_bytes_for_window_update);
            send_window_update(0, increment);
            _connection_receive_window += increment;
            _connection_processed_bytes_for_window_update = 0;
        }
    }

    /**
     * @brief Update initial peer window size setting
     * @param new_size New window size
     */
    void update_initial_peer_window_size(uint32_t new_size) noexcept {
        int32_t delta = static_cast<int32_t>(new_size) - static_cast<int32_t>(_initial_peer_window_size);
        _initial_peer_window_size = new_size;

        // Update all stream windows
        if (delta != 0) {
            for (auto& [stream_id, stream] : _client_streams) {
                if (stream_id % 2 != 0) { // Client-initiated streams
                    int64_t old_stream_peer_window = stream.peer_window_size;
                    stream.peer_window_size += delta;
                    
                    if (stream.peer_window_size > MAX_WINDOW_SIZE_LIMIT) {
                        send_goaway_and_close(ErrorCode::FLOW_CONTROL_ERROR, 
                            "SETTINGS_INITIAL_WINDOW_SIZE change caused stream window to exceed limit");
                        return; 
                    }

                    if (old_stream_peer_window <= 0 && stream.peer_window_size > 0 && 
                        stream.has_pending_data_to_send) {
                        try_send_pending_data_for_stream(stream.id, stream);
                    }
                }
            }
        }
    }
    
    /**
     * @brief Handle framer-detected errors
     * @param reason Error code
     * @param message Error message
     * @param stream_id_context Stream ID context (0 for connection errors)
     */
    void handle_framer_detected_error(ErrorCode reason, const std::string& message, 
                                    uint32_t stream_id_context) noexcept {
        if (!_connection_active && this->ok()) {
            this->not_ok(reason);
            return;
        }
        if (!this->ok()) return;

        if (stream_id_context != 0) {
            auto it = _client_streams.find(stream_id_context);
            if (it != _client_streams.end()) {
                send_rst_stream(stream_id_context, reason, "Framer detected error: " + message);
                if (reason != ErrorCode::FRAME_SIZE_ERROR && reason != ErrorCode::PROTOCOL_ERROR) {
                    send_goaway_and_close(reason, 
                        "Framer detected error (escalated to connection): " + message);
                }
            } else {
                send_goaway_and_close(reason, 
                    "Framer detected error (unknown stream context or general): " + message);
            }
        } else {
            send_goaway_and_close(reason, "Framer detected connection error: " + message);
        }
    }

    /**
     * @brief Handle stream-level error
     * 
     * CRTP implementation to handle stream errors properly
     * 
     * @param stream_id Stream ID
     * @param error_code Error code
     * @param debug_message Error description
     */
    void on_stream_error(uint32_t stream_id, ErrorCode error_code, const std::string& debug_message) noexcept {
        // Send RST_STREAM for the specific stream
        this->send_rst_stream(stream_id, error_code, debug_message);
    }

    /**
     * @brief Handle connection-level error
     * 
     * CRTP implementation to handle connection errors properly
     * 
     * @param error_code Error code
     * @param debug_message Error description
     */
    void on_connection_error(ErrorCode error_code, const std::string& debug_message) noexcept {
        // Send GOAWAY and close the connection
        this->send_goaway_and_close(error_code, debug_message);
    }

    /**
     * @brief Get stream by ID
     * @param stream_id Stream ID
     * @return Pointer to stream or nullptr if not found
     */
    [[nodiscard]] Http2ClientStream* get_stream_by_id(uint32_t stream_id) noexcept {
        auto it = _client_streams.find(stream_id);
        if (it == _client_streams.end()) {
            return nullptr;
        }
        return &it->second;
    }

    /**
     * @brief Get stream by ID (const version)
     * @param stream_id Stream ID
     * @return Const pointer to stream or nullptr if not found
     */
    [[nodiscard]] const Http2ClientStream* get_stream_by_id(uint32_t stream_id) const noexcept {
        auto it = _client_streams.find(stream_id);
        if (it == _client_streams.end()) {
            return nullptr;
        }
        return &it->second;
    }

    /**
     * @brief Process and dispatch complete response
     * @param stream Stream reference
     */
    void process_complete_response_if_ready(Http2ClientStream& stream) {
        LOG_HTTP_TRACE_PA(stream.id, "Client: Checking if response is ready for dispatch");
        
        if (stream.response_dispatched) {
            LOG_HTTP_TRACE_PA(stream.id, "Client: Response already dispatched");
            return;
        }

        // Check if response is complete
        bool main_headers_ok = stream.headers_received_main;
        bool stream_terminated_by_peer = stream.end_stream_received || stream.rst_stream_received;

        if (!main_headers_ok) {
            return;
        }
        
        if (!stream_terminated_by_peer) {
            return;
        }

        if (stream.trailers_expected && !stream.trailers_received && !stream.rst_stream_received) {
            return;
        }

        // Response is complete - dispatch it
        stream.response_dispatched = true;
        stream.assembled_response.parse_set_cookie_headers();
        if (stream.rst_stream_received) {
            // Dispatch error response
            if constexpr (has_method_on<IO_Handler, void, qb::http::Response, uint64_t, ErrorCode>::value) {
                this->get_io_handler().on(std::move(stream.assembled_response), 
                                        stream.application_request_id, stream.error_code);
            } else if constexpr (has_method_on<IO_Handler, void, qb::http::Response, uint64_t>::value) {
                this->get_io_handler().on(std::move(stream.assembled_response), 
                                        stream.application_request_id);
            }
        } else {
            // Dispatch successful response
            if constexpr (has_method_on<IO_Handler, void, qb::http::Response, uint64_t, ErrorCode>::value) {
                this->get_io_handler().on(std::move(stream.assembled_response), 
                                        stream.application_request_id, ErrorCode::NO_ERROR);
            } else if constexpr (has_method_on<IO_Handler, void, qb::http::Response, uint64_t>::value) {
                this->get_io_handler().on(std::move(stream.assembled_response), 
                                        stream.application_request_id);
            }
        }
        
        // Update stream state
        if (stream.end_stream_sent && stream.end_stream_received) {
            stream.state = Http2StreamConcreteState::CLOSED;
        } else if (stream.end_stream_received) {
            stream.state = Http2StreamConcreteState::HALF_CLOSED_REMOTE;
        }
        
        try_close_stream_context_by_id(stream.id);
    }

    /**
     * @brief Process incoming headers
     * @param stream Stream reference
     * @param headers_event Headers frame event
     */
    void process_incoming_headers(Http2ClientStream& stream, 
                                const Http2FrameData<HeadersFrame>& headers_event) {
        if (stream.end_stream_received && !stream.trailers_expected) {
            send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "HEADERS after END_STREAM without trailers");
            return;
        }
        
        if (stream.headers_received_main && !stream.trailers_expected) {
            send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Multiple HEADERS frames not as trailers");
            return;
        }

        if (stream.expecting_continuation) {
            send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "HEADERS while expecting CONTINUATION");
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "HEADERS while expecting CONTINUATION.");
            return;
        }

        _active_header_block_stream_id = stream.id;
        _current_header_block_fragment.insert(_current_header_block_fragment.end(),
                                            headers_event.payload.header_block_fragment.begin(),
                                            headers_event.payload.header_block_fragment.end());

        if (headers_event.header.flags & FLAG_END_HEADERS) {
            std::vector<hpack::HeaderField> decoded_fields;
            bool hpack_incomplete = false;
            
            if (!_hpack_decoder->decode(_current_header_block_fragment, decoded_fields, hpack_incomplete)) {
                send_rst_stream(stream.id, ErrorCode::COMPRESSION_ERROR, "HPACK decoding failed");
                this->send_goaway_and_close(ErrorCode::COMPRESSION_ERROR, "HPACK decoding error.");
                clear_header_assembly_state();
                return;
            }
            
            if (hpack_incomplete) {
                send_rst_stream(stream.id, ErrorCode::COMPRESSION_ERROR, "HPACK incomplete decoding");
                this->send_goaway_and_close(ErrorCode::COMPRESSION_ERROR, "HPACK incomplete decoding.");
                clear_header_assembly_state();
                return;
            }
            
            clear_header_assembly_state();

            bool is_trailers_block = stream.headers_received_main;
            if (!parse_and_validate_headers_into_response(stream, decoded_fields, is_trailers_block)) {
                return;
            }

            if (is_trailers_block) {
                stream.trailers_received = true;
            } else {
                stream.headers_received_main = true;
                // Check for trailer header
                if (!(headers_event.header.flags & FLAG_END_STREAM)) {
                    for (const auto& hf : decoded_fields) {
                        if (hf.name == "trailer" || hf.name == "Trailer") {
                            stream.trailers_expected = true;
                            break;
                        }
                    }
                }
            }
            
            // Update stream state
            if (stream.state == Http2StreamConcreteState::IDLE && stream.id != 0) {
                stream.state = Http2StreamConcreteState::OPEN;
            } else if (stream.state == Http2StreamConcreteState::RESERVED_REMOTE) {
                stream.state = Http2StreamConcreteState::OPEN;
            }

        } else {
            stream.expecting_continuation = true;
        }

        if (headers_event.header.flags & FLAG_END_STREAM) {
            stream.end_stream_received = true;
            
            if (!stream.headers_received_main && (headers_event.header.flags & FLAG_END_HEADERS)) {
                stream.headers_received_main = true;
            }

            if (stream.trailers_expected && !stream.trailers_received && 
                (headers_event.header.flags & FLAG_END_HEADERS)) {
                stream.trailers_received = true;
            }
            
            if (stream.end_stream_sent) {
                stream.state = Http2StreamConcreteState::CLOSED;
            } else {
                if (stream.state == Http2StreamConcreteState::OPEN) {
                    stream.state = Http2StreamConcreteState::HALF_CLOSED_REMOTE;
                }
            }
        }
        
        process_complete_response_if_ready(stream);
    }

    /**
     * @brief Parse and validate headers into response
     * @param stream Stream reference
     * @param decoded_fields Decoded header fields
     * @param is_trailers_block Whether this is a trailers block
     * @return true if parsing succeeded, false on error
     */
    [[nodiscard]] bool parse_and_validate_headers_into_response(
        Http2ClientStream& stream, 
        const std::vector<hpack::HeaderField>& decoded_fields, 
        bool is_trailers_block) {
        
        qb::http::Response& response = stream.assembled_response;
        std::string status_str;

        // Validation flags
        bool pseudo_headers_ended = false;
        bool regular_headers_started = false;
        std::optional<std::string> method_from_connect_response;

        for (const auto& hf : decoded_fields) {
            if (hf.name.empty()) {
                send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Empty header name");
                return false;
            }

            // Check for uppercase letters in header names (except pseudo-headers)
            if (hf.name[0] != ':') {
                for (char c : hf.name) {
                    if (c >= 'A' && c <= 'Z') {
                        send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, 
                                      "Uppercase in header name: " + hf.name);
                        return false;
                    }
                }
            }
            
            // Check for invalid characters in header values
            for (char c_val : hf.value) {
                if ((c_val >= 0 && c_val < 0x20 && c_val != '\t') || c_val == 0x7F) {
                    send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, 
                                  "Invalid char in header value: " + hf.name);
                    return false;
                }
            }

            if (hf.name[0] == ':') { // Pseudo-header
                if (is_trailers_block) {
                    send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, 
                                  "Pseudo-header in trailers: " + hf.name);
                    return false;
                }
                if (regular_headers_started) {
                    send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, 
                                  "Pseudo-header after regular: " + hf.name);
                    return false;
                }

                if (hf.name == ":status") {
                    if (!status_str.empty()) {
                        send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Duplicate :status header");
                        return false;
                    }
                    if (hf.value.length() != 3) {
                        send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, 
                                      "Invalid :status length: " + hf.value);
                        return false;
                    }
                    for (char sc : hf.value) { 
                        if (!isdigit(sc)) { 
                            send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Non-digit in :status");
                            return false;
                        }
                    }
                    status_str = hf.value;
                } else if (hf.name == ":method" && stream.method == "CONNECT") {
                    method_from_connect_response = hf.value;
                } else if (hf.name == ":scheme" || hf.name == ":authority" || hf.name == ":path") {
                    response.add_header(std::string(hf.name), std::string(hf.value));
                } else {
                    response.add_header(std::string(hf.name), std::string(hf.value));
                }
            } else { // Regular header
                pseudo_headers_ended = true;
                regular_headers_started = true;

                // Check for forbidden headers
                static const std::array<std::string_view, 7> forbidden_headers = {
                    "connection", "proxy-connection", "keep-alive", "transfer-encoding", 
                    "upgrade", "host", "te"
                };
                
                std::string name_lower = hf.name;
                std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);

                bool is_forbidden = false;
                for (const auto& forbidden_header_sv : forbidden_headers) {
                    if (name_lower == forbidden_header_sv) {
                        if (name_lower == "te" && hf.value == TE_TRAILERS_VALUE) {
                            // TE: trailers is allowed
                        } else {
                            is_forbidden = true;
                            break;
                        }
                    }
                }

                if (is_forbidden) {
                    send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, 
                                  "Forbidden connection-specific header: " + hf.name);
                    return false;
                }
                
                response.add_header(std::string(hf.name), std::string(hf.value));
            }
        }

        if (!is_trailers_block) {
            if (status_str.empty()) {
                send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Missing :status header");
                return false;
            }
            
            try {
                int status_code = std::stoi(status_str);
                response.status() = status_code;
                
                // Validate CONNECT responses
                if (stream.method == "CONNECT" && (status_code >= 200 && status_code < 300)) {
                    if (method_from_connect_response.has_value() ||
                        response.headers().has(":scheme") || 
                        response.headers().has(":authority") || 
                        response.headers().has(":path")) {
                        send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, 
                                      "Invalid pseudo-headers in 2xx CONNECT response");
                        return false;
                    }
                }

            } catch (const std::exception&) {
                send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, 
                              "Invalid :status value: " + status_str);
                return false;
            }
        }
        
        return true;
    }

    // This method is called when a WINDOW_UPDATE is received or to resume sending.
    void try_send_pending_data_for_stream(uint32_t stream_id_param, Http2ClientStream& active_stream) noexcept {
        if (!this->ok() || !_connection_active) {
            // QB_LOG_WARN_PA(this->getName(), "Client Stream " << stream_id_param << ": try_send_pending_data called but connection not OK or inactive.");
            return;
        }

        if (active_stream.state != Http2StreamConcreteState::OPEN && 
            active_stream.state != Http2StreamConcreteState::HALF_CLOSED_LOCAL) {
            // QB_LOG_DEBUG_PA(this->getName(), "Client Stream " << stream_id_param << ": try_send_pending_data called but stream not in OPEN or HALF_CLOSED_LOCAL state. State: " << static_cast<int>(active_stream.state));
            return; // Can only send data/trailers in these states
        }

        // Attempt to send pending body data first
        if (active_stream.has_pending_data_to_send) {
            // QB_LOG_DEBUG_PA(this->getName(), "Client Stream " << stream_id_param << ": Resuming send for pending body data.");
            if (!this->_send_request_body_data_internal(active_stream)) {
                // A connection/protocol error occurred during body send.
                if (active_stream.state == Http2StreamConcreteState::CLOSED) { // Check if _send_request_body_data_internal closed it
                     try_close_stream_context_by_id(active_stream.id, ErrorCode::STREAM_CLOSED, "DATA in invalid state for stream."); // Pass stream.id
                }
                return;
            }
            if (active_stream.has_pending_data_to_send) {
                // QB_LOG_DEBUG_PA(this->getName(), "Client Stream " << stream_id_param << ": Body data still pending after try_send_body_data_internal (flow control). Offset: " << active_stream.send_buffer_offset);
                return; // Still blocked by flow control for body
            }
        }

        // If we reach here, all body data (if any) has been successfully sent from original_request_to_send.body(),
        // or there was no body data pending initially (has_pending_data_to_send is false).
        // Now, check if trailers need to be sent.
        if (active_stream.client_will_send_trailers && !active_stream.end_stream_sent) {
            // QB_LOG_DEBUG_PA(this->getName(), "Client Stream " << active_stream.id << ": Body fully sent or no body to send, proceeding to send trailers.");
            
            std::vector<hpack::HeaderField> trailer_fields_to_send; 

            if (!active_stream._expected_trailer_names.empty()) {
                // QB_LOG_DEBUG_PA(this->getName(), "Client Stream " << active_stream.id << ": Preparing " << active_stream._expected_trailer_names.size() << " expected trailer fields.");
                for (const std::string& trailer_name_str : active_stream._expected_trailer_names) {
                    if (trailer_name_str.empty() || trailer_name_str[0] == ':') {
                        // QB_LOG_WARN_PA(this->getName(), "Client Stream " << active_stream.id << ": Pseudo-header or empty name '" << trailer_name_str << "' listed in Trailer, ignoring for trailer section.");
                        continue;
                    }

                    const auto& header_map = active_stream.original_request_to_send.headers(); 
                    auto it_header_values = header_map.find(trailer_name_str);

                    if (it_header_values != header_map.end()) {
                        for (const auto& value_type : it_header_values->second) { 
                            std::string value_std_str;
                            using OriginalReqStringType = typename qb::http::Request::string_type;

                            if constexpr (std::is_same_v<OriginalReqStringType, std::string_view>) {
                                value_std_str.assign(value_type.data(), value_type.length());
                            } else { 
                                value_std_str = value_type; 
                            }
                            trailer_fields_to_send.emplace_back(trailer_name_str, value_std_str);
                        }
                    } else {
                        // QB_LOG_WARN_PA(this->getName(), "Client Stream " << active_stream.id << ": Trailer field '" << trailer_name_str << "' listed in Trailer header but not found in original request headers.");
                    }
                }
            } else if (active_stream.client_will_send_trailers) {
                 // QB_LOG_DEBUG_PA(this->getName(), "Client Stream " << active_stream.id << ": 'Trailer' header was present but listed no specific fields (or all were invalid). Sending empty trailer block.");
            }

            Http2FrameData<HeadersFrame> trailers_frame_data;
            trailers_frame_data.header.type = static_cast<uint8_t>(FrameType::HEADERS);
            trailers_frame_data.header.flags = FLAG_END_HEADERS | FLAG_END_STREAM; 
            trailers_frame_data.header.set_stream_id(active_stream.id);

            if (!trailer_fields_to_send.empty()) { 
                if (!(_hpack_encoder && _hpack_encoder->encode(trailer_fields_to_send, trailers_frame_data.payload.header_block_fragment))) {
                    // QB_LOG_ERROR_PA(this->getName(), "Client Stream " << active_stream.id << ": HPACK encoding failed for trailers.");
                    send_rst_stream(active_stream.id, ErrorCode::COMPRESSION_ERROR, "HPACK encoding failed for trailers");
                     if (active_stream.state == Http2StreamConcreteState::CLOSED || active_stream.rst_stream_sent) {
                        try_close_stream_context_by_id(active_stream.id, ErrorCode::COMPRESSION_ERROR, "DATA in invalid state for stream."); // Pass stream.id
                    }
                    return; 
                }
            } 

            this->_io << trailers_frame_data;
            if (this->ok()) {
                active_stream.end_stream_sent = true;
                if (active_stream.state == Http2StreamConcreteState::OPEN || active_stream.state == Http2StreamConcreteState::HALF_CLOSED_LOCAL) { 
                    active_stream.state = Http2StreamConcreteState::HALF_CLOSED_LOCAL;
                } else if (active_stream.state == Http2StreamConcreteState::HALF_CLOSED_REMOTE) {
                    active_stream.state = Http2StreamConcreteState::CLOSED;
                }
                active_stream.client_will_send_trailers = false; 
                // QB_LOG_DEBUG_PA(this->getName(), "Client Stream " << active_stream.id << ": Trailers sent with END_STREAM. State: " << static_cast<int>(active_stream.state) );
            } else {
                // QB_LOG_ERROR_PA(this->getName(), "Client Stream " << active_stream.id << ": Send failed for trailers frame.");
                if (active_stream.client_will_send_trailers) { 
                    active_stream.has_pending_data_to_send = true; 
                }
            }
        }

        if (active_stream.state == Http2StreamConcreteState::CLOSED) {
            try_close_stream_context_by_id(active_stream.id, active_stream.error_code, "Stream closed"); // Pass stream.id
        }
    }

    /**
     * @brief Get the count of active streams.
     * @param server_initiated_check If true, counts even-numbered (pushed) streams.
     *                               If false, counts odd-numbered (client-initiated) streams.
     * @return Number of active streams matching the criteria.
     */
    [[nodiscard]] uint32_t get_active_stream_count(bool server_initiated_check) const noexcept {
        uint32_t count = 0;
        for (const auto& [stream_id, stream_obj] : _client_streams) {
            if (stream_obj.state != Http2StreamConcreteState::IDLE && 
                stream_obj.state != Http2StreamConcreteState::CLOSED &&
                !stream_obj.rst_stream_sent && 
                !stream_obj.rst_stream_received) {
                if (server_initiated_check) { // Count server-initiated (even) streams
                    if (stream_id % 2 == 0) {
                        count++;
                    }
                } else { // Count client-initiated (odd) streams
                    if (stream_id % 2 != 0) {
                        count++;
                    }
                }
            }
        }
        // Also consider _pending_pushed_streams if they count towards a limit before full activation
        // For client checking MAX_CONCURRENT_STREAMS from server (for pushes), active + pending reserved pushes matter.
        if (server_initiated_check) {
            // The _pending_pushed_streams are already accounted for when they are moved to _client_streams in RESERVED_REMOTE state.
            // So, iterating _client_streams with state != IDLE/CLOSED is sufficient.
        }
        return count;
    }

    /**
     * @brief Try to close stream context by stream ID
     * @param stream_id_param Stream ID
     * @param reason Error code
     * @param message Optional error message
     */

    /**
     * @brief Handle PING frame
     * @param ping_event PING frame data
     */
    void on(Http2FrameData<PingFrame> ping_event) noexcept {
        // If this is a PING request (ACK flag not set), send PING response
        if (!(ping_event.header.flags & 0x01)) { // ACK flag is bit 0
            Http2FrameData<PingFrame> ping_response;
            ping_response.header.type = static_cast<uint8_t>(FrameType::PING);
            ping_response.header.flags = 0x01; // ACK flag
            ping_response.header.set_stream_id(0);
            ping_response.payload.opaque_data = ping_event.payload.opaque_data;
            
            this->_io << ping_response;
        }
        // If this is a PING response (ACK flag set), we can ignore it or handle it
        // For now, we just ignore PING responses
    }

}; // class ClientHttp2Protocol

} // namespace qb::protocol::http2