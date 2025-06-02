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
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http2
 */

#pragma once

#include "./base.h" // For qb::protocol::http2::Http2Protocol and frame types


namespace qb::http::well_known {
    constexpr std::string_view COLON_METHOD_SV = ":method";
    constexpr std::string_view COLON_PATH_SV = ":path";
    constexpr std::string_view COLON_SCHEME_SV = ":scheme";
    constexpr std::string_view COLON_AUTHORITY_SV = ":authority";
    constexpr std::string_view CONTENT_LENGTH_SV = "content-length";
    constexpr std::string_view TRANSFER_ENCODING_SV = "transfer-encoding";
    constexpr std::string_view TRAILER_SV = "trailer";
    
    /**
     * @brief Check if a header is hop-by-hop
     * @param header_name Header name to check
     * @return true if header is hop-by-hop
     */
    inline bool is_hop_by_hop(const std::string& header_name) {
        // Convert to lowercase for comparison
        std::string lower_name = header_name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
        
        return lower_name == "connection" ||
               lower_name == "keep-alive" ||
               lower_name == "proxy-authenticate" ||
               lower_name == "proxy-authorization" ||
               lower_name == "te" ||
               lower_name == "trailers" ||
               lower_name == "transfer-encoding" ||
               lower_name == "upgrade";
    }
}

namespace qb::protocol::http2 {

// Constants for readability
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
template<typename IO_Handler>
class ServerHttp2Protocol : public Http2Protocol<IO_Handler, ServerHttp2Protocol<IO_Handler>> {
public:
    using FramerBase = Http2Protocol<IO_Handler, ServerHttp2Protocol<IO_Handler>>;
    friend class qb::protocol::http2::Http2Protocol<IO_Handler, ServerHttp2Protocol<IO_Handler>>; 

private:
    qb::unordered_map<uint32_t, Http2ServerStream> _server_streams;      ///< Active stream contexts
    uint32_t _last_client_initiated_stream_id = 0;                       ///< Last valid client stream ID
    uint32_t _next_server_initiated_stream_id = 2;                       ///< Next server stream ID (for PUSH)

    std::vector<uint8_t> _current_header_block_fragment;                 ///< Header block assembly buffer
    uint32_t _current_header_stream_id = 0;                              ///< Stream ID for header assembly

    int64_t _connection_send_window;                                     ///< Connection-level send window
    int64_t _connection_receive_window = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;  ///< Connection-level receive window
    static constexpr int CONNECTION_WINDOW_THRESHOLD_DIVISOR = 2;

    // Peer (Client) Settings
    uint32_t _initial_peer_window_size = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;     ///< Client's initial window size
    uint32_t _peer_max_concurrent_streams = DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS; ///< Max concurrent streams from client
    uint64_t _peer_max_header_list_size = DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE;   ///< Max header list size client accepts
    bool _peer_allows_push = true;                                                   ///< Whether client allows server push

    // Our Settings
    qb::unordered_map<Http2SettingIdentifier, uint32_t> _our_settings;   ///< Server's HTTP/2 settings
    bool _initial_settings_sent = false;                                  ///< Whether initial SETTINGS sent

    bool _connection_active = true;                                       ///< Connection active flag
    bool _graceful_shutdown_initiated = false;                            ///< Graceful shutdown flag

    std::unique_ptr<qb::protocol::hpack::Decoder> _hpack_decoder;        ///< HPACK decoder instance
    std::unique_ptr<qb::protocol::hpack::Encoder> _hpack_encoder;        ///< HPACK encoder instance

    int64_t _connection_bytes_consumed_since_last_window_update = 0;     ///< Bytes consumed for window update

    // Add as a private member to ServerHttp2Protocol class
    // private:
    //    bool _debug_send_padded_data = false; // Set to true to test sending padded DATA frames

public:
    /**
     * @brief Construct HTTP/2 server protocol handler
     * @param io_handler_ref Reference to IO handler that receives requests
     */
    explicit ServerHttp2Protocol(IO_Handler& io_handler_ref)
        : FramerBase(io_handler_ref),
          _hpack_decoder(std::make_unique<qb::protocol::hpack::HpackDecoderImpl>()),
          _hpack_encoder(std::make_unique<qb::protocol::hpack::HpackEncoderImpl>())
    {
        LOG_HTTP_DEBUG("ServerHttp2Protocol: Constructing HTTP/2 server protocol handler");
        this->_our_max_frame_size = this->initialize_our_max_frame_size();
        _connection_send_window = this->get_initial_window_size_from_settings();
        
        // Apply HPACK encoder settings based on _our_settings
        auto it_table_size = _our_settings.find(Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE);
        if (it_table_size != _our_settings.end() && _hpack_encoder) {
            _hpack_encoder->set_max_capacity(it_table_size->second);
            LOG_HTTP_DEBUG("ServerHttp2Protocol: HPACK encoder max capacity set to " << it_table_size->second);
        }
        
        this->reset();
        LOG_HTTP_INFO("ServerHttp2Protocol: HTTP/2 server protocol handler constructed successfully");
    }

    ~ServerHttp2Protocol() override = default;

    // Disable copy and move
    ServerHttp2Protocol(const ServerHttp2Protocol&) = delete;
    ServerHttp2Protocol& operator=(const ServerHttp2Protocol&) = delete;
    ServerHttp2Protocol(ServerHttp2Protocol&&) = delete;
    ServerHttp2Protocol& operator=(ServerHttp2Protocol&&) = delete;

    /**
     * @brief Reset protocol state to initial conditions
     */
    void reset() noexcept override {
        LOG_HTTP_DEBUG("ServerHttp2Protocol: Resetting protocol state to initial conditions");
        FramerBase::reset(); // Call base class reset first

        _server_streams.clear();
        _current_header_block_fragment.clear();
        _current_header_stream_id = 0;
        _last_client_initiated_stream_id = 0;
        _next_server_initiated_stream_id = 2;
        _connection_active = true;
        _graceful_shutdown_initiated = false;
        _initial_settings_sent = false;

        // Re-initialize our settings and derived values
        this->initialize_our_settings_map();

        _connection_send_window = this->get_initial_window_size_from_settings();
        _connection_receive_window = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;

        _initial_peer_window_size = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;
        FramerBase::set_peer_max_frame_size(DEFAULT_SETTINGS_MAX_FRAME_SIZE);
        _peer_max_concurrent_streams = DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS;
        _peer_max_header_list_size = DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE;
        _peer_allows_push = true;

        if (_hpack_decoder) _hpack_decoder->reset();
        if (_hpack_encoder) {
            _hpack_encoder->reset();
            auto it_table_size = _our_settings.find(Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE);
            if (it_table_size != _our_settings.end()) {
                _hpack_encoder->set_max_capacity(it_table_size->second);
            }
        }
        LOG_HTTP_INFO("ServerHttp2Protocol: Protocol state reset completed");
    }

    /**
     * @brief Handle preface complete event
     * @param event Preface complete event
     */
    void on(qb::protocol::http2::PrefaceCompleteEvent /*event*/) {
        LOG_HTTP_DEBUG("ServerHttp2Protocol: Received preface complete event");
        if (!this->ok() || !_connection_active) {
            LOG_HTTP_WARN("ServerHttp2Protocol: Cannot process preface complete - protocol not OK or connection inactive");
            return;
        }
        
        if (!_initial_settings_sent) {
            LOG_HTTP_DEBUG("Server: Sending initial SETTINGS frame");
            Http2FrameData<SettingsFrame> settings_frame_data;
            settings_frame_data.header.type = static_cast<uint8_t>(FrameType::SETTINGS);
            settings_frame_data.header.flags = 0;
            settings_frame_data.header.set_stream_id(0);

            for(const auto& setting_pair : _our_settings) {
                settings_frame_data.payload.entries.push_back({setting_pair.first, setting_pair.second});
            }

            this->_io << settings_frame_data;
            _initial_settings_sent = true;
            LOG_HTTP_DEBUG("Server: Initial SETTINGS frame sent successfully");
        }
    }

    /**
     * @brief Handle DATA frame
     * @param data_event DATA frame event
     */
    void on(Http2FrameData<DataFrame> data_event) noexcept {
        if (!this->ok() || !_connection_active) return;

        const FrameHeader& header = data_event.header;
        uint32_t stream_id = header.get_stream_id();
        std::size_t data_payload_size = data_event.payload.data_payload.size();

        LOG_HTTP_TRACE_PA(stream_id, "Server: Received DATA frame, size: " << data_payload_size << ", flags: " << (int)header.flags);

        if (stream_id == 0) {
            LOG_HTTP_ERROR_PA(stream_id, "Server: DATA frame received on stream 0.");
            this->on_connection_error(ErrorCode::PROTOCOL_ERROR, "DATA frame received on stream 0.");
            return;
        }
        
        if (static_cast<int64_t>(data_payload_size) > this->_connection_receive_window && data_payload_size > 0) { // allow empty data frames if window is 0
            this->on_connection_error(ErrorCode::FLOW_CONTROL_ERROR, "Connection flow control window underflow on data frame.");
            return;
        }


        auto it = _server_streams.find(stream_id);
        if (it == _server_streams.end()) {
            this->_connection_receive_window -= data_payload_size;
            this->conditionally_send_connection_window_update();
            return;
        }

        Http2ServerStream& stream = it->second;

        if (stream.state == Http2StreamConcreteState::IDLE || stream.state == Http2StreamConcreteState::CLOSED || stream.rst_stream_sent || stream.rst_stream_received) {
             this->_connection_receive_window -= data_payload_size; 
             this->conditionally_send_connection_window_update();
            if (stream.state == Http2StreamConcreteState::IDLE){
                 this->send_rst_stream(stream_id, ErrorCode::STREAM_CLOSED, "DATA frame on IDLE stream.");
            }
            return;
        }
        if (stream.end_stream_received) { 
            //this->send_rst_stream(stream_id, ErrorCode::STREAM_CLOSED, "DATA frame received after END_STREAM.");
            this->send_rst_stream(stream_id, ErrorCode::STREAM_CLOSED, "DATA frame received after END_STREAM.");
             this->_connection_receive_window -= data_payload_size; 
             this->conditionally_send_connection_window_update();
            return;
        }


        if (static_cast<int64_t>(data_payload_size) > stream.local_window_size && data_payload_size > 0) {
            this->send_rst_stream(stream_id, ErrorCode::FLOW_CONTROL_ERROR, "Stream flow control window exceeded.");
            this->_connection_receive_window -= data_payload_size; 
            this->conditionally_send_connection_window_update();
            return;
        }
        
        this->_connection_receive_window -= data_payload_size;

        stream.local_window_size -= data_payload_size;
        
        auto& body_pipe = stream.assembled_request.body().raw();
        body_pipe.put(reinterpret_cast<const char*>(data_event.payload.data_payload.data()), data_event.payload.data_payload.size());


        if (header.flags & FLAG_END_STREAM) {
            stream.end_stream_received = true;
            if (stream.headers_received_main) { 
                this->dispatch_complete_request(stream_id, stream);
            }
             // If END_STREAM also means end of connection for this stream, update state.
            if (stream.end_stream_sent) { // If we also sent END_STREAM
                stream.state = Http2StreamConcreteState::CLOSED;
                this->try_close_stream_context(stream_id);
            } else {
                stream.state = Http2StreamConcreteState::HALF_CLOSED_REMOTE;
            }
        }
        
        // Send WINDOW_UPDATE for stream if necessary
        stream.processed_bytes_for_window_update += data_payload_size;
        if (stream.processed_bytes_for_window_update >= stream.window_update_threshold && stream.window_update_threshold > 0) { // only if threshold > 0
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
    void on(Http2FrameData<HeadersFrame> headers_event) noexcept {
        if (!this->ok() || !_connection_active) return;

        const FrameHeader& header = headers_event.header;
        const uint32_t stream_id = header.get_stream_id();
        const bool end_stream = (header.flags & FLAG_END_STREAM) != 0;
        const bool end_headers = (header.flags & FLAG_END_HEADERS) != 0;

        LOG_HTTP_TRACE_PA(stream_id, "Server: Received HEADERS frame, flags: " << (int)header.flags);

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

        Http2ServerStream* stream_ptr = nullptr;
        auto it = _server_streams.find(stream_id);

        if (it == _server_streams.end()) {
            if (stream_id <= _last_client_initiated_stream_id) {
                this->send_rst_stream(stream_id, ErrorCode::STREAM_CLOSED, "HEADERS for old/closed stream");
                return;
            }
            if (_graceful_shutdown_initiated) {
                 this->send_rst_stream(stream_id, ErrorCode::REFUSED_STREAM, "New stream during graceful shutdown");
                return;
            }
            uint32_t active_client_streams = 0;
            for (const auto& pair : _server_streams) {
                if (pair.first % 2 != 0) { 
                    const auto& s = pair.second;
                    if (s.state == Http2StreamConcreteState::OPEN ||
                        s.state == Http2StreamConcreteState::HALF_CLOSED_LOCAL || 
                        s.state == Http2StreamConcreteState::HALF_CLOSED_REMOTE) { 
                        active_client_streams++;
                    }
                }
            }
            uint32_t max_concurrent_from_us = this->get_setting_value_or_default(Http2SettingIdentifier::SETTINGS_MAX_CONCURRENT_STREAMS, DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS);
            if (active_client_streams >= max_concurrent_from_us) {
                LOG_HTTP_WARN_PA(stream_id, "Server: Refused new stream. Max concurrent streams limit reached: " << max_concurrent_from_us);
                this->send_rst_stream(stream_id, ErrorCode::REFUSED_STREAM, "Exceeded MAX_CONCURRENT_STREAMS limit");
                return;
            }

            LOG_HTTP_DEBUG_PA(stream_id, "Server: Creating new stream for client request");
            Http2ServerStream new_stream(stream_id, _initial_peer_window_size, this->get_initial_window_size_from_settings());
            auto emp_res = _server_streams.emplace(stream_id, std::move(new_stream));
            stream_ptr = &emp_res.first->second;
            _last_client_initiated_stream_id = std::max(_last_client_initiated_stream_id, stream_id);
        } else {
            stream_ptr = &it->second;
        }
        Http2ServerStream& stream = *stream_ptr;

        if (stream.expecting_continuation) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, 
                "New HEADERS frame received for stream " + std::to_string(stream_id) + 
                " while previous header block for this stream was incomplete.");
            this->clear_header_assembly_state(); 
            return;
        }

        if (stream.state == Http2StreamConcreteState::CLOSED || stream.rst_stream_received || stream.rst_stream_sent) {
            return;
        }
        if (stream.state == Http2StreamConcreteState::HALF_CLOSED_REMOTE && !stream.trailers_expected) {
            this->send_rst_stream(stream_id, ErrorCode::PROTOCOL_ERROR, "Unexpected HEADERS frame after client sent END_STREAM (no trailers expected)");
            return;
        }
        bool is_current_block_trailers = stream.headers_received_main;

        if (_current_header_stream_id != 0 && _current_header_stream_id != stream_id) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "Interleaved HEADERS/CONTINUATION frames for different streams");
            return;
        }
        _current_header_stream_id = stream_id;

        _current_header_block_fragment.insert(_current_header_block_fragment.end(),
                                            headers_event.payload.header_block_fragment.begin(),
                                            headers_event.payload.header_block_fragment.end());
        
        if (stream.state == Http2StreamConcreteState::IDLE) { 
            stream.state = Http2StreamConcreteState::OPEN;
        }

        if (end_headers && end_stream) { // Uses the correctly initialized local const booleans
            stream.end_stream_received = true;
            if (stream.state == Http2StreamConcreteState::OPEN) {
                stream.state = Http2StreamConcreteState::HALF_CLOSED_REMOTE;
            } else if (stream.state == Http2StreamConcreteState::HALF_CLOSED_LOCAL) {
                stream.state = Http2StreamConcreteState::CLOSED;
            }
        }

        if (end_headers) { // Uses the correctly initialized local const boolean
            stream.expecting_continuation = false;
            if (!this->process_complete_header_block(stream, is_current_block_trailers)) {
                // Error handled
            } else {
                if (stream.state == Http2StreamConcreteState::CLOSED) {
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
    void on(Http2FrameData<ContinuationFrame> continuation_event) noexcept {
        if (!this->ok() || !_connection_active) return;

        const FrameHeader& header = continuation_event.header;
        const uint32_t stream_id = header.get_stream_id();
        const bool end_headers = header.flags & FLAG_END_HEADERS;

        if (stream_id == 0 || _current_header_stream_id == 0 || stream_id != _current_header_stream_id) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "CONTINUATION frame error (no prior HEADERS or wrong stream_id)");
            this->clear_header_assembly_state(); // Clear any partial state
            return;
        }

        auto it = _server_streams.find(stream_id);
        if (it == _server_streams.end()) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "CONTINUATION for unknown stream (internal state error or stream closed mid-sequence)");
            this->clear_header_assembly_state();
            return;
        }
        Http2ServerStream& stream = it->second;

        if (!stream.expecting_continuation) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "Unexpected CONTINUATION frame");
            this->clear_header_assembly_state();
            return;
        }

        _current_header_block_fragment.insert(_current_header_block_fragment.end(),
                                            continuation_event.payload.header_block_fragment.begin(),
                                            continuation_event.payload.header_block_fragment.end());

        if (end_headers) {
            stream.expecting_continuation = false;
            bool is_current_block_trailers = stream.headers_received_main;

            if (!this->process_complete_header_block(stream, is_current_block_trailers)) {
                // Error handled by process_complete_header_block
            } else {
                if (is_current_block_trailers) {
                    stream.trailers_received = true;
                    stream.trailers_expected = false;
                }
                // stream.headers_received_main would have been set by initial HEADERS.

                // State change depends on END_STREAM from *original* HEADERS frame
                if (stream.end_stream_received) { // True if original HEADERS had END_STREAM
                    if (stream.state == Http2StreamConcreteState::OPEN) {
                stream.state = Http2StreamConcreteState::HALF_CLOSED_REMOTE;
            } else if (stream.state == Http2StreamConcreteState::HALF_CLOSED_LOCAL) {
                stream.state = Http2StreamConcreteState::CLOSED;
                    }
                }

                if (stream.state == Http2StreamConcreteState::CLOSED) {
                    this->dispatch_complete_request(stream_id, stream);
                    this->try_close_stream_context(stream_id);
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
    void on(Http2FrameData<SettingsFrame> settings_event) noexcept {
        if (!this->ok() || !_connection_active) return;

        const FrameHeader& header = settings_event.header;

        LOG_HTTP_TRACE_PA(header.get_stream_id(), "Server: Received SETTINGS frame, flags: " << (int)header.flags);
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
        for (const auto& setting_entry : settings_event.payload.entries) {
            Http2SettingIdentifier id = setting_entry.identifier;
            uint32_t value = setting_entry.value;
            
            // Validate setting using centralized helper
            auto validation_result = SettingsHelper::validate_setting(id, value, true); // true = from client
            if (!validation_result.is_valid) {
                this->send_goaway_and_close(validation_result.error_code, validation_result.error_message);
                return;
            }

            // Apply validated setting
            switch(id) {
                case Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE:
                    // Client informs us the max table size its decoder supports for headers we send.
                    // Our encoder must respect this.
                    if (_hpack_encoder) _hpack_encoder->set_peer_max_dynamic_table_size(value);
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
                    LOG_HTTP_TRACE_PA(0, "Server: Ignoring unknown setting ID " 
                                     << static_cast<uint16_t>(id) << " from client.");
                    break;
            }
        }

        // Send SETTINGS ACK using centralized frame sending
        Http2FrameData<SettingsFrame> ack_frame;
        ack_frame.header.type = static_cast<uint8_t>(FrameType::SETTINGS);
        ack_frame.header.flags = FLAG_ACK;
        ack_frame.header.set_stream_id(0);
        this->_io << ack_frame;
        LOG_HTTP_DEBUG_PA(0, "Server: Processed SETTINGS frame from client. Sending ACK.");
    }

    /**
     * @brief Handle RST_STREAM frame
     * @param rst_event RST_STREAM frame event
     */
    void on(Http2FrameData<RstStreamFrame> rst_event) noexcept {
        if (!this->ok() || !_connection_active) return;

        const uint32_t stream_id = rst_event.header.get_stream_id();
        const ErrorCode error_code = rst_event.payload.error_code;

        if (stream_id == 0) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "RST_STREAM frame on stream 0");
            return;
        }

        auto it = _server_streams.find(stream_id);
        if (it != _server_streams.end()) {
            Http2ServerStream& stream = it->second;
            stream.rst_stream_received = true;
            stream.error_code = error_code;
            stream.state = Http2StreamConcreteState::CLOSED;

            // Notify application if request wasn't dispatched or response wasn't fully sent by us yet.
            if ((!stream.request_dispatched || !stream.end_stream_sent) && stream.error_code != ErrorCode::NO_ERROR) { // Check stream.error_code as rst_stream_received is now true
                Http2StreamErrorEvent stream_error_event{stream_id, error_code, "RST_STREAM received from client"};
                this->_io.on(stream_error_event);
            }
            this->try_close_stream_context(stream_id);
        }
        // If stream not found, RST is for an unknown/already closed stream. Can be ignored.
    }

    /**
     * @brief Handle PUSH_PROMISE frame (error case for server)
     * @param pp_event PUSH_PROMISE frame event
     */
    void on(Http2FrameData<PushPromiseFrame> /*pp_event*/) noexcept {
        // Server should not receive PUSH_PROMISE from client.
        this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "Server received PUSH_PROMISE frame from client");
    }

    /**
     * @brief Handle GOAWAY frame
     * @param goaway_event GOAWAY frame event
     */
    void on(Http2FrameData<GoAwayFrame> goaway_event) noexcept {
        if (!this->ok() && _graceful_shutdown_initiated) return; // Already processing a GOAWAY or shutting down

        const std::string debug_data_str(goaway_event.payload.additional_debug_data.begin(), goaway_event.payload.additional_debug_data.end());
        LOG_HTTP_WARN_PA(0, "Server: Received GOAWAY frame from client. Last Stream ID: " 
            << goaway_event.payload.last_stream_id << ", Error: " << static_cast<int>(goaway_event.payload.error_code) 
            << ", Debug: " << debug_data_str);

        _graceful_shutdown_initiated = true;
        FramerBase::set_last_peer_initiated_stream_id_processed_in_goaway(goaway_event.payload.last_stream_id);
        const ErrorCode error_code = goaway_event.payload.error_code;

        Http2GoAwayEvent event_to_dispatch{
            error_code,
            goaway_event.payload.last_stream_id,
            debug_data_str
        };
        if constexpr (has_method_on<IO_Handler, void, Http2GoAwayEvent>::value) {
            this->get_io_handler().on(event_to_dispatch);
        }

        for (auto it_stream = _server_streams.begin(); it_stream != _server_streams.end(); ) {
            if (it_stream->first % 2 == 0) { // Server-pushed stream
                Http2ServerStream& pushed_stream_ref = it_stream->second;
                bool close_pushed_stream = false;

                if (pushed_stream_ref.id > FramerBase::get_last_peer_initiated_stream_id_processed_in_goaway() && 
                    FramerBase::get_last_peer_initiated_stream_id_processed_in_goaway() != 0) {
                    // This condition might be too aggressive. GOAWAY's last_stream_id refers to peer-initiated streams.
                    // A pushed stream (server-initiated) is primarily affected if its *parent* client stream is affected.
                }

                // More accurately, close pushed stream if its parent client stream is > last_stream_id sent by client in GOAWAY
                // or if the parent stream is now closed/reset due to this GOAWAY.
                if (pushed_stream_ref.parent_stream_id > goaway_event.payload.last_stream_id && goaway_event.payload.last_stream_id !=0 ) {
                     close_pushed_stream = true;
                }
                // Additionally, if the parent stream itself is being cleaned up because it *is* one of the closed client streams:
                auto parent_client_stream_iter = _server_streams.find(pushed_stream_ref.parent_stream_id);
                if (parent_client_stream_iter != _server_streams.end()) {
                    // If parent client stream ID is > last_stream_id from GOAWAY (and it's a client stream)
                    if (parent_client_stream_iter->first % 2 != 0 && 
                        parent_client_stream_iter->first > goaway_event.payload.last_stream_id) {
                        // This parent client stream will be closed by other logic handling GOAWAY for client streams.
                        // So, the pushed stream associated with it should also be closed.
                        close_pushed_stream = true;
                    }
                } else {
                    // Parent stream doesn't exist anymore, so this pushed stream is orphaned.
                    close_pushed_stream = true;
                }

                if (close_pushed_stream && pushed_stream_ref.state != Http2StreamConcreteState::CLOSED) {
                    // QB_LOG_WARN_PA(this->getName(), "Server: Pushed stream " << pushed_stream_ref.id << " (parent: " << pushed_stream_ref.parent_stream_id 
                    //                << ") being closed due to GOAWAY from client (last_stream_id: " << goaway_event.payload.last_stream_id << ").");
                    pushed_stream_ref.state = Http2StreamConcreteState::CLOSED;
                    pushed_stream_ref.error_code = (error_code == ErrorCode::NO_ERROR) ? ErrorCode::CANCEL : error_code;
                    Http2StreamErrorEvent push_stream_error{pushed_stream_ref.id, pushed_stream_ref.error_code, "Pushed stream implicitly closed due to client GOAWAY"};
                    if constexpr (has_method_on<IO_Handler, void, Http2StreamErrorEvent>::value) {
                        this->get_io_handler().on(push_stream_error);
                    }
                    it_stream = _server_streams.erase(it_stream); // Erase and advance iterator
                    continue;
                }
            } else if (it_stream->first % 2 != 0) { // Client-initiated stream
                 Http2ServerStream& client_stream_ref = it_stream->second;
                 if (client_stream_ref.id > goaway_event.payload.last_stream_id && 
                     client_stream_ref.state != Http2StreamConcreteState::IDLE && // Don't try to error out streams that never fully started
                     client_stream_ref.state != Http2StreamConcreteState::CLOSED) {
                    // QB_LOG_WARN_PA(this->getName(), "Server: Client stream " << client_stream_ref.id 
                    //                << " implicitly closed by GOAWAY from client (last_stream_id: " << goaway_event.payload.last_stream_id << ").");
                    client_stream_ref.state = Http2StreamConcreteState::CLOSED;
                    client_stream_ref.rst_stream_received = true; // Treat as if RST received from client perspective for this stream
                    client_stream_ref.error_code = (error_code == ErrorCode::NO_ERROR) ? ErrorCode::STREAM_CLOSED : error_code;
                    Http2StreamErrorEvent client_stream_error{client_stream_ref.id, client_stream_ref.error_code, "Client stream implicitly closed by client GOAWAY"};
                    if constexpr (has_method_on<IO_Handler, void, Http2StreamErrorEvent>::value) {
                        this->get_io_handler().on(client_stream_error);
                    }
                    it_stream = _server_streams.erase(it_stream); // Erase and advance iterator
                    continue;
                 }
            }
            ++it_stream;
        }

        if (error_code != ErrorCode::NO_ERROR) {
            _connection_active = false;
            this->not_ok(error_code); // Signal specific error
        } else {
            // For NO_ERROR GOAWAY, connection closes once all relevant streams are done.
            if (this->are_all_relevant_streams_closed(FramerBase::get_last_peer_initiated_stream_id_processed_in_goaway())) {
                _connection_active = false;
                this->not_ok(ErrorCode::NO_ERROR); // Graceful shutdown complete
            }
        }
    }

    /**
     * @brief Handle WINDOW_UPDATE frame
     * @param wu_event WINDOW_UPDATE frame event
     */
    void on(Http2FrameData<WindowUpdateFrame> wu_event) noexcept {
        const FrameHeader& header = wu_event.header;
        uint32_t stream_id = header.get_stream_id();
        uint32_t window_increment = wu_event.payload.window_size_increment;

        LOG_HTTP_TRACE_PA(stream_id, "Server: Received WINDOW_UPDATE frame with increment " << window_increment);

        if (window_increment == 0) {
            if (stream_id == 0) {
                this->on_connection_error(ErrorCode::PROTOCOL_ERROR, "Received WINDOW_UPDATE with 0 increment on stream 0.");
            } else {
                this->send_rst_stream(stream_id, ErrorCode::PROTOCOL_ERROR, "Received WINDOW_UPDATE with 0 increment.");
            }
            return;
        }

        if (stream_id == 0) { 
            if (this->_connection_send_window > (static_cast<int64_t>(MAX_WINDOW_SIZE_LIMIT) - window_increment)) {
                this->on_connection_error(ErrorCode::FLOW_CONTROL_ERROR, "Connection WINDOW_UPDATE causes flow control window to exceed maximum.");
                return;
            }
            this->_connection_send_window += window_increment;
             for (auto& pair : _server_streams) {
                 if (pair.second.has_pending_data_to_send) {
                     try_send_pending_data_for_stream(pair.first, pair.second);
                     if(!this->_connection_active) break; 
                 }
             }

        } else { 
            auto it = _server_streams.find(stream_id);
            if (it == _server_streams.end()) {
                return;
            }
            Http2ServerStream& stream = it->second;
            if (stream.state == Http2StreamConcreteState::IDLE || stream.state == Http2StreamConcreteState::CLOSED) {
                 // Per RFC 9113, 6.9.1: WINDOW_UPDATE on IDLE or CLOSED (after RST or normal closure) is a PROTOCOL_ERROR if it causes window > 2^31-1.
                 // Otherwise, it can be ignored for closed/rst streams if it doesn't cause overflow.
                 // Simpler to just check for overflow if closed, or treat any WU on IDLE as error.
                 if (stream.state == Http2StreamConcreteState::IDLE) {
                    this->send_rst_stream(stream_id, ErrorCode::PROTOCOL_ERROR, "WINDOW_UPDATE on IDLE stream.");
                    return;
                 }
                 if (stream.peer_window_size > (static_cast<int64_t>(MAX_WINDOW_SIZE_LIMIT) - window_increment)) { 
                    this->send_rst_stream(stream_id, ErrorCode::FLOW_CONTROL_ERROR, "WINDOW_UPDATE on closed stream causes flow control window to exceed maximum.");
                 }
                 return; // Otherwise ignore for CLOSED stream if no overflow
            }

            if (stream.peer_window_size > (static_cast<int64_t>(MAX_WINDOW_SIZE_LIMIT) - window_increment)) {
                this->send_rst_stream(stream_id, ErrorCode::FLOW_CONTROL_ERROR, "Stream WINDOW_UPDATE causes flow control window to exceed maximum.");
                return;
            }
            
            stream.peer_window_size += window_increment;
            // QB_LOG_TRACE_PA(this->getName(), "Server: Stream " << stream_id << " peer window updated from " << old_stream_peer_window << " to " << stream.peer_window_size);

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
    void on(Http2FrameData<PingFrame> ping_event) noexcept {
        if (!this->ok() || !_connection_active) return;
        
        const FrameHeader& header = ping_event.header;

        LOG_HTTP_TRACE_PA(header.get_stream_id(), "Server: Received PING frame, flags: " << (int)header.flags);

        if (header.get_stream_id() != 0) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "PING frame on non-zero stream_id");
            return;
        }

        if (header.flags & FLAG_ACK) {
            // This is a PING ACK from client (server sent PING).
            // QB_LOG_TRACE_PA(this->getName(), "Server: Received PING ACK from client.");
            // TODO: Application could be notified, e.g. for RTT calculation if it sent the PING.
            // This is an application integration point.
        } else {
            // This is a PING from client, send PONG (PING with ACK).
            // QB_LOG_TRACE_PA(this->getName(), "Server: Received PING from client, sending PONG.");
            Http2FrameData<PingFrame> pong_frame;
            pong_frame.header.type = static_cast<uint8_t>(FrameType::PING);
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
    void on(Http2FrameData<PriorityFrame> priority_event) noexcept {
        if (!this->ok() || !_connection_active) return;

        const FrameHeader& header = priority_event.header;
        uint32_t stream_id = header.get_stream_id();

        if (stream_id == 0) {
            this->send_goaway_and_close(ErrorCode::PROTOCOL_ERROR, "PRIORITY frame on stream 0 from client");
            return;
        }
        // PRIORITY frames can be received for any stream state.
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
    bool send_response(uint32_t stream_id, qb::http::Response const &http_response) {
        LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Attempting to send response");
        auto it = _server_streams.find(stream_id);
        if (it == _server_streams.end()) {
            LOG_HTTP_WARN_PA(stream_id, "ServerHttp2Protocol: Attempt to send response on non-existent stream");
            return false; // Or send RST_STREAM(STREAM_CLOSED) if appropriate
        }
        Http2ServerStream& stream = it->second;

        if (stream.state == Http2StreamConcreteState::IDLE || stream.state == Http2StreamConcreteState::RESERVED_LOCAL) {
            LOG_HTTP_WARN_PA(stream_id, "ServerHttp2Protocol: Attempt to send response on stream in IDLE or RESERVED_LOCAL state");
            this->on_stream_error(stream_id, ErrorCode::PROTOCOL_ERROR, "Sending response on stream in invalid state for response.");
            return false;
        }
        
        if (stream.state == Http2StreamConcreteState::CLOSED || stream.state == Http2StreamConcreteState::HALF_CLOSED_LOCAL) {
            LOG_HTTP_INFO_PA(stream_id, "ServerHttp2Protocol: Attempt to send response on already closed/half-closed(local) stream");
            return false; // Stream is already closed or we've already sent END_STREAM
        }

        LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Building response headers with status " << http_response.status().code());
        std::vector<qb::protocol::hpack::HeaderField> hf_vector;
        hf_vector.emplace_back(":status", std::to_string(http_response.status().code()));
        for (const auto& header_item : http_response.headers()) { // Assuming http_response.headers() gives iterable key-value pairs
            for(const auto& value : header_item.second) { // Assuming header_item.second is iterable (e.g. vector of strings for multi-value headers)
                 hf_vector.emplace_back(header_item.first, value);
            }
        }

        std::vector<uint8_t> encoded_headers;
        if (!_hpack_encoder || !_hpack_encoder->encode(hf_vector, encoded_headers)) {
            LOG_HTTP_ERROR_PA(stream_id, "ServerHttp2Protocol: HPACK encoding failed for response headers");
            this->on_connection_error(ErrorCode::COMPRESSION_ERROR, "HPACK encoder failed for response headers.");
            return false;
        }



        if (_peer_max_header_list_size > 0 && encoded_headers.size() > _peer_max_header_list_size) {
            LOG_HTTP_WARN_PA(stream_id, "ServerHttp2Protocol: Encoded headers size " << encoded_headers.size() << " exceeds peer's MAX_HEADER_LIST_SIZE " << _peer_max_header_list_size);
            send_rst_stream(stream_id, ErrorCode::INTERNAL_ERROR); 
            return false;
        }
        
        Http2FrameData<HeadersFrame> headers_frame_data;
        headers_frame_data.header.type = static_cast<uint8_t>(FrameType::HEADERS);
        headers_frame_data.header.set_stream_id(stream_id);
        headers_frame_data.header.flags = FLAG_END_HEADERS; // Always set END_HEADERS

        const auto& body_pipe = http_response.body().raw();
        bool has_body = !body_pipe.empty();

        if (!has_body) {
            headers_frame_data.header.flags |= FLAG_END_STREAM; // No body, HEADERS ends the stream
            LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Response has no body, setting END_STREAM flag");
        } else {
            LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Response has body of size " << body_pipe.size());
        }
        
        headers_frame_data.payload.header_block_fragment = std::move(encoded_headers);

        this->_io << headers_frame_data;
        
        // Update stream state AFTER successful send of HEADERS frame
        if (headers_frame_data.header.flags & FLAG_END_STREAM) {
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
            if (stream.state == Http2StreamConcreteState::CLOSED) {
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
     * @brief Send PUSH_PROMISE to client
     * 
     * Initiates a server push by sending a PUSH_PROMISE frame. The promised
     * stream must be followed by a send_response() call with the actual response.
     * 
     * @param associated_stream_id Stream ID of the client request triggering this push
     * @param promised_stream_id Stream ID for the promised response (must be even)
     * @param promised_request_pseudo_headers Request headers for the promised resource
     * @return true if PUSH_PROMISE sent successfully, false on error
     */
    [[nodiscard]] std::optional<PushPromiseFailureReason> send_push_promise(uint32_t associated_stream_id, uint32_t promised_stream_id, qb::http::Request promised_request_pseudo_headers) {
        LOG_HTTP_DEBUG_PA(associated_stream_id, "Server: Attempting to send PUSH_PROMISE for promised_stream_id " << promised_stream_id);
        if (!this->ok() || !_connection_active) { 
            LOG_HTTP_WARN_PA(associated_stream_id, "Server: Cannot send PUSH_PROMISE. Protocol not OK or connection inactive.");
            return PushPromiseFailureReason::CONNECTION_INACTIVE;
        }
        if (!_peer_allows_push) { 
            LOG_HTTP_INFO_PA(associated_stream_id, "Server: Client has disabled PUSH_PROMISE (SETTINGS_ENABLE_PUSH = 0). Cannot send push for promised_stream_id " << promised_stream_id);
            return PushPromiseFailureReason::PEER_PUSH_DISABLED;
        }
        if (get_active_stream_count(true) >= _peer_max_concurrent_streams) { 
            LOG_HTTP_WARN_PA(associated_stream_id, "Server: Cannot send PUSH_PROMISE for promised_stream_id " << promised_stream_id << ". Would exceed client's MAX_CONCURRENT_STREAMS limit: " << _peer_max_concurrent_streams);
            return PushPromiseFailureReason::PEER_CONCURRENCY_LIMIT_REACHED;
        }

        auto it_assoc_stream = _server_streams.find(associated_stream_id);
        if (it_assoc_stream == _server_streams.end()) {
            // QB_LOG_WARN_PA(this->getName(), "Server: PUSH_PROMISE for non-existent associated stream " << associated_stream_id);
            return PushPromiseFailureReason::INVALID_ASSOCIATED_STREAM;
        }

        if (it_assoc_stream->second.state != Http2StreamConcreteState::OPEN && it_assoc_stream->second.state != Http2StreamConcreteState::HALF_CLOSED_REMOTE) {
            // QB_LOG_WARN_PA(this->getName(), "Server: PUSH_PROMISE on associated stream " << associated_stream_id << " not in valid state.");
            return PushPromiseFailureReason::INVALID_ASSOCIATED_STREAM;
        }

        // Create a new stream context for the promised stream
        Http2ServerStream promised_stream(promised_stream_id, _initial_peer_window_size, this->get_initial_window_size_from_settings());
        promised_stream.state = Http2StreamConcreteState::RESERVED_LOCAL;
        promised_stream.parent_stream_id = associated_stream_id; 
        
        // Emplace the stream
        auto emp_res = _server_streams.emplace(promised_stream_id, std::move(promised_stream));
        if (!emp_res.second) {
            // QB_LOG_ERROR_PA(this->getName(), "Server: Failed to emplace promised stream " << promised_stream_id << " context.");
             return PushPromiseFailureReason::INTERNAL_ERROR; 
        }
        it_assoc_stream->second.associated_push_promises.push_back(promised_stream_id);

        Http2FrameData<PushPromiseFrame> pp_frame_data;
        pp_frame_data.payload.promised_stream_id = promised_stream_id;

        std::vector<hpack::HeaderField> hf_vector;
        // According to RFC 7540 Section 8.2:
        // PUSH_PROMISE frames MUST include pseudo-header fields for :method, :scheme, :authority, and :path.
        // They MAY include other headers that are valid for requests.

        hf_vector.push_back({std::string(qb::http::well_known::COLON_METHOD_SV), std::string(promised_request_pseudo_headers.method())});
        hf_vector.push_back({std::string(qb::http::well_known::COLON_PATH_SV), std::string(promised_request_pseudo_headers.uri().path())});
        hf_vector.push_back({std::string(qb::http::well_known::COLON_SCHEME_SV), std::string(promised_request_pseudo_headers.uri().scheme())});
        if (!promised_request_pseudo_headers.uri().host().empty()) {
             hf_vector.push_back({std::string(qb::http::well_known::COLON_AUTHORITY_SV), std::string(promised_request_pseudo_headers.uri().host())});
        }

        for (const auto& header_entry : promised_request_pseudo_headers.headers()) { // Iterate map from .headers()
            // Skip pseudo-headers already added, and ":content-length" which is forbidden in PUSH_PROMISE
            if (header_entry.first[0] == ':' && 
                (header_entry.first == qb::http::well_known::COLON_METHOD_SV ||
                 header_entry.first == qb::http::well_known::COLON_PATH_SV ||
                 header_entry.first == qb::http::well_known::COLON_SCHEME_SV ||
                 header_entry.first == qb::http::well_known::COLON_AUTHORITY_SV ||
                 header_entry.first == "content-length" )) { // content-length also forbidden
                continue;
            }
            for (const auto& value : header_entry.second) { // Iterate vector of values for this header name
                 hf_vector.push_back({header_entry.first, value});
            }
        }

        std::vector<uint8_t> encoded_headers;
        if (!_hpack_encoder || !_hpack_encoder->encode(hf_vector, encoded_headers)) {
            LOG_HTTP_ERROR_PA(associated_stream_id, "Server: HPACK encoding failed for PUSH_PROMISE on promised_stream_id " << promised_stream_id);
            _server_streams.erase(promised_stream_id); 
            return PushPromiseFailureReason::INTERNAL_HPACK_ERROR;
        }
        
        pp_frame_data.payload.header_block_fragment = std::move(encoded_headers);

        FrameHeader header_to_send;
        header_to_send.type = static_cast<uint8_t>(FrameType::PUSH_PROMISE);
        header_to_send.flags = FLAG_END_HEADERS; // PUSH_PROMISE contains a full header block, so END_HEADERS implicitly
        header_to_send.set_stream_id(associated_stream_id); 
        pp_frame_data.header = header_to_send;
        this->_io << pp_frame_data;
        
        if (!this->ok()) { // Check if the send operation itself failed (e.g. underlying transport error)
             _server_streams.erase(promised_stream_id); // Clean up if send failed
             // The not_ok() might have been set by the transport, leading to CONNECTION_INACTIVE on next attempt
             return PushPromiseFailureReason::CONNECTION_INACTIVE; // Or a more generic send error
        }
        LOG_HTTP_INFO_PA(associated_stream_id, "Server: Sending PUSH_PROMISE for promised_stream_id " << promised_stream_id);
        return std::nullopt; // Success
    }

private:
    /**
     * @brief Initialize server's HTTP/2 settings to defaults
     */
    void initialize_our_settings_map() noexcept {
        _our_settings.clear();
        _our_settings[Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE] = hpack::HPACK_DEFAULT_MAX_TABLE_SIZE;
        _our_settings[Http2SettingIdentifier::SETTINGS_ENABLE_PUSH] = 0; // Server disables push by default
        _our_settings[Http2SettingIdentifier::SETTINGS_MAX_CONCURRENT_STREAMS] = 100; // Max streams we allow client to open
        _our_settings[Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE] = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;
        _our_settings[Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE] = DEFAULT_SETTINGS_MAX_FRAME_SIZE;
        _our_settings[Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE] = DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE;
    }

    /**
     * @brief Calculate and validate max frame size from settings
     * @return Valid max frame size for initialization
     */
    uint32_t initialize_our_max_frame_size() {
        this->initialize_our_settings_map();
        uint32_t calculated_max_frame_size = this->get_setting_value_or_default(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, DEFAULT_SETTINGS_MAX_FRAME_SIZE);
        if (calculated_max_frame_size < DEFAULT_SETTINGS_MAX_FRAME_SIZE || calculated_max_frame_size > MAX_FRAME_SIZE_LIMIT) {
            calculated_max_frame_size = DEFAULT_SETTINGS_MAX_FRAME_SIZE;
        }
        return calculated_max_frame_size;
    }

    /**
     * @brief Get initial window size from settings
     * @return Initial window size value
     */
    uint32_t get_initial_window_size_from_settings() const noexcept {
        return this->get_setting_value_or_default(Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE);
    }

    /**
     * @brief Get setting value or default if not found
     * @param id Setting identifier
     * @param default_val Default value if setting not found
     * @return Setting value or default
     */
    uint32_t get_setting_value_or_default(Http2SettingIdentifier id, uint32_t default_val) const noexcept {
        auto it = _our_settings.find(id);
        if (it != _our_settings.end()) {
            return it->second;
        }
        return default_val;
    }

    /**
     * @brief Clear header assembly state between header blocks
     */
    void clear_header_assembly_state() noexcept {
        _current_header_block_fragment.clear();
        _current_header_stream_id = 0;
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
    bool process_complete_header_block(Http2ServerStream& stream, bool is_trailers_block) {
        
        // Debug: Log raw HPACK bytes (removed in production)
        
        // QB_LOG_TRACE_PA(this->getName(), "Stream " << stream.id << ": Processing complete header block (is_trailers=" << is_trailers_block << ")");
        qb::http::Headers current_headers_decoded; // Decoded headers for this block
        bool possibly_incomplete_hpack = false;

        if (!_hpack_decoder || !_hpack_decoder->decode(_current_header_block_fragment, stream.decoded_header_fields, possibly_incomplete_hpack)) {
            // QB_LOG_ERROR_PA(this->getName(), "Stream " << stream.id << ": HPACK decoding failed.");
            this->on_stream_error(stream.id, ErrorCode::COMPRESSION_ERROR, "HPACK decoding failed");
            return false;
        }
        if (possibly_incomplete_hpack) {
            // QB_LOG_WARN_PA(this->getName(), "Stream " << stream.id << ": HPACK decoding possibly incomplete.");
            // Decide if this is fatal. For now, treat as COMPRESSION_ERROR.
            this->on_stream_error(stream.id, ErrorCode::COMPRESSION_ERROR, "HPACK decoding possibly incomplete");
            return false;
        }



        // Convert decoded_header_fields to qb::http::Headers and qb::http::Request (if main headers)
        // and apply to stream.assembled_request or stream.response_to_send.trailers()
        // Also, validate pseudo-headers for main request headers.

        // Store original current header block fragment for potential PUSH_PROMISE validation if this is a request
        if (!is_trailers_block) {
            stream.last_received_header_block_fragment = _current_header_block_fragment;
        }
        _current_header_block_fragment.clear(); // Clear for next use
        stream.expecting_continuation = false;


        if (!is_trailers_block) { // Main headers (request)
            stream.headers_received_main = true;
            // Validate pseudo-headers and convert to qb::http::Request components
            std::optional<std::string_view> method_sv, scheme_sv, path_sv, authority_sv;
            bool pseudo_headers_finished = false;

            std::string temp_method_str; // Temporary for method conversion

            for (const auto& hf : stream.decoded_header_fields) {
                const std::string& name = hf.name;
                const std::string& value = hf.value;

                if (name.empty()) {
                    this->on_stream_error(stream.id, ErrorCode::PROTOCOL_ERROR, "Empty header field name received."); return false;
                }
                if (name[0] == ':') { // Pseudo-header
                    if (pseudo_headers_finished) {
                        this->on_stream_error(stream.id, ErrorCode::PROTOCOL_ERROR, "Pseudo-header received after regular header."); return false;
                    }
                    // Process pseudo-headers
                    if (name == ":method") {
                        if (method_sv) {
                            this->on_stream_error(stream.id, ErrorCode::PROTOCOL_ERROR, "Duplicate :method pseudo-header."); return false;
                        }
                        method_sv = value;
                        temp_method_str = value; // Store for later conversion
                    } else if (name == ":scheme") {
                        if (scheme_sv) {
                            this->on_stream_error(stream.id, ErrorCode::PROTOCOL_ERROR, "Duplicate :scheme pseudo-header."); return false;
                        }
                        scheme_sv = value;
                    } else if (name == ":path") {
                        if (path_sv) {
                            this->on_stream_error(stream.id, ErrorCode::PROTOCOL_ERROR, "Duplicate :path pseudo-header."); return false;
                        }
                        path_sv = value;
                    } else if (name == ":authority") {
                        if (authority_sv) {
                            this->on_stream_error(stream.id, ErrorCode::PROTOCOL_ERROR, "Duplicate :authority pseudo-header."); return false;
                        }
                        authority_sv = value;
                    } else {
                        // Unknown pseudo-header, could be :status in response or other extension
                        // For now, ignore unknown pseudo-headers in requests
                    }
                } else { // Regular header
                    pseudo_headers_finished = true;
                    // TODO: Validate header name/value format per HTTP rules (e.g., no NULs etc.)
                    // if invalid -> PROTOCOL_ERROR
                    stream.assembled_request.add_header(name, value);
                }
            }

            if (!method_sv || !scheme_sv || !path_sv) {
                this->on_stream_error(stream.id, ErrorCode::PROTOCOL_ERROR, "Missing mandatory pseudo-header (:method, :scheme, or :path)."); return false;
            }
            if (path_sv.value().empty()) {
                 this->on_stream_error(stream.id, ErrorCode::PROTOCOL_ERROR, ":path pseudo-header cannot be empty."); return false;
            }
            // As per RFC 7540 Section 8.1.2.3, :authority is optional if the URI has an authority component.
            // For QB, we'll reconstruct the URI. If authority_sv is present, it takes precedence for the host part.

            qb::http::Method method_from_string_view(temp_method_str);
            if (method_from_string_view == qb::http::Method::Value::UNINITIALIZED) { 
                this->send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Invalid :method value"); return false;
            }
            stream.assembled_request.method() = method_from_string_view;

            std::string uri_str = std::string(scheme_sv.value()) + "://";
            if (authority_sv && !authority_sv.value().empty()) {
                uri_str += std::string(authority_sv.value());
            } else {
                // Fallback: try to get host from Host header if :authority is missing or empty
                // This logic needs to be robust as per RFC requirements
                // For now, if :authority is empty, we might form an origin-form URI if path is absolute
                // Or rely on the application to handle Host header later if needed.
                // Let's assume for now if :authority is not there, it will be an origin-form request or app handles Host.
            }
            uri_str += std::string(path_sv.value());
            stream.assembled_request.uri() = qb::io::uri::parse(uri_str);

            if (stream.end_stream_received) { // end_stream_received would have been set by on(HeadersFrame) if END_STREAM was on the header
                this->dispatch_complete_request(stream.id, stream);
            }

        } else { // Trailers block
            stream.trailers_received = true;
            std::vector<hpack::HeaderField> temp_trailers; // Temporary storage for trailer key-value pairs
            for (const auto& hf : stream.decoded_header_fields) {
                const std::string& name = hf.name;
                const std::string& value = hf.value;
                if (name.empty() || name[0] == ':') {
                    this->on_stream_error(stream.id, ErrorCode::PROTOCOL_ERROR, "Invalid header field name in trailers (empty or pseudo-header)."); return false;
                }
                // TODO: Validate header name/value format
                stream.assembled_request.add_header(name, value); // Add to request trailers
                temp_trailers.push_back(hf);
            }

            // As per RFC 9113, a trailer section's final frame MUST contain END_STREAM.
            // stream.end_stream_received should have been set by the on(HeadersFrame/ContinuationFrame) that had END_HEADERS and END_STREAM.
            if (!stream.end_stream_received) {
                this->send_rst_stream(stream.id, ErrorCode::PROTOCOL_ERROR, "Trailers HEADERS block did not end the stream."); return false;
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
    bool send_response_body(Http2ServerStream& stream, const qb::http::Response& http_response) {
        // This function is called after initial HEADERS are sent.
        // stream.response_to_send should already be populated by the calling send_response function.
        // stream.send_buffer_offset should be 0 if this is the first attempt for this body.

        const auto& body_pipe = http_response.body().raw(); // Use http_response passed in, which should be same as stream.response_to_send
        std::size_t body_size = body_pipe.size();
        const char* body_data_ptr = body_pipe.data(); 

        // send_buffer_offset tracks progress within stream.response_to_send.body(), which is http_response.body()
        // uint32_t sent_bytes_this_function_call = 0; // Tracks what this specific call achieves

        stream.is_trailers = http_response.has_header("Trailer"); // Or a more robust check for actual trailer fields intended
                                                                // For now, presence of "Trailer" header implies intent.

        while (stream.send_buffer_offset < body_size) {
            if (stream.peer_window_size <= 0 || _connection_send_window <= 0) {
                stream.has_pending_data_to_send = true; // Mark that body data remains unsent
                // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream.id << ": Send body blocked by flow control. Offset: " << stream.send_buffer_offset);
                return true; // Successfully buffered/marked pending, not a protocol error
            }

            uint32_t max_can_send_on_stream = static_cast<uint32_t>(std::min(this->FramerBase::get_peer_max_frame_size(), static_cast<uint32_t>(stream.peer_window_size)));
            uint32_t max_can_send_on_conn = static_cast<uint32_t>(std::min(this->FramerBase::get_peer_max_frame_size(), static_cast<uint32_t>(_connection_send_window)));
            uint32_t chunk_size = std::min({
                static_cast<uint32_t>(body_size - stream.send_buffer_offset), 
                max_can_send_on_stream, 
                max_can_send_on_conn, 
                this->FramerBase::get_peer_max_frame_size()
            });

            if (chunk_size == 0 && (body_size - stream.send_buffer_offset) > 0) { 
                stream.has_pending_data_to_send = true;
                // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream.id << ": Send body blocked by zero chunk_size. Offset: " << stream.send_buffer_offset);
                return true; 
            }
             if (chunk_size == 0 && body_size == 0 && stream.send_buffer_offset == 0) { // Empty body case
                 break; // Nothing to send for body
            }
             if (chunk_size == 0 && stream.send_buffer_offset == body_size) { // All body already processed
                break;
            }

            Http2FrameData<DataFrame> data_frame_data;
            data_frame_data.payload.data_payload.assign(body_data_ptr + stream.send_buffer_offset, 
                                                      body_data_ptr + stream.send_buffer_offset + chunk_size);

            FrameHeader header_to_send;
            header_to_send.type = static_cast<uint8_t>(FrameType::DATA);
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
                // QB_LOG_ERROR_PA(this->getName(), "Server Stream " << stream.id << ": Send failed for DATA frame during send_response_body. Reverting offset.");
                stream.send_buffer_offset -= chunk_size; // Revert offset for this failed chunk
                stream.peer_window_size += chunk_size;   // Revert window consumption
                _connection_send_window += chunk_size; // Revert window consumption
                stream.has_pending_data_to_send = true; // Mark as pending because send failed
                return false; // Indicate send failure
            }
            
            if (header_to_send.flags & FLAG_END_STREAM) {
                 stream.end_stream_sent = true;
                 stream.state = Http2StreamConcreteState::HALF_CLOSED_LOCAL; 
                 // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream.id << ": END_STREAM sent with DATA in send_response_body.");
            }

            if(stream.end_stream_sent && !stream.is_trailers) { 
                break; // All body sent, no trailers, we are done with body sending.
            }
        }

        // After loop: if all body is sent (offset == size) and there are trailers, trailers will be handled by try_send_pending_data or a dedicated trailer send call.
        // If not all body is sent, has_pending_data_to_send is already true.
        if (stream.send_buffer_offset == body_size) {
            stream.has_pending_data_to_send = false; // All *body* data processed by this function or was empty.
                                                 // If trailers are present, `is_trailers` will trigger next step.
        } else {
            stream.has_pending_data_to_send = true; // Still more body data to send later.
        }

        // If trailers are expected and all body data has been sent by this function. 
        // The actual sending of trailers is usually handled by try_send_pending_data_for_stream or a subsequent call.
        if (stream.send_buffer_offset == body_size && stream.is_trailers && !stream.end_stream_sent) {
            // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream_id_param << ": Body fully processed in send_response_body, trailers are pending.");
            // At this point, try_send_pending_data_for_stream will pick up trailer sending.
            // Or if this function was meant to be comprehensive, it could call a send_trailers helper.
            // For now, let has_pending_data_to_send = false (for body) and is_trailers=true guide the next step.
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
    void dispatch_complete_request(uint32_t stream_id, Http2ServerStream& stream) {

        if (stream.request_dispatched || stream.rst_stream_sent || stream.rst_stream_received) {
            LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Skipping request dispatch - already dispatched or stream reset");
            return;
        }

        if (this->ok() && this->_connection_active) {
            LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Dispatching complete request to application layer");
            // Assemble qb::http::Request from stream.assembled_request
            // The pseudo-headers should have already populated method and URI components.
            // Body should be in stream.assembled_request.body()
            // Trailers in stream.assembled_request.trailers()
            // Create a final qb::http::Request object.
            // For simplicity, let's assume stream.assembled_request is already mostly a qb::http::Request.
            // If it's a different intermediate struct, copy/move to qb::http::Request here.

            // Ensure mandatory fields are present if not checked earlier during header processing
            if (stream.assembled_request.method() == qb::http::Method::Value::UNINITIALIZED || stream.assembled_request.uri().path().empty()) {
                 LOG_HTTP_ERROR_PA(stream_id, "ServerHttp2Protocol: Attempt to dispatch incomplete request (missing method/path)");
                 this->send_rst_stream(stream_id, ErrorCode::INTERNAL_ERROR, "Attempt to dispatch incomplete request (missing method/path)");
                 return;
            }

            stream.assembled_request.parse_cookie_header();

            // CRITICAL: Mark as dispatched BEFORE calling _io.on() because it might trigger immediate response
            // and close the stream, making the 'stream' reference invalid
            stream.request_dispatched = true;

            this->_io.on(std::move(stream.assembled_request), stream_id); // Pass stream_id as context/correlation
            
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
    void try_close_stream_context(uint32_t stream_id) noexcept {
        auto it = _server_streams.find(stream_id);
        if (it != _server_streams.end()) {
            Http2ServerStream& stream = it->second;

            bool can_cleanup = (stream.state == Http2StreamConcreteState::CLOSED) || stream.rst_stream_sent || stream.rst_stream_received;

            if (can_cleanup) {
                LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Cleaning up stream context");
                // If an error occurred that wasn't dispatched because request/response cycle was aborted by RST
                if ((!stream.request_dispatched || !stream.end_stream_sent) &&
                    (stream.rst_stream_sent || stream.rst_stream_received) && stream.error_code != ErrorCode::NO_ERROR) {
                    // Stream was reset before full lifecycle completion by app. Error already dispatched by RST handler.
                }
                _server_streams.erase(it);
                LOG_HTTP_INFO_PA(stream_id, "ServerHttp2Protocol: Stream context cleaned up successfully");

                if (_graceful_shutdown_initiated && this->_last_peer_initiated_stream_id_processed_in_goaway != 0) {
                    LOG_HTTP_DEBUG("ServerHttp2Protocol: Checking if graceful shutdown can complete after stream " << stream_id << " cleanup");
                    if (this->are_all_relevant_streams_closed(FramerBase::get_last_peer_initiated_stream_id_processed_in_goaway())) {
                        _connection_active = false;
                        LOG_HTTP_INFO("ServerHttp2Protocol: Graceful shutdown complete - all relevant streams closed");
                        this->not_ok(ErrorCode::NO_ERROR); // Graceful shutdown complete
                    }
                } else if (_graceful_shutdown_initiated && _server_streams.empty() && FramerBase::get_last_peer_initiated_stream_id_processed_in_goaway() == 0) {
                    // We initiated GOAWAY (so last_peer_id_processed might be 0 from our side if we didn't process any from peer before deciding to goaway)
                    // and all our streams are now gone.
                    _connection_active = false;
                    LOG_HTTP_INFO("ServerHttp2Protocol: Graceful shutdown complete - all streams closed");
                    // this->not_ok() was already called by send_goaway_and_close.
                }
            } else {
                LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Stream not ready for cleanup yet");
            }
        } else {
            LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Stream context not found for cleanup");
        }
    }

    /**
     * @brief Send RST_STREAM frame
     * 
     * Sends a stream reset frame and marks the stream as closed.
     * 
     * @param stream_id Stream identifier
     * @param error_code Error code for the reset
     * @param context_msg Debug context message
     */
    void send_rst_stream(uint32_t stream_id, ErrorCode error_code, const std::string& context_msg = "") noexcept {

        if (!_connection_active && error_code != ErrorCode::CANCEL) { // CANCEL can be sent on closed connection by app // Removed .load(std::memory_order_relaxed)
            LOG_HTTP_WARN_PA(stream_id, "ServerHttp2Protocol: Tried to send RST_STREAM but connection is not active");
            return;
        }
        LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Sending RST_STREAM with error code " << static_cast<uint32_t>(error_code) << ". Context: " << context_msg);

        Http2FrameData<RstStreamFrame> rst_frame_data;
        rst_frame_data.payload.error_code = error_code;

        FrameHeader header;
        header.type = static_cast<uint8_t>(FrameType::RST_STREAM);
        header.flags = 0;
        header.set_stream_id(stream_id);
        
        rst_frame_data.header = header;
        this->_io << rst_frame_data;

        auto it = _server_streams.find(stream_id);
        if (it != _server_streams.end()) {
            it->second.state = Http2StreamConcreteState::CLOSED; // RST_STREAM immediately closes the stream
            it->second.rst_stream_sent = true;
            it->second.error_code = error_code;
            LOG_HTTP_DEBUG_PA(stream_id, "ServerHttp2Protocol: Stream marked as CLOSED due to sent RST_STREAM");
            
            // Notify IO_Handler if request wasn't dispatched or response wasn't fully sent
            if ((!it->second.request_dispatched || !it->second.end_stream_sent) && error_code != ErrorCode::NO_ERROR) {
                 Http2StreamErrorEvent stream_error_event{stream_id, error_code, "RST_STREAM sent by server: " + context_msg};
                if constexpr (has_method_on<IO_Handler, void, Http2StreamErrorEvent>::value) {
                    this->get_io_handler().on(stream_error_event);
                }
            }
            this->try_close_stream_context(stream_id); // Attempt to clean up if conditions met
        }
        LOG_HTTP_INFO_PA(stream_id, "ServerHttp2Protocol: RST_STREAM sent successfully");
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
    void send_goaway_and_close(ErrorCode error_code, const std::string& debug_message) noexcept {

        if (!_connection_active) { // Removed .load(std::memory_order_relaxed)
            LOG_HTTP_DEBUG("ServerHttp2Protocol: Avoiding GOAWAY send - connection already inactive");
            return; // Avoid sending if already inactive.
        }
        
        LOG_HTTP_WARN("ServerHttp2Protocol: Sending GOAWAY frame. Error: " << static_cast<int>(error_code) << ", Message: " << debug_message);

        Http2FrameData<GoAwayFrame> goaway_frame_data;
        goaway_frame_data.payload.last_stream_id = _last_client_initiated_stream_id; // Report last stream ID client successfully initiated with us
        goaway_frame_data.payload.error_code = error_code;
        if (!debug_message.empty()) {
            goaway_frame_data.payload.additional_debug_data.assign(debug_message.begin(), debug_message.end());
        }

        FrameHeader header;
        header.type = static_cast<uint8_t>(FrameType::GOAWAY);
        header.flags = 0;
        header.set_stream_id(0); // GOAWAY is on stream 0

        goaway_frame_data.header = header;
        this->_io << goaway_frame_data;
        
        _graceful_shutdown_initiated = true;
        _connection_active = false; // Connection is being shut down

        // Notify IO_Handler about sending GOAWAY
        if constexpr (has_method_on<IO_Handler, void, Http2GoAwayEvent>::value) {
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
    void send_window_update(uint32_t stream_id, uint32_t increment) noexcept {
        if (!this->ok() || increment == 0) {
            return;
        }

        Http2FrameData<WindowUpdateFrame> wu_frame_data;
        wu_frame_data.header.type = static_cast<uint8_t>(FrameType::WINDOW_UPDATE);
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
    void conditionally_send_connection_window_update() noexcept {
        const int64_t connection_window_update_thresh = static_cast<int64_t>(DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE) / CONNECTION_WINDOW_THRESHOLD_DIVISOR;
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
    void update_initial_peer_window_size(uint32_t new_size) noexcept {
        // This `new_size` is client's SETTINGS_INITIAL_WINDOW_SIZE
        // It affects how much data *we* (server) can send on *new* streams initiated by client
        // or on PUSH_PROMISE streams we initiate.
        int64_t delta = static_cast<int64_t>(new_size) - static_cast<int64_t>(_initial_peer_window_size);
        _initial_peer_window_size = new_size;

        for (auto& pair : _server_streams) {
            Http2ServerStream& stream = pair.second;
            // Affects streams where server is sending data: OPEN, HALF_CLOSED_LOCAL (server sending, client receiving), RESERVED_LOCAL (for PUSH)
            if (stream.state == Http2StreamConcreteState::OPEN || stream.state == Http2StreamConcreteState::HALF_CLOSED_LOCAL || stream.state == Http2StreamConcreteState::RESERVED_LOCAL) {
                int64_t old_stream_peer_window = stream.peer_window_size;
                stream.peer_window_size += delta;

                if (stream.peer_window_size > static_cast<int64_t>(MAX_WINDOW_SIZE_LIMIT)) {
                     this->send_rst_stream(stream.id, ErrorCode::FLOW_CONTROL_ERROR, "Stream window overflow (server side) due to client SETTINGS_INITIAL_WINDOW_SIZE change");
                     this->send_goaway_and_close(ErrorCode::FLOW_CONTROL_ERROR, "Client SETTINGS_INITIAL_WINDOW_SIZE change caused stream window overflow (conn error)");
                     return;
                }
                if (stream.peer_window_size < 0) {
                     this->send_rst_stream(stream.id, ErrorCode::FLOW_CONTROL_ERROR, "Stream window negative (server side) due to client SETTINGS_INITIAL_WINDOW_SIZE change");
                     this->send_goaway_and_close(ErrorCode::FLOW_CONTROL_ERROR, "Client SETTINGS_INITIAL_WINDOW_SIZE change caused negative stream window (conn error)");
                     return;
                }
                if (old_stream_peer_window <= 0 && stream.peer_window_size > 0 && stream.has_pending_data_to_send) {
                    this->try_send_pending_data_for_stream(stream.id, stream);
                }
            }
        }
    }

    /**
     * @brief Try to send pending data for all streams
     * 
     * Attempts to resume sending for all streams with pending data.
     */
    void try_send_pending_data_all_streams() noexcept {
        if (!this->ok() || !_connection_active) return; // Removed .load(std::memory_order_relaxed)
        for (auto& pair : _server_streams) {
            Http2ServerStream& stream = pair.second;
            if (stream.has_pending_data_to_send &&
                (stream.state == Http2StreamConcreteState::OPEN || stream.state == Http2StreamConcreteState::HALF_CLOSED_LOCAL)) {
                 // Reconstruct or retrieve pending qb::http::Response associated with stream.application_response_id
                 // This is complex as the original Response object might be gone.
                 // A robust pending data queue is needed, storing actual data segments.
                 // For now, this is a placeholder for that logic.
                 // Example: if (stream.application_response_id != 0) {
                 //    qb::http::Response pending_response = get_pending_response_by_id(stream.application_response_id);
                 //    send_response_body(stream, pending_response);
                 // }
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
    void try_send_pending_data_for_stream(uint32_t stream_id_param, Http2ServerStream& stream) noexcept {

        if (!this->ok() || !_connection_active) {
            // QB_LOG_WARN_PA(this->getName(), "Server Stream " << stream_id_param << ": Connection not OK or inactive in try_send_pending_data.");
            return;
        }

        if (stream.state != Http2StreamConcreteState::OPEN && stream.state != Http2StreamConcreteState::HALF_CLOSED_LOCAL) {
            // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream_id_param << ": Attempt to send pending data but stream not in OPEN or HALF_CLOSED_LOCAL state. Current state: " << static_cast<int>(stream.state));
            return;
        }

        bool body_fully_sent_or_empty = (stream.send_buffer_offset == stream.response_to_send.body().size());

        // Part 1: Try to send remaining body data if any
        if (stream.has_pending_data_to_send && !body_fully_sent_or_empty) {
            const auto& body_pipe = stream.response_to_send.body().raw();
            std::size_t total_body_size = body_pipe.size();
            const char* body_data_ptr = body_pipe.data();

            while (stream.send_buffer_offset < total_body_size) {
                if (stream.peer_window_size <= 0 || this->_connection_send_window <= 0) {
                    // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream_id_param << ": Send pending body blocked by flow control. PeerWin: " << stream.peer_window_size << " ConnWin: " << this->_connection_send_window);
                    stream.has_pending_data_to_send = true; // Ensure it's still marked
                    return; // Blocked, will retry later
                }

                uint32_t max_chunk_size = std::min({
                    static_cast<uint32_t>(stream.peer_window_size), 
                    static_cast<uint32_t>(this->_connection_send_window), 
                    this->FramerBase::get_peer_max_frame_size()
                });
                if (max_chunk_size == 0) { 
                    // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream_id_param << ": Max chunk size is 0 for pending body, cannot send.");
                    stream.has_pending_data_to_send = true; // Still effectively blocked
                    return;
                }

                uint32_t remaining_body_to_send = static_cast<uint32_t>(total_body_size - stream.send_buffer_offset);
                uint32_t current_chunk_size = std::min(remaining_body_to_send, max_chunk_size);

                if (current_chunk_size == 0 && remaining_body_to_send > 0) { // Should not happen if max_chunk_size > 0
                    stream.has_pending_data_to_send = true;
                    return;
                }
                if (current_chunk_size == 0 && remaining_body_to_send == 0) break; // All body sent

                // START PADDING LOGIC MODIFICATION FOR SERVER DATA FRAMES
                uint8_t pad_length_s = 0;
                bool add_padding_s = false; // Use the debug flag

                if (add_padding_s && current_chunk_size > 0) {
                    uint32_t max_payload_without_pad_field_s = this->FramerBase::get_peer_max_frame_size() - 1; 
                    if (current_chunk_size >= max_payload_without_pad_field_s) {
                        add_padding_s = false; 
                    } else {
                        uint32_t available_for_padding_s = max_payload_without_pad_field_s - current_chunk_size;
                        pad_length_s = static_cast<uint8_t>(std::min((uint32_t)15, available_for_padding_s)); 
                        if (current_chunk_size + pad_length_s > max_payload_without_pad_field_s) {
                             pad_length_s = static_cast<uint8_t>(max_payload_without_pad_field_s - current_chunk_size);
                        }
                    }
                } else {
                    add_padding_s = false; 
                }

                Http2FrameData<DataFrame> data_frame_event;
                data_frame_event.header.type = static_cast<uint8_t>(FrameType::DATA);
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
                // REVERTED PADDING LOGIC (flow control decrement)

                if (data_frame_event.header.flags & FLAG_END_STREAM) {
                    stream.state = Http2StreamConcreteState::HALF_CLOSED_LOCAL;
                    stream.end_stream_sent = true;
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
            
            std::vector<qb::protocol::hpack::HeaderField> hf_vector_trailers;
            const qb::http::Response& original_response = stream.response_to_send; 

            for (const auto& header_item : original_response.headers()) { 
                if (stream.headers_sent_in_initial_frame.count(header_item.first)) continue; 
                // Standard pseudo-headers and connection-specific headers are forbidden in trailers
                if (header_item.first.empty() || header_item.first[0] == ':' || 
                    qb::http::well_known::is_hop_by_hop(header_item.first) ||
                    header_item.first == qb::http::well_known::CONTENT_LENGTH_SV ||
                    header_item.first == qb::http::well_known::TRANSFER_ENCODING_SV || 
                    header_item.first == qb::http::well_known::TRAILER_SV) { // The "Trailer" header itself shouldn't be a trailer
                    continue;
                }
                for (const auto& value : header_item.second) {
                    hf_vector_trailers.push_back({std::string(header_item.first), value});
                }
            }

            Http2FrameData<HeadersFrame> trailers_frame_event;
            trailers_frame_event.header.type = static_cast<uint8_t>(FrameType::HEADERS);
            trailers_frame_event.header.flags = FLAG_END_HEADERS | FLAG_END_STREAM; // Trailers always end the stream
            trailers_frame_event.header.set_stream_id(stream_id_param);

            if (!hf_vector_trailers.empty()) {
                // QB_LOG_TRACE_PA(this->getName(), "Server Stream " << stream_id_param << ": Encoding " << hf_vector_trailers.size() << " trailer fields.");
                if (_hpack_encoder && _hpack_encoder->encode(hf_vector_trailers, trailers_frame_event.payload.header_block_fragment)) {
                    // Successfully encoded trailers
                } else {
                    // QB_LOG_ERROR_PA(this->getName(), "Server Stream " << stream_id_param << ": HPACK trailer encoding error.");
                    send_rst_stream(stream_id_param, ErrorCode::INTERNAL_ERROR, "HPACK trailer encoding error");
                    return; // Stop processing for this stream
                }
            } else {
                 // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream_id_param << ": No actual trailer fields to send, sending empty HEADERS with END_STREAM for trailers.");
                 // Payload remains empty for empty trailers frame
            }
            
            this->_io << trailers_frame_event;
            if (this->ok()) {
                stream.state = Http2StreamConcreteState::HALF_CLOSED_LOCAL; 
                stream.end_stream_sent = true;
                stream.is_trailers = false; // Trailers have been handled
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
            // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream_id_param << ": END_STREAM is sent. Current state: " << static_cast<int>(stream.state) << ", end_stream_received: " << stream.end_stream_received);
            if (stream.state == Http2StreamConcreteState::HALF_CLOSED_LOCAL && stream.end_stream_received) {
                 stream.state = Http2StreamConcreteState::CLOSED; 
                 // QB_LOG_DEBUG_PA(this->getName(), "Server Stream " << stream_id_param << ": State changed to CLOSED.");
            }
            try_close_stream_context(stream_id_param);
        }
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
    void handle_framer_detected_error(ErrorCode reason, const std::string& message, uint32_t stream_id_context) noexcept {
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
    void on_stream_error(uint32_t stream_id, ErrorCode error_code, const std::string& debug_message) noexcept {
        LOG_HTTP_ERROR_PA(stream_id, "ServerHttp2Protocol: Stream error detected - " << debug_message << " (code: " << static_cast<int>(error_code) << ")");
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
    void on_connection_error(ErrorCode error_code, const std::string& debug_message) noexcept {
        LOG_HTTP_ERROR("ServerHttp2Protocol: Connection error detected - " << debug_message << " (code: " << static_cast<int>(error_code) << ")");
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
    [[nodiscard]] bool are_all_relevant_streams_closed(uint32_t last_known_stream_id) const noexcept {
        // Specific implementation for server-side graceful shutdown.
        // Checks if all streams up to and including last_known_stream_id that were
        // initiated by the peer (client) are in a closed state.
        if (_graceful_shutdown_initiated) {
            for (const auto& pair : _server_streams) {
                const Http2ServerStream& stream = pair.second;
                // Check client-initiated streams (odd IDs) up to the last ID client acknowledged processing.
                if (stream.id % 2 != 0 && stream.id <= last_known_stream_id) {
                    if (stream.state != Http2StreamConcreteState::CLOSED && 
                        stream.state != Http2StreamConcreteState::IDLE && // IDLE might be considered effectively closed for new work
                        !stream.rst_stream_sent && !stream.rst_stream_received) {
                        return false; // Found an active client-initiated stream that should be closed.
                    }
                }
            }
            return true; // All relevant client-initiated streams are closed.
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
    Http2ServerStream& get_or_create_stream_context(uint32_t stream_id, bool /*is_client_initiated -- inferred from stream_id */) {
        auto it = _server_streams.find(stream_id);
        if (it == _server_streams.end()) {
            // Create new stream context
            // For server, is_client_initiated is true if stream_id is odd.
            // bool client_init = (stream_id % 2 != 0);
            Http2ServerStream new_stream(stream_id, _initial_peer_window_size, this->get_initial_window_size_from_settings());
            // new_stream.is_client_initiated = client_init; // is_client_initiated is not a member of Http2ServerStream
            // The count of active client streams is handled elsewhere, e.g. on HEADERS receipt.
            auto result = _server_streams.emplace(stream_id, std::move(new_stream));
            it = result.first;
        }
        return it->second;
    }

    /**
     * @brief Get reference to I/O handler (application layer).
     * @return Reference to I/O handler.
     */
    [[nodiscard]] IO_Handler& get_io_handler() noexcept {
        return this->_io;
    }

    /**
     * @brief Get reference to I/O handler (application layer), const version.
     * @return Const reference to I/O handler.
     */
    [[nodiscard]] const IO_Handler& get_io_handler() const noexcept {
        return this->_io;
    }

    /**
     * @brief Get the count of active streams.
     * @param server_initiated_check If true, counts even-numbered (server-pushed) streams.
     *                               If false, counts odd-numbered (client-initiated) request streams.
     * @return Number of active streams matching the criteria.
     */
    [[nodiscard]] uint32_t get_active_stream_count(bool server_initiated_check) const noexcept {
        uint32_t count = 0;
        for (const auto& [stream_id, stream_obj] : _server_streams) {
            if (stream_obj.state != Http2StreamConcreteState::IDLE && 
                stream_obj.state != Http2StreamConcreteState::CLOSED &&
                !stream_obj.rst_stream_sent && 
                !stream_obj.rst_stream_received) {
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

}; // class ServerHttp2Protocol

} // namespace qb::protocol::http2
