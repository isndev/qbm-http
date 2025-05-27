/**
 * @file base.h
 * @brief HTTP/2 protocol base implementation for qb-io framework
 * @copyright Copyright (c) 2024 isndev. All rights reserved.
 * @license This software is licensed under the terms specified in the LICENSE file
 *          located in the root directory of the project.
 */

#pragma once

#include <memory> // For std::shared_ptr
#include <vector> // For std::vector
#include <string>
#include <string_view>
#include <array>
#include <variant> // Keep for ParsedHttp2Frame, though it's less central now
#include <cstdint> // For uintN_t types
#include <cstring> // For memcpy
#include <algorithm> // For std::min
#include <optional>

#include <qb/io/async/protocol.h> // For qb::io::async::AProtocol
#include <qb/io/uri.h>   // For qb::io::uri
#include <qb/system/container/unordered_map.h> // For qb::unordered_map
#include <qb/system/endian.h> // Added for endian conversion
#include <qb/utility/type_traits.h> // For has_method_on

#include "../../request.h" // For qb::http::Request
#include "../../response.h" // For qb::http::Response
#include "./frames.h" // For ErrorCode, Http2SettingIdentifier, Frame types, FrameHeader etc.
#include "../../logger.h" // For HTTP/2 logging
#include "../../logger.h" // For HTTP/2 logging

/**
 * @brief HTTP/2 connection preface bytes as specified in RFC 9113
 */
constexpr char HTTP2_CONNECTION_PREFACE_BYTES[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/**
 * @brief HTTP/2 connection preface as string_view
 */
constexpr std::string_view HTTP2_CONNECTION_PREFACE(HTTP2_CONNECTION_PREFACE_BYTES, sizeof(HTTP2_CONNECTION_PREFACE_BYTES) - 1);

namespace qb::protocol::http2 {

// --- HTTP/2 Frame Types ---
// enum class FrameType : uint8_t { ... };

// --- HTTP/2 Frame Flags ---
// constexpr uint8_t FLAG_END_STREAM  = 0x1;
// ... other flags ...

// --- HTTP/2 Frame Header Structure ---
// #pragma pack(push, 1)
// struct FrameHeader { ... };
// #pragma pack(pop)
// constexpr std::size_t FRAME_HEADER_SIZE = sizeof(FrameHeader);

// --- Concrete Frame Structures (Payloads) ---
// struct DataFrame { ... };
// struct HeadersFrame { ... };
// struct PriorityFrame { ... }; // Note: Http2PriorityData is now in http2_frames.h
// struct RstStreamFrame { ... };
// struct SettingsFrameEntry { ... }; // Note: Http2SettingIdentifier is in http2_frames.h
// struct SettingsFrame { ... };
// struct PushPromiseFrame { ... };
// struct PingFrame { ... };
// struct GoAwayFrame { ... };
// struct WindowUpdateFrame { ... };
// struct ContinuationFrame { ... };

/**
 * @brief HTTP/2 Protocol parser and framer base class
 * @tparam IO_Handler The I/O handler type from qb-io framework
 * @tparam SideProtocol The derived protocol class (client or server)
 * 
 * This class implements the core HTTP/2 protocol parsing and framing logic
 * according to RFC 9113. It handles:
 * - Connection preface validation
 * - Frame header parsing
 * - Frame payload extraction
 * - Basic protocol error detection
 * 
 * The class follows a state machine pattern with three main states:
 * - EXPECTING_PREFACE: Initial state, waiting for HTTP/2 connection preface
 * - EXPECTING_FRAME_HEADER: Waiting for a 9-byte frame header
 * - EXPECTING_FRAME_PAYLOAD: Waiting for frame payload of known size
 */
template<typename IO_Handler, typename SideProtocol>
class Http2Protocol : public qb::io::async::AProtocol<IO_Handler> {
public:
    using Base = qb::io::async::AProtocol<IO_Handler>;

    /**
     * @brief Parser state machine states
     */
    enum class ParserState {
        EXPECTING_PREFACE,        ///< Waiting for HTTP/2 connection preface
        EXPECTING_FRAME_HEADER,   ///< Waiting for 9-byte frame header
        EXPECTING_FRAME_PAYLOAD   ///< Waiting for frame payload
    };

protected:
    ParserState _current_state = ParserState::EXPECTING_PREFACE;
    std::vector<uint8_t> _preface_buffer;
    FrameHeader _current_frame_header;
    std::size_t _expected_payload_bytes = 0;
    uint32_t _our_max_frame_size = qb::protocol::http2::DEFAULT_MAX_FRAME_SIZE;
    std::optional<ErrorCode> _last_error_code;
    uint32_t _last_peer_initiated_stream_id_processed_in_goaway = 0;
    uint32_t _peer_max_frame_size = qb::protocol::http2::DEFAULT_MAX_FRAME_SIZE;

public:
    /**
     * @brief Construct HTTP/2 protocol parser
     * @param io_handler_ref Reference to the I/O handler
     */
    explicit Http2Protocol(IO_Handler& io_handler_ref)
        : Base(io_handler_ref) {
        _preface_buffer.reserve(HTTP2_CONNECTION_PREFACE.size());
    }

    /**
     * @brief Construct HTTP/2 protocol parser with custom max frame size
     * @param io_handler_ref Reference to the I/O handler
     * @param our_max_frame_size_setting Maximum frame size to advertise
     */
    explicit Http2Protocol(IO_Handler& io_handler_ref, uint32_t our_max_frame_size_setting)
        : Base(io_handler_ref), _our_max_frame_size(our_max_frame_size_setting) {
        if (_our_max_frame_size < qb::protocol::http2::DEFAULT_MAX_FRAME_SIZE || 
            _our_max_frame_size > qb::protocol::http2::MAX_FRAME_SIZE_LIMIT) {
            _our_max_frame_size = qb::protocol::http2::DEFAULT_MAX_FRAME_SIZE;
        }
        _preface_buffer.reserve(HTTP2_CONNECTION_PREFACE.size());
    }

    ~Http2Protocol() override = default;

    // Delete copy and move operations
    Http2Protocol(const Http2Protocol&) = delete;
    Http2Protocol& operator=(const Http2Protocol&) = delete;
    Http2Protocol(Http2Protocol&&) = delete;
    Http2Protocol& operator=(Http2Protocol&&) = delete;

    /**
     * @brief Get the last error code if protocol is in error state
     * @return Optional error code
     */
    [[nodiscard]] std::optional<ErrorCode> get_last_error_code() const {
        return _last_error_code;
    }

    /**
     * @brief Get current frame header for error reporting
     * @return Reference to current frame header
     */
    [[nodiscard]] const FrameHeader& get_current_frame_header_for_error() const { 
        return _current_frame_header; 
    }

    /**
     * @brief Get the expected message size for current parser state
     * @return Number of bytes needed, or 0 if insufficient data
     */
    [[nodiscard]] std::size_t getMessageSize() noexcept override {
        const auto& in_buffer = this->_io.in();

        switch (_current_state) {
            case ParserState::EXPECTING_PREFACE: {
                const auto remaining_preface_needed = HTTP2_CONNECTION_PREFACE.size() - _preface_buffer.size();
                if (remaining_preface_needed == 0) {
                    return 0;
                }
                if (in_buffer.size() < remaining_preface_needed) {
                    return 0;
                }
                return remaining_preface_needed;
            }
            case ParserState::EXPECTING_FRAME_HEADER: {
                if (in_buffer.size() < FRAME_HEADER_SIZE) {
                    return 0;
                }
                return FRAME_HEADER_SIZE;
            }
            case ParserState::EXPECTING_FRAME_PAYLOAD: {
                if (_expected_payload_bytes == 0) {
                    return 0; 
                }
                if (in_buffer.size() < _expected_payload_bytes) {
                    return 0;
                }
                return _expected_payload_bytes;
            }
            default:
                return 0;
        }
    }

    /**
     * @brief Process received message data
     * @param received_size Number of bytes received
     */
    void onMessage(std::size_t received_size) noexcept override {
        auto& in_buffer = this->_io.in();

        switch (_current_state) {
            case ParserState::EXPECTING_PREFACE: {
                const auto bytes_to_copy = received_size;

                if (bytes_to_copy > 0) {
                    if (in_buffer.size() < bytes_to_copy) {
                        this->not_ok(ErrorCode::INTERNAL_ERROR);
                        return;
                    }
                    _preface_buffer.insert(_preface_buffer.end(), 
                                         in_buffer.cbegin(), 
                                         in_buffer.cbegin() + bytes_to_copy);
                }

                if (_preface_buffer.size() == HTTP2_CONNECTION_PREFACE.size()) {
                    if (std::memcmp(_preface_buffer.data(), 
                                  HTTP2_CONNECTION_PREFACE.data(), 
                                  HTTP2_CONNECTION_PREFACE.size()) == 0) {
                        LOG_HTTP_DEBUG("HTTP/2 connection preface validated successfully");
                        _current_state = ParserState::EXPECTING_FRAME_HEADER;
                        if constexpr (has_method_on<SideProtocol, void, qb::protocol::http2::PrefaceCompleteEvent>::value) {
                           static_cast<SideProtocol*>(this)->on(qb::protocol::http2::PrefaceCompleteEvent{});
                        }
                    } else {
                        LOG_HTTP_ERROR("Invalid HTTP/2 connection preface received");
                        this->not_ok(ErrorCode::PROTOCOL_ERROR);
                    }
                } else if (_preface_buffer.size() > HTTP2_CONNECTION_PREFACE.size()) {
                     this->not_ok(ErrorCode::INTERNAL_ERROR);
                }
                break;
            }

            case ParserState::EXPECTING_FRAME_HEADER: {
                if (received_size != FRAME_HEADER_SIZE) {
                    this->not_ok(ErrorCode::INTERNAL_ERROR);
                    return;
                }
                if (in_buffer.size() < FRAME_HEADER_SIZE) {
                     this->not_ok(ErrorCode::INTERNAL_ERROR);
                     return;
                }
                std::memcpy(&_current_frame_header, in_buffer.cbegin(), FRAME_HEADER_SIZE);

                _expected_payload_bytes = _current_frame_header.get_payload_length();
                
                // Validate SETTINGS frames on stream 0
                if (_current_frame_header.get_type() == FrameType::SETTINGS && 
                    _current_frame_header.get_stream_id() != 0) {
                    this->not_ok(ErrorCode::PROTOCOL_ERROR); 
                    return;
                }
                
                // Validate PING/GOAWAY frames on stream 0
                if ((_current_frame_header.get_type() == FrameType::PING || 
                     _current_frame_header.get_type() == FrameType::GOAWAY) && 
                    _current_frame_header.get_stream_id() != 0) {
                    this->not_ok(ErrorCode::PROTOCOL_ERROR); 
                    return;
                }
                
                // Check frame size against our limit
                if (_expected_payload_bytes > get_our_max_frame_size()) {
                    LOG_HTTP_ERROR_PA(_current_frame_header.get_stream_id(), 
                        "Frame size " << _expected_payload_bytes << " exceeds limit " << get_our_max_frame_size());
                    this->not_ok(ErrorCode::FRAME_SIZE_ERROR); 
                    return;
                }

                if (!this->ok()) return;

                if (_expected_payload_bytes == 0) {
                    handle_zero_payload_frame_dispatch();
                    if(this->ok()) {
                        _current_state = ParserState::EXPECTING_FRAME_HEADER;
                    }
                } else {
                    _current_state = ParserState::EXPECTING_FRAME_PAYLOAD;
                }
                break;
            }

            case ParserState::EXPECTING_FRAME_PAYLOAD: {
                if (received_size != _expected_payload_bytes) {
                    this->not_ok(ErrorCode::FRAME_SIZE_ERROR);
                    static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                        ErrorCode::FRAME_SIZE_ERROR, 
                        "Payload size incorrect", 
                        _current_frame_header.get_stream_id());
                     return;
                }

                if (received_size == 0) {
                    // Zero-payload frame already handled
                } else {
                    std::string_view payload_view(in_buffer.begin(), received_size);

                    if (!handle_payload_frame_dispatch(payload_view)) {
                        return;
                    }
                     _current_state = ParserState::EXPECTING_FRAME_HEADER;
                    _expected_payload_bytes = 0;
                }
                break;
            }
            default:
                this->not_ok(ErrorCode::INTERNAL_ERROR);
                return;
        }
    }

    /**
     * @brief Reset protocol parser state
     */
    void reset() noexcept override {
        _current_state = ParserState::EXPECTING_PREFACE;
        _preface_buffer.clear();
        _expected_payload_bytes = 0;
        _last_error_code.reset();
    }

protected: 
    /**
     * @brief Set protocol to error state without specific reason
     */
    void not_ok() noexcept {
        _last_error_code.reset();
        Base::not_ok();
    }

    /**
     * @brief Set protocol to error state with specific error code
     * @param reason The HTTP/2 error code
     */
    void not_ok(ErrorCode reason) noexcept {
        if (reason != ErrorCode::NO_ERROR) {
            LOG_HTTP_ERROR("Protocol error: " << static_cast<int>(reason));
        }
        _last_error_code = reason;
        Base::not_ok();
    }

    /**
     * @brief Send a frame to the peer
     * @tparam FramePayloadType The frame payload type
     * @param header Frame header
     * @param payload Frame payload
     * @param payload_size_for_header Size to set in header
     * @return true if send succeeded, false otherwise
     */
    template<typename FramePayloadType>
    [[nodiscard]] bool send_frame_internal(const FrameHeader& header, 
                                          const FramePayloadType& payload, 
                                          std::size_t payload_size_for_header) noexcept {
        Http2FrameData<FramePayloadType> frame_to_send;
        frame_to_send.header = header;
        frame_to_send.header.set_payload_length(static_cast<uint32_t>(payload_size_for_header));
        frame_to_send.payload = payload;

        if constexpr (has_method_on<IO_Handler, IO_Handler&, Http2FrameData<FramePayloadType>>::value) {
            this->_io << frame_to_send;
        } else {
            this->not_ok(ErrorCode::INTERNAL_ERROR);
            return false;
        }
        return this->ok();
    }

    /**
     * @brief Handle connection-level error
     * @param error_code The error code
     * @param debug_message Error description
     */
    void on_connection_error(ErrorCode error_code, const std::string& debug_message) {
        if constexpr (has_method_on<SideProtocol, void, ErrorCode, const std::string&>::value) {
            static_cast<SideProtocol*>(this)->on_connection_error(error_code, debug_message);
        } else {
            // Default implementation
            this->not_ok(error_code);
        }
    }

    /**
     * @brief Handle stream-level error
     * @param stream_id The stream ID
     * @param error_code The error code
     * @param debug_message Error description
     */
    void on_stream_error(uint32_t stream_id, ErrorCode error_code, const std::string& debug_message) {
        if constexpr (has_method_on<SideProtocol, void, uint32_t, ErrorCode, const std::string&>::value) {
            static_cast<SideProtocol*>(this)->on_stream_error(stream_id, error_code, debug_message);
        } else {
            // Default implementation
            this->not_ok(error_code);
        }
    }

    /**
     * @brief Handle error detected by framer
     * @param reason Error code
     * @param message Error message
     * @param stream_id_context Stream ID context (0 for connection errors)
     */
    void handle_framer_detected_error(ErrorCode reason, 
                                    const std::string& message, 
                                    uint32_t stream_id_context) noexcept {
        if constexpr (has_method_on<SideProtocol, void, ErrorCode, const std::string&, uint32_t>::value) {
            static_cast<SideProtocol*>(this)->handle_framer_detected_error(reason, message, stream_id_context);
        }
        // No default implementation needed - derived classes handle this
    }

    /**
     * @brief Get our advertised max frame size
     * @return Max frame size in bytes
     */
    [[nodiscard]] uint32_t get_our_max_frame_size() const noexcept { 
        return _our_max_frame_size; 
    }

    /**
     * @brief Get last peer-initiated stream ID processed in GOAWAY
     * @return Stream ID
     */
    [[nodiscard]] uint32_t get_last_peer_initiated_stream_id_processed_in_goaway() const noexcept { 
        return _last_peer_initiated_stream_id_processed_in_goaway; 
    }

    /**
     * @brief Set last peer-initiated stream ID processed in GOAWAY
     * @param stream_id Stream ID to set
     */
    void set_last_peer_initiated_stream_id_processed_in_goaway(uint32_t stream_id) noexcept { 
        _last_peer_initiated_stream_id_processed_in_goaway = stream_id; 
    }

    /**
     * @brief Get peer's max frame size setting
     * @return Max frame size in bytes
     */
    [[nodiscard]] uint32_t get_peer_max_frame_size() const noexcept { 
        return _peer_max_frame_size; 
    }

    /**
     * @brief Set peer's max frame size setting
     * @param size Frame size to set (will be clamped to valid range)
     */
    void set_peer_max_frame_size(uint32_t size) noexcept { 
        _peer_max_frame_size = std::max(qb::protocol::http2::DEFAULT_MAX_FRAME_SIZE, 
                                       std::min(size, qb::protocol::http2::MAX_FRAME_SIZE_LIMIT)); 
    }

    /**
     * @brief Check if all relevant streams are closed (for graceful shutdown)
     * @param last_processed_peer_stream_id Last processed peer stream ID
     * @return true if all streams are closed
     */
    [[nodiscard]] bool are_all_relevant_streams_closed(uint32_t last_processed_peer_stream_id) const {
        if constexpr (has_method_on<SideProtocol, bool, uint32_t>::value) {
            return static_cast<const SideProtocol*>(this)->are_all_relevant_streams_closed(last_processed_peer_stream_id);
        } else {
            // Default implementation
            return true;
        }
    }

private:
    /**
     * @brief Handle frames with zero payload
     */
    void handle_zero_payload_frame_dispatch() noexcept {
        if (!this->ok()) return;

        switch (_current_frame_header.get_type()) {
            case FrameType::SETTINGS:
                if (_current_frame_header.flags & FLAG_ACK) {
                    Http2FrameData<SettingsFrame> settings_ack_frame;
                    settings_ack_frame.header = _current_frame_header;
                    static_cast<SideProtocol*>(this)->on(std::move(settings_ack_frame));
                } else {
                    Http2FrameData<SettingsFrame> settings_frame;
                    settings_frame.header = _current_frame_header;
                    static_cast<SideProtocol*>(this)->on(std::move(settings_frame));
                }
                break;
                
            case FrameType::PING:
                // PING frame payload MUST be 8 octets. Zero payload is FRAME_SIZE_ERROR.
                this->not_ok(ErrorCode::FRAME_SIZE_ERROR);
                static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                    ErrorCode::FRAME_SIZE_ERROR, "PING frame with zero payload.", _current_frame_header.get_stream_id()
                );
                break;

            case FrameType::HEADERS:
                {
                    Http2FrameData<HeadersFrame> hf; 
                    hf.header = _current_frame_header;
                    static_cast<SideProtocol*>(this)->on(std::move(hf));
                }
                break;

            case FrameType::DATA:
                {
                    Http2FrameData<DataFrame> df; 
                    df.header = _current_frame_header;
                    static_cast<SideProtocol*>(this)->on(std::move(df));
                }
                break;
            
            // Frames that MUST have a non-zero payload according to RFC 9113 if type is known:
            case FrameType::PRIORITY: // Payload: 5 octets
            case FrameType::RST_STREAM: // Payload: 4 octets
            case FrameType::GOAWAY: // Payload: Min 8 octets
            case FrameType::WINDOW_UPDATE: // Payload: 4 octets
            // PUSH_PROMISE and CONTINUATION typically have payloads, but zero could be valid if padded length equals total length, 
            // however, their structure implies at least some data (e.g. promised stream ID for PP).
            // For CONTINUATION, zero payload is fine if it's just END_HEADERS.
            // For PUSH_PROMISE, it must contain at least Promised Stream ID (4 octets).
            // Let specific handlers decide, but if header says 0 and they expect more, it's an issue.
            // This function is called *when header.payload_length is 0*.
            // So for these, it is a FRAME_SIZE_ERROR.
                this->not_ok(ErrorCode::FRAME_SIZE_ERROR);
                static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                    ErrorCode::FRAME_SIZE_ERROR, 
                    "Frame type " + std::to_string(static_cast<int>(_current_frame_header.get_type())) + 
                    " received with mandatory zero payload.", 
                    _current_frame_header.get_stream_id()
                );
                break;
            
            case FrameType::PUSH_PROMISE: // Requires at least Promised Stream ID (4 octets)
                 this->not_ok(ErrorCode::FRAME_SIZE_ERROR);
                 static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                    ErrorCode::FRAME_SIZE_ERROR, "PUSH_PROMISE frame with zero payload.", _current_frame_header.get_stream_id());
                 break;

            case FrameType::CONTINUATION:
                {
                    Http2FrameData<ContinuationFrame> cf;
                    cf.header = _current_frame_header;
                    static_cast<SideProtocol*>(this)->on(std::move(cf));
                }
                break;

            default:
                // Unknown frame types are ignored as per RFC 9113, Section 4.1.
                // "Implementations MUST ignore and discard frames of unknown types."
                // No error needs to be signaled here for truly unknown frame types.
                // QB_LOG_TRACE_PA(this->getName(), "Ignored unknown frame type " << static_cast<int>(_current_frame_header.get_type()) << " with zero payload.");
                break;
        }
    }

    /**
     * @brief Parse and dispatch frame payloads
     * @param payload_view View of the payload data
     * @return true if parsing succeeded, false on error
     */
    [[nodiscard]] bool handle_payload_frame_dispatch(std::string_view payload_view) noexcept {
        if (!this->ok()) return false;

        const uint8_t* payload_buffer_data = reinterpret_cast<const uint8_t*>(payload_view.data());
        std::size_t payload_buffer_size = payload_view.size();

        switch (_current_frame_header.get_type()) {
            case FrameType::DATA: {
                Http2FrameData<DataFrame> data_f;
                data_f.header = _current_frame_header;
                const uint8_t* p_data = payload_buffer_data;
                std::size_t p_len = payload_buffer_size;
                uint8_t pad_length = 0;

                if (_current_frame_header.flags & FLAG_PADDED) {
                    if (p_len == 0) {
                        this->not_ok(ErrorCode::FRAME_SIZE_ERROR);
                        static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                            ErrorCode::FRAME_SIZE_ERROR, "Padded DATA frame too short for Pad Length.", 
                            _current_frame_header.get_stream_id());
                        return false;
                    }
                    pad_length = p_data[0];
                    p_data++;
                    p_len--;

                    if (pad_length > p_len) {
                        this->not_ok(ErrorCode::PROTOCOL_ERROR);
                        static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                            ErrorCode::PROTOCOL_ERROR, "Pad Length in DATA frame exceeds payload size.", 
                            _current_frame_header.get_stream_id());
                        return false;
                    }
                    data_f.payload.data_payload.assign(p_data, p_data + (p_len - pad_length));
                } else {
                    data_f.payload.data_payload.assign(payload_buffer_data, 
                                                     payload_buffer_data + payload_buffer_size);
                }
                static_cast<SideProtocol*>(this)->on(std::move(data_f));
                break;
            }
            
            case FrameType::HEADERS: {
                Http2FrameData<HeadersFrame> headers_f;
                headers_f.header = _current_frame_header;
                const uint8_t* p_data = payload_buffer_data;
                std::size_t p_len = payload_buffer_size;
                uint8_t pad_length = 0;

                if (_current_frame_header.flags & FLAG_PADDED) {
                    if (p_len == 0) { 
                        this->not_ok(ErrorCode::FRAME_SIZE_ERROR); 
                        static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                            ErrorCode::FRAME_SIZE_ERROR, "Padded HEADERS frame too short for Pad Length.", 
                            _current_frame_header.get_stream_id()); 
                        return false; 
                    }
                    pad_length = p_data[0];
                    p_data++; 
                    p_len--;
                    if (pad_length > p_len) { 
                        this->not_ok(ErrorCode::PROTOCOL_ERROR); 
                        static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                            ErrorCode::PROTOCOL_ERROR, "Pad Length in HEADERS frame exceeds payload size.", 
                            _current_frame_header.get_stream_id()); 
                        return false; 
                    }
                }

                if (_current_frame_header.flags & FLAG_PRIORITY) {
                    if (p_len < (5 + pad_length)) { 
                        this->not_ok(ErrorCode::FRAME_SIZE_ERROR); 
                        static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                            ErrorCode::FRAME_SIZE_ERROR, "HEADERS with PRIORITY flag too short for priority fields.", 
                            _current_frame_header.get_stream_id()); 
                        return false; 
                    }
                    Http2PriorityData pri_data;
                    uint32_t stream_dep_raw = (static_cast<uint32_t>(p_data[0]) << 24) |
                                            (static_cast<uint32_t>(p_data[1]) << 16) |
                                            (static_cast<uint32_t>(p_data[2]) << 8)  |
                                            (static_cast<uint32_t>(p_data[3]));
                    pri_data.exclusive_dependency = (stream_dep_raw >> 31) & 0x1;
                    pri_data.stream_dependency = stream_dep_raw & 0x7FFFFFFF;
                    pri_data.weight = p_data[4];
                    headers_f.payload.priority_info = pri_data;
                    p_data += 5; 
                    p_len -= 5;
                }
                
                std::size_t header_block_size = p_len - pad_length;
                headers_f.payload.header_block_fragment.assign(p_data, p_data + header_block_size);
                static_cast<SideProtocol*>(this)->on(std::move(headers_f));
                break;
            }
            
            case FrameType::PRIORITY: {
                if (payload_buffer_size != 5) { 
                    this->not_ok(ErrorCode::FRAME_SIZE_ERROR); 
                    static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                        ErrorCode::FRAME_SIZE_ERROR, "PRIORITY frame payload incorrect size.", 
                        _current_frame_header.get_stream_id()); 
                    return false; 
                }
                Http2FrameData<PriorityFrame> priority_f;
                priority_f.header = _current_frame_header;
                uint32_t stream_dep_raw = (static_cast<uint32_t>(payload_buffer_data[0]) << 24) |
                                        (static_cast<uint32_t>(payload_buffer_data[1]) << 16) |
                                        (static_cast<uint32_t>(payload_buffer_data[2]) << 8)  |
                                        (static_cast<uint32_t>(payload_buffer_data[3]));
                priority_f.payload.priority_data.exclusive_dependency = (stream_dep_raw >> 31) & 0x1;
                priority_f.payload.priority_data.stream_dependency = stream_dep_raw & 0x7FFFFFFF;
                priority_f.payload.priority_data.weight = payload_buffer_data[4];
                static_cast<SideProtocol*>(this)->on(std::move(priority_f));
                break;
            }
            
            case FrameType::RST_STREAM: {
                if (payload_buffer_size != 4) { 
                    this->not_ok(ErrorCode::FRAME_SIZE_ERROR); 
                    static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                        ErrorCode::FRAME_SIZE_ERROR, "RST_STREAM frame payload incorrect size.", 
                        _current_frame_header.get_stream_id()); 
                    return false; 
                }
                Http2FrameData<RstStreamFrame> rst_f;
                rst_f.header = _current_frame_header;
                rst_f.payload.error_code = static_cast<ErrorCode>(
                    (static_cast<uint32_t>(payload_buffer_data[0]) << 24) |
                    (static_cast<uint32_t>(payload_buffer_data[1]) << 16) |
                    (static_cast<uint32_t>(payload_buffer_data[2]) << 8)  |
                    (static_cast<uint32_t>(payload_buffer_data[3]))
                );
                static_cast<SideProtocol*>(this)->on(std::move(rst_f));
                break;
            }
            
            case FrameType::SETTINGS: {
                if (_current_frame_header.flags & FLAG_ACK) {
                    this->not_ok(ErrorCode::FRAME_SIZE_ERROR); 
                    static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                        ErrorCode::FRAME_SIZE_ERROR, "SETTINGS ACK frame with payload.", 
                        _current_frame_header.get_stream_id()); 
                    return false;
                }
                if (payload_buffer_size % 6 != 0) { 
                    this->not_ok(ErrorCode::FRAME_SIZE_ERROR); 
                    static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                        ErrorCode::FRAME_SIZE_ERROR, "SETTINGS frame payload size not a multiple of 6.", 
                        _current_frame_header.get_stream_id()); 
                    return false; 
                }
                Http2FrameData<SettingsFrame> settings_f;
                settings_f.header = _current_frame_header;
                settings_f.payload.entries.reserve(payload_buffer_size / 6);
                
                for (size_t i = 0; i < payload_buffer_size; i += 6) {
                    SettingsFrameEntry entry;
                    entry.identifier = static_cast<Http2SettingIdentifier>(
                        (static_cast<uint16_t>(payload_buffer_data[i]) << 8) | payload_buffer_data[i+1]
                    );
                    entry.value = (static_cast<uint32_t>(payload_buffer_data[i+2]) << 24) |
                                (static_cast<uint32_t>(payload_buffer_data[i+3]) << 16) |
                                (static_cast<uint32_t>(payload_buffer_data[i+4]) << 8)  |
                                (static_cast<uint32_t>(payload_buffer_data[i+5]));
                    settings_f.payload.entries.push_back(entry);
                }
                static_cast<SideProtocol*>(this)->on(std::move(settings_f));
                break;
            }
            
            case FrameType::PUSH_PROMISE: {
                Http2FrameData<PushPromiseFrame> pp_f;
                pp_f.header = _current_frame_header;
                const uint8_t* p_data = payload_buffer_data;
                std::size_t p_len = payload_buffer_size;
                uint8_t pad_length = 0;

                if (_current_frame_header.flags & FLAG_PADDED) {
                    if (p_len == 0) { 
                        this->not_ok(ErrorCode::FRAME_SIZE_ERROR); 
                        static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                            ErrorCode::FRAME_SIZE_ERROR, "Padded PUSH_PROMISE frame too short for Pad Length.", 
                            _current_frame_header.get_stream_id()); 
                        return false; 
                    }
                    pad_length = p_data[0];
                    p_data++; 
                    p_len--;
                    if (pad_length > p_len) { 
                        this->not_ok(ErrorCode::PROTOCOL_ERROR); 
                        static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                            ErrorCode::PROTOCOL_ERROR, "Pad Length in PUSH_PROMISE frame exceeds payload size.", 
                            _current_frame_header.get_stream_id()); 
                        return false; 
                    }
                }
                if (p_len < (4 + pad_length)) { 
                    this->not_ok(ErrorCode::FRAME_SIZE_ERROR); 
                    static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                        ErrorCode::FRAME_SIZE_ERROR, "PUSH_PROMISE frame too short for Promised Stream ID.", 
                        _current_frame_header.get_stream_id()); 
                    return false; 
                }
                
                pp_f.payload.promised_stream_id = (static_cast<uint32_t>(p_data[0] & 0x7F) << 24) | // Mask R bit
                                                (static_cast<uint32_t>(p_data[1]) << 16) |
                                                (static_cast<uint32_t>(p_data[2]) << 8)  |
                                                (static_cast<uint32_t>(p_data[3]));
                p_data += 4; 
                p_len -= 4;
                pp_f.payload.header_block_fragment.assign(p_data, p_data + (p_len - pad_length));
                static_cast<SideProtocol*>(this)->on(std::move(pp_f));
                break;
            }
            
            case FrameType::PING: {
                if (payload_buffer_size != 8) { 
                    this->not_ok(ErrorCode::FRAME_SIZE_ERROR); 
                    static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                        ErrorCode::FRAME_SIZE_ERROR, "PING frame payload incorrect size.", 
                        _current_frame_header.get_stream_id()); 
                    return false; 
                }
                Http2FrameData<PingFrame> ping_f;
                ping_f.header = _current_frame_header;
                std::copy(payload_buffer_data, payload_buffer_data + payload_buffer_size, 
                         ping_f.payload.opaque_data.begin());
                static_cast<SideProtocol*>(this)->on(std::move(ping_f));
                break;
            }
            
            case FrameType::GOAWAY: {
                if (payload_buffer_size < 8) { 
                    this->not_ok(ErrorCode::FRAME_SIZE_ERROR); 
                    static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                        ErrorCode::FRAME_SIZE_ERROR, "GOAWAY frame payload too short.", 
                        _current_frame_header.get_stream_id()); 
                    return false; 
                }
                
                Http2FrameData<GoAwayFrame> goaway_f;
                goaway_f.header = _current_frame_header;
                goaway_f.payload.last_stream_id = (static_cast<uint32_t>(payload_buffer_data[0] & 0x7F) << 24) | // Mask R bit
                                                 (static_cast<uint32_t>(payload_buffer_data[1]) << 16) |
                                                 (static_cast<uint32_t>(payload_buffer_data[2]) << 8)  |
                                                 (static_cast<uint32_t>(payload_buffer_data[3]));
                goaway_f.payload.error_code = static_cast<ErrorCode>(
                    (static_cast<uint32_t>(payload_buffer_data[4]) << 24) |
                    (static_cast<uint32_t>(payload_buffer_data[5]) << 16) |
                    (static_cast<uint32_t>(payload_buffer_data[6]) << 8)  |
                    (static_cast<uint32_t>(payload_buffer_data[7]))
                );
                if (payload_buffer_size > 8) {
                    goaway_f.payload.additional_debug_data.assign(payload_buffer_data + 8, 
                                                                payload_buffer_data + payload_buffer_size);
                }
                
                static_cast<SideProtocol*>(this)->on(std::move(goaway_f));
                break;
            }
            
            case FrameType::WINDOW_UPDATE: {
                if (payload_buffer_size != 4) { 
                    this->not_ok(ErrorCode::FRAME_SIZE_ERROR); 
                    static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                        ErrorCode::FRAME_SIZE_ERROR, "WINDOW_UPDATE frame payload incorrect size.", 
                        _current_frame_header.get_stream_id()); 
                    return false; 
                }
                
                Http2FrameData<WindowUpdateFrame> wu_f;
                wu_f.header = _current_frame_header;
                wu_f.payload.window_size_increment = (static_cast<uint32_t>(payload_buffer_data[0] & 0x7F) << 24) | // Mask R bit
                                                    (static_cast<uint32_t>(payload_buffer_data[1]) << 16) |
                                                    (static_cast<uint32_t>(payload_buffer_data[2]) << 8)  |
                                                    (static_cast<uint32_t>(payload_buffer_data[3]));
                
                // Validate window size increment
                if (wu_f.payload.window_size_increment == 0) {
                    this->not_ok(ErrorCode::PROTOCOL_ERROR); 
                    static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                        ErrorCode::PROTOCOL_ERROR, "WINDOW_UPDATE with zero increment", 
                        _current_frame_header.get_stream_id()); 
                    return false;
                }
                
                // Check for suspiciously large values
                if (wu_f.payload.window_size_increment > 0x7FFFFFFF) {
                    this->not_ok(ErrorCode::FLOW_CONTROL_ERROR); 
                    static_cast<SideProtocol*>(this)->handle_framer_detected_error(
                        ErrorCode::FLOW_CONTROL_ERROR, "WINDOW_UPDATE increment exceeds maximum", 
                        _current_frame_header.get_stream_id()); 
                    return false;
                }
                
                static_cast<SideProtocol*>(this)->on(std::move(wu_f));
                break;
            }
            
            case FrameType::CONTINUATION: {
                Http2FrameData<ContinuationFrame> cont_f;
                cont_f.header = _current_frame_header;
                cont_f.payload.header_block_fragment.assign(payload_buffer_data, 
                                                           payload_buffer_data + payload_buffer_size);
                static_cast<SideProtocol*>(this)->on(std::move(cont_f));
                break;
            }
            
            default:
                // Unknown frame type - ignore per RFC 9113
                break;
        }
        return this->ok();
    }

}; // class Http2Protocol

} // namespace qb::protocol::http2

namespace qb::allocator {

    // --- Declarations for Http2FrameData<T> Specializations ---
    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::DataFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::DataFrame>& frame_to_send
    );

    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::HeadersFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::HeadersFrame>& frame_to_send
    );

    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::PriorityFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::PriorityFrame>& frame_to_send
    );

    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::RstStreamFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::RstStreamFrame>& frame_to_send
    );

    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::SettingsFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::SettingsFrame>& frame_to_send
    );

    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::PushPromiseFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::PushPromiseFrame>& frame_to_send
    );

    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::PingFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::PingFrame>& frame_to_send
    );

    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::GoAwayFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::GoAwayFrame>& frame_to_send
    );

    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::WindowUpdateFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::WindowUpdateFrame>& frame_to_send
    );

    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::ContinuationFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::ContinuationFrame>& frame_to_send
    );

} // namespace qb::allocator
