/**
 * @file qbm/http/2/protocol/base.h
 * @brief HTTP/2 protocol base implementation for qb-io framework
 *
 * This file provides the foundational HTTP/2 protocol parsing and framing
 * infrastructure built on top of the qb-io asynchronous framework. It includes:
 *
 * - Complete HTTP/2 frame parsing according to RFC 9113
 * - Connection preface validation and handling
 * - State machine-based frame processing
 * - Frame header parsing and payload extraction
 * - Protocol error detection and handling
 * - Support for all HTTP/2 frame types
 * - Flow control and settings management
 * - Template-based design for client/server specialization
 *
 * The parser implements a robust state machine with three main states:
 * preface validation, frame header parsing, and frame payload processing.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http2
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
#include "./stream.h"

/**
 * @brief HTTP/2 connection preface bytes as specified in RFC 9113
 */
constexpr char HTTP2_CONNECTION_PREFACE_BYTES[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/**
 * @brief HTTP/2 connection preface as string_view
 */
constexpr std::string_view HTTP2_CONNECTION_PREFACE(HTTP2_CONNECTION_PREFACE_BYTES, sizeof(HTTP2_CONNECTION_PREFACE_BYTES) - 1);

namespace qb::protocol::http2 {

// --- Binary Utilities ---

/**
 * @brief Extract a 16-bit integer from big-endian byte array
 * @param data Pointer to byte data
 * @return Extracted 16-bit value
 */
[[nodiscard]] inline uint16_t extract_uint16_be(const uint8_t* data) noexcept {
    return (static_cast<uint16_t>(data[0]) << 8) | 
           static_cast<uint16_t>(data[1]);
}

/**
 * @brief Extract a 32-bit integer from big-endian byte array
 * @param data Pointer to byte data
 * @return Extracted 32-bit value
 */
[[nodiscard]] inline uint32_t extract_uint32_be(const uint8_t* data) noexcept {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8)  |
           static_cast<uint32_t>(data[3]);
}

/**
 * @brief Extract a 32-bit integer from big-endian byte array with reserved bit masking
 * @param data Pointer to byte data
 * @return Extracted 31-bit value (R bit masked)
 */
[[nodiscard]] inline uint32_t extract_uint31_be(const uint8_t* data) noexcept {
    return (static_cast<uint32_t>(data[0] & 0x7F) << 24) | // Mask R bit
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8)  |
           static_cast<uint32_t>(data[3]);
}

/**
 * @brief Encode a 16-bit integer to big-endian byte array
 * @param value Value to encode
 * @param data Output byte array (must be at least 2 bytes)
 */
inline void encode_uint16_be(uint16_t value, uint8_t* data) noexcept {
    data[0] = static_cast<uint8_t>((value >> 8) & 0xFF);
    data[1] = static_cast<uint8_t>(value & 0xFF);
}

/**
 * @brief Encode a 32-bit integer to big-endian byte array
 * @param value Value to encode
 * @param data Output byte array (must be at least 4 bytes)
 */
inline void encode_uint32_be(uint32_t value, uint8_t* data) noexcept {
    data[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
    data[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    data[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    data[3] = static_cast<uint8_t>(value & 0xFF);
}

/**
 * @brief Helper class for HTTP/2 SETTINGS processing
 * 
 * Provides common validation and processing logic for SETTINGS frames
 * to avoid duplication between client and server implementations.
 */
class SettingsHelper {
public:
    /**
     * @brief Validation result for a setting
     */
    struct ValidationResult {
        bool is_valid = true;
        ErrorCode error_code = ErrorCode::NO_ERROR;
        std::string error_message;
        
        ValidationResult() = default;
        ValidationResult(ErrorCode code, std::string msg) 
            : is_valid(false), error_code(code), error_message(std::move(msg)) {}
            
        static ValidationResult valid() { return ValidationResult{}; }
        static ValidationResult invalid(ErrorCode code, std::string msg) {
            return ValidationResult{code, std::move(msg)};
        }
    };

    /**
     * @brief Validate a single setting entry
     * @param id Setting identifier
     * @param value Setting value
     * @param is_from_client Whether setting came from client (affects validation)
     * @return Validation result
     */
    static ValidationResult validate_setting(Http2SettingIdentifier id, uint32_t value, bool /*is_from_client*/) {
        switch (id) {
            case Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE:
                // No RFC-mandated limits, decoder will cap internally
                return ValidationResult::valid();
                
            case Http2SettingIdentifier::SETTINGS_ENABLE_PUSH:
                if (value > 1) {
                    return ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                        "SETTINGS_ENABLE_PUSH must be 0 or 1, got: " + std::to_string(value));
                }
                return ValidationResult::valid();
                
            case Http2SettingIdentifier::SETTINGS_MAX_CONCURRENT_STREAMS:
                // No specific limits in RFC
                return ValidationResult::valid();
                
            case Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE:
                if (value > MAX_WINDOW_SIZE_LIMIT) {
                    return ValidationResult::invalid(ErrorCode::FLOW_CONTROL_ERROR, 
                        "SETTINGS_INITIAL_WINDOW_SIZE exceeds maximum: " + std::to_string(value));
                }
                return ValidationResult::valid();
                
            case Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE:
                if (value < MIN_MAX_FRAME_SIZE || value > MAX_FRAME_SIZE_LIMIT) {
                    return ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                        "SETTINGS_MAX_FRAME_SIZE out of range [" + std::to_string(MIN_MAX_FRAME_SIZE) + 
                        ", " + std::to_string(MAX_FRAME_SIZE_LIMIT) + "]: " + std::to_string(value));
                }
                return ValidationResult::valid();
                
            case Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE:
                // No specific limits in RFC
                return ValidationResult::valid();
                
            case Http2SettingIdentifier::SETTINGS_ENABLE_CONNECT_PROTOCOL:
                // Implementation specific - for now just accept any value
                return ValidationResult::valid();
                
            default:
                // Unknown settings MUST be ignored per RFC 9113
                return ValidationResult::valid();
        }
    }

    /**
     * @brief Get default settings map for a given role
     * @param is_server Whether this is for server (affects ENABLE_PUSH default)
     * @return Default settings map
     */
    static qb::unordered_map<Http2SettingIdentifier, uint32_t> get_default_settings(bool is_server) {
        qb::unordered_map<Http2SettingIdentifier, uint32_t> settings;
        settings[Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE] = DEFAULT_SETTINGS_HEADER_TABLE_SIZE;
        settings[Http2SettingIdentifier::SETTINGS_ENABLE_PUSH] = 
            is_server ? DEFAULT_SETTINGS_ENABLE_PUSH_SERVER : DEFAULT_SETTINGS_ENABLE_PUSH_CLIENT;
        settings[Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE] = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;
        settings[Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE] = DEFAULT_SETTINGS_MAX_FRAME_SIZE;
        return settings;
    }

    /**
     * @brief Calculate safe max frame size from settings
     * @param settings Settings map
     * @return Safe max frame size value
     */
    static uint32_t calculate_safe_max_frame_size(const qb::unordered_map<Http2SettingIdentifier, uint32_t>& settings) {
        auto it = settings.find(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE);
        if (it != settings.end()) {
            uint32_t value = it->second;
            if (value >= MIN_MAX_FRAME_SIZE && value <= MAX_FRAME_SIZE_LIMIT) {
                return value;
            }
        }
        return DEFAULT_SETTINGS_MAX_FRAME_SIZE;
    }
};

/**
 * @brief Helper class for HTTP/2 header validation
 * 
 * Provides validation logic for HTTP/2 headers according to RFC 9113
 */
class HeaderValidator {
public:
    /**
     * @brief Check if header name is forbidden in HTTP/2
     * @param name Header name (lowercase)
     * @return true if header is forbidden
     */
    static bool is_forbidden_header(std::string_view name) {
        static const std::array<std::string_view, 8> forbidden = {
            "connection", "upgrade", "http2-settings", "te",
            "transfer-encoding", "proxy-connection", "keep-alive", "host"
        };
        
        // Exception: "te: trailers" is allowed
        if (name == "te") return false; // Let caller check the value
        
        return std::find(forbidden.begin(), forbidden.end(), name) != forbidden.end();
    }

    /**
     * @brief Check if header name is a pseudo-header
     * @param name Header name
     * @return true if it's a pseudo-header (starts with ':')
     */
    static bool is_pseudo_header(std::string_view name) {
        return !name.empty() && name[0] == ':';
    }

    /**
     * @brief Validate pseudo-header order (must come before regular headers)
     * @param headers List of header fields
     * @return true if order is valid
     */
    static bool validate_pseudo_header_order(const std::vector<qb::protocol::hpack::HeaderField>& headers) {
        bool regular_header_seen = false;
        
        for (const auto& header : headers) {
            if (is_pseudo_header(header.name)) {
                if (regular_header_seen) {
                    return false; // Pseudo-header after regular header
                }
            } else {
                regular_header_seen = true;
            }
        }
        return true;
    }

    /**
     * @brief Validate request pseudo-headers
     * @param headers List of header fields
     * @return Validation result with details
     */
    static SettingsHelper::ValidationResult validate_request_pseudo_headers(
            const std::vector<qb::protocol::hpack::HeaderField>& headers) {
        bool has_method = false, has_path = false, has_scheme = false;
        
        for (const auto& header : headers) {
            if (!is_pseudo_header(header.name)) continue;
            
            if (header.name == ":method") {
                if (has_method) {
                    return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                        "Duplicate :method pseudo-header");
                }
                has_method = true;
                if (header.value.empty()) {
                    return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                        "Empty :method value");
                }
            } else if (header.name == ":path") {
                if (has_path) {
                    return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                        "Duplicate :path pseudo-header");
                }
                has_path = true;
                if (header.value.empty()) {
                    return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                        "Empty :path value");
                }
            } else if (header.name == ":scheme") {
                if (has_scheme) {
                    return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                        "Duplicate :scheme pseudo-header");
                }
                has_scheme = true;
                if (header.value.empty()) {
                    return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                        "Empty :scheme value");
                }
            } else if (header.name == ":authority") {
                // Optional, but if present must not be empty
                if (header.value.empty()) {
                    return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                        "Empty :authority value");
                }
            } else {
                return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                    "Unknown pseudo-header: " + std::string(header.name));
            }
        }
        
        if (!has_method || !has_path || !has_scheme) {
            return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                "Missing required pseudo-headers (:method, :path, :scheme)");
        }
        
        return SettingsHelper::ValidationResult::valid();
    }

    /**
     * @brief Validate response pseudo-headers
     * @param headers List of header fields
     * @return Validation result with details
     */
    static SettingsHelper::ValidationResult validate_response_pseudo_headers(
            const std::vector<qb::protocol::hpack::HeaderField>& headers) {
        bool has_status = false;
        
        for (const auto& header : headers) {
            if (!is_pseudo_header(header.name)) continue;
            
            if (header.name == ":status") {
                if (has_status) {
                    return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                        "Duplicate :status pseudo-header");
                }
                has_status = true;
                if (header.value.empty() || header.value.length() != 3) {
                    return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                        "Invalid :status value: " + std::string(header.value));
                }
                // Basic status code validation
                for (char c : header.value) {
                    if (c < '0' || c > '9') {
                        return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                            "Non-numeric :status value: " + std::string(header.value));
                    }
                }
            } else {
                return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                    "Invalid pseudo-header in response: " + std::string(header.name));
            }
        }
        
        if (!has_status) {
            return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, 
                "Missing required :status pseudo-header");
        }
        
        return SettingsHelper::ValidationResult::valid();
    }
};

/**
 * @brief Helper class for HTTP/2 error handling and reporting
 * 
 * Centralizes error handling logic and provides consistent error reporting
 */
class Http2ErrorHandler {
public:
    /**
     * @brief Check if error should escalate from stream to connection level
     * @param error_code The error code
     * @param stream_id Stream ID (0 for connection-level errors)
     * @return true if error should close the connection
     */
    static bool should_escalate_to_connection(ErrorCode error_code, uint32_t stream_id) {
        // Connection-level errors
        if (stream_id == 0) return true;
        
        switch (error_code) {
            case ErrorCode::PROTOCOL_ERROR:
            case ErrorCode::COMPRESSION_ERROR:
            case ErrorCode::CONNECT_ERROR:
            case ErrorCode::ENHANCE_YOUR_CALM:
            case ErrorCode::INADEQUATE_SECURITY:
            case ErrorCode::HTTP_1_1_REQUIRED:
                return true;
                
            case ErrorCode::INTERNAL_ERROR:
            case ErrorCode::FLOW_CONTROL_ERROR:
            case ErrorCode::SETTINGS_TIMEOUT:
            case ErrorCode::FRAME_SIZE_ERROR:
                return true;
                
            case ErrorCode::STREAM_CLOSED:
            case ErrorCode::REFUSED_STREAM:
            case ErrorCode::CANCEL:
                return false; // Stream-specific errors
                
            default:
                return false;
        }
    }

    /**
     * @brief Format error message for logging
     * @param error_code Error code
     * @param context Context information
     * @param stream_id Stream ID (0 for connection errors)
     * @return Formatted error message
     */
    static std::string format_error_message(ErrorCode error_code, 
                                          const std::string& context, 
                                          uint32_t stream_id = 0) {
        std::string message;
        
        if (stream_id == 0) {
            message = "Connection error: ";
        } else {
            message = "Stream " + std::to_string(stream_id) + " error: ";
        }
        
        message += "ErrorCode=" + std::to_string(static_cast<uint32_t>(error_code));
        
        if (!context.empty()) {
            message += " (" + context + ")";
        }
        
        return message;
    }

    /**
     * @brief Get human-readable error code name
     * @param error_code Error code
     * @return Error code name
     */
    static std::string_view get_error_name(ErrorCode error_code) {
        switch (error_code) {
            case ErrorCode::NO_ERROR:           return "NO_ERROR";
            case ErrorCode::PROTOCOL_ERROR:     return "PROTOCOL_ERROR";
            case ErrorCode::INTERNAL_ERROR:     return "INTERNAL_ERROR";
            case ErrorCode::FLOW_CONTROL_ERROR: return "FLOW_CONTROL_ERROR";
            case ErrorCode::SETTINGS_TIMEOUT:   return "SETTINGS_TIMEOUT";
            case ErrorCode::STREAM_CLOSED:      return "STREAM_CLOSED";
            case ErrorCode::FRAME_SIZE_ERROR:   return "FRAME_SIZE_ERROR";
            case ErrorCode::REFUSED_STREAM:     return "REFUSED_STREAM";
            case ErrorCode::CANCEL:             return "CANCEL";
            case ErrorCode::COMPRESSION_ERROR:  return "COMPRESSION_ERROR";
            case ErrorCode::CONNECT_ERROR:      return "CONNECT_ERROR";
            case ErrorCode::ENHANCE_YOUR_CALM:  return "ENHANCE_YOUR_CALM";
            case ErrorCode::INADEQUATE_SECURITY: return "INADEQUATE_SECURITY";
            case ErrorCode::HTTP_1_1_REQUIRED:  return "HTTP_1_1_REQUIRED";
            default:                            return "UNKNOWN_ERROR";
        }
    }
};

/**
 * @brief Helper class for HTTP/2 stream ID validation and management
 * 
 * Centralizes stream ID validation logic to reduce duplication
 * between client and server implementations.
 */
class StreamIdValidator {
public:
    /**
     * @brief Check if stream ID is valid for client-initiated streams
     * @param stream_id Stream ID to validate
     * @return true if valid for client use
     */
    static bool is_valid_client_stream_id(uint32_t stream_id) {
        return stream_id != 0 && (stream_id % 2 == 1); // Odd numbers only
    }

    /**
     * @brief Check if stream ID is valid for server-initiated streams  
     * @param stream_id Stream ID to validate
     * @return true if valid for server use
     */
    static bool is_valid_server_stream_id(uint32_t stream_id) {
        return stream_id != 0 && (stream_id % 2 == 0); // Even numbers only
    }

    /**
     * @brief Check if stream ID is valid for frames that must use stream 0
     * @param stream_id Stream ID to validate
     * @return true if stream ID is 0
     */
    static bool is_connection_stream_id(uint32_t stream_id) {
        return stream_id == 0;
    }

    /**
     * @brief Validate stream ID for a specific frame type
     * @param frame_type Frame type
     * @param stream_id Stream ID
     * @param is_server Whether this is server-side validation
     * @return Validation result with error details if invalid
     */
    static SettingsHelper::ValidationResult validate_stream_id_for_frame(
        FrameType frame_type, 
        uint32_t stream_id, 
        bool is_server) {
        
        switch (frame_type) {
            case FrameType::SETTINGS:
            case FrameType::PING:
            case FrameType::GOAWAY:
                if (!is_connection_stream_id(stream_id)) {
                    return SettingsHelper::ValidationResult::invalid(
                        ErrorCode::PROTOCOL_ERROR,
                        std::string(get_frame_type_name(frame_type)) + " frame must use stream ID 0"
                    );
                }
                break;

            case FrameType::DATA:
            case FrameType::HEADERS:
            case FrameType::PRIORITY:
            case FrameType::RST_STREAM:
            case FrameType::PUSH_PROMISE:
            case FrameType::CONTINUATION:
                if (is_connection_stream_id(stream_id)) {
                    return SettingsHelper::ValidationResult::invalid(
                        ErrorCode::PROTOCOL_ERROR,
                        std::string(get_frame_type_name(frame_type)) + " frame cannot use stream ID 0"
                    );
                }
                
                // Additional validation for peer-initiated streams
                if (frame_type == FrameType::HEADERS || frame_type == FrameType::PUSH_PROMISE) {
                    if (is_server && !is_valid_client_stream_id(stream_id)) {
                        return SettingsHelper::ValidationResult::invalid(
                            ErrorCode::PROTOCOL_ERROR,
                            "Server received " + std::string(get_frame_type_name(frame_type)) + 
                            " on invalid client stream ID: " + std::to_string(stream_id)
                        );
                    }
                    if (!is_server && frame_type == FrameType::PUSH_PROMISE && 
                        !is_valid_server_stream_id(stream_id)) {
                        return SettingsHelper::ValidationResult::invalid(
                            ErrorCode::PROTOCOL_ERROR,
                            "Client received PUSH_PROMISE with invalid server stream ID: " + 
                            std::to_string(stream_id)
                        );
                    }
                }
                break;

            case FrameType::WINDOW_UPDATE:
                // WINDOW_UPDATE can use stream 0 (connection) or specific stream
                break;

            default:
                // Unknown frame types are ignored per RFC 9113
                break;
        }
        
        return SettingsHelper::ValidationResult::valid();
    }

private:
    /**
     * @brief Get human-readable frame type name
     * @param frame_type Frame type
     * @return Frame type name
     */
    static std::string_view get_frame_type_name(FrameType frame_type) {
        switch (frame_type) {
            case FrameType::DATA:          return "DATA";
            case FrameType::HEADERS:       return "HEADERS";
            case FrameType::PRIORITY:      return "PRIORITY";
            case FrameType::RST_STREAM:    return "RST_STREAM";
            case FrameType::SETTINGS:      return "SETTINGS";
            case FrameType::PUSH_PROMISE:  return "PUSH_PROMISE";
            case FrameType::PING:          return "PING";
            case FrameType::GOAWAY:        return "GOAWAY";
            case FrameType::WINDOW_UPDATE: return "WINDOW_UPDATE";
            case FrameType::CONTINUATION:  return "CONTINUATION";
            default:                       return "UNKNOWN";
        }
    }
};

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

// --- HTTP/2 Protocol parser and framer base class
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
     * @brief Helper to report framing error and set not_ok state
     * @param error_code The error code
     * @param message Error message
     * @param stream_id Stream ID context
     * @return Always returns false for convenience in error paths
     */
    [[nodiscard]] bool report_frame_error(ErrorCode error_code, 
                                         const std::string& message, 
                                         uint32_t stream_id = 0) noexcept {
        this->not_ok(error_code);
        static_cast<SideProtocol*>(this)->handle_framer_detected_error(error_code, message, stream_id);
        return false;
    }

    /**
     * @brief Helper to validate frame payload size
     * @param expected_size Expected payload size
     * @param actual_size Actual payload size
     * @param frame_type_name Frame type name for error message
     * @param stream_id Stream ID context
     * @return false if validation fails, true otherwise
     */
    [[nodiscard]] bool validate_payload_size(std::size_t expected_size, 
                                            std::size_t actual_size, 
                                            const std::string& frame_type_name,
                                            uint32_t stream_id) noexcept {
        if (expected_size != actual_size) {
            return report_frame_error(ErrorCode::FRAME_SIZE_ERROR, 
                                    frame_type_name + " frame payload incorrect size.", 
                                    stream_id);
        }
        return true;
    }

    /**
     * @brief Helper to validate minimum payload size
     * @param min_size Minimum expected payload size
     * @param actual_size Actual payload size
     * @param frame_type_name Frame type name for error message
     * @param stream_id Stream ID context
     * @return false if validation fails, true otherwise
     */
    [[nodiscard]] bool validate_min_payload_size(std::size_t min_size, 
                                                std::size_t actual_size, 
                                                const std::string& frame_type_name,
                                                uint32_t stream_id) noexcept {
        if (actual_size < min_size) {
            return report_frame_error(ErrorCode::FRAME_SIZE_ERROR, 
                                    frame_type_name + " frame payload too short.", 
                                    stream_id);
        }
        return true;
    }

    /**
     * @brief Helper to validate padded frame structure
     * @param p_data Pointer to payload data
     * @param p_len Payload length
     * @param frame_type_name Frame type name for error message
     * @param stream_id Stream ID context
     * @return Pair<pad_length, success>
     */
    [[nodiscard]] std::pair<uint8_t, bool> validate_padded_frame(const uint8_t*& p_data, 
                                                               std::size_t& p_len, 
                                                               const std::string& frame_type_name,
                                                               uint32_t stream_id) noexcept {
        if (p_len == 0) {
            (void)report_frame_error(ErrorCode::FRAME_SIZE_ERROR, 
                             "Padded " + frame_type_name + " frame too short for Pad Length.", 
                             stream_id);
            return {0, false};
        }
        
        uint8_t pad_length = p_data[0];
        p_data++;
        p_len--;
        
        if (pad_length > p_len) {
            (void)report_frame_error(ErrorCode::PROTOCOL_ERROR, 
                             "Pad Length in " + frame_type_name + " frame exceeds payload size.", 
                             stream_id);
            return {0, false};
        }
        
        return {pad_length, true};
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

        const uint8_t* payload_data = reinterpret_cast<const uint8_t*>(payload_view.data());
        std::size_t payload_size = payload_view.size();

        switch (_current_frame_header.get_type()) {
            case FrameType::DATA:
                return handle_data_frame_payload(payload_data, payload_size);
            case FrameType::HEADERS:
                return handle_headers_frame_payload(payload_data, payload_size);
            case FrameType::PRIORITY:
                return handle_priority_frame_payload(payload_data, payload_size);
            case FrameType::RST_STREAM:
                return handle_rst_stream_frame_payload(payload_data, payload_size);
            case FrameType::SETTINGS:
                return handle_settings_frame_payload(payload_data, payload_size);
            case FrameType::PUSH_PROMISE:
                return handle_push_promise_frame_payload(payload_data, payload_size);
            case FrameType::PING:
                return handle_ping_frame_payload(payload_data, payload_size);
            case FrameType::GOAWAY:
                return handle_goaway_frame_payload(payload_data, payload_size);
            case FrameType::WINDOW_UPDATE:
                return handle_window_update_frame_payload(payload_data, payload_size);
            case FrameType::CONTINUATION:
                return handle_continuation_frame_payload(payload_data, payload_size);
            default:
                // Unknown frame type - ignore per RFC 9113
                return true;
        }
    }

    /**
     * @brief Handle DATA frame payload parsing
     */
    [[nodiscard]] bool handle_data_frame_payload(const uint8_t* payload_data, std::size_t payload_size) noexcept {
        Http2FrameData<DataFrame> data_f;
        data_f.header = _current_frame_header;
        const uint8_t* p_data = payload_data;
        std::size_t p_len = payload_size;

        if (_current_frame_header.flags & FLAG_PADDED) {
            auto [pad_length, success] = validate_padded_frame(p_data, p_len, "DATA", _current_frame_header.get_stream_id());
            if (!success) return false;
            
            data_f.payload.data_payload.assign(p_data, p_data + (p_len - pad_length));
        } else {
            data_f.payload.data_payload.assign(payload_data, payload_data + payload_size);
        }
        
        static_cast<SideProtocol*>(this)->on(std::move(data_f));
        return true;
    }

    /**
     * @brief Handle HEADERS frame payload parsing
     */
    [[nodiscard]] bool handle_headers_frame_payload(const uint8_t* payload_data, std::size_t payload_size) noexcept {
        Http2FrameData<HeadersFrame> headers_f;
        headers_f.header = _current_frame_header;
        const uint8_t* p_data = payload_data;
        std::size_t p_len = payload_size;
        uint8_t pad_length = 0;

        if (_current_frame_header.flags & FLAG_PADDED) {
            auto [pad_len, success] = validate_padded_frame(p_data, p_len, "HEADERS", _current_frame_header.get_stream_id());
            if (!success) return false;
            pad_length = pad_len;
        }

        if (_current_frame_header.flags & FLAG_PRIORITY) {
            if (!validate_min_payload_size(5 + pad_length, payload_size, "HEADERS with PRIORITY flag", _current_frame_header.get_stream_id())) {
                return false;
            }
            
            Http2PriorityData pri_data;
            uint32_t stream_dep_raw = extract_uint32_be(p_data);
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
        return true;
    }

    /**
     * @brief Handle PRIORITY frame payload parsing
     */
    [[nodiscard]] bool handle_priority_frame_payload(const uint8_t* payload_data, std::size_t payload_size) noexcept {
        if (!validate_payload_size(5, payload_size, "PRIORITY", _current_frame_header.get_stream_id())) {
            return false;
        }
        
        Http2FrameData<PriorityFrame> priority_f;
        priority_f.header = _current_frame_header;
        uint32_t stream_dep_raw = extract_uint32_be(payload_data);
        priority_f.payload.priority_data.exclusive_dependency = (stream_dep_raw >> 31) & 0x1;
        priority_f.payload.priority_data.stream_dependency = stream_dep_raw & 0x7FFFFFFF;
        priority_f.payload.priority_data.weight = payload_data[4];
        
        static_cast<SideProtocol*>(this)->on(std::move(priority_f));
        return true;
    }

    /**
     * @brief Handle RST_STREAM frame payload parsing
     */
    [[nodiscard]] bool handle_rst_stream_frame_payload(const uint8_t* payload_data, std::size_t payload_size) noexcept {
        if (!validate_payload_size(4, payload_size, "RST_STREAM", _current_frame_header.get_stream_id())) {
            return false;
        }
        
        Http2FrameData<RstStreamFrame> rst_f;
        rst_f.header = _current_frame_header;
        rst_f.payload.error_code = static_cast<ErrorCode>(extract_uint32_be(payload_data));
        
        static_cast<SideProtocol*>(this)->on(std::move(rst_f));
        return true;
    }

    /**
     * @brief Handle SETTINGS frame payload parsing
     */
    [[nodiscard]] bool handle_settings_frame_payload(const uint8_t* payload_data, std::size_t payload_size) noexcept {
        if (_current_frame_header.flags & FLAG_ACK) {
            return report_frame_error(ErrorCode::FRAME_SIZE_ERROR, "SETTINGS ACK frame with payload.", _current_frame_header.get_stream_id());
        }
        
        if (payload_size % 6 != 0) {
            return report_frame_error(ErrorCode::FRAME_SIZE_ERROR, "SETTINGS frame payload size not a multiple of 6.", _current_frame_header.get_stream_id());
        }
        
        Http2FrameData<SettingsFrame> settings_f;
        settings_f.header = _current_frame_header;
        settings_f.payload.entries.reserve(payload_size / 6);
        
        for (size_t i = 0; i < payload_size; i += 6) {
            SettingsFrameEntry entry;
            entry.identifier = static_cast<Http2SettingIdentifier>(extract_uint16_be(payload_data + i));
            entry.value = extract_uint32_be(payload_data + i + 2);
            settings_f.payload.entries.push_back(entry);
        }
        
        static_cast<SideProtocol*>(this)->on(std::move(settings_f));
        return true;
    }

    /**
     * @brief Handle PUSH_PROMISE frame payload parsing
     */
    [[nodiscard]] bool handle_push_promise_frame_payload(const uint8_t* payload_data, std::size_t payload_size) noexcept {
        Http2FrameData<PushPromiseFrame> pp_f;
        pp_f.header = _current_frame_header;
        const uint8_t* p_data = payload_data;
        std::size_t p_len = payload_size;
        uint8_t pad_length = 0;

        if (_current_frame_header.flags & FLAG_PADDED) {
            auto [pad_len, success] = validate_padded_frame(p_data, p_len, "PUSH_PROMISE", _current_frame_header.get_stream_id());
            if (!success) return false;
            pad_length = pad_len;
        }
        
        if (!validate_min_payload_size(4 + pad_length, payload_size, "PUSH_PROMISE", _current_frame_header.get_stream_id())) {
            return false;
        }
        
        pp_f.payload.promised_stream_id = extract_uint31_be(p_data); // Masks R bit automatically
        p_data += 4;
        p_len -= 4;
        pp_f.payload.header_block_fragment.assign(p_data, p_data + (p_len - pad_length));
        
        static_cast<SideProtocol*>(this)->on(std::move(pp_f));
        return true;
    }

    /**
     * @brief Handle PING frame payload parsing
     */
    [[nodiscard]] bool handle_ping_frame_payload(const uint8_t* payload_data, std::size_t payload_size) noexcept {
        if (!validate_payload_size(8, payload_size, "PING", _current_frame_header.get_stream_id())) {
            return false;
        }
        
        Http2FrameData<PingFrame> ping_f;
        ping_f.header = _current_frame_header;
        std::copy(payload_data, payload_data + payload_size, ping_f.payload.opaque_data.begin());
        
        static_cast<SideProtocol*>(this)->on(std::move(ping_f));
        return true;
    }

    /**
     * @brief Handle GOAWAY frame payload parsing
     */
    [[nodiscard]] bool handle_goaway_frame_payload(const uint8_t* payload_data, std::size_t payload_size) noexcept {
        if (!validate_min_payload_size(8, payload_size, "GOAWAY", _current_frame_header.get_stream_id())) {
            return false;
        }
        
        Http2FrameData<GoAwayFrame> goaway_f;
        goaway_f.header = _current_frame_header;
        goaway_f.payload.last_stream_id = extract_uint31_be(payload_data); // Masks R bit automatically
        goaway_f.payload.error_code = static_cast<ErrorCode>(extract_uint32_be(payload_data + 4));
        
        if (payload_size > 8) {
            goaway_f.payload.additional_debug_data.assign(payload_data + 8, payload_data + payload_size);
        }
        
        static_cast<SideProtocol*>(this)->on(std::move(goaway_f));
        return true;
    }

    /**
     * @brief Handle WINDOW_UPDATE frame payload parsing
     */
    [[nodiscard]] bool handle_window_update_frame_payload(const uint8_t* payload_data, std::size_t payload_size) noexcept {
        if (!validate_payload_size(4, payload_size, "WINDOW_UPDATE", _current_frame_header.get_stream_id())) {
            return false;
        }
        
        Http2FrameData<WindowUpdateFrame> wu_f;
        wu_f.header = _current_frame_header;
        wu_f.payload.window_size_increment = extract_uint31_be(payload_data); // Masks R bit automatically
        
        // Validate window size increment
        if (wu_f.payload.window_size_increment == 0) {
            return report_frame_error(ErrorCode::PROTOCOL_ERROR, "WINDOW_UPDATE with zero increment", _current_frame_header.get_stream_id());
        }
        
        if (wu_f.payload.window_size_increment > 0x7FFFFFFF) {
            return report_frame_error(ErrorCode::FLOW_CONTROL_ERROR, "WINDOW_UPDATE increment exceeds maximum", _current_frame_header.get_stream_id());
        }
        
        static_cast<SideProtocol*>(this)->on(std::move(wu_f));
        return true;
    }

    /**
     * @brief Handle CONTINUATION frame payload parsing
     */
    [[nodiscard]] bool handle_continuation_frame_payload(const uint8_t* payload_data, std::size_t payload_size) noexcept {
        Http2FrameData<ContinuationFrame> cont_f;
        cont_f.header = _current_frame_header;
        cont_f.payload.header_block_fragment.assign(payload_data, payload_data + payload_size);
        
        static_cast<SideProtocol*>(this)->on(std::move(cont_f));
        return true;
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
