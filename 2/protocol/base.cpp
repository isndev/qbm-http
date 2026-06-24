/**
 * @file qbm/http/2/protocol/base.cpp
 * @brief Out-of-line definitions for the HTTP/2 protocol base helpers
 *
 * This translation unit holds the non-template helper implementations declared
 * in @ref qbm/http/2/protocol/base.h (SETTINGS validation, header validation,
 * error reporting and stream-id validation). The template-based parser/framer
 * (@ref qb::protocol::http2::Http2Protocol) and the binary utilities remain
 * header-only by design.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./base.h"

namespace qb::protocol::http2 {

// --- SettingsHelper ---

SettingsHelper::ValidationResult
SettingsHelper::validate_setting(Http2SettingIdentifier id, uint32_t value, bool /*is_from_client*/) {
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
                                                 "SETTINGS_MAX_FRAME_SIZE out of range [" + std::to_string(MIN_MAX_FRAME_SIZE) + ", "
                                                     + std::to_string(MAX_FRAME_SIZE_LIMIT) + "]: " + std::to_string(value));
            }
            return ValidationResult::valid();

        case Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE:
            // No specific limits in RFC
            return ValidationResult::valid();

        case Http2SettingIdentifier::SETTINGS_ENABLE_CONNECT_PROTOCOL:
            if (value > 1) {
                return ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR,
                                                 "SETTINGS_ENABLE_CONNECT_PROTOCOL must be 0 or 1, got: " + std::to_string(value));
            }
            return ValidationResult::valid();

        default:
            // Unknown settings MUST be ignored per RFC 9113
            return ValidationResult::valid();
    }
}

qb::unordered_map<Http2SettingIdentifier, uint32_t>
SettingsHelper::get_default_settings(bool is_server) {
    qb::unordered_map<Http2SettingIdentifier, uint32_t> settings;
    settings[Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE] = DEFAULT_SETTINGS_HEADER_TABLE_SIZE;
    settings[Http2SettingIdentifier::SETTINGS_ENABLE_PUSH] =
        is_server ? DEFAULT_SETTINGS_ENABLE_PUSH_SERVER : DEFAULT_SETTINGS_ENABLE_PUSH_CLIENT;
    settings[Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE] = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;
    settings[Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE]      = DEFAULT_SETTINGS_MAX_FRAME_SIZE;
    return settings;
}

uint32_t
SettingsHelper::calculate_safe_max_frame_size(const qb::unordered_map<Http2SettingIdentifier, uint32_t> &settings) {
    auto it = settings.find(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE);
    if (it != settings.end()) {
        uint32_t value = it->second;
        if (value >= MIN_MAX_FRAME_SIZE && value <= MAX_FRAME_SIZE_LIMIT) {
            return value;
        }
    }
    return DEFAULT_SETTINGS_MAX_FRAME_SIZE;
}

// --- HeaderValidator ---

bool
HeaderValidator::is_forbidden_header(std::string_view name) {
    static constexpr std::array<std::string_view, 8> forbidden = {"connection",        "upgrade",          "http2-settings", "te",
                                                                  "transfer-encoding", "proxy-connection", "keep-alive",     "host"};

    // Exception: "te: trailers" is allowed
    if (name == "te")
        return false; // Let caller check the value

    return std::find(forbidden.begin(), forbidden.end(), name) != forbidden.end();
}

bool
HeaderValidator::is_valid_request_te_value(std::string_view value) noexcept {
    std::string_view remaining = value;
    bool             saw_token = false;

    while (!remaining.empty()) {
        const auto             comma = remaining.find(',');
        const std::string_view token =
            qb::http::utility::trim_http_whitespace(comma == std::string_view::npos ? remaining : remaining.substr(0, comma));

        if (!token.empty()) {
            saw_token = true;
            if (!qb::http::utility::iequals(token, "trailers")) {
                return false;
            }
        }

        if (comma == std::string_view::npos) {
            break;
        }
        remaining.remove_prefix(comma + 1);
    }

    return saw_token;
}

bool
HeaderValidator::is_valid_header_field(std::string_view name, std::string_view value) noexcept {
    if (name.empty()) {
        return false;
    }

    for (unsigned char c : name) {
        if (c == 0x00 || c == 0x0D || c == 0x0A || (c >= 'A' && c <= 'Z')) {
            return false;
        }
        const bool is_valid_char = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '!' || c == '#' || c == '$' || c == '%' || c == '&'
                                   || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|'
                                   || c == '~';
        if (!is_valid_char) {
            return false;
        }
    }

    return is_valid_header_value(value);
}

bool
HeaderValidator::is_valid_header_value(std::string_view value) noexcept {
    for (unsigned char c : value) {
        if (c == 0x00 || c == 0x0D || c == 0x0A) {
            return false;
        }
        if ((c < 0x20 && c != 0x09) || c == 0x7F) {
            return false;
        }
    }

    return true;
}

bool
HeaderValidator::validate_pseudo_header_order(const std::vector<qb::protocol::hpack::HeaderField> &headers) noexcept {
    bool regular_header_seen = false;

    for (const auto &header : headers) {
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

std::optional<std::uint64_t>
HeaderValidator::parse_content_length(std::string_view value) noexcept {
    value = qb::http::utility::trim_http_whitespace(value);
    if (value.empty()) {
        return std::nullopt;
    }
    std::uint64_t parsed = 0;
    for (unsigned char c : value) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
        const auto digit = static_cast<std::uint64_t>(c - '0');
        if (parsed > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
            return std::nullopt;
        }
        parsed = parsed * 10 + digit;
    }
    return parsed;
}

SettingsHelper::ValidationResult
HeaderValidator::validate_request_pseudo_headers(const std::vector<qb::protocol::hpack::HeaderField> &headers) {
    bool has_method = false, has_path = false, has_scheme = false, has_authority = false;

    for (const auto &header : headers) {
        if (!is_pseudo_header(header.name))
            continue;

        if (header.name == ":method") {
            if (has_method) {
                return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, "Duplicate :method pseudo-header");
            }
            has_method = true;
            if (header.value.empty()) {
                return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, "Empty :method value");
            }
        } else if (header.name == ":path") {
            if (has_path) {
                return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, "Duplicate :path pseudo-header");
            }
            has_path = true;
            if (header.value.empty()) {
                return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, "Empty :path value");
            }
        } else if (header.name == ":scheme") {
            if (has_scheme) {
                return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, "Duplicate :scheme pseudo-header");
            }
            has_scheme = true;
            if (header.value.empty()) {
                return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, "Empty :scheme value");
            }
        } else if (header.name == ":authority") {
            if (has_authority) {
                return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, "Duplicate :authority pseudo-header");
            }
            has_authority = true;
            if (header.value.empty()) {
                return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, "Empty :authority value");
            }
        } else {
            return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, "Unknown pseudo-header: " + std::string(header.name));
        }
    }

    if (!has_method || !has_path || !has_scheme || !has_authority) {
        return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR,
                                                         "Missing required pseudo-headers (:method, :path, :scheme, :authority)");
    }

    return SettingsHelper::ValidationResult::valid();
}

SettingsHelper::ValidationResult
HeaderValidator::validate_response_pseudo_headers(const std::vector<qb::protocol::hpack::HeaderField> &headers) {
    bool has_status = false;

    for (const auto &header : headers) {
        if (!is_pseudo_header(header.name))
            continue;

        if (header.name == ":status") {
            if (has_status) {
                return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, "Duplicate :status pseudo-header");
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
        return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, "Missing required :status pseudo-header");
    }

    return SettingsHelper::ValidationResult::valid();
}

// --- Http2ErrorHandler ---

bool
Http2ErrorHandler::should_escalate_to_connection(ErrorCode error_code, uint32_t stream_id) {
    // Connection-level errors
    if (stream_id == 0)
        return true;

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

std::string
Http2ErrorHandler::format_error_message(ErrorCode error_code, const std::string &context, uint32_t stream_id) {
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

std::string_view
Http2ErrorHandler::get_error_name(ErrorCode error_code) {
    switch (error_code) {
        case ErrorCode::NO_ERROR:
            return "NO_ERROR";
        case ErrorCode::PROTOCOL_ERROR:
            return "PROTOCOL_ERROR";
        case ErrorCode::INTERNAL_ERROR:
            return "INTERNAL_ERROR";
        case ErrorCode::FLOW_CONTROL_ERROR:
            return "FLOW_CONTROL_ERROR";
        case ErrorCode::SETTINGS_TIMEOUT:
            return "SETTINGS_TIMEOUT";
        case ErrorCode::STREAM_CLOSED:
            return "STREAM_CLOSED";
        case ErrorCode::FRAME_SIZE_ERROR:
            return "FRAME_SIZE_ERROR";
        case ErrorCode::REFUSED_STREAM:
            return "REFUSED_STREAM";
        case ErrorCode::CANCEL:
            return "CANCEL";
        case ErrorCode::COMPRESSION_ERROR:
            return "COMPRESSION_ERROR";
        case ErrorCode::CONNECT_ERROR:
            return "CONNECT_ERROR";
        case ErrorCode::ENHANCE_YOUR_CALM:
            return "ENHANCE_YOUR_CALM";
        case ErrorCode::INADEQUATE_SECURITY:
            return "INADEQUATE_SECURITY";
        case ErrorCode::HTTP_1_1_REQUIRED:
            return "HTTP_1_1_REQUIRED";
        default:
            return "UNKNOWN_ERROR";
    }
}

// --- StreamIdValidator ---

SettingsHelper::ValidationResult
StreamIdValidator::validate_stream_id_for_frame(FrameType frame_type, uint32_t stream_id, bool is_server) {
    switch (frame_type) {
        case FrameType::SETTINGS:
        case FrameType::PING:
        case FrameType::GOAWAY:
            if (!is_connection_stream_id(stream_id)) {
                return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR,
                                                                 std::string(get_frame_type_name(frame_type)) + " frame must use stream ID 0");
            }
            break;

        case FrameType::DATA:
        case FrameType::HEADERS:
        case FrameType::PRIORITY:
        case FrameType::RST_STREAM:
        case FrameType::PUSH_PROMISE:
        case FrameType::CONTINUATION:
            if (is_connection_stream_id(stream_id)) {
                return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR, std::string(get_frame_type_name(frame_type))
                                                                                                + " frame cannot use stream ID 0");
            }

            // Additional validation for peer-initiated streams
            if (frame_type == FrameType::HEADERS || frame_type == FrameType::PUSH_PROMISE) {
                if (is_server && !is_valid_client_stream_id(stream_id)) {
                    return SettingsHelper::ValidationResult::invalid(ErrorCode::PROTOCOL_ERROR,
                                                                     "Server received " + std::string(get_frame_type_name(frame_type))
                                                                         + " on invalid client stream ID: " + std::to_string(stream_id));
                }
                if (!is_server && frame_type == FrameType::PUSH_PROMISE && !is_valid_server_stream_id(stream_id)) {
                    return SettingsHelper::ValidationResult::invalid(
                        ErrorCode::PROTOCOL_ERROR, "Client received PUSH_PROMISE with invalid server stream ID: " + std::to_string(stream_id));
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

std::string_view
StreamIdValidator::get_frame_type_name(FrameType frame_type) {
    switch (frame_type) {
        case FrameType::DATA:
            return "DATA";
        case FrameType::HEADERS:
            return "HEADERS";
        case FrameType::PRIORITY:
            return "PRIORITY";
        case FrameType::RST_STREAM:
            return "RST_STREAM";
        case FrameType::SETTINGS:
            return "SETTINGS";
        case FrameType::PUSH_PROMISE:
            return "PUSH_PROMISE";
        case FrameType::PING:
            return "PING";
        case FrameType::GOAWAY:
            return "GOAWAY";
        case FrameType::WINDOW_UPDATE:
            return "WINDOW_UPDATE";
        case FrameType::CONTINUATION:
            return "CONTINUATION";
        default:
            return "UNKNOWN";
    }
}

} // namespace qb::protocol::http2
