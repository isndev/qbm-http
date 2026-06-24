/**
 * @file qbm/http/response.cpp
 * @brief Out-of-line definitions for the HTTP Response message class.
 *
 * Provides the non-template member function bodies of `qb::http::Response`
 * (cookie management) and the `qb::allocator::pipe<char>::put<Response>`
 * serialization specialization.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./response.h"
#include "./1.1/protocol/base.h" // For protocol_limits - SECURITY FIX: DoS protection
#include "./chunk.h"
#include "./utility.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace qb::http {

void
Response::parse_set_cookie_headers() {
    _cookies.clear();
    const auto &set_cookie_iter = this->_headers.find("Set-Cookie");
    if (set_cookie_iter == this->_headers.end()) {
        return;
    }
    for (const std::string &header_value_str : set_cookie_iter->second) {
        if (auto cookie_opt = parse_set_cookie(std::string_view(header_value_str))) {
            _cookies.add(std::move(*cookie_opt));
        }
    }
}

void
Response::remove_cookie(const std::string &name) {
    Cookie removal_cookie(name, "");
    removal_cookie.expires_in(std::chrono::seconds(EXPIRED_COOKIE_OFFSET_SECONDS));
    removal_cookie.max_age(qb::duration::zero());
    add_cookie(std::move(removal_cookie));
}

void
Response::remove_cookie(const std::string &name, const std::string &domain, const std::string &path) {
    Cookie removal_cookie(name, "");
    removal_cookie.expires_in(std::chrono::seconds(EXPIRED_COOKIE_OFFSET_SECONDS));
    removal_cookie.max_age(qb::duration::zero());
    removal_cookie.domain(domain);
    removal_cookie.path(path);
    add_cookie(std::move(removal_cookie));
}

void
Response::update_cookie_header(const std::string &name) {
    Cookie *modified_cookie = _cookies.get(name);
    if (!modified_cookie) {
        return;
    }
    auto &set_cookie_headers = this->_headers["Set-Cookie"];
    set_cookie_headers.erase(std::remove_if(set_cookie_headers.begin(), set_cookie_headers.end(),
                                            [&](const std::string &header_val) {
                                                const auto eq_pos = header_val.find('=');
                                                if (eq_pos == std::string::npos) {
                                                    return false;
                                                }
                                                return utility::iequals(std::string_view(header_val.data(), eq_pos), modified_cookie->name());
                                            }),
                             set_cookie_headers.end());
    this->add_header("Set-Cookie", modified_cookie->to_header());
}

void
Response::update_cookie_headers() {
    this->_headers.erase("Set-Cookie"); // Remove all current Set-Cookie headers
    for (const auto &pair : _cookies.all()) {
        this->add_header("Set-Cookie", pair.second.to_header());
    }
}

} // namespace qb::http

namespace qb::allocator {
namespace {
[[nodiscard]] bool
is_header_name_char(const unsigned char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '!' || c == '#' || c == '$' || c == '%'
           || c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

[[nodiscard]] bool
header_name_is_valid(const std::string &name) noexcept {
    if (name.empty() || name.size() > qb::http::protocol_limits::MAX_HEADER_NAME_LENGTH) {
        return false;
    }
    return std::all_of(name.begin(), name.end(), [](const char c) { return is_header_name_char(static_cast<unsigned char>(c)); });
}

[[nodiscard]] bool
header_value_is_valid(const std::string &value) noexcept {
    if (value.size() > qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](const char c) {
        const auto uc = static_cast<unsigned char>(c);
        return c == '\t' || (uc >= 0x20 && uc != 0x7f);
    });
}

[[nodiscard]] bool
header_is_valid(const std::string &name, const std::string &value) noexcept {
    return header_name_is_valid(name) && header_value_is_valid(value);
}

struct transfer_encoding_result {
    bool ok      = true;
    bool chunked = false;
};

[[nodiscard]] std::optional<std::uint64_t>
parse_content_length(std::string_view value) noexcept {
    value = qb::http::utility::trim_http_whitespace(value);
    if (value.empty()) {
        return std::nullopt;
    }
    std::uint64_t parsed = 0;
    const auto   *begin  = value.data();
    const auto   *end    = value.data() + value.size();
    const auto [ptr, ec] = std::from_chars(begin, end, parsed);
    if (ec != std::errc{} || ptr != end) {
        return std::nullopt;
    }
    return parsed;
}

template <typename Message>
[[nodiscard]] std::optional<std::uint64_t>
declared_content_length(Message const &msg) {
    auto it = msg.headers().find("Content-Length");
    if (it == msg.headers().end()) {
        return std::nullopt;
    }
    std::optional<std::uint64_t> parsed_length;
    for (const auto &raw : it->second) {
        const auto parsed = parse_content_length(raw);
        if (!parsed || (parsed_length && *parsed_length != *parsed)) {
            throw std::length_error("qb::http::Response serialization: invalid or conflicting Content-Length header.");
        }
        parsed_length = *parsed;
    }
    return parsed_length;
}

template <typename Message>
[[nodiscard]] transfer_encoding_result
transfer_encoding(Message const &msg) noexcept {
    auto it = msg.headers().find("Transfer-Encoding");
    if (it == msg.headers().end()) {
        return {};
    }

    std::vector<std::string> tokens;
    for (const auto &value : it->second) {
        for (auto token : qb::http::utility::split_string<std::string>(value, ",")) {
            token = std::string(qb::http::utility::trim_http_whitespace(token));
            if (!token.empty()) {
                tokens.emplace_back(std::move(token));
            }
        }
    }

    if (tokens.empty()) {
        return {false, false};
    }

    if (tokens.size() == 1 && qb::http::utility::iequals(tokens.front(), "chunked")) {
        return {true, true};
    }
    return {false, false};
}

[[nodiscard]] bool
response_must_not_carry_body(qb::http::Response const &r) noexcept {
    const auto status = r.status().code();
    return (status >= 100 && status < 200) || status == 204 || status == 304;
}

[[nodiscard]] bool
response_forbids_nonzero_content_length(qb::http::Response const &r) noexcept {
    const auto status = r.status().code();
    return (status >= 100 && status < 200) || status == 204;
}
} // namespace

/**
 * @brief Serialize an HTTP Response into a byte stream
 * @param r HTTP Response to serialize
 * @return Reference to this pipe
 *
 * Formats an HTTP response into a properly formatted response string
 * including status line, headers, and body.
 *
 * The format follows the HTTP/1.1 specification with:
 * - Status line: HTTP/VERSION STATUS_CODE STATUS_TEXT
 * - Headers: HEADER: VALUE
 * - Empty line separator
 * - Response body (if present)
 *
 * This method also handles automatic compression of the body
 * if Content-Encoding header is present.
 *
 * @security Validation uses qb::http::protocol_limits; oversize messages throw
 *       std::length_error instead of emitting a truncated or empty wire format.
 *
 * @note Performance: Uses reserve() to minimize allocations during serialization.
 *       Estimates output size based on status line, headers, and body size.
 */
template <>
pipe<char> &
pipe<char>::put<qb::http::Response>(const qb::http::Response &r) {
    // SECURITY FIX: Validate body size to prevent DoS
    const std::size_t body_size = r.body().size();
    if (body_size > qb::http::protocol_limits::MAX_BODY_SIZE) {
        this->clear();
        throw std::length_error("qb::http::Response serialization: body size (" + std::to_string(body_size)
                                + ") exceeds "
                                  "qb::http::protocol_limits::MAX_BODY_SIZE ("
                                + std::to_string(qb::http::protocol_limits::MAX_BODY_SIZE)
                                + "); refusing to emit a truncated or empty wire representation.");
    }

    const auto length = r.body().size();
    if (length && response_must_not_carry_body(r)) {
        this->clear();
        throw std::length_error("qb::http::Response serialization: this status code must not carry a body.");
    }

    const auto transfer = transfer_encoding(r);
    if (!transfer.ok) {
        this->clear();
        throw std::length_error("qb::http::Response serialization: unsupported or malformed Transfer-Encoding.");
    }
    if (transfer.chunked && response_must_not_carry_body(r)) {
        this->clear();
        throw std::length_error("qb::http::Response serialization: this status code must not declare Transfer-Encoding.");
    }

    std::optional<std::uint64_t> content_length;
    try {
        content_length = declared_content_length(r);
    } catch (...) {
        this->clear();
        throw;
    }

    if (transfer.chunked && content_length) {
        this->clear();
        throw std::length_error("qb::http::Response serialization: Content-Length is forbidden with Transfer-Encoding.");
    }
    if (response_forbids_nonzero_content_length(r) && content_length && *content_length != 0u) {
        this->clear();
        throw std::length_error("qb::http::Response serialization: this status code must not declare a non-zero Content-Length.");
    }
    if (length && !transfer.chunked && content_length && *content_length != length) {
        this->clear();
        throw std::length_error("qb::http::Response serialization: Content-Length does not match body size.");
    }

    // Performance: Pre-calculate approximate output size to minimize allocations
    std::size_t estimated_size = 32; // Base status line size
    estimated_size += std::to_string(r.status().code()).size();
    estimated_size += 32; // Status text estimate

    // Add headers size
    for (const auto &it : r.headers()) {
        if (!header_name_is_valid(it.first)) {
            this->clear();
            throw std::length_error("qb::http::Response serialization: header name exceeds MAX_HEADER_NAME_LENGTH.");
        }
        estimated_size += it.first.size() + 2; // ": "
        for (const auto &value : it.second) {
            if (!header_value_is_valid(value)) {
                this->clear();
                throw std::length_error("qb::http::Response serialization: header value exceeds MAX_HEADER_VALUE_LENGTH.");
            }
            estimated_size += value.size() + 2; // CRLF
        }
    }
    estimated_size += 2; // Final CRLF
    estimated_size += body_size;

    // SECURITY FIX: Cap maximum serialized size to prevent overflow
    constexpr std::size_t MAX_SERIALIZED_SIZE = 110 * 1024 * 1024; // 110MB (slightly above MAX_BODY_SIZE + headers)
    if (estimated_size > MAX_SERIALIZED_SIZE) {
        this->clear();
        throw std::length_error("qb::http::Response serialization: estimated wire size exceeds internal cap (decompression "
                                "or header explosion); refusing to allocate.");
    }

    // Reserve space in pipe to reduce allocations
    this->reserve(estimated_size);

    // HTTP Status Line
    *this << "HTTP/" << r.major_version << "." << r.minor_version << qb::http::sep << r.status().code() << qb::http::sep
          << std::to_string(r.status()) << qb::http::endl;

    // HTTP Headers
    for (const auto &it : r.headers()) {
        for (const auto &value : it.second) {
            if (!header_is_valid(it.first, value)) {
                this->clear();
                throw std::length_error("qb::http::Response serialization: invalid header name/value.");
            }
            *this << it.first << ": " << value << qb::http::endl;
        }
    }

    // Body
    if (length) {
        if (transfer.chunked) {
            *this << qb::http::endl << qb::http::Chunk(r.body().raw().begin(), length) << qb::http::Chunk();
        } else {
            if (!content_length) {
                *this << "content-length: " << length << qb::http::endl;
            }
            *this << qb::http::endl << r.body().raw();
        }
    } else
        *this << qb::http::endl;
    return *this;
}
} // namespace qb::allocator
