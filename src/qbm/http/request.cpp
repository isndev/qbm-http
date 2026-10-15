/**
 * @file qbm/http/request.cpp
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./request.h"
#include "./1.1/protocol/base.h" // For protocol_limits - SECURITY FIX: DoS protection
#include "./chunk.h"
#include "./utility.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace qb::http {

void
Request::parse_cookie_header() {
    _cookies.clear();
    const std::string &cookie_header_value = this->header("Cookie", 0);
    if (cookie_header_value.empty()) {
        return;
    }
    auto cookies_map = parse_cookies(std::string_view(cookie_header_value), false);
    for (const auto &[name, value] : cookies_map) {
        _cookies.add(name, value);
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

// RFC 9112 §3.2: the request-target is the request line's middle token, so a byte that ends or
// breaks that line -- SP, HTAB, CR, LF, NUL, any other control, DEL -- cannot travel raw; its
// percent-encoded form can, and so can every other byte. qb::io::uri is a generic URI parser: it
// admits only path characters in the path, but keeps the query's raw bytes, so the query is the HTTP/1
// serializer's check (Huly QB-494).
[[nodiscard]] bool
raw_query_is_valid(std::string_view query) noexcept {
    // Eight bytes per step on the serializer's path. Each test is the exact "some byte of the word is..."
    // bit trick: `(x - 0x21..21) & ~x & 0x80..80` is non-zero iff a byte is below 0x21, and the same zero-byte
    // test on `x ^ 0x7F..7F` iff a byte is 0x7F. A byte from 0x80 up passes both, as it must.
    constexpr std::uint64_t ones  = 0x0101010101010101ULL;
    constexpr std::uint64_t highs = 0x8080808080808080ULL;
    const char             *p     = query.data();
    std::size_t             n     = query.size();
    for (; n >= 8; p += 8, n -= 8) {
        std::uint64_t x;
        std::memcpy(&x, p, sizeof x);
        const std::uint64_t del = x ^ (ones * 0x7f);
        if ((((x - ones * 0x21) & ~x) | ((del - ones) & ~del)) & highs)
            return false;
    }
    for (; n; ++p, --n) {
        const auto uc = static_cast<unsigned char>(*p);
        if (uc <= 0x20 || uc == 0x7f)
            return false;
    }
    return true;
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
            throw std::length_error("qb::http::Request serialization: invalid or conflicting Content-Length header.");
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

/**
 * @brief The HTTP/1.1 serialization of a request, with or without its content.
 * @param out Where the bytes go. On a refusal it is cleared and nothing is emitted.
 * @param r The request.
 * @param head_only True for `MessageHead`: the request line and the header section only, and nothing
 *        after them -- no body, no chunked last-chunk. The body, if any, is ignored.
 */
void
serialize_request(pipe<char> &out, const qb::http::Request &r, const bool head_only) {
    // SECURITY FIX: Validate URL size to prevent DoS
    const std::size_t path_size      = r.uri().path().size();
    const std::size_t query_size     = r.uri().encoded_queries().size();
    const std::size_t total_url_size = path_size + query_size;

    if (total_url_size > qb::http::protocol_limits::MAX_URL_LENGTH) {
        out.clear();
        throw std::length_error("qb::http::Request serialization: URL length (" + std::to_string(total_url_size)
                                + ") exceeds "
                                  "qb::http::protocol_limits::MAX_URL_LENGTH ("
                                + std::to_string(qb::http::protocol_limits::MAX_URL_LENGTH) + ").");
    }
    if (!raw_query_is_valid(r.uri().encoded_queries())) {
        out.clear();
        throw std::length_error("qb::http::Request serialization: the query carries SP, a control byte or DEL; "
                                "percent-encode it.");
    }

    // SECURITY FIX: Validate body size to prevent DoS
    const std::size_t body_size = head_only ? 0u : r.body().size();
    if (body_size > qb::http::protocol_limits::MAX_BODY_SIZE) {
        out.clear();
        throw std::length_error("qb::http::Request serialization: body size (" + std::to_string(body_size)
                                + ") exceeds "
                                  "qb::http::protocol_limits::MAX_BODY_SIZE ("
                                + std::to_string(qb::http::protocol_limits::MAX_BODY_SIZE) + ").");
    }

    const auto length   = body_size;
    const auto transfer = transfer_encoding(r);
    if (!transfer.ok) {
        out.clear();
        throw std::length_error("qb::http::Request serialization: unsupported or malformed Transfer-Encoding.");
    }

    std::optional<std::uint64_t> content_length;
    try {
        content_length = declared_content_length(r);
    } catch (...) {
        out.clear();
        throw;
    }

    if (transfer.chunked && content_length) {
        out.clear();
        throw std::length_error("qb::http::Request serialization: Content-Length is forbidden with Transfer-Encoding.");
    }
    if (!head_only && !transfer.chunked && content_length && *content_length != length) {
        out.clear();
        throw std::length_error("qb::http::Request serialization: Content-Length does not match body size.");
    }

    // Performance: Pre-calculate approximate output size to minimize allocations
    std::size_t estimated_size = 64; // Base request line size
    estimated_size += path_size;
    estimated_size += query_size + 1; // ?query

    // Add headers size
    for (const auto &it : r.headers()) {
        if (!header_name_is_valid(it.first)) {
            out.clear();
            throw std::length_error("qb::http::Request serialization: header name exceeds MAX_HEADER_NAME_LENGTH.");
        }
        estimated_size += it.first.size() + 2; // ": "
        for (const auto &value : it.second) {
            if (!header_value_is_valid(value)) {
                out.clear();
                throw std::length_error("qb::http::Request serialization: header value exceeds MAX_HEADER_VALUE_LENGTH.");
            }
            estimated_size += value.size() + 2; // CRLF
        }
    }
    estimated_size += 2; // Final CRLF
    estimated_size += body_size;

    // SECURITY FIX: Cap maximum serialized size to prevent overflow
    constexpr std::size_t MAX_SERIALIZED_SIZE = 110 * 1024 * 1024; // 110MB (slightly above MAX_BODY_SIZE + headers)
    if (estimated_size > MAX_SERIALIZED_SIZE) {
        out.clear();
        throw std::length_error("qb::http::Request serialization: estimated wire size exceeds internal cap; refusing to allocate.");
    }

    // Reserve space in pipe to reduce allocations
    out.reserve(estimated_size);

    // HTTP Request Line: METHOD PATH[?query] HTTP/VERSION.
    // URI fragments are client-side identifiers and are never sent in an HTTP request-target.
    out << ::http_method_name(r.method()) << qb::http::sep << r.uri().path();
    if (!r.uri().encoded_queries().empty())
        out << "?" << r.uri().encoded_queries();
    out << qb::http::sep << "HTTP/" << r.major_version << "." << r.minor_version << qb::http::endl;

    // HTTP Headers
    for (const auto &it : r.headers()) {
        for (const auto &value : it.second) {
            if (!header_is_valid(it.first, value)) {
                out.clear();
                throw std::length_error("qb::http::Request serialization: invalid header name/value.");
            }
            out << it.first << ": " << value << qb::http::endl;
        }
    }

    // Body. A chunked body always ends with its last-chunk, an empty one included: that
    // terminator alone is what delimits it (RFC 9112 §7.1, Huly QB-493) -- unless only the head
    // is wanted, where the header section is all that is written.
    if (transfer.chunked) {
        out << qb::http::endl;
        if (!head_only) {
            if (length)
                out << qb::http::Chunk(r.body().raw().begin(), length);
            out << qb::http::Chunk();
        }
    } else if (length) {
        if (!content_length) {
            out << "content-length: " << length << qb::http::endl;
        }
        out << qb::http::endl << r.body().raw();
    } else
        out << qb::http::endl;
}
} // namespace

/**
 * @brief Serialize an HTTP Request into a byte stream
 * @param r HTTP Request to serialize
 * @return Reference to this pipe
 *
 * Formats an HTTP request into a properly formatted request string
 * including request line, headers, and body.
 *
 * The format follows the HTTP/1.1 specification with:
 * - Request line: METHOD PATH HTTP/VERSION
 * - Headers: HEADER: VALUE
 * - Empty line separator
 * - Request body (if present); a chunked body, even an empty one, ends with its last-chunk
 *
 * @security Validation uses qb::http::protocol_limits; oversize messages throw
 *       std::length_error instead of emitting a truncated or empty wire format. So does a
 *       request-target byte the request line cannot carry (SP, a control byte, DEL).
 *
 * @note Performance: Uses reserve() to minimize allocations during serialization.
 *       Estimates output size based on path, headers, and body size.
 */
template <>
pipe<char> &
pipe<char>::put<qb::http::Request>(const qb::http::Request &r) {
    serialize_request(*this, r, false);
    return *this;
}

/**
 * @brief Serialize the head of an HTTP Request: request line and header section, no content
 * @param r The request, viewed through `qb::http::MessageHead`
 * @return Reference to this pipe
 *
 * The head of a body streamed by hand (`Chunk`s after a `Transfer-Encoding: chunked` head).
 * Validation is the full serializer's.
 */
template <>
pipe<char> &
pipe<char>::put<qb::http::MessageHead<qb::http::Request>>(const qb::http::MessageHead<qb::http::Request> &r) {
    serialize_request(*this, r.message, true);
    return *this;
}
} // namespace qb::allocator
