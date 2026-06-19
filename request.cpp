#include "./request.h"
#include "./1.1/protocol/base.h" // For protocol_limits - SECURITY FIX: DoS protection
#include "./chunk.h"
#include "./utility.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

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
 * - Request body (if present)
 *
 * @security Validation uses qb::http::protocol_limits; oversize messages throw
 *       std::length_error instead of emitting a truncated or empty wire format.
 *
 * @note Performance: Uses reserve() to minimize allocations during serialization.
 *       Estimates output size based on path, headers, and body size.
 */
template <>
pipe<char> &
pipe<char>::put<qb::http::Request>(const qb::http::Request &r) {
    // SECURITY FIX: Validate URL size to prevent DoS
    const std::size_t path_size      = r.uri().path().size();
    const std::size_t query_size     = r.uri().encoded_queries().size();
    const std::size_t total_url_size = path_size + query_size;

    if (total_url_size > qb::http::protocol_limits::MAX_URL_LENGTH) {
        this->clear();
        throw std::length_error("qb::http::Request serialization: URL length (" + std::to_string(total_url_size)
                                + ") exceeds "
                                  "qb::http::protocol_limits::MAX_URL_LENGTH ("
                                + std::to_string(qb::http::protocol_limits::MAX_URL_LENGTH) + ").");
    }

    // SECURITY FIX: Validate body size to prevent DoS
    const std::size_t body_size = r.body().size();
    if (body_size > qb::http::protocol_limits::MAX_BODY_SIZE) {
        this->clear();
        throw std::length_error("qb::http::Request serialization: body size (" + std::to_string(body_size)
                                + ") exceeds "
                                  "qb::http::protocol_limits::MAX_BODY_SIZE ("
                                + std::to_string(qb::http::protocol_limits::MAX_BODY_SIZE) + ").");
    }

    const auto length   = r.body().size();
    const auto transfer = transfer_encoding(r);
    if (!transfer.ok) {
        this->clear();
        throw std::length_error("qb::http::Request serialization: unsupported or malformed Transfer-Encoding.");
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
        throw std::length_error("qb::http::Request serialization: Content-Length is forbidden with Transfer-Encoding.");
    }
    if (!transfer.chunked && content_length && *content_length != length) {
        this->clear();
        throw std::length_error("qb::http::Request serialization: Content-Length does not match body size.");
    }

    // Performance: Pre-calculate approximate output size to minimize allocations
    std::size_t estimated_size = 64; // Base request line size
    estimated_size += path_size;
    estimated_size += query_size + 1; // ?query

    // Add headers size
    for (const auto &it : r.headers()) {
        if (!header_name_is_valid(it.first)) {
            this->clear();
            throw std::length_error("qb::http::Request serialization: header name exceeds MAX_HEADER_NAME_LENGTH.");
        }
        estimated_size += it.first.size() + 2; // ": "
        for (const auto &value : it.second) {
            if (!header_value_is_valid(value)) {
                this->clear();
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
        this->clear();
        throw std::length_error("qb::http::Request serialization: estimated wire size exceeds internal cap; refusing to allocate.");
    }

    // Reserve space in pipe to reduce allocations
    this->reserve(estimated_size);

    // HTTP Request Line: METHOD PATH[?query] HTTP/VERSION.
    // URI fragments are client-side identifiers and are never sent in an HTTP request-target.
    *this << ::http_method_name(r.method()) << qb::http::sep << r.uri().path();
    if (!r.uri().encoded_queries().empty())
        *this << "?" << r.uri().encoded_queries();
    *this << qb::http::sep << "HTTP/" << r.major_version << "." << r.minor_version << qb::http::endl;

    // HTTP Headers
    for (const auto &it : r.headers()) {
        for (const auto &value : it.second) {
            if (!header_is_valid(it.first, value)) {
                this->clear();
                throw std::length_error("qb::http::Request serialization: invalid header name/value.");
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
