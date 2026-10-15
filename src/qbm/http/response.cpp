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

/**
 * @brief Takes back what one serialization wrote when it refuses or throws, and nothing else.
 *
 * A session's output pipe already holds what was queued before this message -- pipelined responses,
 * a request ahead of this one -- so a refusal rewinds to where this message began instead of
 * clearing the pipe (Huly QB-1066). Armed on entry, committed once the message is complete; an
 * exception thrown while writing (an allocation, a chunk) rewinds the same way.
 */
class serialization_rollback {
    pipe<char>       &_out;
    const std::size_t _mark;
    bool              _committed = false;

public:
    explicit serialization_rollback(pipe<char> &out) noexcept
        : _out(out)
        , _mark(out.size()) {}
    serialization_rollback(const serialization_rollback &)            = delete;
    serialization_rollback &operator=(const serialization_rollback &) = delete;
    ~serialization_rollback() {
        if (!_committed)
            _out.free_back(_out.size() - _mark);
    }
    void
    commit() noexcept {
        _committed = true;
    }
};

/**
 * @brief The HTTP/1.1 serialization of a response, with or without its content.
 * @param out Where the bytes go. On a refusal, what this call wrote is taken back; what the pipe held
 *        before it is kept.
 * @param r The response.
 * @param content_suppressed True for `MessageHead`: the status line and the header section only,
 *        framing headers included, and nothing after them -- no body, no chunked last-chunk (the
 *        response to a HEAD request, RFC 9110 §9.3.2). The body, if any, is ignored.
 */
void
serialize_response(pipe<char> &out, const qb::http::Response &r, const bool content_suppressed) {
    serialization_rollback rollback{out};
    // SECURITY FIX: Validate body size to prevent DoS
    const std::size_t body_size = content_suppressed ? 0u : r.body().size();
    if (body_size > qb::http::protocol_limits::MAX_BODY_SIZE) {
        throw std::length_error("qb::http::Response serialization: body size (" + std::to_string(body_size)
                                + ") exceeds "
                                  "qb::http::protocol_limits::MAX_BODY_SIZE ("
                                + std::to_string(qb::http::protocol_limits::MAX_BODY_SIZE)
                                + "); refusing to emit a truncated or empty wire representation.");
    }

    const auto length = body_size;
    if (length && response_must_not_carry_body(r)) {
        throw std::length_error("qb::http::Response serialization: this status code must not carry a body.");
    }

    const auto transfer = transfer_encoding(r);
    if (!transfer.ok) {
        throw std::length_error("qb::http::Response serialization: unsupported or malformed Transfer-Encoding.");
    }
    if (transfer.chunked && response_must_not_carry_body(r)) {
        throw std::length_error("qb::http::Response serialization: this status code must not declare Transfer-Encoding.");
    }

    const std::optional<std::uint64_t> content_length = declared_content_length(r);

    if (transfer.chunked && content_length) {
        throw std::length_error("qb::http::Response serialization: Content-Length is forbidden with Transfer-Encoding.");
    }
    if (response_forbids_nonzero_content_length(r) && content_length && *content_length != 0u) {
        throw std::length_error("qb::http::Response serialization: this status code must not declare a non-zero Content-Length.");
    }
    if (length && !transfer.chunked && content_length && *content_length != length) {
        throw std::length_error("qb::http::Response serialization: Content-Length does not match body size.");
    }

    // A complete chunked message's announced trailer fields travel after its last chunk, not in its
    // header section: HTTP/2's and HTTP/3's contract (RFC 9112 §7.1.2, Huly QB-1067). A MessageHead writes
    // no trailer section of its own, so it keeps every field in the head.
    const std::vector<std::string> trailer_fields = transfer.chunked && !content_suppressed && r.has_header("Trailer")
                                                        ? qb::http::detail::trailer_section_fields(r)
                                                        : std::vector<std::string>{};

    // Performance: Pre-calculate approximate output size to minimize allocations
    std::size_t estimated_size = 32; // Base status line size
    estimated_size += std::to_string(r.status().code()).size();
    estimated_size += 32; // Status text estimate

    // Add headers size
    for (const auto &it : r.headers()) {
        if (!header_name_is_valid(it.first)) {
            throw std::length_error("qb::http::Response serialization: header name exceeds MAX_HEADER_NAME_LENGTH.");
        }
        estimated_size += it.first.size() + 2; // ": "
        for (const auto &value : it.second) {
            if (!header_value_is_valid(value)) {
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
        throw std::length_error("qb::http::Response serialization: estimated wire size exceeds internal cap (decompression "
                                "or header explosion); refusing to allocate.");
    }

    // Reserve space in pipe to reduce allocations
    out.reserve(estimated_size);

    // HTTP Status Line
    out << "HTTP/" << r.major_version << "." << r.minor_version << qb::http::sep << r.status().code() << qb::http::sep << r.status().str()
        << qb::http::endl;

    // HTTP Headers
    for (const auto &it : r.headers()) {
        if (!trailer_fields.empty() && std::find(trailer_fields.begin(), trailer_fields.end(), it.first) != trailer_fields.end()) {
            continue; // in the trailer section, below
        }
        for (const auto &value : it.second) {
            if (!header_is_valid(it.first, value)) {
                throw std::length_error("qb::http::Response serialization: invalid header name/value.");
            }
            out << it.first << ": " << value << qb::http::endl;
        }
    }

    // Body. A chunked body always ends with its last-chunk, an empty one included: that terminator
    // alone is what delimits it (RFC 9112 §7.1, Huly QB-493) -- unless the content is suppressed,
    // where the header section is the whole message.
    if (transfer.chunked) {
        out << qb::http::endl;
        if (!content_suppressed) {
            if (length)
                out << qb::http::Chunk(r.body().raw().begin(), length);
            if (trailer_fields.empty()) {
                out << qb::http::Chunk();
            } else {
                // The last-chunk, the trailer section, then the empty line that ends the message.
                out << '0' << qb::http::endl;
                for (const auto &name : trailer_fields) {
                    const auto field = r.headers().find(name);
                    if (field == r.headers().cend()) {
                        continue; // announced, not set
                    }
                    for (const auto &value : field->second) {
                        out << name << ": " << value << qb::http::endl;
                    }
                }
                out << qb::http::endl;
            }
        }
    } else if (length) {
        if (!content_length) {
            out << "content-length: " << length << qb::http::endl;
        }
        out << qb::http::endl << r.body().raw();
    } else {
        // Empty body: still emit "Content-Length: 0" so the message is self-delimiting on a
        // keep-alive connection (RFC 9112 §6.2). Without it, a peer with no Content-Length and no
        // Transfer-Encoding treats the response as close-delimited (read-until-EOF) and blocks on a
        // connection that never closes. Omit it for statuses that must not carry a body (1xx/204/304)
        // and when Content-Length is already declared.
        if (!content_length && !response_must_not_carry_body(r)) {
            out << "content-length: 0" << qb::http::endl;
        }
        out << qb::http::endl;
    }
    rollback.commit();
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
 * - Response body (if present); a chunked body, even an empty one, ends with its last-chunk
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
    serialize_response(*this, r, false);
    return *this;
}

/**
 * @brief Serialize the head of an HTTP Response: status line and header section, no content
 * @param r The response, viewed through `qb::http::MessageHead`
 * @return Reference to this pipe
 *
 * The response to a HEAD request (RFC 9110 §9.3.2), or the head of a body streamed by hand.
 * Validation is the full serializer's.
 */
template <>
pipe<char> &
pipe<char>::put<qb::http::MessageHead<qb::http::Response>>(const qb::http::MessageHead<qb::http::Response> &r) {
    serialize_response(*this, r.message, true);
    return *this;
}
} // namespace qb::allocator
