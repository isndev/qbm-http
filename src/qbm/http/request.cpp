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

// The request-target check below takes sixteen bytes per step where SSE2 is the baseline (every x86-64
// toolchain) and eight otherwise.
#if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#include <emmintrin.h>
#define QB_HTTP_QUERY_CHECK_SSE2 1
#else
#define QB_HTTP_QUERY_CHECK_SSE2 0
#endif

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
    // On the serializer's path, so wide steps and no byte loop past the first word: the last step re-reads
    // the tail overlapped (a byte checked twice is still checked), which keeps the step count at
    // ceil(n / width) with no scalar epilogue.
    const char *p = query.data();
    std::size_t n = query.size();
#if QB_HTTP_QUERY_CHECK_SSE2
    if (n >= 16) {
        // Sixteen bytes per step: a byte is refused iff max(byte, 0x20) == 0x20 (byte <= 0x20 unsigned)
        // or byte == 0x7F. A byte from 0x80 up passes both, as it must.
        const __m128i sp  = _mm_set1_epi8(0x20);
        const __m128i del = _mm_set1_epi8(0x7f);
        const auto    bad = [&](const char *at) noexcept {
            const __m128i x   = _mm_loadu_si128(reinterpret_cast<const __m128i *>(at));
            const __m128i low = _mm_cmpeq_epi8(_mm_max_epu8(x, sp), sp);
            return _mm_movemask_epi8(_mm_or_si128(low, _mm_cmpeq_epi8(x, del))) != 0;
        };
        for (; n > 16; p += 16, n -= 16) {
            if (bad(p))
                return false;
        }
        return !bad(p + n - 16);
    }
#endif
    // Eight bytes per step. Each test is the exact "some byte of the word is..." bit trick:
    // `(x - 0x21..21) & ~x & 0x80..80` is non-zero iff a byte is below 0x21, and the same zero-byte test
    // on `x ^ 0x7F..7F` iff a byte is 0x7F. A byte from 0x80 up passes both, as it must.
    constexpr std::uint64_t ones  = 0x0101010101010101ULL;
    constexpr std::uint64_t highs = 0x8080808080808080ULL;
    const auto              bad8  = [](const char *at) noexcept {
        std::uint64_t x;
        std::memcpy(&x, at, sizeof x);
        const std::uint64_t del = x ^ (ones * 0x7f);
        return ((((x - ones * 0x21) & ~x) | ((del - ones) & ~del)) & highs) != 0;
    };
    if (n >= 8) {
        for (; n > 8; p += 8, n -= 8) {
            if (bad8(p))
                return false;
        }
        return !bad8(p + n - 8);
    }
    for (; n; ++p, --n) {
        const auto uc = static_cast<unsigned char>(*p);
        if (uc <= 0x20 || uc == 0x7f)
            return false;
    }
    return true;
}

/// The request-line token of @p m, from llhttp's method map; nullptr for a value the map does not
/// hold (llhttp's own http_method_name() abort()s on one).
[[nodiscard]] const char *
method_token(const ::http_method m) noexcept {
#define QB_HTTP_METHOD_TOKEN(NUM, NAME, STRING) \
    case HTTP_##NAME:                           \
        return #STRING;
    switch (m) {
        HTTP_ALL_METHOD_MAP(QB_HTTP_METHOD_TOKEN)
        default:
            return nullptr;
    }
#undef QB_HTTP_METHOD_TOKEN
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
 * @brief The HTTP/1.1 serialization of a request, with or without its content.
 * @param out Where the bytes go. On a refusal, what this call wrote is taken back; what the pipe held
 *        before it is kept.
 * @param r The request.
 * @param head_only True for `MessageHead`: the request line and the header section only, and nothing
 *        after them -- no body, no chunked last-chunk. The body, if any, is ignored.
 */
void
serialize_request(pipe<char> &out, const qb::http::Request &r, const bool head_only) {
    serialization_rollback rollback{out};
    // The method token, from llhttp's method map; a value it does not name -- a default-constructed
    // Request's Method::UNINITIALIZED -- is refused here: http_method_name() would abort() (Huly QB-1066).
    const char *const method = method_token(r.method());
    if (method == nullptr) {
        throw std::length_error("qb::http::Request serialization: the request has no method llhttp can name.");
    }
    // A URI that failed to parse names no target; writing "/" for it would address a resource nobody
    // named (Huly QB-1066).
    if (!r.uri().is_valid()) {
        throw std::length_error("qb::http::Request serialization: the request URI is invalid.");
    }

    // SECURITY FIX: Validate URL size to prevent DoS
    const std::size_t path_size      = r.uri().path().size();
    const std::size_t query_size     = r.uri().encoded_queries().size();
    const std::size_t total_url_size = path_size + query_size;

    if (total_url_size > qb::http::protocol_limits::MAX_URL_LENGTH) {
        throw std::length_error("qb::http::Request serialization: URL length (" + std::to_string(total_url_size)
                                + ") exceeds "
                                  "qb::http::protocol_limits::MAX_URL_LENGTH ("
                                + std::to_string(qb::http::protocol_limits::MAX_URL_LENGTH) + ").");
    }
    if (!raw_query_is_valid(r.uri().encoded_queries())) {
        throw std::length_error("qb::http::Request serialization: the query carries SP, a control byte or DEL; "
                                "percent-encode it.");
    }

    // SECURITY FIX: Validate body size to prevent DoS
    const std::size_t body_size = head_only ? 0u : r.body().size();
    if (body_size > qb::http::protocol_limits::MAX_BODY_SIZE) {
        throw std::length_error("qb::http::Request serialization: body size (" + std::to_string(body_size)
                                + ") exceeds "
                                  "qb::http::protocol_limits::MAX_BODY_SIZE ("
                                + std::to_string(qb::http::protocol_limits::MAX_BODY_SIZE) + ").");
    }

    const auto length   = body_size;
    const auto transfer = transfer_encoding(r);
    if (!transfer.ok) {
        throw std::length_error("qb::http::Request serialization: unsupported or malformed Transfer-Encoding.");
    }

    const std::optional<std::uint64_t> content_length = declared_content_length(r);

    if (transfer.chunked && content_length) {
        throw std::length_error("qb::http::Request serialization: Content-Length is forbidden with Transfer-Encoding.");
    }
    if (!head_only && !transfer.chunked && content_length && *content_length != length) {
        throw std::length_error("qb::http::Request serialization: Content-Length does not match body size.");
    }

    // A complete chunked message's announced trailer fields travel after its last chunk, not in its
    // header section: HTTP/2's and HTTP/3's contract (RFC 9112 §7.1.2, Huly QB-1067). A MessageHead writes
    // no trailer section of its own, so it keeps every field in the head.
    const std::vector<std::string> trailer_fields =
        transfer.chunked && !head_only && r.has_header("Trailer") ? qb::http::detail::trailer_section_fields(r) : std::vector<std::string>{};

    // Performance: Pre-calculate approximate output size to minimize allocations
    std::size_t estimated_size = 64; // Base request line size
    estimated_size += path_size;
    estimated_size += query_size + 1; // ?query

    // Add headers size
    for (const auto &it : r.headers()) {
        if (!header_name_is_valid(it.first)) {
            throw std::length_error("qb::http::Request serialization: header name exceeds MAX_HEADER_NAME_LENGTH.");
        }
        estimated_size += it.first.size() + 2; // ": "
        for (const auto &value : it.second) {
            if (!header_value_is_valid(value)) {
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
        throw std::length_error("qb::http::Request serialization: estimated wire size exceeds internal cap; refusing to allocate.");
    }

    // Reserve space in pipe to reduce allocations
    out.reserve(estimated_size);

    // HTTP Request Line: METHOD PATH[?query] HTTP/VERSION.
    // URI fragments are client-side identifiers and are never sent in an HTTP request-target.
    // An empty path is sent as "/" (RFC 9112 §3.2.1: the client MUST send "/" as the path of an
    // origin-form whose URI has none) -- a default URI, or one naming only an authority (Huly QB-1066).
    const std::string_view path = r.uri().path();
    out << method << qb::http::sep << (path.empty() ? std::string_view{"/"} : path);
    if (!r.uri().encoded_queries().empty())
        out << "?" << r.uri().encoded_queries();
    out << qb::http::sep << "HTTP/" << r.major_version << "." << r.minor_version << qb::http::endl;

    // HTTP Headers
    for (const auto &it : r.headers()) {
        if (!trailer_fields.empty() && std::find(trailer_fields.begin(), trailer_fields.end(), it.first) != trailer_fields.end()) {
            continue; // in the trailer section, below
        }
        for (const auto &value : it.second) {
            if (!header_is_valid(it.first, value)) {
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
    } else
        out << qb::http::endl;
    rollback.commit();
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
