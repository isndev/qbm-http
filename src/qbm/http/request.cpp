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

#include <qb/utility/branch_hints.h> // QB_NOINLINE, QB_COLD

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
    const auto lines = this->_headers.find("Cookie");
    if (lines == this->_headers.cend())
        return;
    // The header section's lines only. A received trailer field is ALSO added to the header fields, after the
    // header section's values of its name (store_received_trailer), and a cookie is never taken from a trailer
    // section: RFC 9110 §6.5.1 forbids trusting a trailer field as a header field.
    std::size_t count = lines->second.size();
    if (has_trailers()) {
        const auto &trailer_fields = static_cast<const Request &>(*this).trailers().headers();
        if (const auto trailer_lines = trailer_fields.find("Cookie"); trailer_lines != trailer_fields.cend())
            count -= std::min(count, trailer_lines->second.size());
    }
    try {
        // The cap is the header's, as if its lines were joined with "; ": splitting it does not lift it.
        std::size_t joined = 0;
        for (std::size_t i = 0; i < count; ++i)
            if (!lines->second[i].empty())
                joined += (joined ? 2 : 0) + lines->second[i].size();
        if (joined > max_cookie_header_size)
            throw std::runtime_error("Cookie header exceeds maximum allowed size of 16KB");
        for (std::size_t i = 0; i < count; ++i) {
            const std::string &line = lines->second[i];
            if (line.empty())
                continue;
            // As in one line, where parse_cookies() keeps a name's first value, the first line wins.
            for (const auto &[name, value] : parse_cookies(std::string_view(line), false))
                if (_cookies.get(name) == nullptr)
                    _cookies.add(name, value);
        }
    } catch (...) {
        _cookies.clear(); // a refused header yields no cookie, not the lines before the refused one
        throw;
    }
}

} // namespace qb::http

namespace qb::allocator {
namespace {
/// Throws a serialization refusal. Out of line and cold: the serializer inlines every write of the
/// message, and the refusals' message building kept it larger than its common path needs (Huly QB-1066).
[[noreturn]] QB_NOINLINE QB_COLD void
refuse(const char *why) {
    throw std::length_error(why);
}

/// Throws the refusal of a size over its limit: `<prefix>(<size>) exceeds <limit_name> (<limit>)<suffix>`.
[[noreturn]] QB_NOINLINE QB_COLD void
refuse_size(const char *prefix, const std::size_t size, const char *limit_name, const std::size_t limit, const char *suffix) {
    throw std::length_error(std::string(prefix) + std::to_string(size) + ") exceeds " + limit_name + " (" + std::to_string(limit) + suffix);
}

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
            refuse("qb::http::Request serialization: invalid or conflicting Content-Length header.");
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
 * @param out Where the bytes go. A refusal writes nothing to it: what the pipe held before is kept.
 * @param r The request.
 * @param head_only True for `MessageHead`: the request line and the header section only, and nothing
 *        after them -- no body, no chunked last-chunk. The body, if any, is ignored.
 */
void
serialize_request(pipe<char> &out, const qb::http::Request &r, const bool head_only) {
    // The method token, from llhttp's method map; a value it does not name -- a default-constructed
    // Request's Method::UNINITIALIZED -- is refused here: http_method_name() would abort() (Huly QB-1066).
    const char *const method = method_token(r.method());
    if (method == nullptr) {
        refuse("qb::http::Request serialization: the request has no method llhttp can name.");
    }
    // A URI that failed to parse names no target; writing "/" for it would address a resource nobody
    // named (Huly QB-1066).
    if (!r.uri().is_valid()) {
        refuse("qb::http::Request serialization: the request URI is invalid.");
    }

    // SECURITY FIX: Validate URL size to prevent DoS
    const std::size_t path_size      = r.uri().path().size();
    const std::size_t query_size     = r.uri().encoded_queries().size();
    const std::size_t total_url_size = path_size + query_size;

    if (total_url_size > qb::http::protocol_limits::MAX_URL_LENGTH) {
        refuse_size("qb::http::Request serialization: URL length (", total_url_size, "qb::http::protocol_limits::MAX_URL_LENGTH",
                    qb::http::protocol_limits::MAX_URL_LENGTH, ").");
    }
    if (!raw_query_is_valid(r.uri().encoded_queries())) {
        refuse("qb::http::Request serialization: the query carries SP, a control byte or DEL; "
               "percent-encode it.");
    }

    // SECURITY FIX: Validate body size to prevent DoS
    const std::size_t body_size = head_only ? 0u : r.body().size();
    if (body_size > qb::http::protocol_limits::MAX_BODY_SIZE) {
        refuse_size("qb::http::Request serialization: body size (", body_size, "qb::http::protocol_limits::MAX_BODY_SIZE",
                    qb::http::protocol_limits::MAX_BODY_SIZE, ").");
    }

    const auto length   = body_size;
    const auto transfer = transfer_encoding(r);
    if (!transfer.ok) {
        refuse("qb::http::Request serialization: unsupported or malformed Transfer-Encoding.");
    }

    const std::optional<std::uint64_t> content_length = declared_content_length(r);

    if (transfer.chunked && content_length) {
        refuse("qb::http::Request serialization: Content-Length is forbidden with Transfer-Encoding.");
    }
    if (!head_only && !transfer.chunked && content_length && *content_length != length) {
        refuse("qb::http::Request serialization: Content-Length does not match body size.");
    }

    // Performance: Pre-calculate approximate output size to minimize allocations
    std::size_t estimated_size = 64; // Base request line size
    estimated_size += path_size;
    estimated_size += query_size + 1; // ?query

    // Add headers size
    for (const auto &it : r.headers()) {
        if (!header_name_is_valid(it.first)) {
            refuse("qb::http::Request serialization: header name exceeds MAX_HEADER_NAME_LENGTH.");
        }
        estimated_size += it.first.size() + 2; // ": "
        for (const auto &value : it.second) {
            if (!header_value_is_valid(value)) {
                refuse("qb::http::Request serialization: header value exceeds MAX_HEADER_VALUE_LENGTH.");
            }
            estimated_size += value.size() + 2; // CRLF
        }
    }
    estimated_size += 2; // Final CRLF
    estimated_size += body_size;

    // SECURITY FIX: Cap maximum serialized size to prevent overflow
    constexpr std::size_t MAX_SERIALIZED_SIZE = 110 * 1024 * 1024; // 110MB (slightly above MAX_BODY_SIZE + headers)
    if (estimated_size > MAX_SERIALIZED_SIZE) {
        refuse("qb::http::Request serialization: estimated wire size exceeds internal cap; refusing to allocate.");
    }

    // Reserve space in pipe to reduce allocations
    out.reserve(estimated_size);

    // Every refusal is above: nothing is written before the message is known to be writable, so a
    // refused message leaves the pipe as it found it -- what was queued before it included (it used to
    // clear() it, Huly QB-1066).

    // A complete chunked message with a trailer section -- the fields its `Trailer` header announces,
    // its trailers() -- is asked for here, before a byte is written (a trailers() field that cannot
    // travel refuses it), and written out of line after the request line: the trailer section after
    // its last chunk, as HTTP/2 and HTTP/3 send it (RFC 9112 §7.1.2, Huly QB-1067, QB-1073). A
    // MessageHead writes no trailer section, so it keeps every field. The request line is written
    // once, below, for both: a second writer of it in this translation unit made MSVC stop inlining
    // the header loop's `operator<<`s into this function (+3 % a message).
    const bool trailed = transfer.chunked && !head_only && qb::http::detail::writes_trailer_section(r, "qb::http::Request serialization");

    // HTTP Request Line: METHOD PATH[?query] HTTP/VERSION.
    // URI fragments are client-side identifiers and are never sent in an HTTP request-target.
    // An empty path is sent as "/" (RFC 9112 §3.2.1: the client MUST send "/" as the path of an
    // origin-form whose URI has none) -- a default URI, or one naming only an authority (Huly QB-1066).
    const std::string_view path        = path_size ? r.uri().path() : std::string_view{"/"};
    const bool             has_query   = r.uri().has_query();
    const auto             method_size = std::strlen(method);
    // The URI owns these bytes independently of the output pipe. Acquire the prefix once:
    // separate appends repeat capacity/alias checks for each token and separator.
    auto *cursor = out.allocate_back(method_size + 1 + path.size() + (has_query ? query_size + 1 : 0));
    std::memcpy(cursor, method, method_size);
    cursor += method_size;
    *cursor++ = ' ';
    std::memcpy(cursor, path.data(), path.size());
    cursor += path.size();
    if (has_query) {
        *cursor++ = '?';
        if (query_size) {
            std::memcpy(cursor, r.uri().encoded_queries().data(), query_size);
        }
    }
    out << qb::http::sep << "HTTP/" << r.major_version << "." << r.minor_version << qb::http::endl;

    if (trailed) [[unlikely]] {
        qb::http::detail::write_trailed_chunked_message(out, r, r.body().raw(), length);
        return;
    }

    // HTTP Headers
    for (const auto &it : r.headers()) {
        // Every name and value was validated above, with the same predicates: no second pass (it doubled
        // the validation and its refusal could no longer be reached).
        for (const auto &value : it.second) {
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
