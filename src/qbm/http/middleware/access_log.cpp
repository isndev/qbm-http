/**
 * @file qbm/http/middleware/access_log.cpp
 * @brief The shipped access-log formats: Apache common and combined, and JSON lines (Huly QB-90).
 *
 * A line is built in a stack buffer and appended to the caller's string once it is complete (or when the buffer
 * fills): the bounded pieces -- the literals, the numbers, the time -- are written through a local cursor, so that a
 * byte store cannot force the compiler to reload the cursor from memory; a quoted field is scanned sixteen or eight
 * bytes at a time and its clean runs are copied whole. The formatted second of each time format is kept per thread
 * and reformatted only when the second changes.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "access_log.h"

#include <bit>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <ctime>
#include <limits>

// A quoted field is scanned sixteen bytes per step where SSE2 is the baseline (every x86-64 toolchain), and eight
// bytes per step otherwise.
#if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#include <emmintrin.h>
#define QB_HTTP_ACCESS_LOG_SSE2 1
#else
#define QB_HTTP_ACCESS_LOG_SSE2 0
#endif

namespace qb::http::access_log_format {

namespace {

constexpr char hex_digits[]       = "0123456789abcdef";
constexpr char month_names[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

/// Which rule escapes a field.
enum class escaping { apache, json };

/// Whether the byte `c` is escaped: `"`, `\` and control characters in both rules, and for Apache every byte
/// outside printable ASCII.
template <escaping E>
[[nodiscard]] constexpr bool
needs_escape(unsigned char const c) noexcept {
    if constexpr (E == escaping::apache)
        return c == '"' || c == '\\' || c < 0x20 || c >= 0x7f;
    else
        return c == '"' || c == '\\' || c < 0x20;
}

constexpr std::uint64_t byte_ones  = 0x0101010101010101ULL;
constexpr std::uint64_t byte_highs = 0x8080808080808080ULL;

/// Nonzero exactly when one of the eight bytes of `x` is below `n` (`n` <= 128): the classic "has less" test.
[[nodiscard]] constexpr std::uint64_t
has_byte_below(std::uint64_t const x, std::uint64_t const n) noexcept {
    return (x - byte_ones * n) & ~x & byte_highs;
}

/// Nonzero exactly when one of the eight bytes of `x` is `b`.
[[nodiscard]] constexpr std::uint64_t
has_byte(std::uint64_t const x, unsigned char const b) noexcept {
    return has_byte_below(x ^ (byte_ones * b), 1);
}

/// Whether one of the eight bytes at `p` is escaped under `E` (the tests are exact as predicates: false proves the
/// eight bytes clean).
template <escaping E>
[[nodiscard]] bool
block8_needs_escape(char const *const p) noexcept {
    std::uint64_t x;
    std::memcpy(&x, p, 8);
    std::uint64_t m = has_byte_below(x, 0x20) | has_byte(x, '"') | has_byte(x, '\\');
    if constexpr (E == escaping::apache)
        m |= (x & byte_highs) | has_byte(x, 0x7f);
    return m != 0;
}

#if QB_HTTP_ACCESS_LOG_SSE2
/// One bit per byte of the sixteen at `p` that is escaped under `E`.
template <escaping E>
[[nodiscard]] unsigned
block16_escape_mask(char const *const p) noexcept {
    const __m128i x = _mm_loadu_si128(reinterpret_cast<const __m128i *>(p));
    __m128i       m = _mm_or_si128(_mm_cmpeq_epi8(x, _mm_set1_epi8('"')), _mm_cmpeq_epi8(x, _mm_set1_epi8('\\')));
    m               = _mm_or_si128(m, _mm_cmpeq_epi8(_mm_min_epu8(x, _mm_set1_epi8(0x1f)), x)); // x <= 0x1f
    if constexpr (E == escaping::apache)
        m = _mm_or_si128(m, _mm_cmpeq_epi8(_mm_max_epu8(x, _mm_set1_epi8(0x7f)), x)); // x >= 0x7f
    return static_cast<unsigned>(_mm_movemask_epi8(m));
}
#endif

/**
 * The length of the longest prefix of `text` that needs no escaping under `E`. Wide steps, and the last one re-reads
 * the tail overlapped instead of finishing byte by byte: the bytes it re-reads were found clean, so the first byte it
 * flags is the first of the field.
 */
template <escaping E>
[[nodiscard]] std::size_t
clean_prefix(std::string_view const text) noexcept {
    const char *const p = text.data();
    const std::size_t n = text.size();
    std::size_t       i = 0;
#if QB_HTTP_ACCESS_LOG_SSE2
    if (n >= 16) {
        for (; n - i > 16; i += 16) {
            if (const unsigned mask = block16_escape_mask<E>(p + i))
                return i + static_cast<std::size_t>(std::countr_zero(mask));
        }
        if (const unsigned mask = block16_escape_mask<E>(p + n - 16))
            return n - 16 + static_cast<std::size_t>(std::countr_zero(mask));
        return n;
    }
#endif
    if (n >= 8) {
        while (n - i > 8 && !block8_needs_escape<E>(p + i))
            i += 8;
        if (n - i <= 8) {
            // Every full step was clean: the last eight bytes, overlapped.
            if (!block8_needs_escape<E>(p + n - 8))
                return n;
            i = n - 8;
        }
    }
    // Fewer than eight bytes, or the eight from `i` hold the first byte to escape.
    while (i < n && !needs_escape<E>(static_cast<unsigned char>(p[i])))
        ++i;
    return i;
}

/// Copies a string literal to `p`; returns the end of the copy.
template <std::size_t N>
[[nodiscard]] char *
put(char *const p, char const (&s)[N]) noexcept {
    std::memcpy(p, s, N - 1);
    return p + N - 1;
}

[[nodiscard]] char *
put(char *const p, std::string_view const s) noexcept {
    std::memcpy(p, s.data(), s.size());
    return p + s.size();
}

/// `v` in decimal: at most 20 bytes.
[[nodiscard]] char *
put_number(char *const p, std::uint64_t const v) noexcept {
    return std::to_chars(p, p + 20, v).ptr;
}

/// `v` (0..99) on two digits.
[[nodiscard]] char *
put_two(char *const p, int const v) noexcept {
    p[0] = static_cast<char>('0' + (v / 10) % 10);
    p[1] = static_cast<char>('0' + v % 10);
    return p + 2;
}

/**
 * Builds a line in a stack buffer and appends it to the caller's string when the buffer fills and at `flush()`.
 * A bounded piece is written through `reserve(n)`, which returns a cursor with `n` free bytes, then `commit(end)`.
 */
class line_writer {
public:
    static constexpr std::size_t capacity = 256;

    explicit line_writer(std::string &out) noexcept
        : _out(out) {}
    line_writer(line_writer const &)            = delete;
    line_writer &operator=(line_writer const &) = delete;

    /// A cursor with at least `n` (<= `capacity`) free bytes after it.
    [[nodiscard]] char *
    reserve(std::size_t const n) {
        if (static_cast<std::size_t>(_buf + capacity - _p) < n)
            flush();
        return _p;
    }

    /// Ends a piece written at the cursor `reserve` returned.
    void
    commit(char *const end) noexcept {
        _p = end;
    }

    /// Bytes copied as they are. An empty view may point nowhere: it copies nothing (memcpy takes no null pointer,
    /// whatever the size).
    void
    raw(std::string_view const s) {
        if (s.empty())
            return;
        if (s.size() <= static_cast<std::size_t>(_buf + capacity - _p)) {
            std::memcpy(_p, s.data(), s.size());
            _p += s.size();
        } else {
            flush();
            _out.append(s);
        }
    }

    /// `text` escaped under `E`: each clean run copied whole, each escaped byte as its sequence.
    template <escaping E>
    void
    escaped(std::string_view text) {
        for (;;) {
            const std::size_t clean = clean_prefix<E>(text);
            raw(std::string_view(text.data(), clean));
            if (clean == text.size())
                return;
            escape_byte<E>(static_cast<unsigned char>(text[clean]));
            text.remove_prefix(clean + 1);
        }
    }

    /// Appends what the buffer holds to the caller's string.
    void
    flush() {
        if (_p != _buf) {
            _out.append(_buf, static_cast<std::size_t>(_p - _buf));
            _p = _buf;
        }
    }

private:
    template <escaping E>
    void
    escape_byte(unsigned char const c) {
        char *p = reserve(6);
        *p++    = '\\';
        if constexpr (E == escaping::apache) {
            if (c == '"' || c == '\\') {
                *p++ = static_cast<char>(c);
            } else {
                *p++ = 'x';
                *p++ = hex_digits[c >> 4];
                *p++ = hex_digits[c & 0xf];
            }
        } else {
            switch (c) {
                case '"':
                case '\\':
                    *p++ = static_cast<char>(c);
                    break;
                case '\n':
                    *p++ = 'n';
                    break;
                case '\r':
                    *p++ = 'r';
                    break;
                case '\t':
                    *p++ = 't';
                    break;
                default:
                    p    = put(p, "u00");
                    *p++ = hex_digits[c >> 4];
                    *p++ = hex_digits[c & 0xf];
            }
        }
        commit(p);
    }

    std::string &_out;
    char         _buf[capacity];
    char        *_p = _buf;
};

/// A second formatted once: the text of the last second a thread formatted in one time format.
struct formatted_second {
    static constexpr std::size_t max_size = 40;

    std::int64_t second = std::numeric_limits<std::int64_t>::min();
    std::size_t  size   = 0;
    char         text[max_size]{};
};

constinit thread_local formatted_second clf_second{};
constinit thread_local formatted_second rfc3339_second{};

/// The whole seconds of `t` since the epoch, rounded down (an instant before 1970 included).
[[nodiscard]] std::int64_t
floor_seconds(qb::wall_time const t) noexcept {
    return static_cast<std::int64_t>(std::chrono::floor<std::chrono::seconds>(t).time_since_epoch().count());
}

/// The text of `second` in `cache`, formatted by `format` (which returns its size) unless `cache` holds it already.
[[nodiscard]] std::string_view
second_text(formatted_second &cache, std::int64_t const second, std::size_t (*const format)(std::tm const &, char *)) {
    if (cache.second != second) {
        std::tm tm_value{};
        (void) qb::safe_gmtime(static_cast<std::time_t>(second), tm_value);
        cache.size   = format(tm_value, cache.text);
        cache.second = second;
    }
    return {cache.text, cache.size};
}

/// `[10/Oct/2000:13:55:36 +0000]` into `text` (at most 36 bytes); returns its size.
[[nodiscard]] std::size_t
format_clf_second(std::tm const &tm_value, char *const text) {
    char *q = put(text, "[");
    q       = put_two(q, tm_value.tm_mday);
    q       = put(q, "/");
    q       = put(q, std::string_view(month_names[tm_value.tm_mon % 12], 3));
    q       = put(q, "/");
    q       = std::to_chars(q, text + 20, tm_value.tm_year + 1900).ptr;
    q       = put(q, ":");
    q       = put_two(q, tm_value.tm_hour);
    q       = put(q, ":");
    q       = put_two(q, tm_value.tm_min);
    q       = put(q, ":");
    q       = put_two(q, tm_value.tm_sec);
    q       = put(q, " +0000]");
    return static_cast<std::size_t>(q - text);
}

/// `2000-10-10T13:55:36` into `text` (at most 35 bytes); returns its size.
[[nodiscard]] std::size_t
format_rfc3339_second(std::tm const &tm_value, char *const text) {
    char *q = std::to_chars(text, text + 20, tm_value.tm_year + 1900).ptr;
    q       = put(q, "-");
    q       = put_two(q, tm_value.tm_mon + 1);
    q       = put(q, "-");
    q       = put_two(q, tm_value.tm_mday);
    q       = put(q, "T");
    q       = put_two(q, tm_value.tm_hour);
    q       = put(q, ":");
    q       = put_two(q, tm_value.tm_min);
    q       = put(q, ":");
    q       = put_two(q, tm_value.tm_sec);
    return static_cast<std::size_t>(q - text);
}

/// `[10/Oct/2000:13:55:36 +0000]`: at most `formatted_second::max_size` bytes.
[[nodiscard]] char *
put_clf_time(char *const p, qb::wall_time const t) {
    return put(p, second_text(clf_second, floor_seconds(t), format_clf_second));
}

/// `2000-10-10T13:55:36.123Z`: at most `formatted_second::max_size` + 5 bytes.
[[nodiscard]] char *
put_rfc3339(char *p, qb::wall_time const t) {
    const std::int64_t second = floor_seconds(t);
    p                         = put(p, second_text(rfc3339_second, second, format_rfc3339_second));
    const auto since_second   = t - qb::wall_time{std::chrono::seconds{second}};
    const auto ms             = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(since_second).count());
    *p++                      = '.';
    *p++                      = static_cast<char>('0' + (ms / 100) % 10);
    p                         = put_two(p, ms % 100);
    *p++                      = 'Z';
    return p;
}

/// `HTTP/1.1`, or `HTTP/2` from version 2 on: at most 46 bytes.
[[nodiscard]] char *
put_protocol(char *p, AccessLogRecord const &record) noexcept {
    p = put(p, "HTTP/");
    p = put_number(p, static_cast<std::uint64_t>(record.major_version));
    if (record.major_version < 2) {
        *p++ = '.';
        p    = put_number(p, static_cast<std::uint64_t>(record.minor_version));
    }
    return p;
}

/// `d` in seconds, rounded to the nearest microsecond: `0.012345`. At most 27 bytes.
[[nodiscard]] char *
put_seconds(char *p, qb::duration const d) noexcept {
    const auto          ns = d.count() < 0 ? std::uint64_t{0} : static_cast<std::uint64_t>(d.count());
    const std::uint64_t us = (ns + 500) / 1000;
    p                      = put_number(p, us / 1000000);
    *p++                   = '.';
    const auto frac        = static_cast<int>(us % 1000000);
    p                      = put_two(p, frac / 10000);
    p                      = put_two(p, frac / 100 % 100);
    return put_two(p, frac % 100);
}

/// `"key":"value"` with the value JSON-escaped, or `"key":null` for an empty value when `null_when_empty`. The key
/// part is the literal before the value: `,"remote":`.
template <std::size_t N>
void
json_field(line_writer &w, char const (&key_part)[N], std::string_view const value, bool const null_when_empty = false) {
    static_assert(N + 4 <= line_writer::capacity);
    char *p = put(w.reserve(N + 4), key_part);
    if (null_when_empty && value.empty()) {
        w.commit(put(p, "null"));
        return;
    }
    *p++ = '"';
    w.commit(p);
    w.escaped<escaping::json>(value);
    p    = w.reserve(1);
    *p++ = '"';
    w.commit(p);
}

[[nodiscard]] std::string_view
outcome_name(RequestOutcome const outcome) noexcept {
    switch (outcome) {
        case RequestOutcome::RESPONDED:
            return "responded";
        case RequestOutcome::SESSION_GONE:
            return "session_gone";
        case RequestOutcome::SUPPRESSED:
            return "suppressed";
    }
    return "unknown";
}

void
write_common(line_writer &w, AccessLogRecord const &record) {
    if (record.remote_address.empty())
        w.raw("-");
    else
        w.raw(record.remote_address);
    char *p = w.reserve(5 + formatted_second::max_size + 2);
    p       = put(p, " - - ");
    p       = put_clf_time(p, record.received);
    w.commit(put(p, " \""));
    w.escaped<escaping::apache>(record.method);
    w.raw(" ");
    w.escaped<escaping::apache>(record.target);
    p    = w.reserve(1 + 46 + 2 + 20 + 1 + 20);
    *p++ = ' ';
    p    = put_protocol(p, record);
    p    = put(p, "\" ");
    p    = put_number(p, static_cast<std::uint64_t>(record.status));
    *p++ = ' ';
    if (record.bytes == 0)
        *p++ = '-';
    else
        p = put_number(p, record.bytes);
    w.commit(p);
}

/// ` "value"`, Apache-escaped, or ` "-"` for an empty value.
void
apache_quoted(line_writer &w, std::string_view const value) {
    if (value.empty()) {
        w.raw(" \"-\"");
        return;
    }
    w.raw(" \"");
    w.escaped<escaping::apache>(value);
    w.raw("\"");
}

} // namespace

void
common(AccessLogRecord const &record, std::string &line) {
    line_writer w(line);
    write_common(w, record);
    w.flush();
}

void
combined(AccessLogRecord const &record, std::string &line) {
    line_writer w(line);
    write_common(w, record);
    apache_quoted(w, record.referer);
    apache_quoted(w, record.user_agent);
    w.flush();
}

void
json(AccessLogRecord const &record, std::string &line) {
    line_writer w(line);
    char       *p = w.reserve(9 + formatted_second::max_size + 5 + 1);
    p             = put(p, "{\"time\":\"");
    p             = put_rfc3339(p, record.received);
    w.commit(put(p, "\""));
    json_field(w, ",\"remote\":", record.remote_address);
    json_field(w, ",\"method\":", record.method);
    json_field(w, ",\"target\":", record.target);
    p = w.reserve(13 + 46 + 11 + 20 + 9 + 20 + 20 + 27);
    p = put(p, ",\"protocol\":\"");
    p = put_protocol(p, record);
    p = put(p, "\",\"status\":");
    p = put_number(p, static_cast<std::uint64_t>(record.status));
    p = put(p, ",\"bytes\":");
    p = put_number(p, record.bytes);
    p = put(p, ",\"duration_seconds\":");
    w.commit(put_seconds(p, record.duration));
    json_field(w, ",\"referer\":", record.referer);
    json_field(w, ",\"user_agent\":", record.user_agent);
    json_field(w, ",\"request_id\":", record.request_id);
    json_field(w, ",\"route\":", record.route, true);
    p = w.reserve(13 + 12 + 2);
    p = put(p, ",\"outcome\":\"");
    p = put(p, outcome_name(record.outcome));
    w.commit(put(p, "\"}"));
    w.flush();
}

} // namespace qb::http::access_log_format
