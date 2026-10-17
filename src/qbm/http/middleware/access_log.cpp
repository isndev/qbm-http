/**
 * @file qbm/http/middleware/access_log.cpp
 * @brief The shipped access-log formats: Apache common and combined, and JSON lines (Huly QB-90).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "access_log.h"

#include <charconv>
#include <chrono>
#include <ctime>

namespace qb::http::access_log_format {

namespace {

constexpr char hex_digits[]       = "0123456789abcdef";
constexpr char month_names[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

void
append_number(std::string &out, std::uint64_t const v) {
    char       buf[24];
    auto const res = std::to_chars(buf, buf + sizeof(buf), v);
    out.append(buf, res.ptr);
}

void
append_two(std::string &out, int const v) {
    out += static_cast<char>('0' + (v / 10) % 10);
    out += static_cast<char>('0' + v % 10);
}

/// A field of a quoted Apache field: `"` and `\` escaped, every byte outside printable ASCII as `\xhh`.
void
append_apache_escaped(std::string &out, std::string_view const text) {
    for (char const ch : text) {
        const auto c = static_cast<unsigned char>(ch);
        if (c == '"' || c == '\\') {
            out += '\\';
            out += ch;
        } else if (c < 0x20 || c >= 0x7f) {
            out += "\\x";
            out += hex_digits[c >> 4];
            out += hex_digits[c & 0xf];
        } else {
            out += ch;
        }
    }
}

/// A JSON string's content: `"` `\` and control characters escaped; other bytes as they are.
void
append_json_escaped(std::string &out, std::string_view const text) {
    for (char const ch : text) {
        const auto c = static_cast<unsigned char>(ch);
        switch (ch) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out += hex_digits[c >> 4];
                    out += hex_digits[c & 0xf];
                } else {
                    out += ch;
                }
        }
    }
}

void
append_json_string(std::string &out, std::string_view const key, std::string_view const value, bool const null_when_empty = false) {
    out += '"';
    out += key;
    out += "\":";
    if (null_when_empty && value.empty()) {
        out += "null";
        return;
    }
    out += '"';
    append_json_escaped(out, value);
    out += '"';
}

[[nodiscard]] std::tm
utc(qb::wall_time const t) noexcept {
    std::tm tm_value{};
    (void) qb::safe_gmtime(std::chrono::system_clock::to_time_t(std::chrono::time_point_cast<std::chrono::seconds>(t)), tm_value);
    return tm_value;
}

/// `[10/Oct/2000:13:55:36 +0000]`
void
append_clf_time(std::string &out, qb::wall_time const t) {
    const std::tm tm_value = utc(t);
    out += '[';
    append_two(out, tm_value.tm_mday);
    out += '/';
    out += month_names[tm_value.tm_mon % 12];
    out += '/';
    append_number(out, static_cast<std::uint64_t>(tm_value.tm_year + 1900));
    out += ':';
    append_two(out, tm_value.tm_hour);
    out += ':';
    append_two(out, tm_value.tm_min);
    out += ':';
    append_two(out, tm_value.tm_sec);
    out += " +0000]";
}

/// `2000-10-10T13:55:36.123Z`
void
append_rfc3339(std::string &out, qb::wall_time const t) {
    const std::tm tm_value = utc(t);
    append_number(out, static_cast<std::uint64_t>(tm_value.tm_year + 1900));
    out += '-';
    append_two(out, tm_value.tm_mon + 1);
    out += '-';
    append_two(out, tm_value.tm_mday);
    out += 'T';
    append_two(out, tm_value.tm_hour);
    out += ':';
    append_two(out, tm_value.tm_min);
    out += ':';
    append_two(out, tm_value.tm_sec);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t - std::chrono::time_point_cast<std::chrono::seconds>(t)).count();
    out += '.';
    out += static_cast<char>('0' + (ms / 100) % 10);
    out += static_cast<char>('0' + (ms / 10) % 10);
    out += static_cast<char>('0' + ms % 10);
    out += 'Z';
}

void
append_protocol(std::string &out, AccessLogRecord const &record) {
    out += "HTTP/";
    append_number(out, static_cast<std::uint64_t>(record.major_version));
    if (record.major_version < 2) {
        out += '.';
        append_number(out, static_cast<std::uint64_t>(record.minor_version));
    }
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

} // namespace

void
common(AccessLogRecord const &record, std::string &line) {
    if (record.remote_address.empty())
        line += '-';
    else
        line += record.remote_address;
    line += " - - ";
    append_clf_time(line, record.received);
    line += " \"";
    append_apache_escaped(line, record.method);
    line += ' ';
    append_apache_escaped(line, record.target);
    line += ' ';
    append_protocol(line, record);
    line += "\" ";
    append_number(line, static_cast<std::uint64_t>(record.status));
    line += ' ';
    if (record.bytes == 0)
        line += '-';
    else
        append_number(line, record.bytes);
}

void
combined(AccessLogRecord const &record, std::string &line) {
    common(record, line);
    line += " \"";
    if (record.referer.empty())
        line += '-';
    else
        append_apache_escaped(line, record.referer);
    line += "\" \"";
    if (record.user_agent.empty())
        line += '-';
    else
        append_apache_escaped(line, record.user_agent);
    line += '"';
}

void
json(AccessLogRecord const &record, std::string &line) {
    line += "{\"time\":\"";
    append_rfc3339(line, record.received);
    line += "\",";
    append_json_string(line, "remote", record.remote_address);
    line += ',';
    append_json_string(line, "method", record.method);
    line += ',';
    append_json_string(line, "target", record.target);
    line += ",\"protocol\":\"";
    append_protocol(line, record);
    line += "\",\"status\":";
    append_number(line, static_cast<std::uint64_t>(record.status));
    line += ",\"bytes\":";
    append_number(line, record.bytes);
    line += ",\"duration_seconds\":";
    {
        char       buf[40];
        auto const res =
            std::to_chars(buf, buf + sizeof(buf), std::chrono::duration<double>(record.duration).count(), std::chars_format::fixed, 6);
        line.append(buf, res.ptr);
    }
    line += ',';
    append_json_string(line, "referer", record.referer);
    line += ',';
    append_json_string(line, "user_agent", record.user_agent);
    line += ',';
    append_json_string(line, "request_id", record.request_id);
    line += ',';
    append_json_string(line, "route", record.route, true);
    line += ",\"outcome\":\"";
    line += outcome_name(record.outcome);
    line += "\"}";
}

} // namespace qb::http::access_log_format
