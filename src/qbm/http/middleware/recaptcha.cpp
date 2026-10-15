/**
 * @file qbm/http/middleware/recaptcha.cpp
 * @brief Out-of-line definitions for the reCAPTCHA verification middleware.
 *
 * Hosts the non-template helper used to assemble the URL-encoded body sent to
 * Google's site verification API. The middleware class itself is templated on
 * the session type and therefore remains header-only.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./recaptcha.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>

namespace qb::http {
namespace detail {
std::string
build_recaptcha_verification_body(std::string_view secret, std::string_view response, std::optional<std::string_view> remote_ip) {
    std::string request_body = "secret=" + qb::io::uri::encode(secret) + "&response=" + qb::io::uri::encode(response);
    if (remote_ip && !remote_ip->empty()) {
        request_body += "&remoteip=" + qb::io::uri::encode(*remote_ip);
    }
    return request_body;
}

std::optional<std::chrono::system_clock::time_point>
parse_recaptcha_challenge_ts(std::string_view value) noexcept {
    using namespace std::chrono;
    std::size_t pos    = 0;
    const auto  number = [&](std::size_t width, int &out) noexcept {
        if (value.size() - pos < width) {
            return false;
        }
        int parsed = 0;
        for (std::size_t i = 0; i < width; ++i) {
            const char c = value[pos + i];
            if (c < '0' || c > '9') {
                return false;
            }
            parsed = parsed * 10 + (c - '0');
        }
        out = parsed;
        pos += width;
        return true;
    };
    const auto literal = [&](char upper, char lower) noexcept {
        if (pos < value.size() && (value[pos] == upper || value[pos] == lower)) {
            ++pos;
            return true;
        }
        return false;
    };

    // RFC 3339 section 5.6: full-date "T" partial-time time-offset.
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    if (!number(4, y) || !literal('-', '-') || !number(2, mo) || !literal('-', '-') || !number(2, d) || !literal('T', 't') || !number(2, h)
        || !literal(':', ':') || !number(2, mi) || !literal(':', ':') || !number(2, s)) {
        return std::nullopt;
    }
    nanoseconds fraction{0};
    if (literal('.', '.')) {
        std::size_t  digits = 0;
        std::int64_t nanos  = 0;
        while (pos < value.size() && value[pos] >= '0' && value[pos] <= '9') {
            if (digits < 9) {
                nanos = nanos * 10 + (value[pos] - '0');
            }
            ++digits;
            ++pos;
        }
        if (digits == 0) {
            return std::nullopt;
        }
        for (std::size_t k = digits; k < 9; ++k) {
            nanos *= 10;
        }
        fraction = nanoseconds{nanos};
    }
    minutes offset{0};
    if (!literal('Z', 'z')) {
        if (pos >= value.size() || (value[pos] != '+' && value[pos] != '-')) {
            return std::nullopt; // a local time without an offset denotes no instant
        }
        const int sign = value[pos] == '-' ? -1 : 1;
        ++pos;
        int oh = 0, om = 0;
        if (!number(2, oh)) {
            return std::nullopt;
        }
        (void) literal(':', ':');
        if (!number(2, om) || oh > 23 || om > 59) {
            return std::nullopt;
        }
        offset = minutes{sign * (oh * 60 + om)};
    }
    if (pos != value.size() || h > 23 || mi > 59 || s > 60) {
        return std::nullopt;
    }
    const year_month_day date{year{y}, month{static_cast<unsigned>(mo)}, day{static_cast<unsigned>(d)}};
    if (!date.ok()) {
        return std::nullopt;
    }
    // A leap second (:60) adds up to the next second, as POSIX time counts it; the offset is
    // subtracted to reach UTC.
    const auto instant = sys_days{date} + hours{h} + minutes{mi} + seconds{s} + fraction - offset;
    return floor<system_clock::duration>(instant);
}
} // namespace detail
} // namespace qb::http
