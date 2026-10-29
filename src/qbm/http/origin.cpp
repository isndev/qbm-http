/**
 * @file qbm/http/origin.cpp
 * @brief Implementation of the shared HTTP origin comparison helpers.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./origin.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <string>
#include <system_error>

#include <qb/io/system/sys__socket.h>

#include "./utility.h"

namespace qb::http::origin {

bool
scheme_eq(std::string_view lhs, std::string_view rhs) noexcept {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        if (qb::http::utility::ascii_to_lower(lhs[i]) != qb::http::utility::ascii_to_lower(rhs[i])) {
            return false;
        }
    }
    return true;
}

bool
host_eq(std::string_view lhs, std::string_view rhs) noexcept {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        if (qb::http::utility::ascii_to_lower(lhs[i]) != qb::http::utility::ascii_to_lower(rhs[i])) {
            return false;
        }
    }
    return true;
}

namespace {
/// Whether @p text equals @p lower -- a lowercase scheme of the same length -- ignoring ASCII case.
[[nodiscard]] constexpr bool
equals_lowercase(std::string_view text, std::string_view lower) noexcept {
    for (std::size_t i = 0; i < lower.size(); ++i) {
        const char c = text[i];
        if ((c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c) != lower[i]) {
            return false;
        }
    }
    return true;
}

/// The default port of @p scheme, compared case-insensitively: ws shares http's (80), wss shares
/// https's (443); empty for any other scheme. Dispatched on the length: one comparison at most, on
/// the path of every request's authority (origin::authority).
[[nodiscard]] std::string_view
scheme_default_port(std::string_view scheme) noexcept {
    // Case-insensitive for ws/wss too (not just http/https): otherwise an upper-cased scheme like
    // "WS://" yields no port and same("ws://x","WS://x") spuriously returns false.
    switch (scheme.size()) {
        case 2:
            return equals_lowercase(scheme, "ws") ? std::string_view{"80"} : std::string_view{};
        case 3:
            return equals_lowercase(scheme, "wss") ? std::string_view{"443"} : std::string_view{};
        case 4:
            return equals_lowercase(scheme, "http") ? std::string_view{"80"} : std::string_view{};
        case 5:
            return equals_lowercase(scheme, "https") ? std::string_view{"443"} : std::string_view{};
        default:
            return {};
    }
}
} // namespace

std::string_view
effective_port(qb::io::uri const &uri) noexcept {
    if (!uri.port().empty()) {
        return uri.port();
    }
    return scheme_default_port(uri.scheme());
}

std::optional<std::uint32_t>
effective_port_number(qb::io::uri const &uri) noexcept {
    auto const port = effective_port(uri);
    if (port.empty()) {
        return std::nullopt;
    }

    std::uint32_t     value  = 0;
    auto const *const begin  = port.data();
    auto const *const end    = begin + port.size();
    auto              result = std::from_chars(begin, end, value);
    if (result.ec != std::errc{} || result.ptr != end || value > 65535u) {
        return std::nullopt;
    }
    return value;
}

bool
same(qb::io::uri const &lhs, qb::io::uri const &rhs) noexcept {
    auto const lhs_port = effective_port_number(lhs);
    auto const rhs_port = effective_port_number(rhs);

    return scheme_eq(lhs.scheme(), rhs.scheme()) && host_eq(lhs.host(), rhs.host()) && lhs_port.has_value() && rhs_port.has_value()
           && *lhs_port == *rhs_port;
}

std::string
authority(qb::io::uri const &uri) {
    std::string_view host = uri.host();
    if (host.empty()) {
        return {};
    }
    // qb::io::uri strips an IP literal's brackets; a host that still has them is taken as the literal.
    bool ip_literal = host.size() >= 2 && host.front() == '[' && host.back() == ']';
    if (ip_literal) {
        host = host.substr(1, host.size() - 2);
    } else {
        ip_literal = host.find(':') != std::string_view::npos; // a reg-name or an IPv4 address never holds one
    }
    if (ip_literal) {
        if (const auto zone = host.find('%'); zone != std::string_view::npos) {
            host = host.substr(0, zone); // the zone identifier never goes on the wire (RFC 9844 §6)
        }
    }
    const std::string_view port      = uri.port();
    const bool             with_port = !port.empty() && port != scheme_default_port(uri.scheme());
    std::string            value;
    value.reserve(host.size() + (ip_literal ? 2u : 0u) + (with_port ? port.size() + 1u : 0u));
    if (ip_literal) {
        value.push_back('[');
    }
    value.append(host);
    if (ip_literal) {
        value.push_back(']');
    }
    if (with_port) {
        value.push_back(':');
        value.append(port);
    }
    return value;
}

namespace {

/// `port = *DIGIT` (RFC 3986 §3.2.3), as a port qb can reach: leading zeros allowed, no greater than 65535 -- from_chars
/// refuses a number past 32 bits instead of wrapping it into range. An empty port is the scheme's default.
[[nodiscard]] bool
is_port(std::string_view const port) noexcept {
    if (port.empty())
        return true;
    std::uint32_t value  = 0;
    auto const    end    = port.data() + port.size();
    auto const    parsed = std::from_chars(port.data(), end, value);
    return parsed.ec == std::errc{} && parsed.ptr == end && value <= 65535u;
}

/// A reg-name or an IPv4 address (RFC 3986 §3.2.2): unreserved characters, sub-delims and percent-encoded octets.
[[nodiscard]] bool
is_reg_name(std::string_view const host) noexcept {
    for (std::size_t i = 0; i < host.size(); ++i) {
        auto const c = static_cast<unsigned char>(host[i]);
        if (c == '%') {
            if (host.size() - i < 3 || !std::isxdigit(static_cast<unsigned char>(host[i + 1]))
                || !std::isxdigit(static_cast<unsigned char>(host[i + 2])))
                return false;
            i += 2;
        } else if (!qb::io::is_unreserved(c) && !qb::io::is_sub_delim(c)) {
            return false;
        }
    }
    return !host.empty();
}

} // namespace

bool
is_request_authority(std::string_view text) noexcept {
    if (text.empty() || text.find('@') != std::string_view::npos)
        return false;
    if (text.front() == '[') {
        // An IP literal is an IPv6 address (RFC 3986 §3.2.2): `[127.0.0.1]` or `[cafe.de]` is none, and qb::io::uri
        // drops the brackets of whatever it reads between them. Hex digits, ':' and '.' only, before inet_pton reads
        // a C string: no NUL, no zone identifier (some inet_pton accept one, others refuse it), no IPvFuture.
        auto const close = text.find(']');
        if (close == std::string_view::npos)
            return false;
        auto const literal = text.substr(1, close - 1);
        if (literal.empty() || literal.size() >= INET6_ADDRSTRLEN
            || literal.find_first_not_of("0123456789abcdefABCDEF:.") != std::string_view::npos)
            return false;
        char address[INET6_ADDRSTRLEN];
        std::memcpy(address, literal.data(), literal.size());
        address[literal.size()] = '\0';
        in6_addr parsed{};
        if (qb::io::inet::ip::compat::inet_pton(AF_INET6, address, &parsed) != 1)
            return false;
        auto const suffix = text.substr(close + 1);
        return suffix.empty() || (suffix.front() == ':' && is_port(suffix.substr(1)));
    }
    auto const colon = text.find(':');
    return is_reg_name(text.substr(0, colon)) && (colon == std::string_view::npos || is_port(text.substr(colon + 1)));
}

std::optional<qb::io::uri>
request_uri(std::string_view scheme, std::string_view authority, std::string_view path, bool options_request) {
    if (!qb::io::uri::is_valid_scheme(scheme) || !is_request_authority(authority))
        return std::nullopt;
    if (options_request && path == "*")
        return qb::io::uri(std::string{"*"});
    // An absolute path and an optional query (RFC 9113 §8.3.1): no fragment, and no byte an HTTP/1.1 request line
    // could not carry either -- a space or a control character.
    if (path.empty() || path.front() != '/' || std::any_of(path.begin(), path.end(), [](char const c) {
            auto const byte = static_cast<unsigned char>(c);
            return c == '#' || byte <= 0x20 || byte == 0x7f;
        }))
        return std::nullopt;
    std::string text;
    text.reserve(scheme.size() + 3 + authority.size() + path.size());
    text.append(scheme).append("://").append(authority).append(path);
    qb::io::uri uri(std::move(text));
    if (!uri.is_valid() || uri.host().empty())
        return std::nullopt;
    return uri;
}

std::optional<qb::io::uri>
request_target_uri(std::string_view target, bool connect_request, bool options_request) {
    if (target.empty() || target.find('#') != std::string_view::npos)
        return std::nullopt; // no target form holds a fragment (RFC 9112 §3.2)
    std::optional<qb::io::uri> uri;
    if (connect_request) {
        if (is_request_authority(target))
            uri = qb::io::uri::authority_form(std::string{target});
    } else if (target.front() == '/') {
        uri = qb::io::uri::origin_form(std::string{target});
    } else if (target == "*") {
        if (options_request)
            uri = qb::io::uri(std::string{"*"});
    } else if (auto const separator = target.find("://"); separator != std::string_view::npos) {
        auto const rest      = target.substr(separator + 3);
        auto const authority = rest.substr(0, rest.find_first_of("/?"));
        if (qb::io::uri::is_valid_scheme(target.substr(0, separator)) && is_request_authority(authority))
            uri.emplace(std::string{target}); // is_request_authority() holds a host: `http:///x` has none
    }
    if (uri && !uri->is_valid())
        uri.reset();
    return uri;
}

} // namespace qb::http::origin
