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

#include <charconv>
#include <string>

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

} // namespace qb::http::origin
