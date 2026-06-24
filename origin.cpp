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

std::string_view
effective_port(qb::io::uri const &uri) noexcept {
    if (!uri.port().empty()) {
        return uri.port();
    }
    if (scheme_eq(uri.scheme(), "http")) {
        return "80";
    }
    if (scheme_eq(uri.scheme(), "https")) {
        return "443";
    }
    return {};
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

} // namespace qb::http::origin
