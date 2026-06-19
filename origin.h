/**
 * @file qbm/http/origin.h
 * @brief Shared HTTP origin helpers.
 */
#pragma once

#include <charconv>
#include <cstdint>
#include <optional>
#include <string_view>

#include <qb/io/uri.h>

#include "./utility.h"

namespace qb::http::origin {

[[nodiscard]] inline bool
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

[[nodiscard]] inline bool
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

[[nodiscard]] inline std::string_view
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

[[nodiscard]] inline std::optional<std::uint32_t>
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

[[nodiscard]] inline bool
same(qb::io::uri const &lhs, qb::io::uri const &rhs) noexcept {
    auto const lhs_port = effective_port_number(lhs);
    auto const rhs_port = effective_port_number(rhs);

    return scheme_eq(lhs.scheme(), rhs.scheme()) && host_eq(lhs.host(), rhs.host()) && lhs_port.has_value() && rhs_port.has_value()
           && *lhs_port == *rhs_port;
}

} // namespace qb::http::origin
