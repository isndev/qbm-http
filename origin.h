/**
 * @file qbm/http/origin.h
 * @brief Shared HTTP origin helpers.
 */
#pragma once

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
        if (qb::http::utility::ascii_to_lower(lhs[i]) !=
            qb::http::utility::ascii_to_lower(rhs[i])) {
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
        if (qb::http::utility::ascii_to_lower(lhs[i]) !=
            qb::http::utility::ascii_to_lower(rhs[i])) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] inline std::string_view
effective_port(qb::io::uri const& uri) noexcept {
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

[[nodiscard]] inline bool
same(qb::io::uri const& lhs, qb::io::uri const& rhs) noexcept {
    return scheme_eq(lhs.scheme(), rhs.scheme()) &&
           host_eq(lhs.host(), rhs.host()) &&
           effective_port(lhs) == effective_port(rhs);
}

} // namespace qb::http::origin
