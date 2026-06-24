/**
 * @file qbm/http/origin.h
 * @brief Shared HTTP origin comparison helpers.
 *
 * Provides case-insensitive scheme/host comparison and effective-port
 * resolution used to determine whether two URIs share the same web origin
 * (scheme + host + effective port), as defined by RFC 6454.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include <qb/io/uri.h>

namespace qb::http::origin {

/**
 * @brief Compares two URI schemes for equality, case-insensitively (ASCII).
 *
 * @param lhs First scheme.
 * @param rhs Second scheme.
 * @return `true` if both schemes are equal ignoring ASCII case, `false`
 *         otherwise.
 */
[[nodiscard]] bool scheme_eq(std::string_view lhs, std::string_view rhs) noexcept;

/**
 * @brief Compares two hosts for equality, case-insensitively (ASCII).
 *
 * @param lhs First host.
 * @param rhs Second host.
 * @return `true` if both hosts are equal ignoring ASCII case, `false`
 *         otherwise.
 */
[[nodiscard]] bool host_eq(std::string_view lhs, std::string_view rhs) noexcept;

/**
 * @brief Resolves the effective port string of a URI.
 *
 * Returns the URI's explicit port when present; otherwise falls back to the
 * well-known default for the scheme ("80" for `http`, "443" for `https`).
 *
 * @param uri URI to inspect.
 * @return The effective port as a string view, or an empty view when neither an
 *         explicit port nor a known default applies.
 */
[[nodiscard]] std::string_view effective_port(qb::io::uri const &uri) noexcept;

/**
 * @brief Resolves the effective port of a URI as a numeric value.
 *
 * Parses the result of @ref effective_port and validates it is a well-formed,
 * fully-consumed decimal integer within the valid port range [0, 65535].
 *
 * @param uri URI to inspect.
 * @return The effective port number, or `std::nullopt` when no effective port
 *         applies or the port string is malformed / out of range.
 */
[[nodiscard]] std::optional<std::uint32_t> effective_port_number(qb::io::uri const &uri) noexcept;

/**
 * @brief Determines whether two URIs share the same web origin.
 *
 * Two URIs are same-origin when their schemes match (case-insensitively),
 * their hosts match (case-insensitively), and both resolve to the same,
 * well-formed effective port.
 *
 * @param lhs First URI.
 * @param rhs Second URI.
 * @return `true` if both URIs share the same origin, `false` otherwise.
 */
[[nodiscard]] bool same(qb::io::uri const &lhs, qb::io::uri const &rhs) noexcept;

} // namespace qb::http::origin
