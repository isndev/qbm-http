/**
 * @file qbm/http/origin.h
 * @brief Shared HTTP origin helpers: comparison, and the authority a request sends.
 *
 * Provides case-insensitive scheme/host comparison and effective-port
 * resolution used to determine whether two URIs share the same web origin
 * (scheme + host + effective port), as defined by RFC 6454, and the one
 * authority writer every protocol uses for `Host` and `:authority`.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>
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

/**
 * @brief The authority a request sends for @p uri: the `Host` field value of HTTP/1.1 and of the
 *        WebSocket handshake (RFC 9110 §7.2), the `:authority` pseudo-header of HTTP/2 and HTTP/3
 *        (RFC 9113 §8.3.1, RFC 9114 §4.3.1) -- one writer for the five places that wrote it
 *        (Huly QB-1064).
 *
 * - The host as the URI writes it; an IPv6 literal between brackets (RFC 3986 §3.2.2) --
 *   `qb::io::uri::host()` returns it without them, the form a socket wants.
 * - An IPv6 literal's zone identifier (`fe80::1%25eth0`) is left out: it has local significance
 *   only and is never sent on the wire (RFC 9844 §6, RFC 6874 §4 before it).
 * - `:port` unless it is the scheme's default (http and ws 80, https and wss 443, the scheme
 *   compared case-insensitively) -- `qb::io::uri` fills the default in when the URI names none.
 *
 * @param uri URI to inspect.
 * @return The authority, e.g. `example.test`, `example.test:8443`, `[2001:db8::1]:8080`; empty when
 *         the URI has no host.
 */
[[nodiscard]] std::string authority(qb::io::uri const &uri);

} // namespace qb::http::origin
