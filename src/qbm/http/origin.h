/**
 * @file qbm/http/origin.h
 * @brief Shared HTTP origin helpers: comparison, the authority a request sends, and the URI a request
 *        received with pseudo-header fields names.
 *
 * Provides case-insensitive scheme/host comparison and effective-port
 * resolution used to determine whether two URIs share the same web origin
 * (scheme + host + effective port), as defined by RFC 6454, the one
 * authority writer every protocol uses for `Host` and `:authority`, and the
 * one reader HTTP/2 and HTTP/3 servers use for `:scheme`, `:authority` and `:path`.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <qb/io/uri.h>
#include <qb/utility/branch_hints.h> // QB_MSVC_FORCEINLINE (is_request_authority, Huly QB-1186)

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

namespace detail {

/// The octets a reg-name holds as themselves (RFC 3986 §3.2.2): the unreserved characters and the sub-delims, as
/// qb::io::is_unreserved() and is_sub_delim() class them -- one lookup an octet, on the path of every request, whose
/// Host field and `:authority` are read here (Huly QB-1186). unit/message-types holds it to those two functions.
inline constexpr auto reg_name_octet = [] {
    std::array<bool, 256> table{};
    for (unsigned char const c : std::string_view{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;="})
        table[c] = true;
    return table;
}();

/// A hexadecimal digit, as std::isxdigit() classes it in the "C" locale: no locale call on the request path.
[[nodiscard]] constexpr bool
is_hex_octet(unsigned char const c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/// `port = *DIGIT` (RFC 3986 §3.2.3), as a port qb can reach: leading zeros allowed, no greater than 65535, read in one
/// pass -- the value is bounded at every digit, so no width can overflow it. An empty port is the scheme's default.
[[nodiscard]] constexpr bool
is_port(std::string_view const port) noexcept {
    std::uint32_t value = 0;
    for (char const c : port) {
        unsigned const digit = static_cast<unsigned char>(c) - static_cast<unsigned>('0');
        if (digit > 9u)
            return false;
        value = value * 10u + digit;
        if (value > 65535u)
            return false;
    }
    return true;
}

/// The IP-literal form of an authority, `[` an IPv6 address `]` and an optional `:port`: the one branch of
/// is_request_authority() that calls out (`inet_pton`), kept off the inline path.
[[nodiscard]] bool is_ip_literal_authority(std::string_view text) noexcept;

} // namespace detail

/**
 * @brief Whether @p text is an authority a request may name: `uri-host [ ":" port ]` (RFC 3986 §3.2)
 *        without a userinfo part -- the `Host` of HTTP/1.1, the `:authority` of HTTP/2 and HTTP/3 (Huly
 *        QB-1177).
 *
 * An IP literal between brackets that is an IPv6 address (`inet_pton`; no zone identifier, no
 * IPvFuture), or a reg-name or an IPv4 address of unreserved characters, sub-delims and
 * percent-encoded octets (RFC 3986 §3.2.2); then nothing, `:`, or `:` and a port of digits, leading
 * zeros allowed, no greater than 65535. Never a userinfo. The redirect target check uses it too.
 *
 * One pass over the text and nothing allocated, inline where the HTTP/1.1 parser checks every request's
 * Host field (Huly QB-1186): the host's octets through one table, the port's digits bounded as they are
 * read; only an IP literal calls out. The first form of this check was an out-of-line function that
 * scanned the host, then re-read the port with std::from_chars: 171 instructions a request on g++ 14. Forced
 * inline on MSVC: once the parser's three helpers around it were, MSVC kept this function out of line instead,
 * one call on the header-complete path of every request (the HTTP/1.1 parser's base.h says what that cost).
 *
 * @param text The field value.
 * @return Whether the text has that shape.
 */
[[nodiscard]] QB_MSVC_FORCEINLINE bool
is_request_authority(std::string_view const text) noexcept {
    if (text.empty())
        return false;
    if (text.front() == '[') [[unlikely]]
        return detail::is_ip_literal_authority(text);
    std::size_t       i = 0;
    std::size_t const n = text.size();
    for (; i < n; ++i) { // the reg-name or IPv4 address, up to the ':' of a port or the end
        auto const c = static_cast<unsigned char>(text[i]);
        if (detail::reg_name_octet[c])
            continue;
        if (c == ':')
            break;
        if (c == '%') { // a percent-encoded octet: two hexadecimal digits must follow
            if (n - i < 3 || !detail::is_hex_octet(static_cast<unsigned char>(text[i + 1]))
                || !detail::is_hex_octet(static_cast<unsigned char>(text[i + 2])))
                return false;
            i += 2;
            continue;
        }
        return false;
    }
    if (i == 0)
        return false; // no host
    return i == n || detail::is_port(text.substr(i + 1));
}

/**
 * @brief The URI of a request received over HTTP/2 or HTTP/3, from its `:scheme`, `:authority` (or `host`)
 *        and `:path` fields (RFC 9113 §8.3.1, RFC 9114 §4.3.1): one reader for the two
 *        servers that composed it on their own (Huly QB-1177).
 *
 * - `scheme://authority` followed by the path. The URI's authority is `:authority` (or the `host` field
 *   that stands for it, Huly QB-1195), never one a `:path` or a userinfo part chose: composed onto
 *   `victim.test`, the `:path` `@evil.test/x` named the host `evil.test`. A `:path` `//a/b` stays the
 *   path it is. The text is read by qb::io::uri::absolute_form(), as an HTTP/1.1 absolute-form target is:
 *   the path may hold `[`, `]` and `|`, which a browser sends unencoded (Huly QB-1187).
 * - The asterisk-form of an OPTIONS request is the URI `*`, without an authority, as HTTP/1.1's is:
 *   the request names no resource of the authority, which `:authority` or `host` gave.
 *
 * @param scheme          `:scheme`: a URI scheme (RFC 3986 §3.1).
 * @param authority       `:authority`, or the `host` field that stands for it: an authority
 *                        is_request_authority() accepts.
 * @param path            `:path`: an absolute path and an optional query, no fragment, no space or control
 *                        byte; or `*` for an OPTIONS request.
 * @param options_request Whether the request's method is OPTIONS.
 * @return The URI, or std::nullopt when the fields are malformed: an invalid scheme, an authority
 *         is_request_authority() refuses, a path that neither begins with '/' nor is the `*` of an
 *         OPTIONS request or that holds a `#`, a space or a control byte, or a text
 *         qb::io::uri::absolute_form() refuses. A malformed request is a stream error
 *         (RFC 9113 §8.1.1, RFC 9114 §4.1.2).
 */
[[nodiscard]] std::optional<qb::io::uri> request_uri(std::string_view scheme, std::string_view authority, std::string_view path,
                                                     bool options_request);

/**
 * @brief The URI of a request received over HTTP/1.1, from its request target, by the target's form
 *        (RFC 9112 §3.2): the reader of the HTTP/1.1 server (Huly QB-1177).
 *
 * - origin-form (`/path?query`): qb::io::uri::origin_form(). `//a/b` is the path `//a/b`, never the
 *   host `a`; the request's authority is its `Host` field.
 * - absolute-form (`scheme://authority/path?query`): qb::io::uri::absolute_form(), whose authority is the
 *   request's (RFC 9112 §3.2.2) and must be one is_request_authority() accepts -- no userinfo, a host.
 * - authority-form, the target of a CONNECT request and of no other: qb::io::uri::authority_form(),
 *   the host and the port.
 * - asterisk-form, the target of an OPTIONS request and of no other: the URI `*`.
 *
 * The path of an origin-form or an absolute-form target may hold `[`, `]` and `|` besides what RFC 3986
 * allows (qb::io::is_request_path_character()): a browser sends them unencoded (Huly QB-1187). The
 * router and the static files take each for its percent-encoding.
 *
 * The target is read INTO @p uri -- the request's own -- through qb::io::uri's in-place readers, never through
 * a uri built apart and moved in, whose two moves of strings and query map were 830 instructions a request, 54 ns
 * of a 263 ns parse on g++ 14. That is the whole saving: the parser rebuilds its request for every message.
 *
 * @param uri             The uri to fill: the request's. When the target names no resource it holds no URI
 *                        worth reading (what it held before, or an invalid reading of the target).
 * @param target          The request target as it was received.
 * @param connect_request Whether the request's method is CONNECT.
 * @param options_request Whether the request's method is OPTIONS.
 * @return Whether the target names a resource; false for a target that is none of those forms -- a fragment,
 *         a `*` for another method, a path byte a request path may not hold (`/a^b`, `/a\b`): the server
 *         answers 400 (RFC 9112 §3.2).
 */
[[nodiscard]] bool request_target_uri(qb::io::uri &uri, std::string_view target, bool connect_request, bool options_request);

} // namespace qb::http::origin
