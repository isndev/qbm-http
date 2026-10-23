/**
 * @file qbm/http/detail/redirect.cpp
 * @brief Strict URI-reference resolution on the opt-in redirect path.
 *
 * Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */
#include "./redirect.h"

#include <charconv>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string>
#include <system_error>
#include <utility>

#include <qb/io/system/sys__socket.h>
#include <qb/utility/branch_hints.h>

#include "../1.1/http.h"
#include "../origin.h"
#include "../request.h"
#include "../response.h"

namespace qb::http::detail {
namespace {

struct UriReference {
    std::string_view scheme;
    std::string_view authority;
    std::string_view path;
    std::string_view query;
    std::string_view fragment;
    bool             has_scheme    = false;
    bool             has_authority = false;
    bool             has_query     = false;
    bool             has_fragment  = false;
};

bool
alpha(unsigned char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool
hex(unsigned char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

bool
component(std::string_view text, bool path, bool query_or_fragment) noexcept {
    for (std::size_t i = 0; i < text.size(); ++i) {
        const auto c = static_cast<unsigned char>(text[i]);
        if (c == '%') {
            if (text.size() - i < 3 || !hex(static_cast<unsigned char>(text[i + 1])) || !hex(static_cast<unsigned char>(text[i + 2]))) {
                return false;
            }
            i += 2;
        } else if (!qb::io::is_unreserved(c) && !qb::io::is_sub_delim(c) && !((path || query_or_fragment) && (c == ':' || c == '@' || c == '/'))
                   && !(query_or_fragment && c == '?')) {
            return false;
        }
    }
    return true;
}

bool
port_valid(std::string_view port) noexcept {
    if (port.empty()) {
        return true; // An empty port selects the scheme default.
    }
    std::uint32_t value  = 0;
    const auto    end    = port.data() + port.size();
    const auto    parsed = std::from_chars(port.data(), end, value);
    return parsed.ec == std::errc{} && parsed.ptr == end && value <= 65535u;
}

bool
authority_valid(std::string_view authority) {
    if (authority.empty() || authority.find('@') != std::string_view::npos) {
        return false;
    }
    if (authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == std::string_view::npos) {
            return false;
        }
        // No name lookup, zone decoding or IPvFuture transport extension here.
        const auto literal = authority.substr(1, close - 1);
        if (literal.empty() || literal.size() >= INET6_ADDRSTRLEN || literal.find('%') != std::string_view::npos) {
            return false;
        }
        char address[INET6_ADDRSTRLEN];
        std::memcpy(address, literal.data(), literal.size());
        address[literal.size()] = '\0';
        in6_addr parsed{};
        if (qb::io::inet::ip::compat::inet_pton(AF_INET6, address, &parsed) != 1) {
            return false;
        }
        const auto suffix = authority.substr(close + 1);
        return suffix.empty() || (suffix.front() == ':' && port_valid(suffix.substr(1)));
    }
    const auto colon = authority.find(':');
    const auto host  = authority.substr(0, colon);
    if (host.empty() || !component(host, false, false)) {
        return false;
    }
    return colon == std::string_view::npos || port_valid(authority.substr(colon + 1));
}

std::optional<UriReference>
split_reference(std::string_view source) {
    for (const auto byte : source) {
        const auto c = static_cast<unsigned char>(byte);
        if (c <= 0x20 || c >= 0x7f) {
            return std::nullopt;
        }
    }
    UriReference parts;
    if (const auto at = source.find('#'); at != std::string_view::npos) {
        parts.has_fragment = true;
        parts.fragment     = source.substr(at + 1);
        source             = source.substr(0, at);
    }
    if (const auto at = source.find('?'); at != std::string_view::npos) {
        parts.has_query = true;
        parts.query     = source.substr(at + 1);
        source          = source.substr(0, at);
    }
    const auto colon = source.find(':');
    const auto slash = source.find('/');
    if (colon != std::string_view::npos && (slash == std::string_view::npos || colon < slash)) {
        parts.scheme = source.substr(0, colon);
        if (parts.scheme.empty() || !alpha(static_cast<unsigned char>(parts.scheme.front()))) {
            return std::nullopt;
        }
        for (const auto c : parts.scheme) {
            if (!qb::io::is_scheme_character(static_cast<unsigned char>(c))) {
                return std::nullopt;
            }
        }
        parts.has_scheme = true;
        source.remove_prefix(colon + 1);
    }
    if (source.starts_with("//")) {
        parts.has_authority = true;
        source.remove_prefix(2);
        const auto end  = source.find('/');
        parts.authority = source.substr(0, end);
        source          = end == std::string_view::npos ? std::string_view{} : source.substr(end);
        if (!authority_valid(parts.authority)) {
            return std::nullopt;
        }
    }
    parts.path = source;
    if (!component(parts.path, true, false) || !component(parts.query, false, true) || !component(parts.fragment, false, true)) {
        return std::nullopt;
    }
    return parts;
}

void
remove_last_segment(std::string &path) {
    const auto slash = path.rfind('/');
    path.resize(slash == std::string::npos ? 0 : slash);
}

// RFC 3986 section 5.2.4: move complete raw segments, including their preceding slash.
// Empty segments and trailing slashes remain significant; percent escapes are never decoded.
std::string
remove_dot_segments(std::string_view input) {
    std::string output;
    output.reserve(input.size());
    while (!input.empty()) {
        if (input.starts_with("../")) {
            input.remove_prefix(3);
        } else if (input.starts_with("./")) {
            input.remove_prefix(2);
        } else if (input.starts_with("/./")) {
            input.remove_prefix(2);
        } else if (input == "/.") {
            input = "/";
        } else if (input.starts_with("/../")) {
            input.remove_prefix(3);
            remove_last_segment(output);
        } else if (input == "/..") {
            input = "/";
            remove_last_segment(output);
        } else if (input == "." || input == "..") {
            input = {};
        } else {
            const auto end   = input.find('/', input.front() == '/' ? 1 : 0);
            const auto count = end == std::string_view::npos ? input.size() : end;
            output.append(input.substr(0, count));
            input.remove_prefix(count);
        }
    }
    return output;
}

bool
http_scheme(std::string_view scheme) noexcept {
    return origin::scheme_eq(scheme, "http") || origin::scheme_eq(scheme, "https");
}

} // namespace

QB_NOINLINE QB_COLD auto
resolve_redirect_location(const qb::io::uri &base, std::string_view location) -> std::optional<qb::io::uri> {
    if (!base.is_valid()) {
        return std::nullopt;
    }
    const auto b = split_reference(base.source());
    const auto r = split_reference(location);
    if (!b || !r || !b->has_scheme || !b->has_authority || !http_scheme(b->scheme)) {
        return std::nullopt;
    }

    UriReference target = *r;
    std::string  path;
    if (r->has_scheme) {
        if (!http_scheme(r->scheme) || !r->has_authority) {
            return std::nullopt;
        }
        path = remove_dot_segments(r->path);
    } else {
        target.scheme = b->scheme;
        if (r->has_authority) {
            path = remove_dot_segments(r->path);
        } else {
            target.authority = b->authority;
            if (r->path.empty()) {
                path = b->path;
                if (!r->has_query) {
                    target.query     = b->query;
                    target.has_query = b->has_query;
                }
            } else if (r->path.front() == '/') {
                path = remove_dot_segments(r->path);
            } else {
                std::string merged;
                if (b->path.empty()) {
                    merged = "/";
                } else if (const auto slash = b->path.rfind('/'); slash != std::string_view::npos) {
                    merged.assign(b->path.substr(0, slash + 1));
                }
                merged.append(r->path);
                path = remove_dot_segments(merged);
            }
        }
    }
    // HTTP Location adds fragment inheritance to generic URI-reference resolution.
    if (!r->has_fragment) {
        target.fragment     = b->fragment;
        target.has_fragment = b->has_fragment;
    }
    std::string result(target.scheme);
    result += "://";
    result.append(target.authority);
    result += path;
    if (target.has_query) {
        result += '?';
        if (!target.query.empty()) {
            result.append(target.query);
        }
    }
    if (target.has_fragment) {
        result += '#';
        if (!target.fragment.empty()) {
            result.append(target.fragment);
        }
    }
    qb::io::uri resolved(std::move(result));
    if (!resolved.is_valid()) {
        return std::nullopt;
    }
    return resolved;
}

QB_NOINLINE QB_COLD bool
prepare_redirect(Request &request, const Response &response, bool allow_cross_origin) {
    const int code = response.status().code();
    if (code != 301 && code != 302 && code != 303 && code != 307 && code != 308)
        return false;
    const auto location = response.headers().find("Location");
    if (location == response.headers().end() || location->second.size() != 1)
        return false;
    auto target = resolve_redirect_location(request.uri(), utility::trim_http_whitespace(location->second.front()));
    if (!target)
        return false;
    const bool crossing = !origin::same(request.uri(), *target);
    if ((crossing && !allow_cross_origin)
        || (origin::scheme_eq(request.uri().scheme(), "https") && origin::scheme_eq(target->scheme(), "http")))
        return false;

    const bool drop_body = code == 303 || ((code == 301 || code == 302) && request.method() == Method::POST);
    if (drop_body) {
        if (request.method() != Method::HEAD)
            request.method() = Method::GET;
        request.body().clear();
        if (request.has_trailers())
            request.trailers() = Headers{};
        for (const auto name :
             {"Content-Length", "Content-Type", "Content-Encoding", "Content-Language", "Content-Location", "Transfer-Encoding", "Trailer",
              "Expect", "Digest", "Content-Digest", "Repr-Digest", "Content-MD5", "Last-Modified"})
            request.remove_header(std::string_view{name});
    } else {
        // The next session encodes the logical body afresh, possibly with compression.
        request.remove_header("Content-Length");
    }
    if (crossing) {
        for (const auto name : {"Authorization", "Proxy-Authorization", "Cookie", "Origin", "Referer"})
            request.remove_header(std::string_view{name});
        request.cookies().clear();
    }
    request.uri() = std::move(*target);
    request.set_header("Host", host_header_value(request.uri()));
    return true;
}

} // namespace qb::http::detail
