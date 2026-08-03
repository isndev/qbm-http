/**
 * @file qbm/http/1.1/http.cpp
 * @brief HTTP/1.1 server explicit template instantiation.
 *
 * The previously hosted synchronous client helpers
 * (`qb::http::GET/POST/PUT/...` returning `Response`) have been removed.
 * They are replaced by coroutine-returning overloads declared inline in
 * `qbm/http/1.1/http.h`, which consume the callback-based
 * `qb::http::async::*` API and yield `qb::http::async::Reply`.
 *
 * See `qbm/http/coro.h` and `qbm/http/readme/14b-coroutine-api.md` for the
 * full contract and migration guide.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "../http.h"

namespace qb::http {

namespace {
/// @brief @p scheme equals @p lower_ascii (fixed), ASCII case-insensitive.
[[nodiscard]] bool
scheme_eq_ignore_case(std::string_view scheme, std::string_view lower) noexcept {
    if (scheme.size() != lower.size()) {
        return false;
    }
    for (std::size_t i = 0; i < scheme.size(); ++i) {
        if (static_cast<char>(::tolower(static_cast<unsigned char>(scheme[i]))) != lower[i]) {
            return false;
        }
    }
    return true;
}
} // namespace

[[nodiscard]] std::string
host_header_value(const qb::io::uri &uri) {
    std::string host_value             = std::string(uri.host());
    const bool  already_bracketed_ipv6 = host_value.size() >= 2 && host_value.front() == '[' && host_value.back() == ']';
    if (!already_bracketed_ipv6 && host_value.find(':') != std::string::npos) {
        host_value = "[" + host_value + "]";
    }

    const std::string_view port = uri.port();
    if (port.empty()) {
        return host_value;
    }

    const std::string_view scheme                = uri.scheme();
    const bool             is_default_http_port  = scheme_eq_ignore_case(scheme, std::string_view{"http", 4u}) && port == "80";
    const bool             is_default_https_port = scheme_eq_ignore_case(scheme, std::string_view{"https", 5u}) && port == "443";
    if (!is_default_http_port && !is_default_https_port) {
        host_value += ":";
        host_value += port;
    }
    return host_value;
}

template class Server<DefaultSession>;
} // namespace qb::http
