/**
 * @file qbm/http/middleware/csrf.cpp
 * @brief Out-of-line definitions of CsrfOptions: where a request comes from, the signed token, the cookie.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "csrf.h"

#include <algorithm>
#include <stdexcept>

#include "../headers.h"
#include "../multipart.h"
#include "../origin.h"

#ifdef QB_HAS_SSL
#include <openssl/crypto.h>
#include <qb/io/crypto.h>
#endif

namespace qb::http {
namespace {

/// The methods a browser may send cross-site without a check: they must not change state (RFC 9110 §9.2.1).
[[nodiscard]] bool
safe_method(Method const method) noexcept {
    return method == qb::http::method::GET || method == qb::http::method::HEAD || method == qb::http::method::OPTIONS;
}

[[nodiscard]] bool
iequals(std::string_view const lhs, std::string_view const rhs) noexcept {
    return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin(), [](char const a, char const b) {
               return (a >= 'A' && a <= 'Z' ? a + ('a' - 'A') : a) == (b >= 'A' && b <= 'Z' ? b + ('a' - 'A') : b);
           });
}

[[nodiscard]] bool
istarts_with(std::string_view const text, std::string_view const prefix) noexcept {
    return text.size() >= prefix.size() && iequals(text.substr(0, prefix.size()), prefix);
}

/// `scheme://authority`, nothing after the authority, the scheme `http` or `https`: what a browser writes in
/// `Origin` for a page of a web origin (RFC 6454 §6.1). `null` (an opaque origin) and anything else is none.
[[nodiscard]] std::optional<qb::io::uri>
parse_origin(std::string_view const text) {
    auto const separator = text.find("://");
    if (separator == std::string_view::npos)
        return std::nullopt;
    auto const scheme    = text.substr(0, separator);
    auto const authority = text.substr(separator + 3);
    if (!(iequals(scheme, "http") || iequals(scheme, "https")) || authority.empty()
        || authority.find_first_of("/?#@\\ \t") != std::string_view::npos)
        return std::nullopt;
    auto parsed = qb::io::uri::parse(std::string(text));
    if (!parsed.is_valid() || parsed.host().empty() || !origin::effective_port_number(parsed))
        return std::nullopt;
    return parsed;
}

/// The authority the request was sent to: the URI's when the target carries a scheme -- HTTP/2 and HTTP/3
/// rebuild it from `:scheme` and `:authority`, an absolute-form HTTP/1.1 target names it (RFC 9112 §3.2.2) --,
/// the `Host` field otherwise. Never the URI's host alone: an origin-form `//host/path` is a path on HTTP/1.1,
/// which a reference parser reads as an authority the sender chose.
[[nodiscard]] std::string
request_authority(Request const &request) {
    if (!request.uri().scheme().empty() && !request.uri().host().empty())
        return origin::authority(request.uri());
    return request.header("Host");
}

/// Whether @p origin_value names the request's own host and port. The scheme is the Origin's: the authority
/// does not say whether the request arrived over TLS (a TLS-terminating proxy hides it), so an http page
/// posting to the https site passes -- as in Go's CrossOriginProtection, which leaves that case to HSTS.
[[nodiscard]] bool
origin_is_request_authority(qb::io::uri const &origin_uri, Request const &request) {
    auto const authority = request_authority(request);
    if (authority.empty() || authority.find_first_of("/?#@\\ \t") != std::string::npos)
        return false;
    auto const self = qb::io::uri::parse(std::string(origin_uri.scheme()) + "://" + authority);
    return self.is_valid() && !self.host().empty() && origin::same(origin_uri, self);
}

/// A cookie name: an RFC 6265 §4.1.1 token (RFC 9110 §5.6.2 tchar).
[[nodiscard]] bool
is_cookie_name(std::string_view const name) noexcept {
    constexpr std::string_view separators = "()<>@,;:\\\"/[]?={} \t";
    return !name.empty() && std::all_of(name.begin(), name.end(), [&](char const c) {
        return c > 0x20 && c < 0x7f && separators.find(c) == std::string_view::npos;
    });
}

/// A `__Host-` or `__Secure-` cookie is dropped by the browser unless it is `Secure` (RFC 6265bis §4.1.3).
[[nodiscard]] bool
needs_secure(std::string_view const name) noexcept {
    return istarts_with(name, "__Host-") || istarts_with(name, "__Secure-");
}

/// The value of field @p name in an `application/x-www-form-urlencoded` body, its first occurrence.
[[nodiscard]] std::string
form_value(std::string_view const body, std::string const &name) {
    std::size_t start = 0;
    while (start <= body.size()) {
        auto end = body.find('&', start);
        if (end == std::string_view::npos)
            end = body.size();
        auto const pair  = body.substr(start, end - start);
        auto const equal = pair.find('=');
        if (qb::io::uri::decode(pair.substr(0, equal)) == name)
            return equal == std::string_view::npos ? std::string{} : qb::io::uri::decode(pair.substr(equal + 1));
        start = end + 1;
    }
    return {};
}

/// Whether the first cookie-pair named @p name, case aside, in the request's `Cookie` lines -- the one the
/// case-insensitive jar keeps -- is spelled exactly @p name. The jar folds the names it stores, so the spelling is
/// read from the lines. Called with a value in the jar only, which a header-section line gave: those lines come
/// before any trailer section's (store_received_trailer appends), so the first match is always the header's.
[[nodiscard]] bool
first_cookie_spelled(Request const &request, std::string_view const name) {
    auto const &fields = request.headers();
    auto const  lines  = fields.find("Cookie");
    if (lines == fields.cend())
        return false;
    for (std::string_view line : lines->second) {
        while (!line.empty()) {
            auto const end  = line.find(';');
            auto       pair = line.substr(0, end);
            line            = end == std::string_view::npos ? std::string_view{} : line.substr(end + 1);
            pair            = pair.substr(0, pair.find('='));
            while (!pair.empty() && (pair.front() == ' ' || pair.front() == '\t'))
                pair.remove_prefix(1);
            while (!pair.empty() && (pair.back() == ' ' || pair.back() == '\t'))
                pair.remove_suffix(1);
            if (iequals(pair, name))
                return pair == name;
        }
    }
    return false;
}

/// The value of field @p name in a `multipart/form-data` body -- an HTML form with a file input -- its first part
/// whose `Content-Disposition` names it; empty for a body that does not parse.
[[nodiscard]] std::string
multipart_value(Request const &request, std::string const &name) {
    const auto form = request.body().try_as<Multipart>();
    if (!form)
        return {};
    for (auto const &part : form->parts()) {
        try {
            const auto attributes = parse_header_attributes(part.header("Content-Disposition"));
            if (const auto it = attributes.find("name"); it != attributes.end() && it->second == name)
                return part.body;
        } catch (...) {
            // a malformed Content-Disposition names no field
        }
    }
    return {};
}

#ifdef QB_HAS_SSL
/// A token is the nonce and its signature, both base64url, joined by a dot.
constexpr std::size_t      nonce_bytes  = 32;
constexpr std::string_view token_domain = "qb-csrf-v1";

[[nodiscard]] std::size_t
nonce_text_size() {
    static std::size_t const size = qb::crypto::base64url_encode(std::vector<unsigned char>(nonce_bytes)).size();
    return size;
}

[[nodiscard]] bool
is_base64url(std::string_view const text) noexcept {
    return std::all_of(text.begin(), text.end(), [](char const c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    });
}

[[nodiscard]] bool
equal_in_constant_time(std::string_view const lhs, std::string_view const rhs) {
    return qb::crypto::constant_time_compare(std::vector<unsigned char>(lhs.begin(), lhs.end()),
                                             std::vector<unsigned char>(rhs.begin(), rhs.end()));
}
#endif

} // namespace

std::string_view
to_string(CsrfVerdict const verdict) noexcept {
    switch (verdict) {
        case CsrfVerdict::allowed:
            return "allowed";
        case CsrfVerdict::cross_site:
            return "cross-site request";
        case CsrfVerdict::origin_mismatch:
            return "origin mismatch";
        case CsrfVerdict::token_missing:
            return "CSRF token missing";
        case CsrfVerdict::token_invalid:
            return "CSRF token invalid";
    }
    return "unknown";
}

CsrfOptions::CsrfOptions() = default;

CsrfOptions::~CsrfOptions() {
#ifdef QB_HAS_SSL
    if (!_secret.empty())
        OPENSSL_cleanse(_secret.data(), _secret.size());
#endif
}

CsrfOptions &
CsrfOptions::trusted_origin(std::string_view const origin) {
    auto parsed = parse_origin(origin);
    if (!parsed)
        throw std::invalid_argument("CsrfOptions::trusted_origin: \"" + std::string(origin)
                                    + "\" is not an origin -- scheme://host[:port], the scheme http or https");
    _trusted.push_back(std::move(*parsed));
    return *this;
}

CsrfOptions &
CsrfOptions::exempt(RequestPredicate predicate) {
    if (!predicate)
        throw std::invalid_argument("CsrfOptions::exempt: an empty predicate");
    _exempt.push_back(std::move(predicate));
    return *this;
}

CsrfOptions &
CsrfOptions::tokens(std::string_view const secret) {
#ifdef QB_HAS_SSL
    if (secret.size() < min_secret_size)
        throw std::invalid_argument("CsrfOptions::tokens: the secret has " + std::to_string(secret.size()) + " bytes, at least "
                                    + std::to_string(min_secret_size) + " are needed");
    _secret.assign(secret.begin(), secret.end());
    return *this;
#else
    (void) secret;
    throw std::logic_error("CsrfOptions::tokens: CSRF tokens need qb built with SSL (QB_HAS_SSL)");
#endif
}

CsrfOptions &
CsrfOptions::session_binding(SessionBinding binding) {
    _binding = std::move(binding);
    return *this;
}

CsrfOptions &
CsrfOptions::cookie_name(std::string name) {
    if (!is_cookie_name(name))
        throw std::invalid_argument("CsrfOptions::cookie_name: \"" + name + "\" is not a cookie name");
    if (needs_secure(name) && !_secure)
        throw std::invalid_argument("CsrfOptions::cookie_name: a \"" + name + "\" cookie must be Secure");
    _cookie_name = std::move(name);
    return *this;
}

CsrfOptions &
CsrfOptions::cookie_secure(bool const secure) {
    if (!secure && needs_secure(_cookie_name))
        throw std::invalid_argument("CsrfOptions::cookie_secure: a \"" + _cookie_name + "\" cookie must be Secure");
    if (!secure && _same_site == SameSite::None)
        throw std::invalid_argument("CsrfOptions::cookie_secure: a SameSite=None cookie must be Secure");
    _secure = secure;
    return *this;
}

CsrfOptions &
CsrfOptions::cookie_same_site(SameSite const same_site) {
    // A browser drops a SameSite=None cookie that is not Secure (RFC 6265bis §5.4.7).
    if (same_site == SameSite::None && !_secure)
        throw std::invalid_argument("CsrfOptions::cookie_same_site: a SameSite=None cookie must be Secure");
    _same_site = same_site;
    return *this;
}

CsrfOptions &
CsrfOptions::cookie_max_age(qb::duration const max_age) {
    if (max_age < std::chrono::seconds(1) || max_age > std::chrono::hours(24 * 400))
        throw std::invalid_argument("CsrfOptions::cookie_max_age: between 1 s and 400 days");
    _max_age = max_age;
    return *this;
}

CsrfOptions &
CsrfOptions::header_name(std::string name) {
    if (name.empty())
        throw std::invalid_argument("CsrfOptions::header_name: an empty header name");
    _header_name = std::move(name);
    return *this;
}

CsrfOptions &
CsrfOptions::form_field(std::string name) {
    _form_field = std::move(name);
    return *this;
}

bool
CsrfOptions::tokens_enabled() const noexcept {
    return !_secret.empty();
}

std::string const &
CsrfOptions::cookie_name() const noexcept {
    return _cookie_name;
}

std::string const &
CsrfOptions::header_name() const noexcept {
    return _header_name;
}

std::string const &
CsrfOptions::form_field() const noexcept {
    return _form_field;
}

CsrfVerdict
CsrfOptions::check(Request const &request, bool const secure_connection) const {
    if (safe_method(request.method()))
        return CsrfVerdict::allowed;
    CsrfVerdict const source = check_source(request, secure_connection);
    if (source == CsrfVerdict::allowed && !tokens_enabled())
        return CsrfVerdict::allowed;
    if (exempted(request))
        return CsrfVerdict::allowed;
    if (source != CsrfVerdict::allowed)
        return source;
    return check_token(request);
}

CsrfVerdict
CsrfOptions::check_source(Request const &request, bool const secure_connection) const {
    // Fetch Metadata first: a browser that sends it says where the request comes from, whatever Origin says.
    if (std::string const &site = request.header("Sec-Fetch-Site"); !site.empty())
        return site == "same-origin" || site == "none" ? CsrfVerdict::allowed : CsrfVerdict::cross_site;
    std::string const &origin_value = request.header("Origin");
    if (origin_value.empty())
        return CsrfVerdict::allowed; // neither header: no browser sends an unsafe request like this
    auto const origin_uri = parse_origin(origin_value);
    // Over TLS here, an http page of the same host is another origin: an active attacker's, on a host without HSTS.
    if (!origin_uri || (secure_connection && !iequals(origin_uri->scheme(), "https")))
        return CsrfVerdict::origin_mismatch;
    return origin_is_request_authority(*origin_uri, request) ? CsrfVerdict::allowed : CsrfVerdict::origin_mismatch;
}

bool
CsrfOptions::exempted(Request const &request) const {
    if (!_trusted.empty()) {
        if (std::string const &origin_value = request.header("Origin"); !origin_value.empty()) {
            if (auto const origin_uri = parse_origin(origin_value)) {
                for (auto const &trusted : _trusted)
                    if (origin::same(*origin_uri, trusted))
                        return true;
            }
        }
    }
    return std::any_of(_exempt.begin(), _exempt.end(), [&](RequestPredicate const &predicate) { return predicate(request); });
}

std::string_view
CsrfOptions::cookie_token(Request const &request) const {
    std::string const &value = request.cookie_value(_cookie_name);
    if (value.empty() || !first_cookie_spelled(request, _cookie_name))
        return {};
    return value;
}

CsrfVerdict
CsrfOptions::check_token(Request const &request) const {
#ifdef QB_HAS_SSL
    std::string_view const cookie = cookie_token(request);
    if (cookie.empty())
        return CsrfVerdict::token_missing; // before any body is read: a request without the cookie costs nothing
    std::string submitted = request.header(_header_name);
    if (submitted.empty() && !_form_field.empty()) {
        // A form cannot set a header: its field submits the token -- read only when the header is absent.
        std::string const &type = request.content_type().type();
        if (iequals(type, "application/x-www-form-urlencoded"))
            submitted = form_value(request.body().as<std::string_view>(), _form_field);
        else if (iequals(type, "multipart/form-data"))
            submitted = multipart_value(request, _form_field);
    }
    if (submitted.empty())
        return CsrfVerdict::token_missing;
    if (!equal_in_constant_time(cookie, submitted) || !token_valid(cookie, request))
        return CsrfVerdict::token_invalid;
    return CsrfVerdict::allowed;
#else
    (void) request;
    return CsrfVerdict::token_invalid; // unreachable: tokens() refuses to turn them on without SSL
#endif
}

std::string
CsrfOptions::signature(std::string_view const nonce, Request const &request) const {
#ifdef QB_HAS_SSL
    // The binding's length first, so no two (binding, nonce) pairs sign the same bytes.
    std::string const binding = _binding ? _binding(request) : std::string{};
    std::string       data;
    data.reserve(token_domain.size() + binding.size() + nonce.size() + 24);
    data.append(token_domain).append(1, '\n').append(std::to_string(binding.size())).append(1, '\n');
    data.append(binding).append(1, '\n').append(nonce);
    return qb::crypto::base64url_encode(qb::crypto::hmac_sha256(_secret, data));
#else
    (void) nonce;
    (void) request;
    return {};
#endif
}

std::string
CsrfOptions::issue_token(Request const &request) const {
    if (!tokens_enabled())
        throw std::logic_error("CsrfOptions::issue_token: tokens are off (CsrfOptions::tokens)");
#ifdef QB_HAS_SSL
    std::string token = qb::crypto::base64url_encode(qb::crypto::generate_random_bytes(nonce_bytes));
    token += '.';
    token += signature(std::string_view(token).substr(0, token.size() - 1), request);
    return token;
#else
    (void) request;
    return {};
#endif
}

bool
CsrfOptions::token_valid(std::string_view const token, Request const &request) const {
#ifdef QB_HAS_SSL
    if (!tokens_enabled())
        return false;
    auto const dot = token.find('.');
    if (dot != nonce_text_size() || !is_base64url(token.substr(0, dot)))
        return false;
    return equal_in_constant_time(token.substr(dot + 1), signature(token.substr(0, dot), request));
#else
    (void) token;
    (void) request;
    return false;
#endif
}

Cookie
CsrfOptions::token_cookie(std::string token) const {
    Cookie cookie(std::string(_cookie_name), std::move(token));
    // Readable by the page's scripts on purpose: they echo it in the header. No Domain: the host's only.
    cookie.path("/").secure(_secure).http_only(false).same_site(_same_site);
    if (_max_age)
        cookie.max_age(*_max_age);
    return cookie;
}

} // namespace qb::http
