/**
 * @file qbm/http/middleware/csrf.h
 * @brief Cross-site request forgery protection: CsrfMiddleware and its CsrfOptions.
 *
 * A browser attaches a site's cookies to every request sent to that site, whichever page sent it: a form
 * on another site that posts to `/transfer` arrives with the user's session. CsrfMiddleware refuses such
 * a request before it reaches the handler, in two layers:
 *
 * 1. **Where the request comes from** (always on, nothing to configure). A safe method (`GET`, `HEAD`,
 *    `OPTIONS`) passes. Otherwise the browser's `Sec-Fetch-Site` decides when it is present --
 *    `same-origin` and `none` (the user typed the address, a bookmark) pass, `same-site` and `cross-site`
 *    are refused; without it the `Origin` header must name the request's own host and port -- `Host`, or
 *    the authority of a target that carries a scheme (HTTP/2 and HTTP/3 rebuild it from `:scheme` and
 *    `:authority`; an absolute-form HTTP/1.1 target), never the `//host` of an origin-form path -- and,
 *    over a TLS connection, the `https` scheme; a request with neither header passes, since a browser
 *    sends one of the two on every unsafe request (all of them since 2023) and anything else is not a
 *    browser. The algorithm and its trade-offs are those of Go's `net/http.CrossOriginProtection` (Go
 *    1.25), the current OWASP recommendation, which needs no token and no client-side code.
 * 2. **A signed double-submit token** (opt in, `CsrfOptions::tokens(secret)`, needs `QB_HAS_SSL`) for
 *    defence in depth: a cookie carrying a random value and its HMAC-SHA256 under a server secret, bound to
 *    the user's session when `session_binding()` names it, which an unsafe request must echo in a header
 *    or a form field -- a urlencoded or a multipart/form-data body (the OWASP "signed double-submit cookie").
 *
 * A trusted origin (`trusted_origin()`) and an exempt request (`exempt()`) skip both layers. The middleware
 * belongs on what a browser with the user's cookies can reach: an API authenticated by a bearer token in a
 * header, never by a cookie, cannot be forged this way. Out of its reach: a WebSocket upgrade is a `GET`
 * (check its `Origin` in the upgrade handler: cross-site WebSocket hijacking), and a DNS-rebound name makes
 * `Origin` equal `Host` (serve only the host names you expect).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <qb/io/uri.h>
#include <qb/system/time.h>

#include "../cookie.h"
#include "../logger.h"
#include "../request.h"
#include "../routing/context.h"
#include "../routing/middleware.h"
#include "../routing/slot.h"
#include "../types.h"
#include "./security_headers.h" // internal::arrived_over_secure_transport

namespace qb::http {

/**
 * @brief What CsrfMiddleware decided about one request; `to_string()` names it, and a refusal's response
 *        body says it.
 */
enum class CsrfVerdict : std::uint8_t {
    allowed,         ///< A safe method, a same-origin request, a trusted origin, an exemption or a valid token.
    cross_site,      ///< `Sec-Fetch-Site` is `same-site` or `cross-site`: another origin's page sent it.
    origin_mismatch, ///< `Origin` names neither the request's own host and port nor a trusted origin.
    token_missing,   ///< Tokens on: the token cookie, or the token the request submits, is absent.
    token_invalid    ///< Tokens on: the two differ, or the cookie's is not signed for this session.
};

/** @brief The verdict's name: `"allowed"`, `"cross-site request"`, `"origin mismatch"`, `"CSRF token missing"`,
 *         `"CSRF token invalid"`. */
[[nodiscard]] std::string_view to_string(CsrfVerdict verdict) noexcept;

/// The token CsrfMiddleware issued or accepted for the request (tokens on), for a page to embed in its forms
/// (`<input type="hidden" name="_csrf" value="...">`) or a script to send back: `ctx->get_if(csrf_token_slot)`.
inline constexpr Slot<std::string> csrf_token_slot{"qb.http.csrf.token"};

namespace detail {

/// Key material wiped (OPENSSL_cleanse) before it is released or replaced -- at destruction, on an assignment, by
/// `assign()` -- and left empty when moved from: what CsrfOptions keeps its token secret in.
class wiped_bytes {
public:
    wiped_bytes()                    = default;
    wiped_bytes(wiped_bytes const &) = default;
    wiped_bytes(wiped_bytes &&other) noexcept;
    wiped_bytes &operator=(wiped_bytes const &other);
    wiped_bytes &operator=(wiped_bytes &&other) noexcept;
    ~wiped_bytes();

    void assign(std::string_view bytes);
    [[nodiscard]] bool
    empty() const noexcept {
        return _bytes.empty();
    }
    [[nodiscard]] std::vector<unsigned char> const &
    bytes() const noexcept {
        return _bytes;
    }

private:
    void                       wipe() noexcept;
    std::vector<unsigned char> _bytes;
};

} // namespace detail

/**
 * @brief Configuration of CsrfMiddleware, and its decisions, usable on their own (`check()`, `issue_token()`).
 *
 * Copyable; the middleware keeps its own copy. The defaults verify where requests come from and issue no
 * token.
 */
class CsrfOptions {
public:
    /// Whether a request skips the checks (a webhook, a callback endpoint authenticated otherwise).
    using RequestPredicate = std::function<bool(Request const &)>;
    /// The value a token is bound to: the user's session identifier, typically the session cookie's value.
    using SessionBinding = std::function<std::string(Request const &)>;

    /// The token's secret must be at least this long: 32 bytes, the HMAC-SHA256 output.
    static constexpr std::size_t min_secret_size = 32;

    CsrfOptions();

    /**
     * @brief Trusts @p origin to send unsafe requests (a front end on another host): its requests skip the
     *        checks, the token included -- name only origins you control.
     * @param origin `scheme://host[:port]`, the scheme `http` or `https`, nothing after the authority -- the
     *        form a browser writes in `Origin` (`https://app.example.com`, `http://localhost:5173`).
     * @throws std::invalid_argument for anything else (a path, a query, user information, another scheme).
     */
    CsrfOptions &trusted_origin(std::string_view origin);

    /// Adds a predicate; a request any of them accepts skips the checks (an unsafe one only: a safe method
    /// is never checked).
    CsrfOptions &exempt(RequestPredicate predicate);

    /**
     * @brief Turns the token layer on, signing with @p secret.
     * @param secret At least `min_secret_size` bytes, kept secret and shared by every server instance that
     *        serves the same users; changing it invalidates every token issued, each re-issued on the user's
     *        next request.
     * @throws std::invalid_argument when @p secret is shorter; std::logic_error in a build without
     *         `QB_HAS_SSL` (the HMAC and the random source are qb::crypto's).
     */
    CsrfOptions &tokens(std::string_view secret);

    /// Binds each token to the value @p binding returns for the request (a session identifier), so a token
    /// taken from one session is refused in another; a token issued before a login is re-issued after it.
    /// Without a binding a token is only signed.
    CsrfOptions &session_binding(SessionBinding binding);

    /// The token cookie's name, `__Host-csrf` by default: a `__Host-` cookie is refused by the browser unless
    /// it is `Secure`, has no `Domain` and has `Path=/`, so a sibling subdomain cannot plant one. Name it
    /// otherwise, with `cookie_secure(false)`, to serve over plain HTTP (local development).
    /// @throws std::invalid_argument when @p name is not a cookie name (RFC 6265 token).
    CsrfOptions &cookie_name(std::string name);

    /// `Secure` on the token cookie (on by default).
    /// @throws std::invalid_argument when turned off under a `__Host-` or `__Secure-` name, or with `SameSite::None`.
    CsrfOptions &cookie_secure(bool secure);

    /// `SameSite` on the token cookie, `Lax` by default.
    /// @throws std::invalid_argument for `SameSite::None` on a cookie that is not `Secure`.
    CsrfOptions &cookie_same_site(SameSite same_site);

    /// `Max-Age` on the token cookie; none by default (it ends with the browser session).
    /// @throws std::invalid_argument outside [1 s, 400 days] -- zero deletes the cookie, and a browser caps it
    ///         at 400 days (RFC 6265bis §5.5).
    CsrfOptions &cookie_max_age(qb::duration max_age);

    /// The header an unsafe request submits its token in, `X-CSRF-Token` by default.
    CsrfOptions &header_name(std::string name);

    /// The field of an `application/x-www-form-urlencoded` or `multipart/form-data` body that submits the token
    /// when the header is absent, `_csrf` by default; empty reads the header only. A multipart body is parsed for
    /// it only then: a form with a file input pays that, a script that sends the header does not.
    CsrfOptions &form_field(std::string name);

    [[nodiscard]] bool               tokens_enabled() const noexcept;
    [[nodiscard]] std::string const &cookie_name() const noexcept;
    [[nodiscard]] std::string const &header_name() const noexcept;
    [[nodiscard]] std::string const &form_field() const noexcept;

    /**
     * @brief The decision on @p request: `allowed` or the reason it is refused. Token issuance is the
     *        middleware's; this reads the token cookie and the submitted token as the request carries them.
     * @param secure_connection The request arrived over TLS on this connection (the middleware reads it from
     *        the session's transport): its `Origin` must then be `https`. False when TLS ends at a proxy in
     *        front: the scheme is then not compared, as in Go, and HSTS covers the downgrade.
     */
    [[nodiscard]] CsrfVerdict check(Request const &request, bool secure_connection) const;

    /// The token cookie @p request carries: the first pair named exactly `cookie_name()` (`Request::cookie_value_exact`)
    /// -- a `__host-csrf` or a `__Host -csrf` another host planted is no `__Host-csrf`, and does not hide the real
    /// one sent after it --; empty when there is none.
    [[nodiscard]] std::string cookie_token(Request const &request) const;

    /// A new token for @p request's session (tokens on). @throws std::logic_error when tokens are off.
    [[nodiscard]] std::string issue_token(Request const &request) const;

    /// Whether @p token is well formed and signed for @p request's session (false when tokens are off).
    [[nodiscard]] bool token_valid(std::string_view token, Request const &request) const;

    /// The cookie that carries @p token, with this configuration's attributes.
    [[nodiscard]] Cookie token_cookie(std::string token) const;

private:
    [[nodiscard]] CsrfVerdict check_source(Request const &request, bool secure_connection) const;
    [[nodiscard]] bool        exempted(Request const &request) const;
    [[nodiscard]] CsrfVerdict check_token(Request const &request) const;
    [[nodiscard]] std::string signature(std::string_view nonce, Request const &request) const;

    std::vector<qb::io::uri>      _trusted;
    std::vector<RequestPredicate> _exempt;
    detail::wiped_bytes           _secret; ///< Wiped before it is released or replaced
    SessionBinding                _binding;
    std::string                   _cookie_name = "__Host-csrf";
    std::string                   _header_name = "X-CSRF-Token";
    std::string                   _form_field  = "_csrf";
    std::optional<qb::duration>   _max_age;
    SameSite                      _same_site = SameSite::Lax;
    bool                          _secure    = true;
};

/**
 * @brief Refuses a cross-site request forgery before the handler runs (see the file's description).
 *
 * A refused request is answered `403 Forbidden`, `text/plain`, the verdict in the body, unless
 * `on_reject()` writes the response; the chain stops there. Tokens on, every response to a request whose
 * cookie is absent or not valid for its session carries a fresh token cookie -- a token refusal's included,
 * never one refused for where it comes from (an unsafe request another site's page makes rotates nothing) -- and
 * the request's token is in `csrf_token_slot`. A request that does not carry the cookie still gets one: a
 * cross-site link under `cookie_same_site(SameSite::Strict)` (the browser withholds a Strict cookie on it), an
 * exempt request. Requests that arrive at once without a cookie (tabs restored
 * together, a page's first parallel calls) are each issued their own token and the last cookie set wins: a
 * page reads the token from the cookie when it sends, or from the slot of the response it renders.
 *
 * @tparam SessionType The session type carried by the request context.
 */
template <typename SessionType>
class CsrfMiddleware final : public IMiddleware<SessionType> {
public:
    using ContextPtr = std::shared_ptr<Context<SessionType>>;
    /// Writes the response of a refused request (status, headers, body); the middleware completes it.
    using RejectHandler = std::function<void(Context<SessionType> &, CsrfVerdict)>;

    explicit CsrfMiddleware(CsrfOptions options = {}, std::string name = "CsrfMiddleware")
        : _options(std::make_shared<CsrfOptions const>(std::move(options)))
        , _name(std::move(name)) {}

    /// Replaces the default `403` response of a refusal (a JSON error, a redirect to a page that explains).
    CsrfMiddleware &
    on_reject(RejectHandler handler) {
        _on_reject = std::move(handler);
        return *this;
    }

    void
    process(ContextPtr ctx) override {
        auto const       &request = ctx->request();
        CsrfVerdict const verdict = _options->check(request, internal::arrived_over_secure_transport(*ctx));
        // Refused for where it comes from: nothing issued, so another site's page cannot rotate the cookie.
        if (_options->tokens_enabled() && verdict != CsrfVerdict::cross_site && verdict != CsrfVerdict::origin_mismatch) {
            std::string cookie = _options->cookie_token(request);
            if (!cookie.empty() && _options->token_valid(cookie, request)) {
                ctx->set(csrf_token_slot, std::move(cookie));
            } else {
                std::string token = _options->issue_token(request);
                ctx->set(csrf_token_slot, token);
                // The last word on the response: a handler that rebuilds it keeps the cookie.
                ctx->add_lifecycle_hook([options = _options, token = std::move(token)](Context<SessionType> &c, HookPoint point) {
                    if (point == HookPoint::PRE_RESPONSE_SEND)
                        c.response().add_cookie(options->token_cookie(token));
                });
            }
        }
        if (verdict == CsrfVerdict::allowed) {
            ctx->complete(AsyncTaskResult::CONTINUE);
            return;
        }
        LOG_HTTP_DEBUG("[" << _name << "] refused " << std::to_string(request.method()) << " " << request.uri().path() << ": "
                           << to_string(verdict));
        if (_on_reject) {
            _on_reject(*ctx, verdict);
        } else {
            ctx->response().status() = qb::http::status::FORBIDDEN;
            ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
            ctx->response().body() = std::string("Forbidden: ") + std::string(to_string(verdict));
        }
        ctx->complete(AsyncTaskResult::COMPLETE);
    }

    [[nodiscard]] std::string
    name() const override {
        return _name;
    }

    void
    cancel() override {}

    [[nodiscard]] CsrfOptions const &
    options() const noexcept {
        return *_options;
    }

private:
    std::shared_ptr<CsrfOptions const> _options;
    std::string                        _name;
    RejectHandler                      _on_reject;
};

/**
 * @brief Creates a CsrfMiddleware (`router().use(qb::http::csrf_middleware<Session>())`).
 * @param options Its configuration; the default verifies where requests come from and issues no token.
 * @param name Its name, for logs.
 */
template <typename SessionType>
[[nodiscard]] std::shared_ptr<CsrfMiddleware<SessionType>>
csrf_middleware(CsrfOptions options = {}, std::string name = "CsrfMiddleware") {
    return std::make_shared<CsrfMiddleware<SessionType>>(std::move(options), std::move(name));
}

} // namespace qb::http
