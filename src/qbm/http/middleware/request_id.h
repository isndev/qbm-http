/**
 * @file qbm/http/middleware/request_id.h
 * @brief `RequestIdMiddleware`: one id per request, generated or propagated, in the context and the response.
 *
 * The middleware gives every request it sees an identifier: a fresh random UUID (version 4), or -- only when
 * told to trust it -- the id the client sent in the request header. The id is stored in the request's
 * `Context` under `qb::http::request_id_slot` (the key `"request.id"`) for the handlers, the `LoggingMiddleware`
 * and the `AccessLog` to read, and it is written back in the same header of the response (Huly QB-166).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <cstddef>     // For std::size_t
#include <memory>      // For std::shared_ptr, std::make_shared
#include <stdexcept>   // For std::invalid_argument
#include <string>      // For std::string
#include <string_view> // For std::string_view
#include <utility>     // For std::move

#include <qb/uuid.h> // For qb::generate_random_uuid, uuids::to_string

#include "../routing/middleware.h" // For IMiddleware, Context, AsyncTaskResult
#include "../routing/slot.h"       // For qb::http::Slot

namespace qb::http {

/**
 * @brief The context slot that holds the request id: `"request.id"`, a `std::string`.
 * @details Written by `RequestIdMiddleware`; read with `ctx->get_if(qb::http::request_id_slot)` (a
 *          `const std::string*`, null when no `RequestIdMiddleware` ran for the request). `LoggingMiddleware`
 *          and `AccessLog` read it too.
 */
inline constexpr Slot<std::string> request_id_slot{"request.id"};

/// The longest incoming request id `RequestIdMiddleware` accepts when it trusts the client's.
inline constexpr std::size_t max_request_id_length = 128;

/**
 * @brief Whether `id` is an incoming request id `RequestIdMiddleware` may adopt: 1 to `max_request_id_length`
 *        characters, each an ASCII letter, a digit, `.`, `_` or `-`.
 * @details The id goes into logs and into the response unchanged, so nothing else gets through: no space, no
 *          quote, no control byte, no non-ASCII byte.
 */
[[nodiscard]] constexpr bool
is_valid_request_id(std::string_view const id) noexcept {
    if (id.empty() || id.size() > max_request_id_length)
        return false;
    for (char const c : id) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

/**
 * @brief Options of `RequestIdMiddleware`.
 */
struct RequestIdOptions {
    /// The request header an incoming id is read from, and the response header the id is written to.
    std::string header_name = "X-Request-ID";
    /// Adopt the client's id when it passes `is_valid_request_id()`. Off by default: a client can send anything,
    /// and an id it chose is not a correlation the server can rely on.
    bool trust_incoming = false;

    /// Sets `header_name`.
    RequestIdOptions &
    header(std::string name) {
        header_name = std::move(name);
        return *this;
    }

    /// Sets `trust_incoming`.
    RequestIdOptions &
    trust_incoming_id(bool const trust = true) noexcept {
        trust_incoming = trust;
        return *this;
    }
};

/**
 * @brief Gives every request an id, stores it in `request_id_slot` and answers it in a response header.
 *
 * `process()` takes the id the client sent in `RequestIdOptions::header_name` when `trust_incoming` is on and
 * the value passes `is_valid_request_id()`; otherwise -- the default -- it generates a random UUID version 4 in
 * its 36-character text form. An id it refuses is never echoed. It then sets the response header (the id is
 * there whatever the handler answers, a 404 or an error included, unless a handler removes the header) and
 * continues the chain.
 *
 * Install it first, as global middleware (`router().use(qb::http::request_id_middleware<S>())`): the
 * middleware that run before it see no id, and global middleware also runs for the 404 and 405 answers. A
 * request answered before any chain runs -- a path over the router's length limit -- gets no id.
 *
 * The id is not a secret: the UUID comes from the thread's `std::mt19937` (`qb::generate_random_uuid()`).
 *
 * @tparam SessionType The session type of the router.
 */
template <typename SessionType>
class RequestIdMiddleware final : public IMiddleware<SessionType> {
public:
    /** @brief Convenience alias for a shared pointer to the request `Context`. */
    using ContextPtr = std::shared_ptr<Context<SessionType>>;

    /**
     * @brief Constructs the middleware.
     * @param options The header name and the trust policy.
     * @param instance_name The name `name()` returns.
     * @throws std::invalid_argument if `options.header_name` is empty.
     */
    explicit RequestIdMiddleware(RequestIdOptions options = {}, std::string instance_name = "RequestIdMiddleware")
        : _options(std::move(options))
        , _name(std::move(instance_name)) {
        if (_options.header_name.empty())
            throw std::invalid_argument("RequestIdMiddleware: the header name cannot be empty.");
    }

    /**
     * @brief Chooses the request's id, stores it in `request_id_slot`, sets the response header, continues.
     * @param ctx The request's context.
     */
    void
    process(ContextPtr ctx) override {
        std::string id;
        if (_options.trust_incoming) {
            const std::string &incoming = ctx->request().header(_options.header_name);
            if (is_valid_request_id(incoming))
                id = incoming;
        }
        if (id.empty())
            id = uuids::to_string(qb::generate_random_uuid());
        ctx->response().set_header(_options.header_name, id);
        ctx->set(request_id_slot, std::move(id));
        ctx->complete(AsyncTaskResult::CONTINUE);
    }

    /** @brief The name given at construction. */
    [[nodiscard]] std::string
    name() const override {
        return _name;
    }

    /** @brief Nothing to cancel: `process()` completes before it returns. */
    void
    cancel() noexcept override {}

    /** @brief The options the middleware was built with. */
    [[nodiscard]] RequestIdOptions const &
    options() const noexcept {
        return _options;
    }

private:
    RequestIdOptions _options;
    std::string      _name;
};

/**
 * @brief Creates a `RequestIdMiddleware`.
 * @tparam SessionType The session type of the router.
 * @param options The header name and the trust policy (default: `X-Request-ID`, the client's id not trusted).
 * @param name The middleware's name.
 * @return A `std::shared_ptr` to the middleware, for `router().use(...)`.
 * @throws std::invalid_argument if `options.header_name` is empty.
 */
template <typename SessionType>
[[nodiscard]] std::shared_ptr<RequestIdMiddleware<SessionType>>
request_id_middleware(RequestIdOptions options = {}, std::string name = "RequestIdMiddleware") {
    return std::make_shared<RequestIdMiddleware<SessionType>>(std::move(options), std::move(name));
}

} // namespace qb::http
