/**
 * @file qbm/http/redirect.h
 * @brief Opt-in HTTP/HTTPS one-shot redirections with bounded history.
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0.
 * @ingroup Http
 */
#pragma once

#include <cstddef>
#include <memory>
#include <optional>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "./1.1/http.h"
#include "./detail/redirect.h"
#include "./origin.h"

namespace qb::http {

/** @brief Explicit one-shot redirect policy; existing overloads never follow redirects. */
struct RedirectOptions {
    std::size_t max_hops           = 5;
    bool        allow_cross_origin = false;
};

namespace async {
/**
 * @brief Terminal exchange plus the exchanges followed to reach it.
 * Each request snapshot has the same preparation/compression semantics as Reply.
 * The terminal response is not repeated in hops. History retains complete bodies.
 */
struct RedirectReply : Reply {
    std::vector<Reply> hops;
};
} // namespace async

namespace detail {

template <typename Completion>
bool
redirect_completion_alive(const Completion &) noexcept {
    return true;
}

template <typename T>
bool
redirect_completion_alive(const async::detail::http_completion<T> &complete) noexcept {
    return static_cast<bool>(complete);
}

template <typename Completion>
class redirect_state : public std::enable_shared_from_this<redirect_state<Completion>> {
    static_assert(std::is_nothrow_move_constructible_v<async::Reply>);
    Request                     _logical;
    Completion                  _complete;
    RedirectOptions             _options;
    qb::duration                _timeout;
    bool                        _verify_peer;
    bool                        _finished      = false;
    bool                        _session_alive = false;
    std::optional<async::Reply> _pending;
    std::vector<async::Reply>   _hops;

    // A session can delete itself during an inline failed connection. Its moved,
    // exclusively owned callable marks destruction without a second allocation.
    // Older sessions must not change the lease of a later hop.
    struct flight_completion {
        std::shared_ptr<redirect_state> state;
        std::size_t                     generation;

        flight_completion(std::shared_ptr<redirect_state> owner, std::size_t value) noexcept
            : state(std::move(owner))
            , generation(value) {}
        flight_completion(flight_completion &&) noexcept = default;
        flight_completion(const flight_completion &)     = delete;
        ~flight_completion() {
            if (state && state->_hops.size() == generation)
                state->_session_alive = false;
        }
        void
        operator()(async::Reply &&reply) const noexcept {
            state->receive(std::move(reply));
        }
    };

    template <typename Transport>
    void
    launch(Request &request) {
        using Session      = async::session<flight_completion, Transport>;
        _session_alive     = true;
        const auto cleanup = [this](Session *session) noexcept {
            if (_session_alive)
                delete session;
        };
        std::unique_ptr<Session, decltype(cleanup)> session{
            new Session(flight_completion{this->shared_from_this(), _hops.size()}, request), cleanup
        };
        try {
            session->connect(_timeout, _verify_peer);
        } catch (...) {
            // An inline answer already transferred ownership (possibly deleting
            // the session). Do not add a second synchronous error to that reply.
            if (_pending || _finished) {
                session.release();
                return;
            }
            // connector::run unwinds its watcher/self-hold before this cleanup.
            throw;
        }
        session.release();
    }

    void
    finish() {
        _finished = true;
        async::RedirectReply result{std::move(*_pending), std::move(_hops)};
        _pending.reset();
        _logical.reset();
        // Outside the planning catch: user exceptions never cause another completion.
        _complete(std::move(result));
    }

    void
    process() {
        if (_finished || !redirect_completion_alive(_complete)) {
            _finished = true;
            return;
        }
        bool recorded = false;
        try {
            if (_hops.size() < _options.max_hops && prepare_redirect(_logical, _pending->response, _options.allow_cross_origin)) {
                _hops.push_back(std::move(*_pending));
                _pending.reset();
                recorded = true;
                start();
                return;
            }
        } catch (...) {
            // Preserve the last received response if a next attempt cannot be prepared.
            // In particular, defer's exception containment must not strand an awaiter.
            if (recorded && !_pending) {
                _pending.emplace(std::move(_hops.back()));
                _hops.pop_back();
            }
        }
        finish();
    }

    void
    receive(async::Reply &&reply) noexcept {
        if (_finished || !redirect_completion_alive(_complete)) {
            _finished = true;
            return;
        }
        _pending.emplace(std::move(reply));
        // Never run the next flight or user code from the old session's dispatch.
        // Queue allocation failure follows the existing noexcept event boundary.
        qb::io::async::defer([self = this->shared_from_this()] { self->process(); });
    }

public:
    redirect_state(Request request, Completion complete, qb::duration timeout, bool verify_peer, RedirectOptions options)
        : _logical(std::move(request))
        , _complete(std::move(complete))
        , _options(options)
        , _timeout(timeout)
        , _verify_peer(verify_peer) {}

    void
    start() {
        if (_finished || !redirect_completion_alive(_complete)) {
            _finished = true;
            return;
        }
        // Only this opt-in path pays for a logical replay copy. The session may
        // compress its own request; its prepared Reply is never sent a second time.
        Request request{_logical};
        if (!request.has_header("Host"))
            request.set_header("Host", host_header_value(request.uri()));
        const bool secure = origin::scheme_eq(request.uri().scheme(), "https");
        if (!secure && !origin::scheme_eq(request.uri().scheme(), "http")) {
            receive(async::Reply{std::move(request), Response{status::BAD_REQUEST}});
            return;
        }
#if QB_HAS_SSL
        if (secure)
            launch<qb::io::transport::stcp>(request);
        else
            launch<qb::io::transport::tcp>(request);
#else
        if (secure)
            receive(async::Reply{std::move(request), Response{status::SERVICE_UNAVAILABLE}});
        else
            launch<qb::io::transport::tcp>(request);
#endif
    }
};

} // namespace detail

/**
 * @brief Follow 301/302/303/307/308 only with an explicit policy argument.
 * The timeout is the existing connect/inactivity timeout for each attempt.
 * At the cap, on an invalid Location, on forbidden origin/downgrade or when
 * preparation fails, return the last response unchanged. No synthetic 508.
 * Callbacks are owned by value and invoked once after network dispatch.
 */
template <typename Completion>
requires std::is_invocable_v<std::decay_t<Completion> &, async::RedirectReply &&>
void
REQUEST(Request request, Completion &&complete, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    auto state = std::make_shared<detail::redirect_state<std::decay_t<Completion>>>(std::move(request), std::forward<Completion>(complete),
                                                                                    timeout, verify_peer, options);
    state->start();
}

/** @brief Coroutine opt-in; destroying its awaiter prevents subsequent redirect attempts. */
[[nodiscard]] inline auto
REQUEST(Request request, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    return async::detail::make_slot_awaiter<async::RedirectReply>(
        [request = std::move(request), timeout, verify_peer, options](auto complete) mutable {
            REQUEST(std::move(request), std::move(complete), timeout, verify_peer, options);
        });
}

/// @brief Explicit redirect overload; see REQUEST for policy and lifetime.
template <typename Completion>
requires std::is_invocable_v<std::decay_t<Completion> &, async::RedirectReply &&>
void
GET(Request request, Completion &&complete, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    request.method() = Method::GET;
    REQUEST(std::move(request), std::forward<Completion>(complete), timeout, verify_peer, options);
}

/// @brief Coroutine form of the explicit redirect overload.
[[nodiscard]] inline auto
GET(Request request, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    request.method() = Method::GET;
    return REQUEST(std::move(request), timeout, verify_peer, options);
}

/// @brief Explicit redirect overload; see REQUEST for policy and lifetime.
template <typename Completion>
requires std::is_invocable_v<std::decay_t<Completion> &, async::RedirectReply &&>
void
POST(Request request, Completion &&complete, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    request.method() = Method::POST;
    REQUEST(std::move(request), std::forward<Completion>(complete), timeout, verify_peer, options);
}

/// @brief Coroutine form of the explicit redirect overload.
[[nodiscard]] inline auto
POST(Request request, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    request.method() = Method::POST;
    return REQUEST(std::move(request), timeout, verify_peer, options);
}

/// @brief Explicit redirect overload; see REQUEST for policy and lifetime.
template <typename Completion>
requires std::is_invocable_v<std::decay_t<Completion> &, async::RedirectReply &&>
void
PUT(Request request, Completion &&complete, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    request.method() = Method::PUT;
    REQUEST(std::move(request), std::forward<Completion>(complete), timeout, verify_peer, options);
}

/// @brief Coroutine form of the explicit redirect overload.
[[nodiscard]] inline auto
PUT(Request request, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    request.method() = Method::PUT;
    return REQUEST(std::move(request), timeout, verify_peer, options);
}

/// @brief Explicit redirect overload; see REQUEST for policy and lifetime.
template <typename Completion>
requires std::is_invocable_v<std::decay_t<Completion> &, async::RedirectReply &&>
void
DEL(Request request, Completion &&complete, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    request.method() = Method::DEL;
    REQUEST(std::move(request), std::forward<Completion>(complete), timeout, verify_peer, options);
}

/// @brief Coroutine form of the explicit redirect overload.
[[nodiscard]] inline auto
DEL(Request request, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    request.method() = Method::DEL;
    return REQUEST(std::move(request), timeout, verify_peer, options);
}

/// @brief Explicit redirect overload; see REQUEST for policy and lifetime.
template <typename Completion>
requires std::is_invocable_v<std::decay_t<Completion> &, async::RedirectReply &&>
void
HEAD(Request request, Completion &&complete, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    request.method() = Method::HEAD;
    REQUEST(std::move(request), std::forward<Completion>(complete), timeout, verify_peer, options);
}

/// @brief Coroutine form of the explicit redirect overload.
[[nodiscard]] inline auto
HEAD(Request request, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    request.method() = Method::HEAD;
    return REQUEST(std::move(request), timeout, verify_peer, options);
}

/// @brief Explicit redirect overload; see REQUEST for policy and lifetime.
template <typename Completion>
requires std::is_invocable_v<std::decay_t<Completion> &, async::RedirectReply &&>
void
OPTIONS(Request request, Completion &&complete, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    request.method() = Method::OPTIONS;
    REQUEST(std::move(request), std::forward<Completion>(complete), timeout, verify_peer, options);
}

/// @brief Coroutine form of the explicit redirect overload.
[[nodiscard]] inline auto
OPTIONS(Request request, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    request.method() = Method::OPTIONS;
    return REQUEST(std::move(request), timeout, verify_peer, options);
}

/// @brief Explicit redirect overload; see REQUEST for policy and lifetime.
template <typename Completion>
requires std::is_invocable_v<std::decay_t<Completion> &, async::RedirectReply &&>
void
PATCH(Request request, Completion &&complete, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    request.method() = Method::PATCH;
    REQUEST(std::move(request), std::forward<Completion>(complete), timeout, verify_peer, options);
}

/// @brief Coroutine form of the explicit redirect overload.
[[nodiscard]] inline auto
PATCH(Request request, qb::duration timeout, bool verify_peer, RedirectOptions options) {
    request.method() = Method::PATCH;
    return REQUEST(std::move(request), timeout, verify_peer, options);
}

} // namespace qb::http
