/**
 * @file qbm/http/routing/observer.h
 * @brief `IRequestObserver`: a router-level observer told when each request starts and when its response is
 *        decided -- what `RequestMetrics` and `AccessLog` are built on (Huly QB-90).
 *
 * An observer is registered on the router (`Router::add_observer`), not on each request: the router hands every
 * context it creates the router's list (one reference count, only when the list is not empty) and nothing else.
 * Lifecycle hooks would do the same work for a cost the observer does not pay -- a hook is copied into every
 * context (a `std::function` and, for the first one, the hooks vector), and a duration needs a start time stored
 * in the context's custom data. A router with no observer pays one test of a null pointer when a request starts
 * and one when it is finalized.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <cstdint> // For std::uint8_t
#include <memory>  // For std::shared_ptr
#include <vector>  // For std::vector

#include <qb/system/time.h> // For qb::duration

namespace qb::http {

template <typename SessionType>
class Context;

/// How a routed request ended, as `IRequestObserver::on_response` is told.
enum class RequestOutcome : std::uint8_t {
    RESPONDED,    ///< its response was decided and handed to the session that received the request
    SESSION_GONE, ///< its response was decided after its session had gone (a disconnect): nothing was sent
    SUPPRESSED,   ///< finalized without a response: `Context::suppress_response()` (an upgrade handed over)
};

/// The end of a routed request: how it ended and how long it took.
struct RequestEnd {
    /// How the request ended.
    RequestOutcome outcome = RequestOutcome::RESPONDED;
    /**
     * @brief From the router receiving the request (before the `PRE_ROUTING` hooks) to its response handed to the
     *        session: the routing, the middleware and the handler -- however long an asynchronous handler kept
     *        it -- the `PRE_RESPONSE_SEND` hooks, and the protocol's serialization of the response into the
     *        connection's output (HTTP/1.1) or its frames (HTTP/2, HTTP/3). The transmission to the peer is not in
     *        it, and neither is the reading and parsing of the request before the router received it. For a
     *        suppressed response, up to the context's destruction.
     */
    qb::duration duration{};
};

/**
 * @brief Observes every request a router creates a context for.
 * @details Both functions run on the router's thread, synchronously, and must not throw (`noexcept`: a throw
 *          terminates). `on_request` runs once the context exists, before the `PRE_ROUTING` hooks; `on_response`
 *          runs exactly once per context that `on_request` saw, when its response is decided: after the
 *          `PRE_RESPONSE_SEND` hooks and the hand-over to the session, so `ctx.response()` is what was sent (status,
 *          headers, body), and `ctx.route_pattern()` names the route that matched. A request a session answers
 *          without routing it -- a request over a size limit or whose target names no resource, refused by
 *          the protocol -- reaches no observer.
 *          An observer instance is shared by every request of its router: keep per-request state in the context.
 * @tparam SessionType The session type of the router.
 */
template <typename SessionType>
class IRequestObserver {
public:
    virtual ~IRequestObserver() = default;

    /// A request was received: its context exists, nothing of it has run. Does nothing by default.
    virtual void
    on_request(Context<SessionType> const &ctx) noexcept {
        (void) ctx;
    }

    /// The request's response was decided (see `RequestEnd` for what its duration covers). A `SUPPRESSED` end is
    /// told from the context's destructor: do not call `shared_from_this()` on it.
    virtual void on_response(Context<SessionType> const &ctx, RequestEnd const &end) noexcept = 0;
};

namespace detail {
/// The observers of a router, shared by every context it created while they were registered.
template <typename SessionType>
using observer_list = std::vector<std::shared_ptr<IRequestObserver<SessionType>>>;
} // namespace detail

} // namespace qb::http
