/**
 * @file qbm/http/middleware/metrics.h
 * @brief `RequestMetrics`: an HTTP server's request counts and latencies, in the `qb::metrics` model -- and
 *        `metrics_handler`, the `/metrics` endpoint that exposes a scrape of every core (Huly QB-90, QB-154).
 *
 * `RequestMetrics` is a router observer (`Router::add_observer`), not a chain task: it sees every request the
 * router routes -- a 404, a 405, an error chain, a request whose client left -- and pays no allocation per
 * request once a series (a route, a method and a status) has been seen. Its counters are plain integers of the
 * server's core; `collect()` describes them into a `qb::metrics::snapshot`, from the core's
 * `qb::metrics::Registry` (`add_source`), so a scrape reads them on their own core.
 *
 * Families: `qb_http_requests_total{method,route,status}`, `qb_http_request_duration_seconds{method,route}` (a
 * histogram; see `RequestEnd::duration` for what it measures) and `qb_http_requests_in_flight`. `route` is the
 * pattern of the route that matched (`/users/:id`), `unmatched` for a request no route matched -- never the raw
 * path, whose cardinality is the client's to choose. `qb::http::add_connections()` describes a server's open
 * connections (`qb_http_connections{protocol}`).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <chrono>      // For std::chrono::seconds
#include <cstddef>     // For std::size_t
#include <cstdint>     // For std::uint64_t
#include <memory>      // For std::shared_ptr, std::make_shared, std::unique_ptr
#include <string>      // For std::string
#include <string_view> // For std::string_view
#include <utility>     // For std::move, std::pair
#include <vector>      // For std::vector

#include <qb/core/metrics.h>                   // For qb::metrics::snapshot
#include <qb/core/metrics_registry.h>          // For qb::metrics::scrape, qb::metrics::Registry (metrics_handler)
#include <qb/system/container/unordered_map.h> // For qb::unordered_map
#include <qb/system/time.h>                    // For qb::duration

#include "../routing/context.h"  // For Context
#include "../routing/observer.h" // For IRequestObserver, RequestEnd
#include "../types.h"            // For qb::http::method

namespace qb::http {

/**
 * @brief Options of `RequestMetrics`.
 */
struct RequestMetricsOptions {
    /// The upper bounds, in seconds, of the duration histogram's buckets: finite, strictly ascending. Prometheus'
    /// defaults (`qb::metrics::default_duration_buckets`, 5 ms to 10 s) unless set.
    std::vector<double> buckets{qb::metrics::default_duration_buckets.begin(), qb::metrics::default_duration_buckets.end()};

    /// Sets `buckets`.
    RequestMetricsOptions &
    with_buckets(std::vector<double> bounds) {
        buckets = std::move(bounds);
        return *this;
    }
};

namespace detail {

/**
 * @brief What `RequestMetrics` counts: one series per route, method and status, one histogram per route and
 *        method. Plain integers, one thread. The non-template half of `RequestMetrics`.
 */
class request_metrics_store {
public:
    /// @throws std::invalid_argument when `bounds` are not finite and strictly ascending, or empty.
    explicit request_metrics_store(std::vector<double> bounds);

    /// A request started.
    void
    started() noexcept {
        ++_in_flight;
    }

    /// A request ended: counted under its route (`unmatched` when empty), method and status, its duration observed.
    void finished(qb::http::method method, std::string_view route, int status, qb::duration duration) noexcept;

    /// Describes the counts into `snap`.
    void collect(qb::metrics::snapshot &snap) const;

    /// Requests counted for this route, method and status (`route` empty for `unmatched`).
    [[nodiscard]] std::uint64_t count(qb::http::method method, std::string_view route, int status) const noexcept;

    /// Requests started and not yet ended.
    [[nodiscard]] std::uint64_t
    in_flight() const noexcept {
        return _in_flight;
    }

private:
    struct histogram {
        std::vector<std::uint64_t> buckets;
        double                     sum = 0.0;
    };
    struct series_count {
        int           method   = 0; ///< `qb::http::method::Value`, as an int
        int           status   = 0;
        std::uint64_t requests = 0;
    };
    struct route_series {
        std::string                            route;
        std::vector<series_count>              counts;    ///< by method and status
        std::vector<std::pair<int, histogram>> durations; ///< by method
    };

    std::vector<double>                                                _bounds;
    qb::unordered_map<std::string_view, std::unique_ptr<route_series>> _routes; ///< keys view each series' route
    std::uint64_t                                                      _in_flight = 0;
};

} // namespace detail

/**
 * @brief Counts an HTTP server's requests by route, method and status, and their durations.
 *
 * Register it on the server's router and publish it through the core's metrics registry:
 * `router().add_observer(metrics)`, then
 * `getService<qb::metrics::Registry>()->add_source([m = metrics](auto &s) { m->collect(s); })`. One instance per
 * router: its counters belong to the router's thread. A router with no observer pays nothing for this class.
 *
 * @tparam SessionType The session type of the router.
 */
template <typename SessionType>
class RequestMetrics final : public IRequestObserver<SessionType> {
    detail::request_metrics_store _store;

public:
    /// @throws std::invalid_argument when `options.buckets` are not finite and strictly ascending, or empty.
    explicit RequestMetrics(RequestMetricsOptions options = {})
        : _store(std::move(options.buckets)) {}

    /// Counts a request in flight.
    void
    on_request(Context<SessionType> const &) noexcept override {
        _store.started();
    }

    /// Counts the request under its route pattern, method and status, and observes its duration.
    void
    on_response(Context<SessionType> const &ctx, RequestEnd const &end) noexcept override {
        _store.finished(ctx.request().method(), ctx.route_pattern(), static_cast<int>(ctx.response().status()), end.duration);
    }

    /// Describes the counts into `snap`: `qb_http_requests_total`, `qb_http_request_duration_seconds`,
    /// `qb_http_requests_in_flight`.
    void
    collect(qb::metrics::snapshot &snap) const {
        _store.collect(snap);
    }

    /// Requests counted for this route pattern, method and status (`route` empty: `unmatched`).
    [[nodiscard]] std::uint64_t
    count(qb::http::method method, std::string_view route, int status) const noexcept {
        return _store.count(method, route, status);
    }

    /// Requests started and not yet ended.
    [[nodiscard]] std::uint64_t
    in_flight() const noexcept {
        return _store.in_flight();
    }
};

/**
 * @brief Creates a `RequestMetrics`.
 * @tparam SessionType The session type of the router.
 * @param options The duration buckets.
 * @return A `std::shared_ptr`, for `router().add_observer(...)` and a registry source.
 */
template <typename SessionType>
[[nodiscard]] std::shared_ptr<RequestMetrics<SessionType>>
request_metrics(RequestMetricsOptions options = {}) {
    return std::make_shared<RequestMetrics<SessionType>>(std::move(options));
}

/**
 * @brief Describes a server's open connections: `qb_http_connections{protocol}`.
 * @param snap The snapshot to fill.
 * @param protocol `"http/1.1"`, `"h2"`, `"h3"` or any name the application uses.
 * @param open The open connections (`session_count()` of the server).
 */
void add_connections(qb::metrics::snapshot &snap, std::string_view protocol, std::size_t open);

/**
 * @brief Options of `metrics_handler`.
 */
struct MetricsEndpointOptions {
    /// How long each core's registry has to answer: a core that does not is reported `qb_scrape_core_up{core} 0`.
    qb::duration timeout = std::chrono::seconds(1);
    /// The cores to scrape; empty (the default) scrapes every core of the engine (the actor's `getCoreSet()`).
    std::vector<qb::CoreId> cores;

    /// Sets `timeout`.
    MetricsEndpointOptions &
    with_timeout(qb::duration t) noexcept {
        timeout = t;
        return *this;
    }
    /// Sets `cores`.
    MetricsEndpointOptions &
    with_cores(std::vector<qb::CoreId> c) {
        cores = std::move(c);
        return *this;
    }
};

/**
 * @brief Answers `ctx` with `snap` in the Prometheus text format: 200, `Content-Type:
 *        text/plain; version=0.0.4; charset=utf-8`, completed.
 * @tparam SessionType The session type of the router.
 * @param ctx The request's context.
 * @param snap What to expose (a `qb::metrics::scrape()` result, or a snapshot of the application's own).
 */
template <typename SessionType>
void
metrics_response(Context<SessionType> &ctx, qb::metrics::snapshot const &snap) {
    ctx.text(qb::metrics::write_text(snap), qb::http::status::OK, std::string(qb::metrics::text_content_type));
}

/**
 * @brief A `GET` handler for a Prometheus endpoint: it scrapes every core's `qb::metrics::Registry` through the
 *        registry of `actor`'s core and answers the text (`metrics_response`).
 * @details A coroutine route handler: mount it on the router of an actor whose core has a registry --
 *          `router().get("/metrics", qb::http::metrics_handler<S>(*this))`. The scrape is
 *          `qb::metrics::scrape(actor, cores, timeout)`: a core that does not answer in time is reported down, never
 *          an error; a core without a registry for `actor` answers 500. The endpoint exposes the process's internals:
 *          mount it behind authentication or on a listener of its own -- nothing mounts it for you.
 * @tparam SessionType The session type of the router.
 * @param actor The actor whose router serves the route; it must outlive the router (it owns it, as a server does).
 * @param options The timeout and the cores.
 * @return The handler, for `router().get(path, ...)`.
 */
template <typename SessionType>
[[nodiscard]] auto
metrics_handler(qb::Actor &actor, MetricsEndpointOptions options = {}) {
    return [&actor, options = std::move(options)](std::shared_ptr<Context<SessionType>> ctx) -> qb::io::async::task<void> {
        // `actor` and `options` are read before the first suspension, `ctx` after it: the frame owns it.
        auto                        scrape = options.cores.empty() ? qb::metrics::scrape(actor, actor.getCoreSet(), options.timeout)
                                                                   : qb::metrics::scrape(actor, options.cores, options.timeout);
        const qb::metrics::snapshot snap   = co_await std::move(scrape);
        metrics_response(*ctx, snap);
    };
}

} // namespace qb::http
