/**
 * @file qbm/http/middleware/metrics.cpp
 * @brief The counts of `RequestMetrics` and their description (Huly QB-90, QB-154).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "metrics.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <stdexcept>
#include <string>

namespace qb::http {

namespace {
constexpr std::string_view unmatched_route = "unmatched";

[[nodiscard]] int
method_value(qb::http::method const method) noexcept {
    return qb::to_underlying(static_cast<qb::http::method::Value>(method));
}

[[nodiscard]] qb::http::method
method_of(int const value) noexcept {
    return qb::http::method(static_cast<::http_method>(value));
}
} // namespace

namespace detail {

request_metrics_store::request_metrics_store(std::vector<double> bounds)
    : _bounds(std::move(bounds)) {
    if (_bounds.empty())
        throw std::invalid_argument("RequestMetrics: the duration histogram needs at least one bucket bound");
    for (std::size_t i = 0; i < _bounds.size(); ++i) {
        if (!std::isfinite(_bounds[i]) || (i > 0 && !(_bounds[i - 1] < _bounds[i])))
            throw std::invalid_argument("RequestMetrics: bucket bounds must be finite and strictly ascending");
    }
}

void
request_metrics_store::finished(qb::http::method const method, std::string_view route, int const status, qb::duration const duration) noexcept {
    if (_in_flight > 0)
        --_in_flight;
    if (route.empty())
        route = unmatched_route;
    try {
        auto it = _routes.find(route);
        if (it == _routes.end()) {
            auto series   = std::make_unique<route_series>();
            series->route = std::string(route);
            const std::string_view key{series->route};
            it = _routes.emplace(key, std::move(series)).first;
        }
        route_series &series = *it->second;

        const int m     = method_value(method);
        auto      count = std::find_if(series.counts.begin(), series.counts.end(),
                                       [m, status](auto const &c) { return c.method == m && c.status == status; });
        if (count == series.counts.end())
            series.counts.push_back({m, status, 1});
        else
            ++count->requests;

        auto hist = std::find_if(series.durations.begin(), series.durations.end(), [m](auto const &h) { return h.first == m; });
        if (hist == series.durations.end()) {
            series.durations.emplace_back(m, histogram{std::vector<std::uint64_t>(_bounds.size() + 1, 0), 0.0});
            hist = std::prev(series.durations.end());
        }
        const double seconds = std::chrono::duration<double>(duration).count();
        const auto   bucket  = static_cast<std::size_t>(std::lower_bound(_bounds.begin(), _bounds.end(), seconds) - _bounds.begin());
        ++hist->second.buckets[bucket]; // le: the first bound >= the observation; past the last, the +Inf bucket
        hist->second.sum += seconds;
    } catch (...) {
        // Out of memory on a series' first sighting: that request is not counted.
    }
}

void
request_metrics_store::collect(qb::metrics::snapshot &snap) const {
    std::vector<route_series const *> routes;
    routes.reserve(_routes.size());
    for (auto const &r : _routes)
        routes.push_back(r.second.get());
    std::sort(routes.begin(), routes.end(), [](auto const *a, auto const *b) { return a->route < b->route; });

    // One family at a time: a family reference is invalidated by the next family added to the snapshot.
    auto &requests = snap.counter("qb_http_requests_total", "HTTP requests answered, by method, route pattern and status.");
    for (auto const *series : routes) {
        auto counts = series->counts;
        std::sort(counts.begin(), counts.end(),
                  [](auto const &a, auto const &b) { return a.method != b.method ? a.method < b.method : a.status < b.status; });
        for (auto const &c : counts) {
            requests.add({{"method", std::to_string(method_of(c.method))}, {"route", series->route}, {"status", std::to_string(c.status)}},
                         c.requests);
        }
    }
    auto &durations =
        snap.histogram("qb_http_request_duration_seconds",
                       "Time from the router receiving a request to its response handed to the connection, by method and route pattern.");
    for (auto const *series : routes) {
        auto hists = series->durations;
        std::sort(hists.begin(), hists.end(), [](auto const &a, auto const &b) { return a.first < b.first; });
        for (auto const &[m, h] : hists)
            durations.add({{"method", std::to_string(method_of(m))}, {"route", series->route}}, _bounds, h.buckets, h.sum);
    }
    snap.gauge("qb_http_requests_in_flight", "HTTP requests received and not yet answered.").add({}, _in_flight);
}

std::uint64_t
request_metrics_store::count(qb::http::method const method, std::string_view route, int const status) const noexcept {
    if (route.empty())
        route = unmatched_route;
    const auto it = _routes.find(route);
    if (it == _routes.end())
        return 0;
    const int m = method_value(method);
    for (auto const &c : it->second->counts)
        if (c.method == m && c.status == status)
            return c.requests;
    return 0;
}

} // namespace detail

void
add_connections(qb::metrics::snapshot &snap, std::string_view const protocol, std::size_t const open) {
    snap.gauge("qb_http_connections", "Open HTTP connections, by protocol.").add({{"protocol", std::string(protocol)}}, open);
}

} // namespace qb::http
