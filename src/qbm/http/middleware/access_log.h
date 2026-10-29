/**
 * @file qbm/http/middleware/access_log.h
 * @brief `AccessLog`: one line per HTTP request -- Apache's common or combined format, or JSON -- written to a
 *        sink of the application's choosing (Huly QB-90).
 *
 * `AccessLog` is a router observer (`Router::add_observer`), not a chain task: it logs every request the router
 * routes, a 404, a 405, an error and a request whose client left included, once its response is decided -- with
 * the status, the size and the headers that response really carries. The request id a `RequestIdMiddleware`
 * gave the request (`request_id_slot`) goes into the JSON line. The line is formatted into a buffer the instance
 * reuses.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <cstdint>     // For std::uint64_t
#include <functional>  // For std::function
#include <memory>      // For std::shared_ptr, std::make_shared
#include <stdexcept>   // For std::invalid_argument
#include <string>      // For std::string
#include <string_view> // For std::string_view
#include <utility>     // For std::move

#include <qb/system/time.h> // For qb::duration, qb::wall_time, qb::wall_now

#include "../logger.h"           // For LOG_HTTP_WARN
#include "../routing/context.h"  // For Context
#include "../routing/observer.h" // For IRequestObserver, RequestEnd, RequestOutcome
#include "./request_id.h"        // For request_id_slot

namespace qb::http {

/**
 * @brief Everything one access-log line may say about a request. Views into the request, its response and its
 *        context: valid during the formatter's call only.
 */
struct AccessLogRecord {
    std::string_view remote_address; ///< the client's address (its socket's peer), empty when unknown or the session is gone
    qb::wall_time    received;       ///< when the router received the request (wall clock)
    std::string_view method;         ///< `GET`, `POST`, ...
    std::string_view target;         ///< the request target as received: path and query
    int              major_version = 1;
    int              minor_version = 1;
    int              status        = 0; ///< the response's status code
    std::uint64_t    bytes         = 0; ///< the response body's size, in bytes (a streamed one's: Context::streamed_bytes())
    std::string_view referer;           ///< the `Referer` request header, empty when absent
    std::string_view user_agent;        ///< the `User-Agent` request header, empty when absent
    qb::duration     duration{};        ///< `RequestEnd::duration`
    std::string_view request_id;        ///< `request_id_slot`, empty when no `RequestIdMiddleware` ran
    std::string_view route;             ///< the route pattern that matched, empty for none
    RequestOutcome   outcome = RequestOutcome::RESPONDED;
};

/// Appends one access-log line for `record` to `line` (no line feed: the sink receives lines).
using AccessLogFormatter = std::function<void(AccessLogRecord const &record, std::string &line)>;

/// The shipped access-log formats.
namespace access_log_format {
/**
 * @brief Apache's Common Log Format: `%h %l %u %t "%r" %>s %b` --
 *        `127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /a?b=1 HTTP/1.1" 200 2326`. The time is UTC; `%b` is
 *        `-` for an empty body; `"` and `\` and every non-printable byte of a quoted field are escaped as Apache
 *        escapes them (`\"`, `\\`, `\xhh`).
 */
void common(AccessLogRecord const &record, std::string &line);
/// Apache's Combined Log Format: the common line, then `"%{Referer}i" "%{User-agent}i"` (`-` when absent).
void combined(AccessLogRecord const &record, std::string &line);
/**
 * @brief One JSON object per line: `time` (RFC 3339, UTC, milliseconds), `remote`, `method`, `target`,
 *        `protocol`, `status`, `bytes`, `duration_seconds` (rounded to the microsecond), `referer`, `user_agent`,
 *        `request_id`, `route` (`null` when no route matched), `outcome` (`responded`, `session_gone`,
 *        `suppressed`). Strings are JSON-escaped (control characters as `\u00XX`); other bytes are copied as is.
 */
void json(AccessLogRecord const &record, std::string &line);
} // namespace access_log_format

/**
 * @brief Writes one line per request to a sink, in the format a formatter gives it.
 *
 * Register it on the router: `router().add_observer(qb::http::access_log<S>(sink))`. The sink receives each line
 * without its line feed, on the router's thread, when the request's response is decided; an exception from the
 * formatter or the sink is contained and logged. The address comes from session ip(): stock sockets cache
 * successful peer lookups; custom transports keep their own behavior. Empty once the session is gone.
 *
 * @tparam SessionType The session type of the router.
 */
template <typename SessionType>
class AccessLog final : public IRequestObserver<SessionType> {
public:
    /// What receives each line.
    using Sink = std::function<void(std::string_view line)>;

    /**
     * @brief Constructs the access log.
     * @param sink Receives each line. Required.
     * @param formatter Formats each line: `access_log_format::combined` unless given.
     * @throws std::invalid_argument when `sink` or `formatter` is empty.
     */
    explicit AccessLog(Sink sink, AccessLogFormatter formatter = access_log_format::combined)
        : _sink(std::move(sink))
        , _formatter(std::move(formatter)) {
        if (!_sink || !_formatter)
            throw std::invalid_argument("AccessLog: the sink and the formatter cannot be empty.");
    }

    /// Formats the request's line and hands it to the sink.
    void
    on_response(Context<SessionType> const &ctx, RequestEnd const &end) noexcept override {
        try {
            const auto &request  = ctx.request();
            const auto &response = ctx.response();
            std::string remote;
            if constexpr (requires(SessionType const &s) { s.ip(); }) {
                if (auto const session = ctx.session())
                    remote = std::string(session->ip());
            }
            AccessLogRecord record;
            record.remote_address = remote;
            record.received       = qb::wall_now() - std::chrono::duration_cast<qb::wall_time::duration>(end.duration);
            record.method         = std::string_view(request.method());
            record.target         = request.uri().source();
            record.major_version  = request.major_version;
            record.minor_version  = request.minor_version;
            record.status         = static_cast<int>(response.status());
            record.bytes          = ctx.is_streaming() ? ctx.streamed_bytes() : response.body().size();
            record.referer        = request.header("Referer");
            record.user_agent     = request.header("User-Agent");
            record.duration       = end.duration;
            if (const std::string *id = ctx.get_if(request_id_slot))
                record.request_id = *id;
            record.route   = ctx.route_pattern();
            record.outcome = end.outcome;
            _line.clear();
            _formatter(record, _line);
            _sink(_line);
        } catch (...) {
            LOG_HTTP_WARN("AccessLog: an exception from the formatter or the sink was suppressed");
        }
    }

private:
    Sink               _sink;
    AccessLogFormatter _formatter;
    std::string        _line; ///< reused for every line
};

/**
 * @brief Creates an `AccessLog`.
 * @tparam SessionType The session type of the router.
 * @param sink Receives each line (without its line feed).
 * @param formatter `access_log_format::combined` unless given.
 * @return A `std::shared_ptr`, for `router().add_observer(...)`.
 * @throws std::invalid_argument when `sink` or `formatter` is empty.
 */
template <typename SessionType>
[[nodiscard]] std::shared_ptr<AccessLog<SessionType>>
access_log(typename AccessLog<SessionType>::Sink sink, AccessLogFormatter formatter = access_log_format::combined) {
    return std::make_shared<AccessLog<SessionType>>(std::move(sink), std::move(formatter));
}

} // namespace qb::http
