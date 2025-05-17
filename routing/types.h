#pragma once

#include <functional>
#include <string> // For std::string
#include <memory> // Required for std::shared_ptr
#include "../types.h" // For qb::http::method, qb::http::status
#undef ERROR

namespace qb::http {

// Forward declarations
template <typename SessionType>
class Context;

/**
 * @brief Defines points in the request lifecycle where hooks can be attached.
 */
enum class HookPoint {
    PRE_ROUTING,         // Before the router attempts to match a route
    PRE_HANDLER_EXECUTION, // Before the main handler task is executed
    POST_HANDLER_EXECUTION, // After the main handler task has completed (or an error occurred)
    PRE_RESPONSE_SEND,   // Before the response is serialized and sent
    POST_RESPONSE_SEND,  // After the response has been sent (or an attempt was made)
    REQUEST_COMPLETE     // After all processing for the request is finished
};

/**
 * @brief Represents the outcome of an asynchronous task.
 */
enum class AsyncTaskResult {
    CONTINUE,                // Continue to the next task in the chain
    COMPLETE,                // Current task completed the request, finalize
    CANCELLED,               // Request processing was cancelled
    ERROR,                   // An error occurred, attempt error handling chain
    FATAL_SPECIAL_HANDLER_ERROR // An error occurred in a special handler (e.g. 404) that should bypass main error chain and result in 500
};

/**
 * @brief Callback to signal the completion of an asynchronous task.
 */
// template <typename Session> // This type alias seems unused with the new IAsyncTask model
// using AsyncTaskCompletionCallback = std::function<void(Context<Session>& ctx, AsyncTaskResult result)>;

/**
 * @brief Signature for a user-defined route handler.
 * This is the corrected version that should be used project-wide.
 */
template <typename SessionType>
using RouteHandlerFn = std::function<void(std::shared_ptr<Context<SessionType>> ctx)>;

/**
 * @brief Signature for a user-defined middleware handler.
 *
 * The middleware should call the `next` callback to proceed to the next
 * middleware or the main route handler.
 */
template <typename SessionType>
using MiddlewareHandlerFn = std::function<void(std::shared_ptr<Context<SessionType>> ctx, std::function<void()> next)>;

// Helper to convert http_method enum to string for logging/debugging
// This is a simplified version. A more robust one might use the existing HTTP_METHOD_MAP.
inline std::string http_method_to_string(qb::http::method m) {
    switch (m) {
        case qb::http::method::HTTP_DELETE:     return "DELETE";
        case qb::http::method::HTTP_GET:        return "GET";
        case qb::http::method::HTTP_HEAD:       return "HEAD";
        case qb::http::method::HTTP_POST:       return "POST";
        case qb::http::method::HTTP_PUT:        return "PUT";
        case qb::http::method::HTTP_CONNECT:    return "CONNECT";
        case qb::http::method::HTTP_OPTIONS:    return "OPTIONS";
        case qb::http::method::HTTP_TRACE:      return "TRACE";
        case qb::http::method::HTTP_COPY:       return "COPY";
        case qb::http::method::HTTP_LOCK:       return "LOCK";
        case qb::http::method::HTTP_MKCOL:      return "MKCOL";
        case qb::http::method::HTTP_MOVE:       return "MOVE";
        case qb::http::method::HTTP_PROPFIND:   return "PROPFIND";
        case qb::http::method::HTTP_PROPPATCH:  return "PROPPATCH";
        case qb::http::method::HTTP_SEARCH:     return "SEARCH";
        case qb::http::method::HTTP_UNLOCK:     return "UNLOCK";
        case qb::http::method::HTTP_BIND:       return "BIND";
        case qb::http::method::HTTP_REBIND:     return "REBIND";
        case qb::http::method::HTTP_UNBIND:     return "UNBIND";
        case qb::http::method::HTTP_ACL:        return "ACL";
        case qb::http::method::HTTP_REPORT:     return "REPORT";
        case qb::http::method::HTTP_MKACTIVITY: return "MKACTIVITY";
        case qb::http::method::HTTP_CHECKOUT:   return "CHECKOUT";
        case qb::http::method::HTTP_MERGE:      return "MERGE";
        case qb::http::method::HTTP_MSEARCH:    return "M-SEARCH";
        case qb::http::method::HTTP_NOTIFY:     return "NOTIFY";
        case qb::http::method::HTTP_SUBSCRIBE:  return "SUBSCRIBE";
        case qb::http::method::HTTP_UNSUBSCRIBE:return "UNSUBSCRIBE";
        case qb::http::method::HTTP_PATCH:      return "PATCH";
        case qb::http::method::HTTP_PURGE:      return "PURGE";
        case qb::http::method::HTTP_MKCALENDAR: return "MKCALENDAR";
        default: return "UNKNOWN_METHOD";
    }
}

} // namespace qb::http 