/**
 * @file qbm/http/1.1/http.cpp
 * @brief HTTP/1.1 client implementation for qb-io framework
 *
 * This file implements synchronous HTTP/1.1 client functions built on top of
 * the qb-io asynchronous framework. It includes:
 *
 * - Synchronous wrappers for all HTTP methods (GET, POST, PUT, DELETE, etc.)
 * - Automatic request/response handling with timeout support
 * - Content compression and decompression support
 * - Integration with the asynchronous HTTP client infrastructure
 * - Template instantiation for the HTTP server with default session
 *
 * The implementation provides a simple synchronous API while leveraging
 * the powerful asynchronous capabilities of the underlying framework.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include "../http.h"
#include "../multipart.h"

#include <sstream>
#include <iostream>

namespace qb::http {
namespace { // Anonymous namespace for file-local helpers

    // Helper function to call the appropriate asynchronous version and wait for the reply.
    // The AsyncHttpFunction is a callable that takes (Request, CallbackLambda, double timeout)
    template <typename AsyncHttpFunction>
    Response _execute_sync_request_internal(AsyncHttpFunction& async_function_caller, Request request, double timeout) {
        Response response_obj;
        bool wait_flag = true;

        // Directly call the passed asynchronous function (e.g., qb::http::GET, qb::http::POST)
        async_function_caller(
            std::move(request),
            [&response_obj, &wait_flag](async::Reply &&reply) {
                response_obj = std::move(reply.response);
                wait_flag    = false;
            },
            timeout
        );

        qb::io::async::run_until(wait_flag);
        return response_obj;
    }

} // anonymous namespace

    // --- Synchronous HTTP Client Function Definitions ---

    Response REQUEST(Request request, double timeout) {
        // For the generic REQUEST, we pass the qb::http::REQUEST (async) function.
        // The compiler needs help to pick the correct overload, so we use a lambda to call it.
        auto async_caller = [](Request req, auto&& cb, double t) {
            qb::http::REQUEST(std::move(req), std::forward<decltype(cb)>(cb), t);
        };
        return _execute_sync_request_internal(async_caller, std::move(request), timeout);
    }

    Response GET(Request request, double timeout) {
        auto async_caller = [](Request req, auto&& cb, double t) {
            qb::http::GET(std::move(req), std::forward<decltype(cb)>(cb), t);
        };
        return _execute_sync_request_internal(async_caller, std::move(request), timeout);
    }

    Response POST(Request request, double timeout) {
        auto async_caller = [](Request req, auto&& cb, double t) {
            qb::http::POST(std::move(req), std::forward<decltype(cb)>(cb), t);
        };
        return _execute_sync_request_internal(async_caller, std::move(request), timeout);
    }

    Response PUT(Request request, double timeout) {
        auto async_caller = [](Request req, auto&& cb, double t) {
            qb::http::PUT(std::move(req), std::forward<decltype(cb)>(cb), t);
        };
        return _execute_sync_request_internal(async_caller, std::move(request), timeout);
    }

    Response DEL(Request request, double timeout) {
        auto async_caller = [](Request req, auto&& cb, double t) {
            // Assuming DEL is the async version for DELETE method
            qb::http::DEL(std::move(req), std::forward<decltype(cb)>(cb), t);
        };
        return _execute_sync_request_internal(async_caller, std::move(request), timeout);
    }

    Response HEAD(Request request, double timeout) {
        auto async_caller = [](Request req, auto&& cb, double t) {
            qb::http::HEAD(std::move(req), std::forward<decltype(cb)>(cb), t);
        };
        return _execute_sync_request_internal(async_caller, std::move(request), timeout);
    }

    Response OPTIONS(Request request, double timeout) {
        auto async_caller = [](Request req, auto&& cb, double t) {
            qb::http::OPTIONS(std::move(req), std::forward<decltype(cb)>(cb), t);
        };
        return _execute_sync_request_internal(async_caller, std::move(request), timeout);
    }

    Response PATCH(Request request, double timeout) {
        auto async_caller = [](Request req, auto&& cb, double t) {
            qb::http::PATCH(std::move(req), std::forward<decltype(cb)>(cb), t);
        };
        return _execute_sync_request_internal(async_caller, std::move(request), timeout);
    }

    template class Server<DefaultSession>;
} // namespace qb::http
