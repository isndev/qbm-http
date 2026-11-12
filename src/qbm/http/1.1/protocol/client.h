/**
 * @file qbm/http/1.1/protocol/client.h
 * @brief HTTP/1.1 client protocol implementation for qb-io framework
 *
 * This file provides HTTP/1.1 client-side protocol handling built on top of
 * the qb-io asynchronous framework. It includes:
 *
 * - HTTP/1.1 response parsing and processing
 * - Cookie parsing from Set-Cookie headers
 * - Asynchronous response handling through callbacks
 * - Integration with the base HTTP/1.1 protocol parser
 *
 * @note The previous `client_view` (string_view-based response handling)
 *       has been retired for the same reasons as `server_view`:
 *       the qb-io input pipe may relocate bytes between reads, and the
 *       asynchronous pipeline (shared `Context`, middleware chain,
 *       coroutine plan) requires response data to outlive the socket
 *       read that produced it.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once
#include "../../logger.h" // For LOG_HTTP_WARN - SECURITY FIX: Required for exception logging
#include "../../response.h"
#include "./base.h"

namespace qb::protocol::http {

/**
 * @brief HTTP/1.1 client-side protocol handler.
 * @tparam IO_Handler qb-io handler type that owns the underlying socket and
 *                    receives parsed responses via its @c on() overloads.
 *
 * Specializes the shared HTTP/1.1 @ref base parser for @ref qb::http::Response,
 * driving response parsing for an outbound connection. Each completed response
 * has its Set-Cookie headers parsed before being handed to the IO handler.
 *
 * @ingroup Http
 */
template <typename IO_Handler>
class client : public base<IO_Handler, qb::http::Response> {
    using base_t = base<IO_Handler, qb::http::Response>;

public:
    /**
     * @brief Default constructor is deleted
     *
     * HTTP client must be constructed with an IO handler.
     */
    client() = delete;

    /**
     * @brief Constructor with IO handler
     * @param io IO handler for network operations
     *
     * Creates an HTTP client protocol handler attached to the provided
     * IO handler, which manages the underlying socket connections.
     */
    explicit client(IO_Handler &io) noexcept
        : base_t(io) {}

    using response = qb::http::Response;

    /**
     * @brief Process an incoming HTTP response
     * @param size Size of the incoming message
     *
     * This method is called when a complete HTTP response is received from a server.
     * It parses the response data using the HTTP parser, then passes the
     * response to the client's callback handler.
     *
     * @security CRITICAL FIX: All cookie parsing exceptions are caught to prevent
     * std::terminate() in noexcept context. Malformed cookies are logged and ignored.
     */
    void
    onMessage(std::size_t) noexcept final {
        auto &response_obj = this->_http_obj.get_parsed_message();
        // Parse cookies from the Set-Cookie headers
        // SECURITY: Wrap in try/catch - parse_set_cookie_headers() can throw
        try {
            response_obj.parse_set_cookie_headers();
        } catch (const std::exception &e) {
            // Log error but continue processing response without cookies
            // This prevents std::terminate() in noexcept context
            LOG_HTTP_WARN("Failed to parse Set-Cookie headers: " << e.what());
        } catch (...) {
            LOG_HTTP_WARN("Failed to parse Set-Cookie headers: unknown exception");
        }
        this->_io.on(std::move(response_obj));
        this->_http_obj.reset();
    }

    /// The bound that cut the response a connection lost, named for the clients' errors -- empty for any other end (Huly
    /// QB-1248). The body limit when the parser refused the body on it: a declared length before a byte of it is read, a
    /// chunked body as its bytes pass it, a close-delimited one, which once its header section is read fails for nothing else.
    /// qb-io's read cap when the connection ended for a full input buffer (`buffer_overflow`; @p reason, the disconnection's)
    /// once the header section was read: a response is held whole until it completes, so a body under the limit is cut there
    /// -- under a limit of none, or one raised past the cap. A limit of none is never named.
    [[nodiscard]] std::string
    cut_by(int reason) const {
        const auto limit = this->_http_obj.max_body_size();
        const auto named = "HTTP/1.1 response body exceeds the client's limit of " + std::to_string(limit) + " bytes";
        if (this->_http_obj.refusal_status() == HTTP_STATUS_PAYLOAD_TOO_LARGE && limit != std::numeric_limits<std::size_t>::max())
            return named;
        if (!this->_http_obj.headers_completed())
            return {};
        if (reason == static_cast<int>(qb::io::async::event::disconnect_reason::buffer_overflow))
            return "HTTP/1.1 response exceeds the connection's read buffer cap of " + std::to_string(QB_MAX_READ_BUFFER_SIZE)
                   + " bytes (QB_MAX_READ_BUFFER_SIZE)";
        if (!this->ok() && http_message_needs_eof(&this->_http_obj) && limit != std::numeric_limits<std::size_t>::max())
            return named;
        return {};
    }

    /// The answer a one-shot request gets when its response failed: 502, the bound that cut it as its text/plain body.
    [[nodiscard]] qb::http::Response
    failed_response(int reason) const {
        qb::http::Response response{qb::http::status::BAD_GATEWAY};
        if (auto cut = cut_by(reason); !cut.empty()) {
            response.body() = std::move(cut);
            response.set_header("content-type", "text/plain");
        }
        return response;
    }
};

} // namespace qb::protocol::http
