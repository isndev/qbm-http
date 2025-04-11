
#pragma once

#include "./message_base.h"

namespace qb::http {

template <typename String, typename Session>
class Router;

template <typename String>
struct TRequest : public internal::MessageBase<String> {
    constexpr static const http_type_t type = HTTP_REQUEST;
    http_method method;
    qb::io::uri _uri;

public:
    /**
     * @brief Default constructor
     * 
     * Creates an empty HTTP request with GET method.
     */
    TRequest() noexcept
        : method(HTTP_GET) {}
    
    /**
     * @brief Constructor with method, URI, headers, and body
     * @param method HTTP method for the request
     * @param url URI for the request
     * @param headers Map of headers for the request
     * @param body Body content for the request
     * 
     * Creates an HTTP request with the specified method, URI, headers, and body.
     * All parameters except method and URL are optional.
     */
    TRequest(
        http::method method, qb::io::uri url, qb::icase_unordered_map<std::vector<String>> headers = {}, Body body = {})
        : internal::MessageBase<String>(std::move(headers), std::move(body))
        , method(method)
        , _uri{std::move(url)} {}
    
    /**
     * @brief Constructor with URI, headers, and body
     * @param url URI for the request
     * @param headers Map of headers for the request
     * @param body Body content for the request
     * 
     * Creates an HTTP request with GET method and the specified URI, headers, and body.
     * Headers and body are optional.
     */
    TRequest(qb::io::uri url, qb::icase_unordered_map<std::vector<String>> headers = {}, Body body = {})
        : internal::MessageBase<String>(std::move(headers), std::move(body))
        , method(HTTP_GET)
        , _uri{std::move(url)} {}
    
    /**
     * @brief Copy constructor
     * @param other The request to copy
     */
    TRequest(TRequest const &) = default;
    
    /**
     * @brief Move constructor
     * @param other The request to move
     */
    TRequest(TRequest &&) noexcept = default;
    
    /**
     * @brief Copy assignment operator
     * @param other The request to copy
     * @return Reference to this request
     */
    TRequest &operator=(TRequest const &) = default;
    
    /**
     * @brief Move assignment operator
     * @param other The request to move
     * @return Reference to this request
     */
    TRequest &operator=(TRequest &&) noexcept = default;

    /**
     * @brief Get the URI of the request (const version)
     * @return Const reference to the URI object
     * 
     * This method provides read-only access to the request's URI,
     * which contains the path, query parameters, and other URI components.
     */
    qb::io::uri const &
    uri() const {
        return _uri;
    }

    /**
     * @brief Get the URI of the request
     * @return Mutable reference to the URI object
     * 
     * This method provides mutable access to the request's URI,
     * allowing modification of the path, query parameters, and other URI components.
     */
    qb::io::uri &
    uri() {
        return _uri;
    }

    /**
     * @brief Get a query parameter value
     * @tparam T Query parameter name type
     * @param name Query parameter name
     * @param index Index for multiple values
     * @param not_found Default value to return if parameter not found
     * @return Query parameter value or default value if not found
     * 
     * Retrieves the value of a query parameter from the request URI.
     * For query strings like "?foo=bar&foo=baz", index 0 returns "bar" and index 1 returns "baz".
     * If the parameter is not found, the not_found value is returned.
     */
    template <typename T>
    [[nodiscard]] std::string const &
    query(T &&name, std::size_t const index = 0, std::string const &not_found = "") const {
        return _uri.query<T>(std::forward<T>(name), index, not_found);
    }

    /**
     * @brief Get the query parameters map
     * @return Mutable reference to the query parameters map
     * 
     * Provides access to the map of query parameters, allowing
     * modification of the parameters. Each parameter can have
     * multiple values stored as a vector.
     */
    auto &
    queries() {
        return _uri.queries();
    }
    
    /**
     * @brief Get the query parameters map (const version)
     * @return Const reference to the query parameters map
     * 
     * Provides read-only access to the map of query parameters.
     * Each parameter can have multiple values stored as a vector.
     */
    [[nodiscard]] auto const &
    queries() const {
        return _uri.queries();
    }

    /**
     * @brief Reset the request to its default state
     * 
     * Resets the HTTP method to GET, clears the URI,
     * and resets all headers and the body to their defaults.
     * This allows reusing the same request object for a new request.
     */
    void
    reset() {
        method = HTTP_GET;
        _uri = qb::io::uri{};
        static_cast<internal::MessageBase<String> &>(*this).reset();
    }

    /**
     * @brief HTTP Router for handling requests
     * 
     * This router provides a flexible and efficient way to handle HTTP requests
     * with support for path parameters, controllers, and custom route handlers.
     * It also supports asynchronous request handling through an event-driven approach.
     */
    template <typename Session>
    using Router = Router<String, Session>;
};

using Request = TRequest<std::string>;
using request = Request;
using RequestView = TRequest<std::string_view>;
using request_view = RequestView;

}