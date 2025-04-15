
#pragma once

#include "./message_base.h"

namespace qb::http {
/**
 * @brief HTTP response message template
 * @tparam String String type used for storage (std::string or std::string_view)
 *
 * Represents an HTTP response message with status code, reason phrase, headers, and
 * body. This template class can use either std::string or std::string_view as the
 * underlying storage type, allowing for efficient memory management depending
 * on the use case:
 *
 * - std::string for mutable responses that may be modified
 * - std::string_view for immutable responses that are processed once
 *
 * The class provides comprehensive functionality for HTTP response handling:
 * - Status code and reason phrase management
 * - Header manipulation with case-insensitive keys
 * - Protocol version control
 * - Content type handling with charset management
 * - Flexible body content manipulation
 *
 * It also implements a Router system for status code-based response handling,
 * allowing for customized responses to different HTTP status codes.
 */
template <typename String>
struct TResponse : public internal::MessageBase<String> {
    constexpr static const http_type_t type = HTTP_RESPONSE;
    http_status                        status_code;
    String                             status;

    TResponse() noexcept
        : status_code(HTTP_STATUS_OK) {}

    void
    reset() {
        status_code = HTTP_STATUS_OK;
        status      = {};
        static_cast<internal::MessageBase<String> &>(*this).reset();
    }

    /**
     * @brief Router for handling HTTP status responses
     * @tparam Session Session type
     *
     * Maps HTTP status codes to handler functions for generating
     * appropriate responses.
     */
    template <typename Session>
    class Router {
    public:
        /**
         * @brief Context for response handlers
         *
         * Contains references to the session and response
         * for use by handler functions.
         */
        struct Context {
            Session   &session;
            TResponse &response;

            const auto &
            header(String const &name, String const &not_found = "") const {
                return response.header(name, not_found);
            }
        };

    private:
        /**
         * @brief Interface for all route handlers
         *
         * Base class for routes that defines the common interface
         * for processing HTTP requests. All route implementations
         * must inherit from this class and implement the process method.
         */
        class IRoute {
        public:
            /**
             * @brief Virtual destructor
             *
             * Ensures proper cleanup of derived classes.
             */
            virtual ~IRoute() = default;

            /**
             * @brief Process an HTTP request
             * @param ctx Request context with all necessary information
             *
             * Abstract method that must be implemented by derived classes
             * to handle the actual request processing. Implementations will
             * typically extract information from the request and populate
             * the response.
             */
            virtual void process(Context &ctx) = 0;
        };

        /**
         * @brief Templated route handler for HTTP status responses
         * @tparam Func Function type for handling routes
         *
         * Implements the IRoute interface with a specific function type.
         * Routes are used to handle HTTP responses based on their status code.
         */
        template <typename Func>
        class TRoute : public IRoute {
            Func _func;

        public:
            TRoute(TRoute const &) = delete;
            /**
             * @brief Constructor for TRoute
             * @param func Function or callable to handle the route
             *
             * Creates a route handler with the specified function.
             */
            explicit TRoute(Func &&func)
                : _func(func) {}

            virtual ~TRoute() = default;

            /**
             * @brief Process a context through this route
             * @param ctx Context containing session and response
             *
             * Invokes the function stored in this route with the provided context.
             */
            void
            process(Context &ctx) final {
                _func(ctx);
            }
        };

        /**
         * @brief Map of status codes to route handlers
         *
         * Stores route handlers indexed by HTTP status codes.
         */
        qb::unordered_map<int, IRoute *> _routes;

    public:
        /**
         * @brief Default constructor
         *
         * Creates an empty router with no routes.
         */
        Router() = default;

        /**
         * @brief Destructor
         *
         * Cleans up all registered route handlers.
         */
        ~Router() noexcept {
            for (auto const &it : _routes)
                delete it.second;
        }

        /**
         * @brief Route a response based on its status code
         * @param session Current HTTP session
         * @param response HTTP response to route
         * @return true if a route handler was found and executed, false otherwise
         *
         * Looks up the response's status code in the route map and
         * executes the corresponding handler if found.
         */
        bool
        route(Session &session, TResponse &response) const {
            const auto &it = _routes.find(response.status_code);
            if (it != _routes.end()) {
                Context ctx{session, response};
                it->second->process(ctx);
                return true;
            }
            return false;
        }

#define REGISTER_ROUTE_FUNCTION(num, name, description)                                 \
    /**                                                                                 \
     * @brief Register a handler for HTTP status: description                           \
     * @tparam _Func Function type                                                      \
     * @param func Function or callable to handle the route                             \
     * @return Reference to this router                                                 \
     *                                                                                  \
     * Associates a function with HTTP status code num.                                 \
     * When a response with this status code is processed, the function will be called. \
     */                                                                                 \
    template <typename _Func>                                                           \
    Router &name(_Func &&func) {                                                        \
        _routes.emplace(static_cast<http_status>(num),                                  \
                        new TRoute<_Func>(std::forward<_Func>(func)));                  \
        return *this;                                                                   \
    }

        HTTP_STATUS_MAP(REGISTER_ROUTE_FUNCTION)

#undef REGISTER_ROUTE_FUNCTION
    };

    template <typename session>
    using router = Router<session>;
};

using Response      = TResponse<std::string>;
using response      = TResponse<std::string>;
using ResponseView  = TResponse<std::string_view>;
using response_view = TResponse<std::string_view>;

} // namespace qb::http