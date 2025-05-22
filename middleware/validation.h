/**
 * @file qbm/http/middleware/validation.h
 * @brief Defines middleware for validating HTTP requests using a RequestValidator.
 *
 * This file provides the `ValidationMiddleware` class template, which integrates the
 * `qb::http::validation::RequestValidator` into the qb-http middleware chain.
 * It validates incoming requests based on configured rules and, if validation fails,
 * generates an appropriate error response (typically 400 Bad Request) containing
 * details of the validation errors in a JSON format.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Middleware
 */
#pragma once

#include <memory>       // For std::shared_ptr, std::make_shared
#include <string>       // For std::string
#include <vector>       // For std::vector (used indirectly by Result)
#include <stdexcept>    // For std::invalid_argument
#include <utility>      // For std::move

#include "../routing/middleware.h"           // For IMiddleware, Context, AsyncTaskResult
#include "../validation/request_validator.h" // For qb::http::validation::RequestValidator
#include "../validation/error.h"             // For qb::http::validation::Result and validation::Error
#include "../response.h"                     // For qb::http::Response
#include "../types.h"                        // For qb::http::status constants
#include <qb/json.h>                          // For qb::json

namespace qb::http {
    // Middleware typically resides in qb::http namespace

    /**
     * @brief Middleware that validates incoming HTTP requests using a `RequestValidator`.
     *
     * This middleware takes a configured `qb::http::validation::RequestValidator` and uses it
     * to validate the current request. If validation passes, it continues to the next task
     * in the chain. If validation fails, it generates an HTTP 400 Bad Request response
     * with a JSON body detailing the validation errors and completes the request processing.
     *
     * @tparam SessionType The type of the session object managed by the router.
     */
    template<typename SessionType>
    class ValidationMiddleware : public IMiddleware<SessionType> {
    public:
        /** @brief Convenience alias for a shared pointer to the request `Context`. */
        using ContextPtr = std::shared_ptr<Context<SessionType> >;

        /**
         * @brief Constructs a `ValidationMiddleware` instance.
         * @param validator A `std::shared_ptr` to a `qb::http::validation::RequestValidator` instance.
         *                  This validator should be pre-configured with all necessary validation rules.
         * @param name An optional name for this middleware instance, useful for logging or debugging.
         *             Defaults to "ValidationMiddleware".
         * @throws std::invalid_argument if the provided `validator` is null.
         */
        explicit ValidationMiddleware(std::shared_ptr<qb::http::validation::RequestValidator> validator,
                                      std::string name = "ValidationMiddleware")
            : _validator(std::move(validator)), _name(std::move(name)) {
            if (!_validator) {
                throw std::invalid_argument("ValidationMiddleware: RequestValidator cannot be null.");
            }
        }

        /**
         * @brief Processes the incoming request by validating it against the configured `RequestValidator`.
         *
         * Calls `_validator->validate()`, passing the request object and path parameters from the context.
         * If validation is successful, the context proceeds to the next task (`AsyncTaskResult::CONTINUE`).
         * If validation fails, an HTTP 400 Bad Request response is generated. The response body
         * will be a JSON object containing a general "Validation failed." message and an array of
         * specific error details (field, rule violated, message, offending value if available).
         * The context is then completed (`AsyncTaskResult::COMPLETE`).
         *
         * @param ctx The shared `Context` for the current request.
         */
        void process(ContextPtr ctx) override {
            validation::Result validation_result;
            // Pass a pointer to ctx->path_parameters() to RequestValidator::validate
            bool is_valid = _validator->validate(ctx->request(), validation_result, &(ctx->path_parameters()));

            if (is_valid) {
                ctx->complete(AsyncTaskResult::CONTINUE);
            } else {
                ctx->response().status() = qb::http::status::BAD_REQUEST;
                // Or qb::http::status::UNPROCESSABLE_ENTITY (422)
                ctx->response().set_header("Content-Type", "application/json; charset=utf-8");

                qb::json error_body;
                error_body["message"] = "Validation failed.";
                qb::json errors_array = qb::json::array();
                for (const auto &err: validation_result.errors()) {
                    qb::json error_detail;
                    error_detail["field"] = err.field_path;
                    error_detail["rule"] = err.rule_violated;
                    error_detail["message"] = err.message;
                    if (err.offending_value.has_value()) {
                        error_detail["value"] = err.offending_value.value();
                    }
                    errors_array.push_back(std::move(error_detail));
                }
                error_body["errors"] = std::move(errors_array);
                ctx->response().body() = error_body.dump(2); // Use dump(2) for pretty-printing with 2 spaces indent

                ctx->complete(AsyncTaskResult::COMPLETE);
            }
        }

        /** @brief Gets the configured name of this middleware instance. */
        [[nodiscard]] std::string name() const noexcept override {
            return _name;
        }

        /** 
         * @brief Handles a cancellation notification.
         * This middleware itself does not perform long-running asynchronous operations that need explicit cancellation.
         */
        void cancel() noexcept override {
            // No specific cancellation logic needed for this synchronous validation step.
        }

    private:
        std::shared_ptr<qb::http::validation::RequestValidator> _validator; ///< The request validator instance.
        std::string _name; ///< Name of this middleware instance.
    };

    /**
     * @brief Factory function to create a `std::shared_ptr` to a `ValidationMiddleware` instance.
     * @tparam SessionType The session type used by the HTTP context.
     * @param validator A `std::shared_ptr` to a pre-configured `qb::http::validation::RequestValidator`.
     * @param name An optional name for the middleware instance. Defaults to "ValidationMiddleware".
     * @return A `std::shared_ptr<ValidationMiddleware<SessionType>>`.
     * @throws std::invalid_argument if `validator` is null (via `ValidationMiddleware` constructor).
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<ValidationMiddleware<SessionType> > validation_middleware(
        std::shared_ptr<qb::http::validation::RequestValidator> validator,
        const std::string &name = "ValidationMiddleware"
    ) {
        return std::make_shared<ValidationMiddleware<SessionType> >(std::move(validator), name);
    }
} // namespace qb::http 
