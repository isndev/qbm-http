/**
 * @file qbm/http/routing/context.h
 * @brief Defines the Context class, which encapsulates the state of an HTTP request's processing lifecycle.
 *
 * The `Context` object is a central piece of the qb-http routing system. It holds the
 * HTTP request and response objects, a reference to the client session, extracted path
 * parameters, and any custom data set by middleware or handlers. It manages the execution
 * of a chain of asynchronous tasks (middleware and the final route handler) and provides
 * mechanisms for tasks to signal their completion or cancellation. It also supports lifecycle
 * hooks for custom actions at various stages of request processing.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include <memory>       // For std::shared_ptr, std::weak_ptr, std::enable_shared_from_this
#include <string>       // For std::string
#include <vector>       // For std::vector (task_chain, lifecycle_hooks)
#include <any>          // For std::any (custom_data)
#include <functional>   // For std::function (LifecycleHook, _on_finalized_callback)
#include <stdexcept>    // For std::bad_any_cast, std::runtime_error (potentially from user code)
#include <optional>     // For std::optional
#include <utility>      // For std::move

#include "../request.h"  // For qb::http::Request
#include "../response.h" // For qb::http::Response
#include "./path_parameters.h" // For qb::http::PathParameters
#include "./types.h"       // For HookPoint, AsyncTaskResult, http_method_to_string, HTTP_STATUS_*
#include "./async_task.h"  // For IAsyncTask
#include <qb/system/container/unordered_map.h> // For qb::unordered_map

// Forward declaration for RouterCore to break circular dependency if Context needs methods from it.
namespace qb::http {
    template<typename SessionType>
    class RouterCore;
}

namespace qb::http {
    /**
     * @brief Encapsulates all information and state for a single HTTP request throughout its processing lifecycle.
     *
     * A `Context` object is created for each incoming HTTP request and is passed through the chain of
     * middleware and to the final route handler. It provides access to:
     * - The `qb::http::Request` object (mutable).
     * - The `qb::http::Response` object (mutable, to be populated by handlers/middleware).
     * - A `std::shared_ptr` to the `SessionType` representing the client connection.
     * - Extracted `PathParameters` from the URL.
     * - A key-value store (`CustomDataMap`) for middleware and handlers to share custom data.
     * - Methods to manage the execution flow of a task chain (`complete`, `cancel`).
     * - A mechanism to add `LifecycleHook` functions to be called at specific points.
     * - Helper methods for commonly used response types (e.g. JSON, redirect, error statuses).
     *
     * The `Context` is responsible for orchestrating the execution of an `IAsyncTask` chain,
     * handling task results, managing error states, and ensuring proper finalization.
     *
     * @tparam SessionType The type of the session object associated with this request (e.g., a server connection class).
     *                     This session type must provide a `send_response(Response&&)` method if the default
     *                     `_on_finalized_callback` (which sends the response) is used by `RouterCore`.
     */
    template<typename SessionType>
    class Context : public std::enable_shared_from_this<Context<SessionType> > {
        friend class RouterCore<SessionType>;
    public:
        /** 
         * @brief Defines the current processing phase of the context within the router.
         * This helps in determining how to handle errors or subsequent task executions.
         */
        enum class ProcessingPhase {
            INITIAL, ///< Context created, before any primary task chain (normal, not_found, error) has started.
            NORMAL_CHAIN, ///< Currently executing the main task chain for a matched route.
            NOT_FOUND_CHAIN, ///< Currently executing the task chain for "404 Not Found" responses.
            ERROR_CHAIN ///< Currently executing a user-defined error handling task chain.
        };

        /** 
         * @brief Defines the signature for a lifecycle hook function.
         * @param context Reference to the current `Context` object.
         * @param point The `HookPoint` at which this hook is being invoked.
         */
        using LifecycleHook = std::function<void(Context<SessionType> &context, HookPoint point)>;
        /** 
         * @brief Type alias for the map used to store custom data within the context.
         * Keys are strings, values are `std::any` to allow storing arbitrary types.
         */
        using CustomDataMap = qb::unordered_map<std::string, std::any>;

    private:
        Request _request; ///< The HTTP request object associated with this context.
        Response _response; ///< The HTTP response object to be populated and sent.
        std::shared_ptr<SessionType> _session; ///< Shared pointer to the client session object.
        PathParameters _path_parameters; ///< Path parameters extracted from the route match.
        std::vector<LifecycleHook> _lifecycle_hooks; ///< List of registered lifecycle hook functions.
        CustomDataMap _custom_data; ///< Map for storing arbitrary custom data.
        std::optional<std::string> _cancellation_reason_internal;
        ///< Stores the reason if context processing is cancelled.

        std::vector<std::shared_ptr<IAsyncTask<SessionType> > > _task_chain;
        ///< The current chain of tasks to be executed.
        size_t _current_task_index = 0; ///< Index of the next task to be executed in `_task_chain`.
        bool _is_cancelled = false; ///< Flag: `true` if `cancel()` has been called.
        bool _is_completed_internally = false;
        ///< Flag: `true` if `complete()` has been called with a terminal result (COMPLETE, CANCELLED, ERROR leading to finalization).

        /** @brief Callback invoked when the context processing is fully finalized. Typically sends the response. */
        std::function<void(Context<SessionType> &)> _on_finalized_callback;
        /** @brief Weak pointer to the `RouterCore` that created this context. Used to access global error handlers. */
        std::weak_ptr<RouterCore<SessionType> > _router_core_wptr;
        /** @brief The current processing phase of this context (e.g., normal chain, error chain). */
        ProcessingPhase _current_processing_phase = ProcessingPhase::INITIAL;
        /** @brief Stores the result provided by the most recently completed `IAsyncTask`. */
        AsyncTaskResult _last_task_result = AsyncTaskResult::COMPLETE;
        /** @brief Guards against multiple calls to `finalize_processing_internal()`. */
        bool _finalize_called = false;

        /**
         * @brief (Private) Executes all registered lifecycle hooks for a given `HookPoint`.
         * Exceptions thrown by hook functions are caught and suppressed.
         * @param point The `HookPoint` for which to execute hooks.
         */
        void execute_hook_internal(HookPoint point) {
            for (const auto &hook: _lifecycle_hooks) {
                if (hook) {
                    try {
                        hook(*this, point);
                    } catch (...) {
                        // Log: Context::execute_hook_internal: Exception in lifecycle hook for point [point].
                    }
                }
            }
        }

        /**
         * @brief (Private) Finalizes the processing of the request context.
         * Ensures `POST_HANDLER_EXECUTION` hooks run and calls `_on_finalized_callback`.
         * Guards against multiple invocations.
         */
        void finalize_processing_internal() {
            if (_finalize_called) {
                return;
            }
            _finalize_called = true;
            _is_completed_internally = true;

            execute_hook_internal(HookPoint::POST_HANDLER_EXECUTION);

            if (_on_finalized_callback) {
                try {
                    _on_finalized_callback(*this);
                } catch (...) {
                    // Log: Context::finalize_processing_internal: Exception in _on_finalized_callback.
                }
            }
        }

        /**
         * @brief (Private) Executes the next task in the current `_task_chain`.
         * If the chain is exhausted or context is cancelled/finalized, it calls `finalize_processing_internal()`.
         * Handles exceptions from task execution by calling `complete(AsyncTaskResult::ERROR)`.
         */
        void proceed_to_next_task_internal() {
            if (_is_cancelled || _finalize_called) {
                if (!_finalize_called) finalize_processing_internal();
                return;
            }

            if (_current_task_index < _task_chain.size()) {
                auto task_to_execute = _task_chain[_current_task_index];
                if (task_to_execute) {
                    task_to_execute->startProcessing();
                    try {
                        task_to_execute->execute(this->shared_from_this());
                    } catch (...) {
                        task_to_execute->finishProcessing();
                        // Only call complete() if context is not already finalized or cancelled
                        // This prevents double finalization and ensures robust error handling
                        if (!_finalize_called && !_is_cancelled) {
                            this->complete(AsyncTaskResult::ERROR);
                        }
                        // If already finalized/cancelled, the exception is ignored as the context
                        // is already in a terminal state
                    }
                } else {
                    _current_task_index++;
                    proceed_to_next_task_internal();
                }
            } else {
                _is_completed_internally = true;
                finalize_processing_internal();
            }
        }

        /**
         * @brief Sets the current task chain for the context and starts its execution.
         *
         * If the context is already completed or cancelled, this method does nothing.
         * If the provided `chain` is empty, the context is immediately completed with `AsyncTaskResult::COMPLETE`.
         * Otherwise, the context's internal task chain is replaced with `chain`, the task index is reset,
         * and `proceed_to_next_task_internal()` is called to start processing the first task.
         *
         * @param chain A `std::vector` of `std::shared_ptr<IAsyncTask<SessionType>>` representing the new task chain.
         *              The vector is moved into the context.
         */
        void set_task_chain_and_start(std::vector<std::shared_ptr<IAsyncTask<SessionType> > > chain) {
            if (_is_completed_internally || _is_cancelled) {
                return;
            }
            _task_chain = std::move(chain);
            _current_task_index = 0;

            if (_task_chain.empty()) {
                complete(AsyncTaskResult::COMPLETE);
                return;
            }
            proceed_to_next_task_internal();
        }

        /**
         * @brief Sets the current processing phase of the context.
         * This is typically managed by the `RouterCore` or by the context itself when transitioning
         * to an error handling chain.
         * @param new_phase The `ProcessingPhase` to set.
         */
        void set_processing_phase(ProcessingPhase new_phase) noexcept {
            _current_processing_phase = new_phase;
        }

                /**
         * @brief Sets the path parameters for this context.
         * This is typically called by the `RouterCore` after matching a route.
         * @param params A `PathParameters` object to be moved into the context.
         */
        void set_path_parameters(PathParameters params) noexcept {
            _path_parameters = std::move(params);
        }

    public:
        /**
         * @brief Constructs a `Context` object.
         * @param request The HTTP request object (moved into the context).
         * @param response_prototype A prototype `Response` object (moved).
         * @param session A `std::shared_ptr` to the client session object.
         * @param on_finalized_callback A function called when this context is fully finalized.
         * @param router_core_wptr A `std::weak_ptr` to the `RouterCore`.
         */
        Context(Request request,
                Response response_prototype,
                std::shared_ptr<SessionType> session,
                std::function<void(Context<SessionType> &)> on_finalized_callback,
                std::weak_ptr<RouterCore<SessionType> > router_core_wptr)
            : _request(std::move(request)),
              _response(std::move(response_prototype)),
              _session(std::move(session)),
              _on_finalized_callback(std::move(on_finalized_callback)),
              _router_core_wptr(std::move(router_core_wptr)) {
        }

        /**
         * @brief Destructor.
         * Ensures finalization logic (`finalize_processing_internal()`) is executed if not already done.
         * Also executes any `REQUEST_COMPLETE` lifecycle hooks.
         */
        ~Context() {
            if (!_finalize_called) {
                finalize_processing_internal();
            }
            execute_hook_internal(qb::http::HookPoint::REQUEST_COMPLETE);
        }

        // --- Accessors ---
        /**
         * @brief Gets a mutable reference to the HTTP request object.
         * @return Reference to the `qb::http::Request` object.
         */
        [[nodiscard]] Request &request() noexcept { return _request; }
        /**
         * @brief Gets a constant reference to the HTTP request object.
         * @return Constant reference to the `qb::http::Request` object.
         */
        [[nodiscard]] const Request &request() const noexcept { return _request; }
        /**
         * @brief Gets a mutable reference to the HTTP response object.
         * @return Reference to the `qb::http::Response` object.
         */
        [[nodiscard]] Response &response() noexcept { return _response; }
        /**
         * @brief Gets a constant reference to the HTTP response object.
         * @return Constant reference to the `qb::http::Response` object.
         */
        [[nodiscard]] const Response &response() const noexcept { return _response; }
        /**
         * @brief Gets a shared pointer to the mutable client session object.
         * @return `std::shared_ptr<SessionType>` to the client session.
         */
        [[nodiscard]] std::shared_ptr<SessionType> session() noexcept { return _session; }
        /**
         * @brief Gets a shared pointer to the constant client session object.
         * @return `std::shared_ptr<const SessionType>` to the client session.
         */
        [[nodiscard]] std::shared_ptr<const SessionType> session() const noexcept { return _session; }
        /**
         * @brief Gets a mutable reference to the path parameters extracted from the URL.
         * @return Reference to the `qb::http::PathParameters` object.
         */
        [[nodiscard]] PathParameters &path_parameters() noexcept { return _path_parameters; }
        /**
         * @brief Gets a constant reference to the path parameters extracted from the URL.
         * @return Constant reference to the `qb::http::PathParameters` object.
         */
        [[nodiscard]] const PathParameters &path_parameters() const noexcept { return _path_parameters; }

        /**
         * @brief Retrieves a specific path parameter by name.
         * @param name The name of the path parameter (e.g., "id" from "/users/:id").
         * @param not_found_value The value to return if the parameter is not found. Defaults to an empty string.
         * @return The string value of the path parameter, or `not_found_value` if it doesn't exist.
         */
        [[nodiscard]] std::string path_param(const std::string &name, const std::string &not_found_value = "") const {
            auto value_opt = _path_parameters.get(name);
            return value_opt ? std::string(*value_opt) : not_found_value;
        }

        // --- Lifecycle Hooks ---
        /**
         * @brief Adds a lifecycle hook function to be called at specific points during request processing.
         * Hooks are executed in the order they are added for a given `HookPoint`.
         * @param hook_fn A `LifecycleHook` function (std::function) to be added. If `hook_fn` is null, it's ignored.
         */
        void add_lifecycle_hook(LifecycleHook hook_fn) {
            if (hook_fn) {
                _lifecycle_hooks.push_back(std::move(hook_fn));
            }
        }

        /**
         * @brief Manually executes all registered lifecycle hooks for a given `HookPoint`.
         * This is generally called internally by the `Context` or `RouterCore` at appropriate times.
         * Exceptions thrown by hook functions are caught and suppressed to prevent them from disrupting
         * the main processing flow. Consider logging such exceptions if a logging mechanism is available.
         * @param point The `HookPoint` for which to execute hooks.
         */
        void execute_hook(HookPoint point) {
            execute_hook_internal(point);
        }

        // --- Custom Data Management ---
        /**
         * @brief Stores a custom key-value pair in the context. Useful for sharing data between middleware and handlers.
         * The value is stored as `std::any`, allowing for arbitrary types.
         * If the key already exists, its value is overwritten.
         * @tparam T The type of the value to store.
         * @param key The string key for the custom data.
         * @param value The value to store (moved into `std::any`).
         */
        template<typename T>
        void set(const std::string &key, T value) {
            _custom_data[key] = std::move(value);
        }

        /**
         * @brief Retrieves a custom data value by key, attempting to cast it to type `T`.
         * @tparam T The expected type of the data.
         * @param key The string key of the custom data to retrieve.
         * @return An `std::optional<T>` containing the value if the key exists and the type cast is successful.
         *         Returns `std::nullopt` if the key is not found or if the stored type cannot be cast to `T`.
         *         Catches `std::bad_any_cast` internally and returns `std::nullopt` in case of a type mismatch.
         */
        template<typename T>
        [[nodiscard]] std::optional<T> get(const std::string &key) const {
            auto it = _custom_data.find(key);
            if (it != _custom_data.end()) {
                try {
                    return std::any_cast<T>(it->second);
                } catch (const std::bad_any_cast & /*e*/) {
                    // Log: Context::get: Bad any_cast for key 'key'.
                }
            }
            return std::nullopt;
        }

        /**
         * @brief Retrieves a pointer to a custom data value by key, attempting to cast it to `T*`.
         * This method provides direct (mutable) access to the stored `std::any` if the type matches.
         * @tparam T The expected type of the data.
         * @param key The string key of the custom data to retrieve.
         * @return A pointer `T*` to the value if the key exists and the type matches. Returns `nullptr` otherwise.
         *         Returns `nullptr` if `std::any_cast` to `T*` fails (e.g. type mismatch).
         */
        template<typename T>
        [[nodiscard]] T *get_ptr(const std::string &key) noexcept {
            auto it = _custom_data.find(key);
            if (it != _custom_data.end()) {
                return std::any_cast<T>(&(it->second));
            }
            return nullptr;
        }

        /**
         * @brief Retrieves a constant pointer to a custom data value by key, attempting to cast it to `const T*`.
         * This method provides direct (read-only) access to the stored `std::any` if the type matches.
         * @tparam T The expected type of the data.
         * @param key The string key of the custom data to retrieve.
         * @return A pointer `const T*` to the value if the key exists and the type matches. Returns `nullptr` otherwise.
         *         Returns `nullptr` if `std::any_cast` to `const T*` fails (e.g. type mismatch).
         */
        template<typename T>
        [[nodiscard]] const T *get_ptr(const std::string &key) const noexcept {
            auto it = _custom_data.find(key);
            if (it != _custom_data.end()) {
                return std::any_cast<const T>(&(it->second));
            }
            return nullptr;
        }

        /**
         * @brief Checks if custom data with the given key exists in the context.
         * @param key The string key to check.
         * @return `true` if data with the specified key exists, `false` otherwise.
         */
        [[nodiscard]] bool has(const std::string &key) const noexcept {
            return _custom_data.count(key) > 0;
        }

        /**
         * @brief Removes custom data associated with the given key from the context.
         * @param key The string key of the custom data to remove.
         * @return `true` if an element was removed, `false` otherwise (e.g., if the key was not found).
         */
        [[nodiscard]] bool remove(const std::string &key) noexcept {
            return _custom_data.erase(key) > 0;
        }

        // --- Response Helpers ---

        /**
         * @brief Sets the response for a redirect.
         * This method updates the response status code and sets the "Location" header.
         * @param url The URL to redirect to.
         * @param status_code The HTTP status code for the redirect (e.g., `qb::http::status::FOUND` (302),
         *                    `qb::http::status::MOVED_PERMANENTLY` (301)). Defaults to `qb::http::status::FOUND`.
         */
        void redirect(const std::string& url, qb::http::status status_code = qb::http::status::FOUND) {
            _response.status() = status_code;
            _response.set_header("Location", url);
            complete(AsyncTaskResult::COMPLETE);
        }

        /**
         * @brief Sets the response body to a JSON object.
         * Sets Content-Type to "application/json; charset=utf-8".
         * @param json_data The qb::json object to send.
         * @param status_code The HTTP status code. Defaults to 200 OK (`qb::http::status::OK`).
         */
        void json(const qb::json& json_data, qb::http::status status_code = qb::http::status::OK) {
            _response.status() = status_code;
            _response.set_content_type("application/json; charset=utf-8");
            _response.body() = json_data;
            complete(AsyncTaskResult::COMPLETE);
        }

        /**
         * @brief Sets the response body to a plain text string.
         * @param text_data The string to send.
         * @param status_code The HTTP status code. Defaults to 200 OK (`qb::http::status::OK`).
         * @param content_type The Content-Type header value. Defaults to "text/plain; charset=utf-8".
         */
        void text(const std::string& text_data, qb::http::status status_code = qb::http::status::OK, const std::string& content_type = "text/plain; charset=utf-8") {
            _response.status() = status_code;
            _response.set_content_type(content_type);
            _response.body() = text_data;
            complete(AsyncTaskResult::COMPLETE);
        }

        /**
         * @brief Sets the response body to an HTML string.
         * Sets Content-Type to "text/html; charset=utf-8".
         * @param html_data The HTML string to send.
         * @param status_code The HTTP status code. Defaults to 200 OK (`qb::http::status::OK`).
         */
        void html(const std::string& html_data, qb::http::status status_code = qb::http::status::OK) {
            _response.status() = status_code;
            _response.set_content_type("text/html; charset=utf-8");
            _response.body() = html_data;
            complete(AsyncTaskResult::COMPLETE);
        }

        /**
         * @brief Sets the response status to 204 No Content and clears the body.
         * This also removes "Content-Type" and "Content-Length" headers, as they are
         * typically omitted for 204 No Content responses.
         */
        void no_content() {
            _response.status() = qb::http::status::NO_CONTENT;
            _response.body().clear();
            _response.remove_header("Content-Type");
            _response.remove_header("Content-Length");
            complete(AsyncTaskResult::COMPLETE);
        }

        /**
         * @brief Sets the response status code.
         * @param status_code The HTTP status code to set (e.g., `qb::http::status::OK`, `qb::http::status::NOT_FOUND`).
         */
        Context<SessionType> &status(qb::http::status status_code) {
            _response.status() = status_code;
            return *this;
        }

        /**
         * @brief Sets a 400 Bad Request response.
         * The response body will be plain text.
         * @param error_message The error message for the response body. Defaults to "Bad Request".
         */
        void bad_request(const std::string& error_message = "Bad Request") {
            text(error_message, qb::http::status::BAD_REQUEST);
        }

        /**
         * @brief Sets a 401 Unauthorized response.
         * The response body will be plain text.
         * @param error_message The error message for the response body. Defaults to "Unauthorized".
         */
        void unauthorized(const std::string& error_message = "Unauthorized") {
            text(error_message, qb::http::status::UNAUTHORIZED);
        }

        /**
         * @brief Sets a 403 Forbidden response.
         * The response body will be plain text.
         * @param error_message The error message for the response body. Defaults to "Forbidden".
         */
        void forbidden(const std::string& error_message = "Forbidden") {
            text(error_message, qb::http::status::FORBIDDEN);
        }

        /**
         * @brief Sets a 404 Not Found response.
         * The response body will be plain text.
         * @param error_message The error message for the response body. Defaults to "Not Found".
         */
        void not_found(const std::string& error_message = "Not Found") {
            text(error_message, qb::http::status::NOT_FOUND);
        }

        /**
         * @brief Sets a 500 Internal Server Error response.
         * The response body will be plain text.
         * @param error_message The error message for the response body. Defaults to "Internal Server Error".
         */
        void internal_server_error(const std::string& error_message = "Internal Server Error") {
            text(error_message, qb::http::status::INTERNAL_SERVER_ERROR);
        }
        
        /**
         * @brief Signals the completion of the current task in the processing chain.
         *
         * This method is crucial for the progression of the HTTP request lifecycle. Each `IAsyncTask` (middleware or handler)
         * must call `complete()` on its `Context` when it has finished its processing to indicate its outcome.
         * The `result` parameter dictates how the `Context` should proceed:
         * - `AsyncTaskResult::CONTINUE`: Proceeds to the next task in the current chain.
         * - `AsyncTaskResult::COMPLETE`: Finalizes processing for this request. No further tasks in the current chain are run.
         * - `AsyncTaskResult::CANCELLED`: Marks the context as cancelled and finalizes processing.
         * - `AsyncTaskResult::ERROR`: Attempts to switch to a configured error handling chain. If no error chain is set, or if
         *   the context is already in an error chain, it sets a 500 Internal Server Error and finalizes.
         * - `AsyncTaskResult::FATAL_SPECIAL_HANDLER_ERROR`: Indicates a critical error in a special handler (like 404 or error chain).
         *   Sets a 500 error and finalizes immediately, bypassing further error chain logic.
         *
         * If the context is already finalized (`_finalize_called` is true) or cancelled (`_is_cancelled` is true),
         * most calls to `complete()` (except with `AsyncTaskResult::CANCELLED`) will be ignored to prevent conflicts.
         * The method also ensures that the `finishProcessing()` method of the current task is called.
         *
         * @param result The outcome of the current task. Defaults to `AsyncTaskResult::COMPLETE`.
         * @throws Can indirectly lead to exceptions if `finalize_processing_internal()` or subsequent task executions throw,
         *         though this method itself tries to catch exceptions during its switch statement logic and set a 500 error.
         */
        void complete(AsyncTaskResult result = AsyncTaskResult::COMPLETE) {
            if (_finalize_called && result != AsyncTaskResult::CANCELLED) {
                return;
            }
            if (_is_cancelled && result != AsyncTaskResult::CANCELLED) {
                if (!_finalize_called) {
                    finalize_processing_internal();
                }
                return;
            }

            if (!_task_chain.empty() && _current_task_index < _task_chain.size()) {
                auto current_task_ptr = _task_chain[_current_task_index];
                if (current_task_ptr) {
                    current_task_ptr->finishProcessing();
                }
            }

            _last_task_result = result;

            try {
                switch (result) {
                    case AsyncTaskResult::CONTINUE:
                        if (_is_cancelled) {
                            finalize_processing_internal();
                            return;
                        }
                        _current_task_index++;
                        proceed_to_next_task_internal();
                        break;

                    case AsyncTaskResult::COMPLETE:
                        _is_completed_internally = true;
                        finalize_processing_internal();
                        break;

                    case AsyncTaskResult::CANCELLED:
                        _is_cancelled = true;
                        _is_completed_internally = true;
                        finalize_processing_internal();
                        break;

                    case AsyncTaskResult::FATAL_SPECIAL_HANDLER_ERROR:
                        _response.status() = qb::http::status::INTERNAL_SERVER_ERROR;
                        _is_completed_internally = true;
                        finalize_processing_internal();
                        break;

                    case AsyncTaskResult::ERROR:
                        if (_is_cancelled) {
                            finalize_processing_internal();
                            return;
                        }
                        if (_current_processing_phase == ProcessingPhase::ERROR_CHAIN) {
                            _response.status() = qb::http::status::INTERNAL_SERVER_ERROR;
                            _is_completed_internally = true;
                            finalize_processing_internal();
                        } else {
                            auto router_core_shared = _router_core_wptr.lock();
                            if (router_core_shared && router_core_shared->is_error_chain_set()) {
                                auto error_chain_tasks = router_core_shared->get_compiled_error_tasks();
                                if (!error_chain_tasks.empty()) {
                                    set_processing_phase(ProcessingPhase::ERROR_CHAIN);
                                    _task_chain = std::move(error_chain_tasks);
                                    _current_task_index = 0;
                                    proceed_to_next_task_internal();
                                } else {
                                    _response.status() = qb::http::status::INTERNAL_SERVER_ERROR;
                                    _is_completed_internally = true;
                                    finalize_processing_internal();
                                }
                            } else {
                                _response.status() = qb::http::status::INTERNAL_SERVER_ERROR;
                                _is_completed_internally = true;
                                finalize_processing_internal();
                            }
                        }
                        break;
                }
            } catch (...) {
                _response.status() = qb::http::status::INTERNAL_SERVER_ERROR;
                _is_completed_internally = true;
                finalize_processing_internal();
            }
        }

        /**
         * @brief Cancels the current request processing.
         *
         * This method is used to manually cancel the request processing. It sets the context's cancellation flag,
         * records the cancellation reason, and attempts to cancel the currently executing task.
         *
         * @param reason The reason for cancellation. Defaults to "Cancelled by application".
         */
        void cancel(const std::string &reason = "Cancelled by application") noexcept {
            if (_is_cancelled || _finalize_called) {
                return;
            }
            _is_cancelled = true;
            _cancellation_reason_internal = reason;

            if (!_task_chain.empty() && _current_task_index < _task_chain.size()) {
                auto current_task_shared_ptr = _task_chain[_current_task_index];
                if (current_task_shared_ptr && current_task_shared_ptr->isCurrentlyProcessing()) {
                    try {
                        current_task_shared_ptr->cancel();
                    } catch (...) {
                        // Log: Context::cancel: Exception during task's cancel() method.
                    }
                }
            }
            // Always set to Service Unavailable on cancellation, regardless of previous state.
            _response.status() = qb::http::status::SERVICE_UNAVAILABLE;

            AsyncTaskResult cancel_result = AsyncTaskResult::CANCELLED;
            this->complete(cancel_result);
        }

        /**
         * @brief Checks if the request processing has been cancelled.
         * @return `true` if `cancel()` has been called on this context, `false` otherwise.
         */
        [[nodiscard]] bool is_cancelled() const noexcept {
            return _is_cancelled;
        }

        /**
         * @brief Checks if the request processing has been fully completed and finalized.
         * @return `true` if the finalization logic has been run (i.e., `finalize_processing_internal()` has been called
         *         and `_finalize_called` is true), `false` otherwise.
         */
        [[nodiscard]] bool is_completed() const noexcept {
            return _finalize_called;
        }

        /**
         * @brief Retrieves the reason for cancellation, if the context was cancelled.
         * @return An `std::optional<std::string>` containing the cancellation reason if `is_cancelled()` is true.
         *         Returns `std::nullopt` if the context has not been cancelled.
         */
        [[nodiscard]] std::optional<std::string> cancellation_reason() const noexcept {
            return _cancellation_reason_internal;
        }

        /**
         * @brief Gets the current processing phase of the context.
         * @return The current `ProcessingPhase` (e.g., `NORMAL_CHAIN`, `ERROR_CHAIN`).
         */
        [[nodiscard]] ProcessingPhase get_processing_phase() const noexcept {
            return _current_processing_phase;
        }
    };
} // namespace qb::http 
