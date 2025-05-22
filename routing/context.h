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
                        this->complete(AsyncTaskResult::ERROR);
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
         * Ensures finalization logic is executed if not already done.
         */
        ~Context() {
            if (!_finalize_called) {
                finalize_processing_internal();
            }
            execute_hook_internal(qb::http::HookPoint::REQUEST_COMPLETE);
        }

        // --- Accessors ---
        [[nodiscard]] Request &request() noexcept { return _request; }
        [[nodiscard]] const Request &request() const noexcept { return _request; }
        [[nodiscard]] Response &response() noexcept { return _response; }
        [[nodiscard]] const Response &response() const noexcept { return _response; }
        [[nodiscard]] std::shared_ptr<SessionType> session() noexcept { return _session; }
        [[nodiscard]] std::shared_ptr<const SessionType> session() const noexcept { return _session; }
        [[nodiscard]] PathParameters &path_parameters() noexcept { return _path_parameters; }
        [[nodiscard]] const PathParameters &path_parameters() const noexcept { return _path_parameters; }

        [[nodiscard]] std::string path_param(const std::string &name, const std::string &not_found_value = "") const {
            auto value_opt = _path_parameters.get(name);
            return value_opt ? std::string(*value_opt) : not_found_value;
        }

        void set_path_parameters(PathParameters params) noexcept {
            _path_parameters = std::move(params);
        }

        // --- Lifecycle Hooks ---
        void add_lifecycle_hook(LifecycleHook hook_fn) {
            if (hook_fn) {
                _lifecycle_hooks.push_back(std::move(hook_fn));
            }
        }

        void execute_hook(HookPoint point) {
            execute_hook_internal(point);
        }

        // --- Custom Data Management ---
        template<typename T>
        void set(const std::string &key, T value) {
            _custom_data[key] = std::move(value);
        }

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

        template<typename T>
        [[nodiscard]] T *get_ptr(const std::string &key) noexcept {
            auto it = _custom_data.find(key);
            if (it != _custom_data.end()) {
                return std::any_cast<T>(&(it->second));
            }
            return nullptr;
        }

        template<typename T>
        [[nodiscard]] const T *get_ptr(const std::string &key) const noexcept {
            auto it = _custom_data.find(key);
            if (it != _custom_data.end()) {
                return std::any_cast<const T>(&(it->second));
            }
            return nullptr;
        }

        [[nodiscard]] bool has(const std::string &key) const noexcept {
            return _custom_data.count(key) > 0;
        }

        [[nodiscard]] bool remove(const std::string &key) noexcept {
            return _custom_data.erase(key) > 0;
        }

        // --- Task Chain Management ---
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
                                auto error_chain_tasks_list = router_core_shared->get_compiled_error_tasks();
                                if (!error_chain_tasks_list.empty()) {
                                    set_processing_phase(ProcessingPhase::ERROR_CHAIN);
                                    std::vector<std::shared_ptr<IAsyncTask<SessionType> > > error_chain_vec(
                                        error_chain_tasks_list.begin(), error_chain_tasks_list.end());
                                    _task_chain = std::move(error_chain_vec);
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

        [[nodiscard]] bool is_cancelled() const noexcept {
            return _is_cancelled;
        }

        [[nodiscard]] bool is_completed() const noexcept {
            return _finalize_called;
        }

        [[nodiscard]] std::optional<std::string> cancellation_reason() const noexcept {
            return _cancellation_reason_internal;
        }

        void set_processing_phase(ProcessingPhase new_phase) noexcept {
            _current_processing_phase = new_phase;
        }

        [[nodiscard]] ProcessingPhase get_processing_phase() const noexcept {
            return _current_processing_phase;
        }
    };
} // namespace qb::http 
