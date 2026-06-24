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
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include <any>        // For std::any (custom_data)
#include <charconv>   // For std::from_chars (typed path/query params)
#include <cstdint>    // For std::uint64_t
#include <functional> // For std::function (LifecycleHook, _on_finalized_callback)
#include <memory>     // For std::shared_ptr, std::weak_ptr, std::enable_shared_from_this
#include <optional>   // For std::optional
#include <stdexcept>  // For std::bad_any_cast, std::runtime_error (potentially from user code)
#include <string>     // For std::string
#include <type_traits> // For std::is_arithmetic_v, std::is_same_v (typed accessors)
#include <utility>    // For std::move
#include <vector>     // For std::vector (task_chain, lifecycle_hooks)

#include <qb/system/container/unordered_map.h> // For qb::unordered_map
#include "../request.h"                        // For qb::http::Request
#include "../response.h"                       // For qb::http::Response
#include "./async_task.h"                      // For IAsyncTask
#include "./path_parameters.h"                 // For qb::http::PathParameters
#include "./slot.h"                            // For qb::http::Slot<T> &mdash; typed compile-time keys
#include "./types.h"                           // For HookPoint, AsyncTaskResult, http_method_to_string, HTTP_STATUS_*

// Forward declaration for RouterCore to break circular dependency if Context needs methods from it.
namespace qb::http {
template <typename SessionType>
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
template <typename SessionType>
class Context : public std::enable_shared_from_this<Context<SessionType>> {
    friend class RouterCore<SessionType>;

public:
    /**
     * @brief Defines the current processing phase of the context within the router.
     * This helps in determining how to handle errors or subsequent task executions.
     */
    enum class ProcessingPhase {
        INITIAL,                  ///< Context created, before any primary task chain (normal, not_found, error) has started.
        NORMAL_CHAIN,             ///< Currently executing the main task chain for a matched route.
        NOT_FOUND_CHAIN,          ///< Currently executing the task chain for "404 Not Found" responses.
        METHOD_NOT_ALLOWED_CHAIN, ///< Currently executing the task chain for "405 Method Not Allowed" responses.
        ERROR_CHAIN               ///< Currently executing a user-defined error handling task chain.
    };

    /**
     * @brief High-level lifecycle state of the context.
     *
     * Consolidates the former `_is_completed_internally` / `_finalize_called` flags
     * into a single enum. Cancellation is tracked orthogonally via an sticky flag
     * because cancel happens *before* finalisation (the chain still needs to run its
     * finalise callback exactly once after a cancel).
     */
    enum class State : std::uint8_t {
        Ready,    ///< Context constructed, no task chain started yet.
        Running,  ///< A task chain is currently executing on this context.
        Finalised ///< Terminal state: `finalize_processing_internal()` has run.
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
    Request  _request;  ///< The HTTP request object associated with this context.
    Response _response; ///< The HTTP response object to be populated and sent.
    // Weak pointer to break the circular reference:
    //   HttpSession._context (shared_ptr<Context>) <-> Context._session (originally shared_ptr<Session>).
    // Using weak_ptr here prevents both objects from keeping each other alive indefinitely.
    std::weak_ptr<SessionType> _session;         ///< Weak pointer to the client session object.
    PathParameters             _path_parameters; ///< Path parameters extracted from the route match.
    std::vector<LifecycleHook> _lifecycle_hooks; ///< List of registered lifecycle hook functions.
    CustomDataMap              _custom_data;     ///< Map for storing arbitrary custom data.
    std::optional<std::string> _cancellation_reason_internal;
    ///< Stores the reason if context processing is cancelled.

    /// The current chain of tasks to be executed. Held by `shared_ptr<const ...>` so the immutable,
    /// shared compiled chain is referenced — not deep-copied — per request (a route's task list is
    /// built once at compile time and reused across requests). Null == no chain.
    std::shared_ptr<const std::vector<std::shared_ptr<IAsyncTask<SessionType>>>> _task_chain;
    size_t      _current_task_index          = 0; ///< Index of the next task to be executed in `_task_chain`.
    std::size_t _finalization_deferral_depth = 0;
    bool        _finalization_pending        = false;

    /** @brief Callback invoked when the context processing is fully finalized. Typically sends the response. */
    std::function<void(Context<SessionType> &)> _on_finalized_callback;
    /** @brief Weak pointer to the `RouterCore` that created this context. Used to access global error handlers. */
    std::weak_ptr<RouterCore<SessionType>> _router_core_wptr;

    /**
     * @brief Consolidated lifecycle state (F24).
     *
     * Packs the five orthogonal state fields previously scattered across
     * the class into a single cache-friendly POD:
     *
     *   - `state`: high-level 3-state machine (Ready / Running / Finalised).
     *   - `phase`: which task chain is being executed (Normal / NotFound / Error / Initial).
     *   - `last_result`: the `AsyncTaskResult` returned by the most recently
     *     completed task. Carried across `complete()` calls so `cancel()` /
     *     `finalize()` know how the chain exited.
     *   - `is_cancelled`: sticky cancellation flag. Orthogonal to `state`:
     *     cancellation can happen at any point while the chain is `Running`
     *     and must survive across finalisation so POST hooks can observe it.
     *   - `task_in_flight`: true between an `IAsyncTask::execute()` call
     *     and the matching `complete()`. Consulted exclusively by
     *     `cancel()` to decide whether to call `IAsyncTask::cancel()` on
     *     the in-flight task &mdash; replaces the per-task
     *     `_is_being_processed` flag, which was unsound because
     *     `IAsyncTask` instances are shared across pipelined/multiplexed
     *     requests.
     *
     * Invariants (asserted in debug builds where applicable):
     *   - `task_in_flight` => `state == Running`
     *   - `is_cancelled` is monotonic: once set, never cleared
     *   - `state` transitions only forward: Ready &rarr; Running &rarr; Finalised
     */
    struct Lifecycle {
        State           state            = State::Ready;
        ProcessingPhase phase            = ProcessingPhase::INITIAL;
        AsyncTaskResult last_result      = AsyncTaskResult::COMPLETE;
        std::uint64_t   completion_count = 0;
        bool            is_cancelled     = false;
        bool            task_in_flight   = false;
    };
    Lifecycle _lc;

    // --- Semantic queries (all `noexcept`) ---

    /// @return `true` when the context has entered its terminal
    /// `Finalised` state &mdash; no further tasks will run.
    [[nodiscard]] bool
    is_finalised_internal() const noexcept {
        return _lc.state == State::Finalised;
    }

    /// @return `true` when either the context has been cancelled or
    /// already reached its terminal state. This is the guard the
    /// task-dispatch loop uses to bail out of further work.
    [[nodiscard]] bool
    is_cancelled_or_done_internal() const noexcept {
        return _lc.is_cancelled || _lc.state == State::Finalised;
    }

    /**
     * @brief (Private) Executes all registered lifecycle hooks for a given `HookPoint`.
     * Exceptions thrown by hook functions are caught and suppressed.
     * @param point The `HookPoint` for which to execute hooks.
     */
    void
    execute_hook_internal(HookPoint point) {
        for (const auto &hook : _lifecycle_hooks) {
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
    void
    finalize_processing_internal() {
        if (_lc.state == State::Finalised) {
            return;
        }
        if (_finalization_deferral_depth > 0) {
            _finalization_pending = true;
            return;
        }
        _lc.state             = State::Finalised;
        _lc.task_in_flight    = false;
        _finalization_pending = false;

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
    void
    proceed_to_next_task_internal() {
        if (is_cancelled_or_done_internal()) {
            if (!is_finalised_internal())
                finalize_processing_internal();
            return;
        }

        if (_task_chain && _current_task_index < _task_chain->size()) {
            // Pin the list alive across execute(): the error path may reseat `_task_chain`, which would
            // otherwise free the vector this task reference points into. One refcount bump, not a copy.
            const auto  chain_pin       = _task_chain;
            const auto &task_to_execute = (*chain_pin)[_current_task_index];
            if (task_to_execute) {
                _lc.task_in_flight = true;
                try {
                    task_to_execute->execute(this->shared_from_this());
                } catch (...) {
                    _lc.task_in_flight = false;
                    // Only call complete() if context is not already finalized or cancelled
                    // This prevents double finalization and ensures robust error handling
                    if (!is_cancelled_or_done_internal()) {
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
     * @param chain A `shared_ptr` to the (immutable, shared) compiled task chain for this request.
     *              The pointer is moved in — the underlying vector is referenced, never copied.
     */
    void
    set_task_chain_and_start(std::shared_ptr<const std::vector<std::shared_ptr<IAsyncTask<SessionType>>>> chain) {
        if (is_cancelled_or_done_internal()) {
            return;
        }
        _task_chain         = std::move(chain);
        _current_task_index = 0;
        _lc.state           = State::Running;

        if (!_task_chain || _task_chain->empty()) {
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
    void
    set_processing_phase(ProcessingPhase new_phase) noexcept {
        _lc.phase = new_phase;
    }

    /**
     * @brief Sets the path parameters for this context.
     * This is typically called by the `RouterCore` after matching a route.
     * @param params A `PathParameters` object to be moved into the context.
     */
    void
    set_path_parameters(PathParameters params) noexcept {
        _path_parameters = std::move(params);
    }

public:
    /**
     * @brief Internal RAII guard used by functional middleware that supports
     *        synchronous post-`next()` response mutation.
     *
     * While a guard is alive, terminal completion marks finalisation as
     * pending instead of sending immediately. When the outermost guard leaves
     * scope, pending finalisation is resumed. This keeps synchronous
     * middleware post-processing observable without changing the public
     * `next()` API or the normal async task contract.
     */
    class ScopedFinalizationDeferral {
    private:
        Context<SessionType> *_ctx = nullptr;

        explicit ScopedFinalizationDeferral(Context<SessionType> &ctx) noexcept
            : _ctx(&ctx) {
            ++_ctx->_finalization_deferral_depth;
        }

        friend class Context<SessionType>;

    public:
        ScopedFinalizationDeferral(const ScopedFinalizationDeferral &)            = delete;
        ScopedFinalizationDeferral &operator=(const ScopedFinalizationDeferral &) = delete;

        ScopedFinalizationDeferral(ScopedFinalizationDeferral &&other) noexcept
            : _ctx(std::exchange(other._ctx, nullptr)) {}

        ScopedFinalizationDeferral &
        operator=(ScopedFinalizationDeferral &&other) noexcept {
            if (this != &other) {
                release();
                _ctx = std::exchange(other._ctx, nullptr);
            }
            return *this;
        }

        ~ScopedFinalizationDeferral() noexcept {
            release();
        }

    private:
        void
        release() noexcept {
            if (!_ctx) {
                return;
            }
            auto *ctx = std::exchange(_ctx, nullptr);
            if (ctx->_finalization_deferral_depth > 0) {
                --ctx->_finalization_deferral_depth;
            }
            if (ctx->_finalization_deferral_depth == 0 && ctx->_finalization_pending) {
                ctx->finalize_processing_internal();
            }
        }
    };

    [[nodiscard]] ScopedFinalizationDeferral
    defer_finalization_scope() noexcept {
        return ScopedFinalizationDeferral(*this);
    }

    /**
     * @brief Constructs a `Context` object.
     * @param request The HTTP request object (moved into the context).
     * @param response_prototype A prototype `Response` object (moved).
     * @param session A `std::shared_ptr` to the client session object.
     * @param on_finalized_callback A function called when this context is fully finalized.
     * @param router_core_wptr A `std::weak_ptr` to the `RouterCore`.
     */
    Context(Request request, Response response_prototype, std::shared_ptr<SessionType> session,
            std::function<void(Context<SessionType> &)> on_finalized_callback, std::weak_ptr<RouterCore<SessionType>> router_core_wptr)
        : _request(std::move(request))
        , _response(std::move(response_prototype))
        , _session(std::move(session))
        , _on_finalized_callback(std::move(on_finalized_callback))
        , _router_core_wptr(std::move(router_core_wptr)) {}

    /**
     * @brief Destructor.
     *
     * Acts as a defensive safety net for misuse: callers are expected to drive
     * the context to `State::Finalised` via `complete()` / `cancel()` before
     * the last `shared_ptr` reference is dropped. If that invariant is broken
     * (e.g. the task chain throws and no one catches it), the destructor:
     *   1. Marks the context as `Finalised` to prevent further state changes.
     *   2. Invokes the finalisation callback inside a `try/catch` (never throws).
     *   3. Fires the `REQUEST_COMPLETE` hook chain, also inside `try/catch`.
     *
     * The destructor is `noexcept`: any exception from the hooks or the
     * finalisation callback is swallowed rather than propagated during stack
     * unwinding. Hooks invoked here MUST NOT call `shared_from_this()` on the
     * context – the control block is already in terminal release state.
     */
    ~Context() noexcept {
        try {
            if (!is_finalised_internal()) {
                finalize_processing_internal();
            }
            execute_hook_internal(qb::http::HookPoint::REQUEST_COMPLETE);
        } catch (...) {
            // Intentionally swallow: a failing hook must never take down the process
            // during stack unwinding. See the contract described above.
        }
    }

    // --- Accessors ---
    /**
     * @brief Gets a mutable reference to the HTTP request object.
     * @return Reference to the `qb::http::Request` object.
     */
    [[nodiscard]] Request &
    request() noexcept {
        return _request;
    }
    /**
     * @brief Gets a constant reference to the HTTP request object.
     * @return Constant reference to the `qb::http::Request` object.
     */
    [[nodiscard]] const Request &
    request() const noexcept {
        return _request;
    }
    /**
     * @brief Gets a mutable reference to the HTTP response object.
     * @return Reference to the `qb::http::Response` object.
     */
    [[nodiscard]] Response &
    response() noexcept {
        return _response;
    }
    /**
     * @brief Gets a constant reference to the HTTP response object.
     * @return Constant reference to the `qb::http::Response` object.
     */
    [[nodiscard]] const Response &
    response() const noexcept {
        return _response;
    }
    /**
     * @brief Gets a shared pointer to the mutable client session object.
     * @return `std::shared_ptr<SessionType>` to the client session, or nullptr if the session
     *         has already been destroyed (e.g. after extraction or disconnection).
     */
    [[nodiscard]] std::shared_ptr<SessionType>
    session() noexcept {
        return _session.lock();
    }
    /**
     * @brief Gets a shared pointer to the constant client session object.
     * @return `std::shared_ptr<const SessionType>` to the client session, or nullptr if expired.
     */
    [[nodiscard]] std::shared_ptr<const SessionType>
    session() const noexcept {
        return _session.lock();
    }
    /**
     * @brief Gets a mutable reference to the path parameters extracted from the URL.
     * @return Reference to the `qb::http::PathParameters` object.
     */
    [[nodiscard]] PathParameters &
    path_parameters() noexcept {
        return _path_parameters;
    }
    /**
     * @brief Gets a constant reference to the path parameters extracted from the URL.
     * @return Constant reference to the `qb::http::PathParameters` object.
     */
    [[nodiscard]] const PathParameters &
    path_parameters() const noexcept {
        return _path_parameters;
    }

    /**
     * @brief Retrieves a specific path parameter by name (zero-copy).
     * @param name The name of the path parameter (e.g., "id" from "/users/:id").
     * @return A constant reference to the parameter's value if present, otherwise to a process-wide
     *         static empty string (always safe to keep). For a custom fallback use
     *         `path_param_or<std::string>(name, fallback)`; for a typed value use `path_param<T>(name)`.
     */
    [[nodiscard]] const std::string &
    path_param(std::string_view name) const {
        const auto it = _path_parameters.find(name);
        return it != _path_parameters.end() ? it->second : detail::empty_string_value;
    }

    // --- Typed accessors (C++20) ----------------------------------------------
    // Parse a captured value into T without exceptions: integral/floating via
    // std::from_chars (whole-string match required), bool from true/false/1/0,
    // string/string_view pass through. Returns nullopt on absence OR parse error.

    /**
     * @brief Parse a raw captured value into `T` (no throw). Used by the typed
     *        `path_param<T>` / `query_param<T>` accessors.
     */
    template <typename T>
    [[nodiscard]] static std::optional<T>
    parse_value(std::string_view sv) noexcept {
        if constexpr (std::is_same_v<T, std::string>) {
            return std::string(sv);
        } else if constexpr (std::is_same_v<T, std::string_view>) {
            return sv;
        } else if constexpr (std::is_same_v<T, bool>) {
            if (sv == "true" || sv == "1") return true;
            if (sv == "false" || sv == "0") return false;
            return std::nullopt;
        } else if constexpr (std::is_arithmetic_v<T>) {
            T          out{};
            const auto first = sv.data();
            const auto last  = sv.data() + sv.size();
            auto [ptr, ec]   = std::from_chars(first, last, out);
            if (ec == std::errc{} && ptr == last)
                return out;
            return std::nullopt;
        } else {
            static_assert(sizeof(T) == 0,
                          "path_param<T>/query_param<T>: T must be string, string_view, bool, "
                          "or an arithmetic type");
            return std::nullopt;
        }
    }

    /**
     * @brief Typed path parameter: `ctx->path_param<int>("id")` → `std::optional<int>`.
     * @return The parsed value, or `std::nullopt` if the parameter is absent or unparseable.
     */
    template <typename T>
    [[nodiscard]] std::optional<T>
    path_param(std::string_view name) const {
        auto v = _path_parameters.get(name);
        return v ? parse_value<T>(*v) : std::nullopt;
    }

    /** @brief Typed path parameter with a fallback: never fails, returns `fallback` on absence/parse error. */
    template <typename T>
    [[nodiscard]] T
    path_param_or(std::string_view name, T fallback) const {
        return path_param<T>(name).value_or(std::move(fallback));
    }

    /**
     * @brief Typed query parameter: `ctx->query_param<int>("page")` → `std::optional<int>`.
     * @return The parsed value, or `std::nullopt` if absent/empty or unparseable.
     */
    template <typename T = std::string>
    [[nodiscard]] std::optional<T>
    query_param(std::string_view name) const {
        // Zero-copy: Request::query() returns a stable reference (the stored value, or a static empty
        // string on a miss), so binding a const-ref here is safe.
        const std::string &raw = _request.query(name);
        if (raw.empty())
            return std::nullopt;
        return parse_value<T>(raw);
    }

    /** @brief Typed query parameter with a fallback. */
    template <typename T>
    [[nodiscard]] T
    query_param_or(std::string_view name, T fallback) const {
        return query_param<T>(name).value_or(std::move(fallback));
    }

    /**
     * @brief Deserialize the request body into `T` (no throw).
     * @details `bind<qb::json>()` parses JSON; `bind<std::string>()` returns the raw body; any other
     *          `T` is parsed as JSON then converted via `qb::json::get<T>()` (e.g. a
     *          `NLOHMANN_DEFINE_TYPE` model). Returns `std::nullopt` on any parse/convert failure.
     * @code
     * auto dto = ctx->bind<CreateTask>();
     * if (!dto) { ctx->bad_request("invalid body"); return; }
     * use(*dto);
     * @endcode
     */
    template <typename T>
    [[nodiscard]] std::optional<T>
    bind() const {
        static_assert(!std::is_same_v<T, std::string_view>,
                      "bind<std::string_view> would dangle (view into a temporary qb::json); "
                      "use bind<std::string>()");
        try {
            if constexpr (std::is_same_v<T, std::string>) {
                return _request.body().template as<std::string>();
            } else if constexpr (std::is_same_v<T, qb::json>) {
                return _request.body().template as<qb::json>();
            } else {
                return _request.body().template as<qb::json>().template get<T>();
            }
        } catch (...) {
            return std::nullopt;
        }
    }

    // --- Lifecycle Hooks ---
    /**
     * @brief Adds a lifecycle hook function to be called at specific points during request processing.
     * Hooks are executed in the order they are added for a given `HookPoint`.
     * @param hook_fn A `LifecycleHook` function (std::function) to be added. If `hook_fn` is null, it's ignored.
     */
    void
    add_lifecycle_hook(LifecycleHook hook_fn) {
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
    void
    execute_hook(HookPoint point) {
        execute_hook_internal(point);
    }

    // --- Custom Data Management ---
    /**
     * @brief Stores a custom key-value pair in the context. Useful for sharing data between middleware and handlers.
     * The value is stored as `std::any`, allowing for arbitrary types.
     * If the key already exists, its value is overwritten.
     * @tparam T The (deduced) type of the value to store. May be specified explicitly (e.g.
     *            `ctx->set<qb::json>("key", payload)`) to guarantee a specific `std::any` tag.
     * @param key The string key for the custom data.
     * @param value The value to store. Accepted by value so that rvalues are moved into the
     *              `std::any` and lvalues incur a single copy – on par with perfect forwarding
     *              for practical payload sizes while remaining robust against explicit
     *              template-parameter specification.
     */
    template <typename T>
    void
    set(const std::string &key, T value) {
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
    template <typename T>
    [[nodiscard]] std::optional<T>
    get(const std::string &key) const {
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
    template <typename T>
    [[nodiscard]] T *
    get_if(const std::string &key) noexcept {
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
    template <typename T>
    [[nodiscard]] const T *
    get_if(const std::string &key) const noexcept {
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
    [[nodiscard]] bool
    has(const std::string &key) const noexcept {
        return _custom_data.find(key) != _custom_data.end();
    }

    /**
     * @brief Alias of `has()`; provided for STL alignment.
     */
    [[nodiscard]] bool
    contains(const std::string &key) const noexcept {
        return has(key);
    }

    /**
     * @brief Removes custom data associated with the given key from the context.
     * @param key The string key of the custom data to remove.
     * @return `true` if an element was removed, `false` otherwise (e.g., if the key was not found).
     * @note The return value is informational — callers legitimately ignore it when performing
     *       best-effort cleanup; we therefore deliberately do NOT annotate this with `[[nodiscard]]`.
     */
    bool
    remove(const std::string &key) noexcept {
        return _custom_data.erase(key) > 0;
    }

    // --- Typed slot API (F23) -------------------------------------------------
    //
    // Overloads of the string-keyed API that accept a strongly-typed `Slot<T>`
    // instead of a raw string. They share the same underlying `CustomDataMap`
    // so they interoperate transparently with the legacy API:
    //
    //   inline constexpr qb::http::Slot<User> kUser{"auth.user"};
    //   ctx->set(kUser, user);                    // typed
    //   const User* u = ctx->get_if(kUser);       // typed, no any_cast cost footgun
    //   std::optional<User> copy = ctx->get(kUser);
    //   if (ctx->contains(kUser)) { ... }
    //   ctx->remove(kUser);
    //
    // The compile-time type check fires at `set` / `get` sites. Reads stay as
    // fast as the string-keyed `get_if<T>(key)` since `any_cast<T>(&any)` is the
    // same operation &mdash; what you gain is the impossibility of writing
    // `int` and reading `std::size_t` into a silent `nullopt`.

    /**
     * @brief Stores a value under a strongly-typed slot.
     *
     * Equivalent to `set<Slot<T>::value_type>(slot.name, value)` but the
     * declared value type of the slot must match `T` &mdash; passing the
     * wrong type is a compile error.
     *
     * @tparam T Deduced; must be the slot's `value_type`.
     * @param slot  The strongly-typed slot (usually a `constexpr` global).
     * @param value The value to store (moved into the map's `std::any`).
     */
    template <typename T>
    void
    set(const Slot<T> &slot, T value) {
        _custom_data[detail::slot_key_to_string(slot.name)] = std::move(value);
    }

    /**
     * @brief Constructs a value in-place under a strongly-typed slot.
     *
     * Avoids the move that `set()` performs. Useful for non-movable types or
     * to save one relocation for large payloads.
     *
     * @tparam T The slot's `value_type`.
     * @tparam Args The argument types forwarded to `T`'s constructor.
     * @param slot The strongly-typed slot.
     * @param args Constructor arguments for `T`.
     * @return Reference to the newly-constructed value.
     */
    template <typename T, typename... Args>
    T &
    emplace(const Slot<T> &slot, Args &&...args) {
        auto &any_ref = _custom_data[detail::slot_key_to_string(slot.name)];
        any_ref.template emplace<T>(std::forward<Args>(args)...);
        return *std::any_cast<T>(&any_ref);
    }

    /**
     * @brief Retrieves a copy of the value under a strongly-typed slot.
     * @return `std::optional<T>` containing the value if present and
     *         type-compatible; `std::nullopt` otherwise. With typed slots
     *         a `nullopt` return strictly means "slot not set yet" &mdash;
     *         there is no runtime type mismatch path unless the slot key
     *         was also written to via the legacy string API with a
     *         different `T`.
     */
    template <typename T>
    [[nodiscard]] std::optional<T>
    get(const Slot<T> &slot) const {
        auto it = _custom_data.find(detail::slot_key_to_string(slot.name));
        if (it != _custom_data.end()) {
            if (const T *ptr = std::any_cast<T>(&(it->second))) {
                return *ptr;
            }
        }
        return std::nullopt;
    }

    /**
     * @brief Returns a mutable pointer to the value under a typed slot, or
     *        `nullptr` if absent.
     *
     * Preferred over `get()` in the hot path: no copy, no `std::optional`
     * wrapping. Mirrors `std::get_if` semantics.
     */
    template <typename T>
    [[nodiscard]] T *
    get_if(const Slot<T> &slot) noexcept {
        auto it = _custom_data.find(detail::slot_key_to_string(slot.name));
        if (it != _custom_data.end()) {
            return std::any_cast<T>(&(it->second));
        }
        return nullptr;
    }

    /**
     * @brief `get_if` overload returning `const T*`.
     */
    template <typename T>
    [[nodiscard]] const T *
    get_if(const Slot<T> &slot) const noexcept {
        auto it = _custom_data.find(detail::slot_key_to_string(slot.name));
        if (it != _custom_data.end()) {
            return std::any_cast<const T>(&(it->second));
        }
        return nullptr;
    }

    /**
     * @brief Returns the value under the slot, or `fallback` if the slot
     *        is not set (or holds an incompatible type).
     *
     * @tparam T The slot's `value_type`.
     * @tparam U A type convertible to `T` used to produce the fallback.
     *           Defaults to `T` to allow `ctx->get_or(kUser, User{})`.
     */
    template <typename T, typename U = T>
    [[nodiscard]] T
    get_or(const Slot<T> &slot, U &&fallback) const {
        if (const T *ptr = get_if(slot)) {
            return *ptr;
        }
        return static_cast<T>(std::forward<U>(fallback));
    }

    /**
     * @brief Returns whether a value has been stored under the typed slot.
     *
     * Mirrors the semantics of the string-keyed `contains()` but with
     * compile-time checking of the slot name / value type pair. Does not
     * verify the stored type &mdash; it only checks key presence &mdash;
     * so this remains a cheap map lookup.
     */
    template <typename T>
    [[nodiscard]] bool
    contains(const Slot<T> &slot) const noexcept {
        return _custom_data.find(detail::slot_key_to_string(slot.name)) != _custom_data.end();
    }

    /**
     * @brief Removes the value stored under the typed slot.
     * @return `true` if an element was removed.
     */
    template <typename T>
    bool
    remove(const Slot<T> &slot) noexcept {
        return _custom_data.erase(detail::slot_key_to_string(slot.name)) > 0;
    }

    // --- Response Helpers ---

    /**
     * @brief Sets the response for a redirect and finalises the context.
     *
     * Sets the status and `Location` header. Does not force `Content-Length`; if you attach
     * an HTML body for clients that ignore the status, set `_response.body()` (and headers)
     * **before** calling this method. Always calls `complete(AsyncTaskResult::COMPLETE)` —
     * no further headers or body changes apply after this returns.
     *
     * @param url The URL to redirect to.
     * @param status_code The HTTP status code for the redirect (e.g., `qb::http::status::FOUND` (302),
     *                    `qb::http::status::MOVED_PERMANENTLY` (301)). Defaults to `qb::http::status::FOUND`.
     */
    void
    redirect(const std::string &url, qb::http::status status_code = qb::http::status::FOUND) {
        _response.status() = status_code;
        _response.set_header("Location", url);
        complete(AsyncTaskResult::COMPLETE);
    }

    /**
     * @brief Sets the response body to a JSON object and finalises the context.
     *
     * Sets Content-Type to "application/json; charset=utf-8", then calls
     * `complete(AsyncTaskResult::COMPLETE)`. Set all headers first if you need custom fields.
     *
     * @param json_data The qb::json object to send (by-value sink: moved into the body, so a
     *                  temporary is consumed without a copy; an lvalue is copied once as before).
     * @param status_code The HTTP status code. Defaults to 200 OK (`qb::http::status::OK`).
     */
    void
    json(qb::json json_data, qb::http::status status_code = qb::http::status::OK) {
        _response.status() = status_code;
        _response.set_content_type("application/json; charset=utf-8");
        _response.body() = std::move(json_data);
        complete(AsyncTaskResult::COMPLETE);
    }

    /**
     * @brief Sets the response body to a plain text string and finalises the context.
     *
     * Ends with `complete(AsyncTaskResult::COMPLETE)`; add headers before calling.
     *
     * @param text_data The string to send (by-value sink: moved into the body).
     * @param status_code The HTTP status code. Defaults to 200 OK (`qb::http::status::OK`).
     * @param content_type The Content-Type header value. Defaults to "text/plain; charset=utf-8".
     */
    void
    text(std::string text_data, qb::http::status status_code = qb::http::status::OK,
         const std::string &content_type = "text/plain; charset=utf-8") {
        _response.status() = status_code;
        _response.set_content_type(content_type);
        _response.body() = std::move(text_data);
        complete(AsyncTaskResult::COMPLETE);
    }

    /**
     * @brief Sets the response body to an HTML string and finalises the context.
     *
     * Sets Content-Type to "text/html; charset=utf-8", then `complete(AsyncTaskResult::COMPLETE)`.
     *
     * @param html_data The HTML string to send (by-value sink: moved into the body).
     * @param status_code The HTTP status code. Defaults to 200 OK (`qb::http::status::OK`).
     */
    void
    html(std::string html_data, qb::http::status status_code = qb::http::status::OK) {
        _response.status() = status_code;
        _response.set_content_type("text/html; charset=utf-8");
        _response.body() = std::move(html_data);
        complete(AsyncTaskResult::COMPLETE);
    }

    /**
     * @brief Sets the response status to 204 No Content and clears the body.
     * This also removes "Content-Type" and "Content-Length" headers, as they are
     * typically omitted for 204 No Content responses.
     */
    void
    no_content() {
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
    Context<SessionType> &
    status(qb::http::status status_code) {
        _response.status() = status_code;
        return *this;
    }

    /**
     * @brief Sets a 400 Bad Request response.
     * The response body will be plain text.
     * @param error_message The error message for the response body. Defaults to "Bad Request".
     */
    void
    bad_request(const std::string &error_message = "Bad Request") {
        text(error_message, qb::http::status::BAD_REQUEST);
    }

    /**
     * @brief Sets a 401 Unauthorized response.
     * The response body will be plain text.
     * @param error_message The error message for the response body. Defaults to "Unauthorized".
     */
    void
    unauthorized(const std::string &error_message = "Unauthorized") {
        text(error_message, qb::http::status::UNAUTHORIZED);
    }

    /**
     * @brief Sets a 403 Forbidden response.
     * The response body will be plain text.
     * @param error_message The error message for the response body. Defaults to "Forbidden".
     */
    void
    forbidden(const std::string &error_message = "Forbidden") {
        text(error_message, qb::http::status::FORBIDDEN);
    }

    /**
     * @brief Sets a 404 Not Found response.
     * The response body will be plain text.
     * @param error_message The error message for the response body. Defaults to "Not Found".
     */
    void
    not_found(const std::string &error_message = "Not Found") {
        text(error_message, qb::http::status::NOT_FOUND);
    }

    /**
     * @brief Sets a 500 Internal Server Error response.
     * The response body will be plain text.
     * @param error_message The error message for the response body. Defaults to "Internal Server Error".
     */
    void
    internal_server_error(const std::string &error_message = "Internal Server Error") {
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
     * If the context is already finalized (`_lc.state == State::Finalised`) or cancelled (`_lc.is_cancelled` is true),
     * most calls to `complete()` (except with `AsyncTaskResult::CANCELLED`) will be ignored to prevent conflicts.
     * The method also clears the in-flight flag of the current task.
     *
     * @param result The outcome of the current task. Defaults to `AsyncTaskResult::COMPLETE`.
     * @throws Can indirectly lead to exceptions if `finalize_processing_internal()` or subsequent task executions throw,
     *         though this method itself tries to catch exceptions during its switch statement logic and set a 500 error.
     */
    void
    complete(AsyncTaskResult result = AsyncTaskResult::COMPLETE) {
        if (is_finalised_internal() && result != AsyncTaskResult::CANCELLED) {
            return;
        }
        if (_lc.is_cancelled && result != AsyncTaskResult::CANCELLED) {
            if (!is_finalised_internal()) {
                finalize_processing_internal();
            }
            return;
        }

        _lc.task_in_flight = false;
        _lc.last_result    = result;
        ++_lc.completion_count;

        try {
            switch (result) {
                case AsyncTaskResult::CONTINUE:
                    if (_lc.is_cancelled) {
                        finalize_processing_internal();
                        return;
                    }
                    _current_task_index++;
                    proceed_to_next_task_internal();
                    break;

                case AsyncTaskResult::COMPLETE:
                    finalize_processing_internal();
                    break;

                case AsyncTaskResult::CANCELLED:
                    _lc.is_cancelled = true;
                    finalize_processing_internal();
                    break;

                case AsyncTaskResult::FATAL_SPECIAL_HANDLER_ERROR:
                    _response.status() = qb::http::status::INTERNAL_SERVER_ERROR;
                    finalize_processing_internal();
                    break;

                case AsyncTaskResult::ERROR:
                    if (_lc.is_cancelled) {
                        finalize_processing_internal();
                        return;
                    }
                    if (_lc.phase == ProcessingPhase::ERROR_CHAIN) {
                        _response.status() = qb::http::status::INTERNAL_SERVER_ERROR;
                        finalize_processing_internal();
                    } else {
                        auto router_core_shared = _router_core_wptr.lock();
                        if (router_core_shared && router_core_shared->is_error_chain_set()) {
                            auto error_chain_tasks = router_core_shared->get_compiled_error_tasks();
                            if (error_chain_tasks && !error_chain_tasks->empty()) {
                                set_processing_phase(ProcessingPhase::ERROR_CHAIN);
                                _task_chain         = std::move(error_chain_tasks);
                                _current_task_index = 0;
                                proceed_to_next_task_internal();
                            } else {
                                _response.status() = qb::http::status::INTERNAL_SERVER_ERROR;
                                finalize_processing_internal();
                            }
                        } else {
                            _response.status() = qb::http::status::INTERNAL_SERVER_ERROR;
                            finalize_processing_internal();
                        }
                    }
                    break;
            }
        } catch (...) {
            _response.status() = qb::http::status::INTERNAL_SERVER_ERROR;
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
    void
    cancel(const std::string &reason = "Cancelled by application") noexcept {
        if (is_cancelled_or_done_internal()) {
            return;
        }
        _lc.is_cancelled              = true;
        _cancellation_reason_internal = reason;

        if (_lc.task_in_flight && _task_chain && _current_task_index < _task_chain->size()) {
            auto current_task_shared_ptr = (*_task_chain)[_current_task_index];
            if (current_task_shared_ptr) {
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
    [[nodiscard]] bool
    is_cancelled() const noexcept {
        return _lc.is_cancelled;
    }

    /**
     * @brief Checks if the request processing has been fully completed and finalized.
     * @return `true` if the finalization logic has been run (i.e., the context is in
     *         `State::Finalised`), `false` otherwise.
     */
    [[nodiscard]] bool
    is_completed() const noexcept {
        return is_finalised_internal();
    }

    /**
     * @brief Returns the current lifecycle state of the context.
     */
    [[nodiscard]] State
    state() const noexcept {
        return _lc.state;
    }

    /**
     * @brief Marks this context as finalized without invoking the response-sending callback.
     *
     * Use when ownership of the request and/or response has been transferred elsewhere
     * (e.g., during a WebSocket protocol upgrade) so that the Context destructor does not
     * attempt to send a stale or moved-from HTTP response over the original transport.
     *
     * After this call `is_completed()` returns `true` and neither the finalisation
     * callback nor any POST_HANDLER_EXECUTION hooks will be executed.
     */
    void
    suppress_response() noexcept {
        _on_finalized_callback = nullptr;
        _lc.state              = State::Finalised;
        _lc.task_in_flight     = false;
    }

    /**
     * @brief Retrieves the reason for cancellation, if the context was cancelled.
     * @return An `std::optional<std::string>` containing the cancellation reason if `is_cancelled()` is true.
     *         Returns `std::nullopt` if the context has not been cancelled.
     */
    [[nodiscard]] std::optional<std::string>
    cancellation_reason() const noexcept {
        return _cancellation_reason_internal;
    }

    /**
     * @brief Gets the current processing phase of the context.
     * @return The current `ProcessingPhase` (e.g., `NORMAL_CHAIN`, `ERROR_CHAIN`).
     */
    [[nodiscard]] ProcessingPhase
    get_processing_phase() const noexcept {
        return _lc.phase;
    }

    /**
     * @brief Returns the `AsyncTaskResult` reported by the most recently
     *        completed task in the chain.
     *
     * Exposed for instrumentation / testing &mdash; the normal request
     * lifecycle does not need to inspect this value.
     */
    [[nodiscard]] AsyncTaskResult
    last_task_result() const noexcept {
        return _lc.last_result;
    }

    /**
     * @brief Returns how many times `complete()` has been invoked on this context.
     *
     * Intended for advanced adapters (e.g., coroutine wrappers) that need to know
     * whether user code already signaled a completion outcome.
     */
    [[nodiscard]] std::uint64_t
    completion_count() const noexcept {
        return _lc.completion_count;
    }
};
} // namespace qb::http
