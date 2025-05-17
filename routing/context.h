#pragma once

#include <memory>
#include <string>
#include <vector>
#include <any>
#include <functional>
#include <stdexcept>
#include <iostream> // For temporary logging
#include <optional>
#include <map>

#include "../request.h"
#include "../response.h"
#include "./path_parameters.h"
#include "./types.h" // For HookPoint, AsyncTaskResult
#include "./async_task.h" // For IAsyncTask

// Forward declaration for RouterCore
namespace qb::http { 
template <typename SessionType> class RouterCore; 
}

namespace qb::http {

/**
 * @brief Encapsulates all information about a single HTTP request and its processing state.
 *
 * The Context object is passed through the entire chain of tasks (middleware and handlers)
 * and provides access to the request, response, session, and other relevant data.
 * It also manages lifecycle hooks.
 */
template <typename SessionType>
class Context : public std::enable_shared_from_this<Context<SessionType>> {
public:
    enum class ProcessingPhase {
        INITIAL,          // Before any main chain starts or for standalone contexts not tied to a chain
        NORMAL_CHAIN,     // Executing the primary request task chain
        NOT_FOUND_CHAIN,  // Executing the "not found" task chain
        ERROR_CHAIN       // Executing the main error handling task chain
    };

    using LifecycleHook = std::function<void(Context<SessionType>&, HookPoint)>;
    using CustomDataMap = qb::unordered_map<std::string, std::any>;

    // New static logging utility
    static void log_task_chain_snapshot(
        const std::vector<std::shared_ptr<IAsyncTask<SessionType>>>& chain,
        const std::string& chain_description,
        std::optional<size_t> current_task_idx_opt = std::nullopt
    ) {
        std::cerr << "Context Log: Task Chain Snapshot for '" << chain_description << "':" << std::endl;
        if (chain.empty()) {
            std::cerr << "  (empty)" << std::endl;
            return;
        }
        for (size_t i = 0; i < chain.size(); ++i) {
            const auto& task = chain[i];
            std::string task_name = "Unknown/Null Task";
            if (task) {
                try {
                    task_name = task->name();
                } catch (const std::exception& e) {
                    task_name = "Error getting task name";
                }
            }
            
            std::string current_marker;
            if (current_task_idx_opt && current_task_idx_opt.value() == i) {
                current_marker = " (current/next to execute)";
            }
            std::cerr << "  [" << i << "] " << task_name << current_marker << std::endl;
        }
    }

private:
    Request _request;
    Response _response;
    std::shared_ptr<SessionType> _session;
    PathParameters _path_parameters;
    std::vector<LifecycleHook> _lifecycle_hooks;
    CustomDataMap _custom_data;
    std::optional<std::string> _cancellation_reason_internal;

    std::vector<std::shared_ptr<IAsyncTask<SessionType>>> _task_chain;
    size_t _current_task_index = 0;
    bool _is_cancelled = false;
    bool _is_completed = false;

    std::function<void(Context<SessionType>&)> _on_finalized_callback;
    std::weak_ptr<RouterCore<SessionType>> _router_core_wptr;
    ProcessingPhase _current_processing_phase = ProcessingPhase::INITIAL;
    AsyncTaskResult _current_task_result = AsyncTaskResult::COMPLETE; // Stores the result of the task that just finished
    bool _finalize_called = false; // Guard for finalize_processing()

public:
    /**
     * @brief Executes lifecycle hooks for a given point.
     * This is now public to be callable by RouterCore.
     */
    void execute_hook(HookPoint point) {
        for (const auto& hook : _lifecycle_hooks) {
            try {
                hook(*this, point);
            } catch (const std::exception& e) {
                std::cerr << "Context: Exception in lifecycle hook: " << e.what() << std::endl;
            }
        }
    }
    
    void finalize_processing() {
        if (_finalize_called) { // Guard against re-entry
            std::cerr << "Context::finalize_processing: Already called. Returning." << std::endl;
            return;
        }
        _finalize_called = true; // Mark that finalization has started
        _is_completed = true;    // Signify that the context's lifecycle is now definitely over.
        
        std::cerr << "Context::finalize_processing: EXECUTING. Session: " << _session.get() 
                  << ", Request: " << _request.uri().path() << std::endl;

        execute_hook(HookPoint::POST_HANDLER_EXECUTION);

        if (_on_finalized_callback) {
            try {
                _on_finalized_callback(*this);
            } catch (const std::exception& e) {
                 std::cerr << "Context: Exception in _on_finalized_callback: " << e.what() << std::endl;
            }
        }
    }

public:
    /**
     * @brief Constructor for Context.
     * @param session The client session.
     * @param request The HTTP request (moved into context).
     */
    Context(Request request,
            Response response_prototype,
            std::shared_ptr<SessionType> session,
            std::function<void(Context<SessionType>&)> on_finalized_callback,
            std::weak_ptr<RouterCore<SessionType>> router_core_wptr)
        : _request(std::move(request)),
          _response(std::move(response_prototype)),
          _session(std::move(session)),
          _on_finalized_callback(std::move(on_finalized_callback)),
          _router_core_wptr(router_core_wptr) {
        // execute_hook(HookPoint::PRE_ROUTING); // Moved to RouterCore before matching
    }

    ~Context() {
        if (!_finalize_called) {
             std::cerr << "Context Destructor: Finalizing because _finalize_called is false. IsCancelled: " << _is_cancelled << ", IsCompleted (before this finalize): " << _is_completed << std::endl;
             finalize_processing();
        }
        execute_hook(qb::http::HookPoint::REQUEST_COMPLETE);
    }

    /**
     * @brief Get a reference to the HTTP request.
     */
    Request& request() { return _request; }
    const Request& request() const { return _request; }

    /**
     * @brief Get a reference to the HTTP response.
     */
    Response& response() { return _response; }
    const Response& response() const { return _response; }

    /**
     * @brief Get a shared pointer to the session.
     */
    std::shared_ptr<SessionType> session() { return _session; }
    std::shared_ptr<const SessionType> session() const { return _session; }

    /**
     * @brief Get a reference to the path parameters.
     */
    PathParameters& path_parameters() { return _path_parameters; }
    const PathParameters& path_parameters() const { return _path_parameters; }

    /**
     * @brief Get a specific path parameter by name.
     * @param name The name of the parameter.
     * @param not_found The value to return if the parameter is not found.
     * @return The parameter's value as a string, or the not_found value.
     */
    std::string path_param(const std::string& name, const std::string& not_found = "") const {
        auto value_opt = _path_parameters.get(name);
        if (value_opt) {
            return std::string(value_opt.value());
        }
        return not_found;
    }

    /**
     * @brief Sets the path parameters (typically done by the RadixTree/Matcher).
     */
    void set_path_parameters(PathParameters params) {
        _path_parameters = std::move(params);
    }

    /**
     * @brief Adds a hook to a specific point in the request lifecycle.
     * @param point The lifecycle point to attach the hook to.
     * @param hook_fn The function to execute at the hook point.
     */
    void add_lifecycle_hook(LifecycleHook hook) {
        _lifecycle_hooks.push_back(std::move(hook));
    }

    /**
     * @brief Stores custom data associated with a key.
     * Useful for passing data between middleware and handlers.
     * @tparam T The type of the data to store.
     * @param key The key to associate the data with.
     * @param value The data to store.
     */
    template <typename T>
    void set(const std::string& key, T value) {
        _custom_data[key] = std::move(value);
    }

    /**
     * @brief Retrieves custom data associated with a key.
     * @tparam T The type of the data to retrieve.
     * @param key The key of the data to retrieve.
     * @return An optional containing the data if found and type matches, otherwise std::nullopt.
     */
    template <typename T>
    std::optional<T> get(const std::string& key) {
        auto it = _custom_data.find(key);
        if (it != _custom_data.end()) {
            try {
                return std::any_cast<T>(it->second);
            } catch (const std::bad_any_cast& e) {
                std::cerr << "Context::get: Bad any_cast for key '" << key << "'. " << e.what() << std::endl;
                return std::nullopt;
            }
        }
        return std::nullopt;
    }

    /**
     * @brief Retrieves custom data associated with a key, as a pointer.
     * Useful for types that should not be copied or for checking existence.
     * @tparam T The type of the data to retrieve.
     * @param key The key of the data to retrieve.
     * @return A pointer to the data if found and type matches, otherwise nullptr.
     */
    template <typename T>
    T* get_ptr(const std::string& key) {
        auto it = _custom_data.find(key);
        if (it != _custom_data.end()) {
            return std::any_cast<T>(&it->second);
        }
        return nullptr;
    }

    /**
     * @brief Checks if custom data exists for a given key.
     * @param key The key to check.
     * @return True if data exists for the key, false otherwise.
     */
    bool has(const std::string& key) const {
        return _custom_data.count(key);
    }

    /**
     * @brief Removes custom data associated with a key.
     * @param key The key of the data to remove.
     * @return True if data was found and removed, false otherwise.
     */
    bool remove(const std::string& key) {
        return _custom_data.erase(key) > 0;
    }

    /**
     * @brief Sets the task chain and starts processing.
     * @param chain The task chain to set and start.
     */
    void set_task_chain_and_start(std::vector<std::shared_ptr<IAsyncTask<SessionType>>> chain) {
        if (_is_completed || _is_cancelled) {
            std::cerr << "Context::set_task_chain_and_start: Called on already completed or cancelled context. Ignoring." << std::endl;
            return;
        }
        _task_chain = std::move(chain);
        _current_task_index = 0;

        if (_task_chain.empty()) {
            std::cerr << "Context::set_task_chain_and_start: Chain is empty, completing context." << std::endl;
            // If the chain is empty from the start, it implies a no-op or a direct 404 if not handled by RadixTree.
            // However, RadixTree should provide _compiled_not_found_tasks if no match.
            // This complete() might result in 200 OK if response wasn't touched, or 404 if it was.
            complete(AsyncTaskResult::COMPLETE); 
            return;
        }
        proceed_to_next_task();
    }

public: // Public API for tasks
    /**
     * @brief Signals that the current asynchronous task has finished processing.
     *
     * This method is called by IAsyncTask instances (or wrappers around them)
     * to indicate their outcome. The Context then decides what to do next:
     * - Proceed to the next task in the chain (if AsyncTaskResult::CONTINUE).
     * - Finalize the request (if AsyncTaskResult::COMPLETE or AsyncTaskResult::CANCELLED).
     * - Attempt to execute an error handling chain (if AsyncTaskResult::ERROR).
     *
     * @param result The outcome of the asynchronous task.
     */
    void complete(AsyncTaskResult result = AsyncTaskResult::COMPLETE) {
        std::cerr << "Context::complete ENTRY - Result: " << static_cast<int>(result)
                  << ", CurrentPhase: " << static_cast<int>(_current_processing_phase)
                  << ", IsCancelled: " << _is_cancelled
                  << ", IsCompleted: " << _is_completed // IsCompleted refers to overall completion (finalize_called)
                  << ", FinalizeCalled: " << _finalize_called
                  << ", CurrentTaskIdx (at entry): " << _current_task_index // Log _current_task_index at entry
                  << ", TaskChainSize: " << _task_chain.size() << std::endl;

        if (_finalize_called && result != AsyncTaskResult::CANCELLED) { 
             std::cerr << "Context::complete: Already completed. Ignoring result: " << static_cast<int>(result) << std::endl;
            return;
        }
        if (_is_cancelled && result != AsyncTaskResult::CANCELLED) {
            std::cerr << "Context::complete: Cancelled, but received non-CANCELLED result: " << static_cast<int>(result) << ". Prioritizing cancellation." << std::endl;
            // If already cancelled, we should only be processing an AsyncTaskResult::CANCELLED to finalize.
            // Any other result at this point is likely a late-arriving task completion after cancellation took effect.
            // We ensure finalization happens based on the cancellation state.
            if (!_is_completed) { // Finalize if not already done by the cancel path
                finalize_processing();
            }
            return;
        }

        // Mark the current task (if any) as no longer being processed for cancellation purposes
        if (!_task_chain.empty() && _current_task_index < _task_chain.size()) {
            auto current_task_ptr = _task_chain[_current_task_index];
            if(current_task_ptr) {
                 current_task_ptr->is_being_processed = false;
                 std::cerr << "Context::complete: Marked task '" << current_task_ptr->name() << "' at index " << _current_task_index << " as no longer processed." << std::endl;
            }
        }

        _current_task_result = result; // Store the result from the current task
        std::cerr << "Context::complete: Stored _current_task_result = " << static_cast<int>(_current_task_result) << std::endl;

        try {
            switch (result) {
                case AsyncTaskResult::CONTINUE:
                    if (_is_cancelled) {
                        std::cerr << "Context::complete: CONTINUE received but context is cancelled. Finalizing. CurrentTaskIdx: " << _current_task_index << std::endl;
                        finalize_processing();
                        return;
                    }
                    std::cerr << "Context::complete: CONTINUE received. Old _current_task_index: " << _current_task_index << std::endl;
                    _current_task_index++;
                    std::cerr << "Context::complete: CONTINUE. New _current_task_index: " << _current_task_index << ". Calling proceed_to_next_task." << std::endl;
                    proceed_to_next_task();
                    break;

                case AsyncTaskResult::COMPLETE:
                    std::cerr << "Context::complete: COMPLETE received. Calling finalize_processing. CurrentTaskIdx: " << _current_task_index << std::endl;
                    finalize_processing();
                    break;

                case AsyncTaskResult::CANCELLED:
                    _is_cancelled = true; 
                    std::cerr << "Context::complete: CANCELLED received. Calling finalize_processing. CurrentTaskIdx: " << _current_task_index << std::endl;
                    finalize_processing();
                    break;

                case AsyncTaskResult::FATAL_SPECIAL_HANDLER_ERROR:
                    std::cerr << "Context::complete: FATAL_SPECIAL_HANDLER_ERROR received. Finalizing with 500. CurrentTaskIdx: " << _current_task_index << std::endl;
                    _response.status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
                    finalize_processing();
                    break;

                case AsyncTaskResult::ERROR:
                    std::cerr << "Context::complete: ERROR received. CurrentPhase: " 
                              << static_cast<int>(_current_processing_phase) << std::endl;

                    if (_is_cancelled) {
                        std::cerr << "Context::complete: ERROR received but context is cancelled. Prioritizing cancellation. Finalizing." << std::endl;
                        finalize_processing(); // Finalize with cancellation status
                        return;
        }

                    if (_current_processing_phase == ProcessingPhase::ERROR_CHAIN) { // Error in error chain is fatal
                        std::cerr << "Context::complete: ERROR while already in ERROR_CHAIN. Finalizing with 500. CurrentTaskIdx: " << _current_task_index << std::endl;
                        _response.status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
                        finalize_processing();
                    } else { // INITIAL, NORMAL_CHAIN, or NOT_FOUND_CHAIN - attempt to use main error chain
                        if (_current_processing_phase == ProcessingPhase::NOT_FOUND_CHAIN) {
                             std::cerr << "Context::complete: ERROR in NOT_FOUND_CHAIN. Attempting to switch to user-defined error chain." << std::endl;
                        } else { // INITIAL or NORMAL_CHAIN
                             std::cerr << "Context::complete: ERROR in INITIAL/NORMAL_CHAIN. Attempting to switch to user-defined error chain." << std::endl;
                        }
                        auto router_core_shared = _router_core_wptr.lock();
                        if (router_core_shared) {
                            auto error_chain_tasks = router_core_shared->get_compiled_error_tasks();
                            if (!error_chain_tasks.empty()) {
                                set_processing_phase(ProcessingPhase::ERROR_CHAIN);
                                
                                std::vector<std::shared_ptr<IAsyncTask<SessionType>>> error_chain_vec;
                                std::copy(error_chain_tasks.begin(), error_chain_tasks.end(), std::back_inserter(error_chain_vec));
                                
                                log_task_chain_snapshot(error_chain_vec, "User-Defined Error Handling Chain", 0);
                                
                                std::cerr << "Context::complete: ERROR. Switching to user-defined error chain. Old _current_task_index: " << _current_task_index << std::endl;
                                _task_chain = std::move(error_chain_vec);
                                _current_task_index = 0;
                                std::cerr << "Context::complete: ERROR. New _current_task_index: " << _current_task_index << ". Calling proceed_to_next_task." << std::endl;
                                proceed_to_next_task();
                            } else {
                                std::cerr << "Context::complete: Main error chain is set/retrieved but is empty. Finalizing with 500. CurrentTaskIdx: " << _current_task_index << std::endl;
                                _response.status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
                                finalize_processing();
                            }
                        } else {
                            std::cerr << "Context::complete: RouterCore weak_ptr expired. Cannot use error chain. Finalizing with 500." << std::endl;
                            _response.status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
                            finalize_processing();
                        }
                    }
                    break;
            }
        } catch (const std::exception& e) {
            std::cerr << "Context::complete: Exception during task completion/next task execution: " << e.what() 
                      << ". CurrentPhase: " << static_cast<int>(_current_processing_phase) << std::endl;
            
            if (_is_cancelled) {
                std::cerr << "Context::complete: Exception occurred but context is cancelled. Finalizing." << std::endl;
                finalize_processing();
            } else if (_current_processing_phase == ProcessingPhase::ERROR_CHAIN) { // Exception in error chain is fatal
                std::cerr << "Context::complete: Exception occurred while in ERROR_CHAIN. Finalizing with 500." << std::endl;
                _response.status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
                finalize_processing();
            } else { // INITIAL, NORMAL_CHAIN, or NOT_FOUND_CHAIN during exception - attempt to use main error chain
                 if (_current_processing_phase == ProcessingPhase::NOT_FOUND_CHAIN) {
                    std::cerr << "Context::complete: Exception occurred in NOT_FOUND_CHAIN. Attempting to switch to error chain." << std::endl;
                 } else { // INITIAL or NORMAL_CHAIN
                    std::cerr << "Context::complete: Exception occurred in INITIAL/NORMAL_CHAIN. Attempting to switch to error chain." << std::endl;
                 }
                 _response.status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR; // Set a default error status before trying error chain
                auto router_core_shared = _router_core_wptr.lock();
                if (router_core_shared) {
                    auto error_chain_tasks = router_core_shared->get_compiled_error_tasks();
                     if (!error_chain_tasks.empty()) {
                        set_processing_phase(ProcessingPhase::ERROR_CHAIN);
                        std::vector<std::shared_ptr<IAsyncTask<SessionType>>> error_chain_vec;
                        std::copy(error_chain_tasks.begin(), error_chain_tasks.end(), std::back_inserter(error_chain_vec));
                        log_task_chain_snapshot(error_chain_vec, "User-Defined Error Handling Chain (due to exception)", 0);
                        std::cerr << "Context::complete: Exception handling. Switching to user-defined error chain. Old _current_task_index: " << _current_task_index << std::endl;
                        _task_chain = std::move(error_chain_vec);
                        _current_task_index = 0;
                        std::cerr << "Context::complete: Exception handling. New _current_task_index: " << _current_task_index << ". Calling proceed_to_next_task." << std::endl;
                        proceed_to_next_task();
                    } else {
                        std::cerr << "Context::complete: Error chain (due to exception) is set but empty. Finalizing. CurrentTaskIdx: " << _current_task_index << std::endl;
                        finalize_processing(); // Finalize with the status set before (INTERNAL_SERVER_ERROR)
                    }
                } else {
                     std::cerr << "Context::complete: RouterCore weak_ptr expired (due to exception). Finalizing." << std::endl;
                    finalize_processing(); // Finalize with the status set before (INTERNAL_SERVER_ERROR)
                }
            }
        }
        std::cerr << "Context::complete EXIT" << std::endl;
    }

    /**
     * @brief Cancels the current request processing.
     *
     * Marks the context as cancelled, notifies the currently executing task (if any),
     * and typically sets an appropriate response status. This will also prevent
     * further tasks in the main chain from executing and trigger finalization.
     * The error handling chain is NOT invoked by a direct cancellation.
     *
     * @param reason A description of why cancellation occurred.
     */
    void cancel(const std::string& reason = "Cancelled by application") {
        std::cerr << "Context::cancel ENTRY - Reason: " << reason 
                  << ", IsCancelled: " << _is_cancelled
                  << ", IsCompleted: " << _is_completed 
                  << ", CurrentTaskIdx: " << _current_task_index << std::endl;

        if (_is_cancelled || _is_completed) {
            std::cerr << "Context::cancel: Already cancelled or completed. Ignoring." << std::endl;
            return;
        }
        _is_cancelled = true;
        _cancellation_reason_internal = reason;

        // Notify the current task if it's still marked as being processed
        if (!_task_chain.empty() && _current_task_index < _task_chain.size()) {
            auto current_task_shared_ptr = _task_chain[_current_task_index];
            if (current_task_shared_ptr && current_task_shared_ptr->is_being_processed) {
                try {
                    std::cerr << "Context::cancel: Notifying task '" << current_task_shared_ptr->name() << "' to cancel." << std::endl;
                    current_task_shared_ptr->cancel(); 
                } catch (const std::exception& e) {
                    std::cerr << "Context::cancel: Exception during task's cancel() method: " << e.what() << std::endl;
    }
            }
        }

        _response.status_code = HTTP_STATUS_SERVICE_UNAVAILABLE; // Default for cancellation
        // Consider making this configurable or based on the type of cancellation.

        std::cerr << "Context::cancel: Calling complete(CANCELLED). IsCancelled: " << _is_cancelled << ", IsCompleted: " << _is_completed << std::endl;
        this->complete(AsyncTaskResult::CANCELLED);
        std::cerr << "Context::cancel EXIT. IsCancelled: " << _is_cancelled << ", IsCompleted: " << _is_completed << std::endl;
    }

    bool is_cancelled() const {
        return _is_cancelled;
    }
    
    bool is_completed() const {
        return _is_completed;
    }

    std::optional<std::string> cancellation_reason() const {
        return _cancellation_reason_internal;
    }

    // Method to explicitly set the processing phase, e.g., by RouterCore
    void set_processing_phase(ProcessingPhase new_phase) {
        std::cerr << "Context::set_processing_phase: Transitioning from " 
                  << static_cast<int>(_current_processing_phase) 
                  << " to " << static_cast<int>(new_phase) << std::endl;
        _current_processing_phase = new_phase;
    }

public: // Ensuring this section is public or continuing a public one
    void proceed_to_next_task() {
        std::cerr << "Context::proceed_to_next_task ENTRY. CurrentTaskIdx: " << _current_task_index
                  << ", TaskChainSize: " << _task_chain.size() 
                  << ", IsCancelled: " << _is_cancelled 
                  << ", IsCompleted: " << _is_completed << std::endl;

        if (_is_cancelled || _is_completed) {
            std::cerr << "Context::proceed_to_next_task: Cancelled or already completed. Finalizing. CurrentTaskIdx: " << _current_task_index << std::endl;
            if (!_is_completed) finalize_processing(); // Ensure finalization if not already done
            return;
        }

        if (_current_task_index < _task_chain.size()) {
            auto task_to_execute = _task_chain[_current_task_index];
            if (task_to_execute) {
                std::cerr << "Context::proceed_to_next_task: Executing task '" << task_to_execute->name()
                          << "' at index " << _current_task_index << std::endl;
                task_to_execute->is_being_processed = true;
                try {
                    task_to_execute->execute(this->shared_from_this());
                } catch (const std::exception& e) {
                    std::cerr << "Context::proceed_to_next_task: Exception during task->execute() for '" 
                              << task_to_execute->name() << "': " << e.what() << std::endl;
                    // Mark as not processed before calling complete, as complete() will do it for the *next* index if error leads to chain switch
                    task_to_execute->is_being_processed = false; 
                    std::cerr << "Context::proceed_to_next_task: Exception. Calling complete(ERROR). CurrentTaskIdx: " << _current_task_index << std::endl;
                    this->complete(AsyncTaskResult::ERROR);
                } catch (...) {
                    std::cerr << "Context::proceed_to_next_task: Unknown exception during task->execute() for '" 
                              << task_to_execute->name() << "'." << std::endl;
                    task_to_execute->is_being_processed = false;
                    std::cerr << "Context::proceed_to_next_task: Unknown exception. Calling complete(ERROR). CurrentTaskIdx: " << _current_task_index << std::endl;
                    this->complete(AsyncTaskResult::ERROR);
                }
            } else {
                std::cerr << "Context::proceed_to_next_task: Null task found at index " << _current_task_index << ". Skipping." << std::endl;
                _current_task_index++; // Skip null task
                std::cerr << "Context::proceed_to_next_task: Null task. New _current_task_index: " << _current_task_index << ". Calling proceed_to_next_task (recursive)." << std::endl;
                proceed_to_next_task(); // Try next
            }
        } else {
            std::cerr << "Context::proceed_to_next_task: Task chain exhausted. CurrentTaskIdx: " << _current_task_index << ". Finalizing." << std::endl;
            // If we were in an error chain and it finished, finalize.
            // If it was a normal chain, this also means successful completion.
            finalize_processing();
        }
        std::cerr << "Context::proceed_to_next_task EXIT. CurrentTaskIdx: " << _current_task_index << std::endl;
    }
}; // End of class Context<SessionType>

} // namespace qb::http 