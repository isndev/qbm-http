#pragma once

#include <memory>
#include <string>

namespace qb { namespace http {

/**
 * @brief Interface for an asynchronous task in the request processing chain.
 *
 * Each task (middleware, main handler) in the request lifecycle will implement
 * this interface. Tasks are executed sequentially.
 */
template <typename SessionType>
class IAsyncTask {
public:
    virtual ~IAsyncTask() = default;

    /**
     * @brief Executes the asynchronous task.
     * The implementation is responsible for performing its work and then calling
     * ctx->complete() to signal completion and allow the request processing chain to continue.
     * If the task initiates a truly asynchronous operation (e.g., network call, DB query),
     * it should capture the 'ctx' (e.g., in a lambda) and call ctx->complete() from the
     * callback of that asynchronous operation.
     * @param ctx The shared context for this request.
     */
    virtual void execute(std::shared_ptr<Context<SessionType>> ctx) = 0;

    /**
     * @brief Called if the context associated with this task is cancelled.
     * The task should attempt to gracefully terminate any ongoing operations.
     * This method might be called from a different thread than execute().
     * The task should not call ctx->complete() from here, as the context
     * is already handling the cancellation and finalization process.
     */
    virtual void cancel() = 0;

    /**
     * @brief Gets a descriptive name for the task (for logging/debugging).
     * @return The name of the task.
     */
    virtual std::string name() const = 0;

    // Flag to indicate if the Context is currently processing this task.
    // Managed by the Context itself.
    bool is_being_processed = false;
};

}} // namespace qb::http 