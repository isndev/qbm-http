#pragma once

#include "./async_task.h"
#include "./context.h" // For Context type, though not directly used in interface methods
#include <list>
#include <memory>
#include <string>

namespace qb::http {

/**
 * @brief Interface for a custom route handler.
 * Allows for more complex, stateful, or class-based route handling logic compared to a simple lambda.
 * The custom route is responsible for the entire response generation for its matched path.
 */
template <typename SessionType>
class ICustomRoute {
public:
    virtual ~ICustomRoute() = default;

    /**
     * @brief Handles the request for this custom route.
     * @param ctx The shared context for the request. The handler must call ctx->complete()
     *            when its processing is done.
     */
    virtual void process(std::shared_ptr<Context<SessionType>> ctx) = 0;

    /**
     * @brief Gets a descriptive name for the custom route (for logging/debugging).
     * @return The name of the custom route.
     */
    virtual std::string name() const = 0;

    /**
     * @brief Called if the context associated with this custom route execution is cancelled.
     * The route should attempt to gracefully terminate any ongoing operations.
     */
    virtual void cancel() = 0;
};

} // namespace qb::http 