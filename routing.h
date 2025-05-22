/**
 * @file qbm/http/routing.h
 * @brief Main convenience header for the QB HTTP Routing system.
 *
 * This header serves as a single include point for all essential public components
 * of the qb-http routing module. By including this file, users gain access to
 * core routing elements such as `Router`, `RouteGroup`, `Controller`, `Context`,
 * `IMiddleware`, `IAsyncTask`, and various routing-specific types.
 *
 * Internal components like `RadixTree` or `RouterCore` are typically not included
 * directly through this header as they are not part of the primary public API for defining routes.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

// This file is the primary entry point for users of the QB HTTP Routing system.
// It includes all necessary public headers for defining and managing HTTP routes,
// middleware, controllers, and request processing contexts.

// Core types and interfaces for the routing system
#include "./routing/types.h"         // Basic types, enums (HookPoint, AsyncTaskResult), function signatures (RouteHandlerFn).


#include "./routing/async_task.h"    // IAsyncTask interface for tasks in the processing chain.
#include "./routing/context.h"       // Context object for request/response lifecycle management.
#include "./routing/middleware.h"    // IMiddleware interface and MiddlewareTask adapter.
#include "./routing/path_parameters.h" // PathParameters class for extracted route parameters.

// Building blocks for route definitions
#include "./routing/handler_node.h"  // IHandlerNode base class for routes, groups, controllers.
#include "./routing/route.h"         // Route class for defining specific endpoints.
#include "./routing/custom_route.h"  // ICustomRoute interface for advanced route handlers.
#include "./routing/route_group.h"   // RouteGroup for organizing routes under common prefixes/middleware.
#include "./routing/controller.h"    // Controller base class for grouping related routes.

// Main router class
#include "./routing/router.h"        // The main Router class for defining the routing tree.

// Note: Internal implementation details such as RadixTree.h (the routing tree algorithm)
// and RouterCore.h (the router's internal logic engine) are not exposed through this
// main include file as they are not typically interacted with directly by users.

/**
 * @namespace qb::http
 * @brief Main namespace for QB HTTP functionalities.
 * The routing system components are typically defined within `qb::http` or the
 * nested `qb::http::routing` namespace (though specific types might be directly in `qb::http`).
 */
namespace qb::http {
    // This convenience header primarily includes other headers.
    // No specific declarations or definitions are typically placed directly in routing.h itself.

    /**
     * @namespace qb::http::routing
     * @brief Contains core components and types specific to the HTTP routing system.
     * This namespace is not explicitly opened here but is documented as many included
     * files will declare types within it.
     */
} // namespace qb::http 
