#pragma once

// Main include file for the new QB HTTP Routing system.
// Include this file to get access to all routing components.

#include "./routing/types.h"
#include "./routing/async_task.h"
#include "./routing/context.h"
#include "./routing/middleware.h"
#include "./routing/handler_node.h"
#include "./routing/route.h"
#include "./routing/route_group.h"
#include "./routing/controller.h"
#include "./routing/router.h"

// Note: RadixTree.h and RouterCore.h are internal and typically not directly included by users. 