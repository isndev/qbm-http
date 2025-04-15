#pragma once

#include "./routing/async_completion_handler.h"
#include "./routing/async_types.h"
#include "./routing/context.h"
#include "./routing/cors_options.h"
#include "./routing/path_parameters.h"
#include "./routing/radix_tree.h"
#include "./routing/route_types.h"
#include "./routing/router.h"
#include "./routing/router.tpp"

// This is the main include file for all routing-related types
namespace qb::http {
// Re-export all types
}