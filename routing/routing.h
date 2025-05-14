/**
 * @file routing.h
 * @brief Main convenience include file for the qb::http routing module.
 *
 * This header aggregates all necessary headers for the HTTP routing system,
 * including request/response context, route definitions, router logic,
 * asynchronous operation handlers, and path parameter utilities.
 * Including this single file provides access to all routing components.
 */
#pragma once

#include "./async_completion_handler.h"
#include "./async_types.h"
#include "./context.h"
#include "./path_parameters.h"
#include "./radix_tree.h"
#include "./route_types.h"
#include "./router.h"
#include "./router.tpp" // Template implementations are typically included in headers or main .cpp

// The qb::http namespace encapsulates all HTTP related functionalities.
namespace qb::http {
// This file primarily serves as an aggregate include.
// Specific type re-exports could be added here if desired for a simpler API,
// but currently, users would use types via their full qb::http::TypeName or by including specific headers.
}