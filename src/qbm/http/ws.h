/**
 * @file qbm/http/ws.h
 * @brief Umbrella include for WebSocket support in qbm-http.
 *
 * Include this header when an application wants the complete WebSocket surface:
 * frame/message types, callback clients, CRTP clients, server-side protocol
 * switching helpers, and coroutine adapters. This header only aggregates the
 * WebSocket sub-headers and defines no symbols of its own.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include "./ws/coro.h"
#include "./ws/ws.h"
