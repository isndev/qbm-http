/**
 * @file http/ws.h
 * @brief Umbrella include for WebSocket support in qbm-http.
 *
 * Include this header when an application wants the complete WebSocket surface:
 * frame/message types, callback clients, CRTP clients, server-side protocol
 * switching helpers, and coroutine adapters.
 */
#pragma once

#include "./ws/ws.h"
#include "./ws/coro.h"
