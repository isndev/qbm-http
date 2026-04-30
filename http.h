/**
 * @file qbm/http/http.h
 * @brief Main HTTP module interface for qb-io framework
 *
 * This file provides the main entry point for the comprehensive HTTP module
 * built on top of the qb-io asynchronous framework. It includes:
 *
 * - Complete HTTP/1.1 support
 * - HTTP/2 protocol support when SSL/ALPN is available
 * - Optional HTTP/3 support when SSL, QUIC and nghttp3 are available
 * - RFC 6455 WebSocket support via `qb::http::ws` when crypto is available
 * - Unified request/response foundations across supported protocols
 * - Request and response handling classes
 * - Asynchronous client and server implementations
 * - High-performance message parsing and processing
 * - Content compression and decompression support
 * - Cookie management and multipart form handling
 * - Customizable routing and middleware support
 * - SSL/TLS support for secure connections
 *
 * The module is designed for high performance and seamless integration with
 * the qb-io asynchronous I/O layer, supporting HTTP/1.1 and optional
 * SSL-backed protocols with a coherent API.
 *
 * @code
 * // Include HTTP/1.1 and optional SSL-backed protocol support
 * #include <http/http.h>
 *
 * // Use HTTP/1.1 server
 * auto http1_server = qb::http::make_server();
 *
 * // Use HTTP/2 server when QB_HAS_SSL is enabled
 * auto http2_server = qb::http2::make_server();
 * @endcode
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#ifndef QB_MODULE_HTTP_H_
#define QB_MODULE_HTTP_H_
#include "./1.1/http.h"
#include "./1.1/client.h"
#ifdef QB_HAS_SSL
#include "./2/http2.h"
#include "./ws/ws.h"
#endif
#ifdef QBM_HTTP_HAS_HTTP3
#include "./3/http3.h"
#include "./3/client.h"
#include "./3/dual_stack.h"
#endif
#endif // QB_MODULE_HTTP_H_
