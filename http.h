/**
 * @file qbm/http/http.h
 * @brief Main HTTP module interface for qb-io framework
 *
 * This file provides the main entry point for the comprehensive HTTP module
 * built on top of the qb-io asynchronous framework. It includes:
 *
 * - Complete HTTP/1.1 and HTTP/2 protocol support
 * - Unified interface for both HTTP versions
 * - Request and response handling classes
 * - Asynchronous client and server implementations
 * - High-performance message parsing and processing
 * - Content compression and decompression support
 * - Cookie management and multipart form handling
 * - Customizable routing and middleware support
 * - SSL/TLS support for secure connections
 *
 * The module is designed for high performance and seamless integration with
 * the qb-io asynchronous I/O layer, supporting both HTTP/1.1 and HTTP/2
 * protocols with a unified API.
 *
 * @code
 * // Include both HTTP/1.1 and HTTP/2 support
 * #include <qbm/http/http.h>
 * 
 * // Use HTTP/1.1 server
 * auto http1_server = qb::http::make_server();
 * 
 * // Use HTTP/2 server  
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
#include "./2/http2.h"
#endif // QB_MODULE_HTTP_H_
