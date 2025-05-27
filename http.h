/**
 * @file qbm/http/http.h
 * @brief Main include file for the QB HTTP client and server module.
 *
 * This header aggregates all core components of the qb-http module, providing a comprehensive
 * suite for HTTP/1.1 communication. It defines foundational classes for requests (`qb::http::Request`),
 * responses (`qb::http::Response`), message parsing (`qb::http::Parser`), asynchronous client
 * operations (`qb::http::async`), protocol handlers (`qb::protocol::http_server`, `qb::protocol::http_client`),
 * and server-side routing (`qb::http::Router`).
 *
 * The module is designed for high performance and integration with the qb-io asynchronous
 * I/O layer, leveraging libev for event handling. It supports features like content
 * compression, cookie management, multipart forms, and customizable routing.
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
