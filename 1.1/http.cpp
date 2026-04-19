/**
 * @file qbm/http/1.1/http.cpp
 * @brief HTTP/1.1 server explicit template instantiation.
 *
 * The previously hosted synchronous client helpers
 * (`qb::http::GET/POST/PUT/...` returning `Response`) have been removed.
 * They are replaced by coroutine-returning overloads declared inline in
 * `qbm/http/1.1/http.h`, which consume the callback-based
 * `qb::http::async::*` API and yield `qb::http::async::Reply`.
 *
 * See `qbm/http/coro.h` and `qbm/http/readme/14b-coroutine-api.md` for the
 * full contract and migration guide.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include "../http.h"

namespace qb::http {
    template class Server<DefaultSession>;
} // namespace qb::http
