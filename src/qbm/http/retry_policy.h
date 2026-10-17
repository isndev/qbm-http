/**
 * @file qbm/http/retry_policy.h
 * @brief The reconnection backoff policy of the qbm-http clients: qb-io's shared `reconnect_policy`.
 *
 * `qb::http::RetryPolicy` is `qb::io::reconnect_policy` (`qb/io/reconnect.h`), the one policy every
 * qb client that reconnects follows -- the same type as `qb::redis::RetryPolicy`. Attempt 1 is
 * immediate, attempt 2 waits `initial_delay`, every further attempt multiplies the wait by
 * `multiplier` up to `max_delay`, each wait jittered by up to a quarter either way when `jitter` is
 * on, `max_attempts` bounds the run (-1 = unlimited), and `on_retry(attempt, next_delay)` is told,
 * before each wait, how many attempts failed and how long the wait will be. The HTTP/2 client's
 * attempts keep the deadline its own `set_connect_timeout()` sets.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <qb/io/reconnect.h>

namespace qb::http {

/// The reconnection backoff of the qbm-http clients (Huly QB-103): qb-io's `qb::io::reconnect_policy`.
using RetryPolicy = qb::io::reconnect_policy;

} // namespace qb::http
