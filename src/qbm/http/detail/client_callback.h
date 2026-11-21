/**
 * @file qbm/http/detail/client_callback.h
 * @brief How the HTTP/1.1, HTTP/2 and HTTP/3 clients run a user callback that must not throw past them (Huly QB-1246).
 *
 * A client that is being destroyed answers what it still holds -- every request in flight or queued, every connect()
 * still waiting -- by calling the program's callbacks from its destructor. What one of them throws cannot leave a
 * destructor (`std::terminate`), and must not keep the callbacks after it from running: it is logged and goes no
 * further. The same holds for every callback the loop brings -- a response, a failure, a timeout, a close, the client's
 * own turn: no caller of the program is there to hear what it throws, so the client contains it where it calls the
 * callback and logs it, as qb-io's loop does at its own boundaries. The HTTP/1.1 client contains every user callback,
 * at any time (`contained()`); the HTTP/2 and HTTP/3 clients the ones their destructor runs (`notify()`) and the ones
 * the loop brings (`escaped()`), and let what a callback throws under a call of the program reach that call. Not part
 * of the public API.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <exception>
#include <utility>

#include "../logger.h"

namespace qb::http::detail {

/**
 * @brief Runs @p fn; what it throws is logged at WARN under @p client and goes no further -- nor does what the log
 *        itself throws (a stdout logger's allocation): this is noexcept, and a throw here would end the process.
 * @param client The client's name in the line logged: `"HTTP/1.1"`, `"HTTP/2"`, `"HTTP/3"`.
 * @param fn The call: a user callback, or what the line names.
 * @param what What @p fn runs, in the line logged.
 */
template <typename Fn>
void
contained([[maybe_unused]] char const *const client, Fn &&fn, [[maybe_unused]] char const *const what = "callback") noexcept {
    try {
        std::forward<Fn>(fn)();
    } catch ([[maybe_unused]] std::exception const &e) {
        try {
            LOG_HTTP_WARN("exception escaped an " << client << " client " << what << "; contained: " << e.what());
        } catch (...) {
            // the line could not be written: nothing more is said
        }
    } catch (...) {
        try {
            LOG_HTTP_WARN("exception escaped an " << client << " client " << what << "; contained");
        } catch (...) {
            // the line could not be written: nothing more is said
        }
    }
}

/**
 * @brief For the handler of a `try` around a user callback the loop brought: logs the exception being handled, at
 *        WARN under @p client, in the form of contained(), and lets it go no further. Never throws.
 * @param client The client's name in the line logged.
 */
inline void
escaped(char const *const client) noexcept {
    contained(client, [] { throw; });
}

/**
 * @brief Runs @p fn, the call of a user callback: contained while the client is being destroyed, plainly otherwise.
 * @param destroying The client's destructor runs.
 * @param client The client's name in the line logged.
 * @param fn The call of a user callback, with whatever it allocates to make it: a failed allocation is contained too.
 */
template <typename Fn>
void
notify(bool const destroying, char const *const client, Fn &&fn) {
    if (destroying) {
        contained(client, std::forward<Fn>(fn));
        return;
    }
    std::forward<Fn>(fn)();
}

} // namespace qb::http::detail
