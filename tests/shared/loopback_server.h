/**
 * @file qbm/http/tests/shared/loopback_server.h
 * @brief In-process loopback HTTP/WS server RAII fixture for the qbm-http system suite.
 *
 * This header centralizes the "spin up a real server on a worker thread, pump
 * its event loop, tear it down deterministically" pattern that was copy-pasted
 * (with subtly different sleeps and fixed ports) across every system test. It
 * REPLACES, in one place:
 *
 *   - the hand-rolled `std::thread` + `std::atomic<bool> server_ready` + busy
 *     `while (run(EVRUN_ONCE|EVRUN_NOWAIT)) ... sleep_for(10ms)` loops, and
 *   - the `sleep_for(200ms)` "give the server time to come up" warmups, and
 *   - the fixed magic ports (29876, 29878, 29880, ...) that flake under
 *     parallel CTest because two suites collide on the same port.
 *
 * Instead:
 *   - @ref ServerThread owns the server, runs its loop on a worker thread, and
 *     signals readiness through a condition variable (NO sleep_for warmup).
 *   - @ref ephemeral_port() binds :0 and reads the kernel-assigned port back, so
 *     concurrent suites never collide.
 *   - @ref ServerThread::pump_until drives the CALLER's loop until a predicate
 *     holds or a wall budget elapses, and FAILS LOUD (ADD_FAILURE) on timeout —
 *     it never hangs the suite.
 *
 * Threading model: the server runs its own `qb::io::async` listener on the
 * worker thread (each thread gets its own listener via `qb::io::async::init()`).
 * The client side (driven by the test body, typically `qb::http::run_sync(...)`)
 * runs on the main thread's listener. This mirrors the proven two-thread layout
 * of the original system tests.
 *
 * Reconciled from the server-thread fixtures and pump/warmup idioms in:
 *   - tests/system/server/make-server-factory.cpp   (ServerThread shape, readiness flag)
 *   - tests/system/http1/http1-loopback-basic.cpp    (worker-thread run loop, MakeClientRequest)
 *   - tests/test-session-http.cpp                     (pump_event_loop_while -> pump_until)
 *   - tests/test-integration-middleware.cpp, tests/test-coro-*.cpp (server-thread RAII)
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#ifndef QBM_HTTP_TESTS_SHARED_LOOPBACK_SERVER_H
#define QBM_HTTP_TESTS_SHARED_LOOPBACK_SERVER_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>

#include <gtest/gtest.h>

#include <qb/io/async.h>
#include <qb/io/tcp/listener.h>

namespace qb::http::test {

/**
 * @brief Bind a fresh TCP listener to an ephemeral port and return the port.
 *
 * Asks the kernel for an unused port by binding to :0 on the loopback-capable
 * wildcard address, reads the assigned port back via `local_endpoint().port()`,
 * then closes the probe listener. There is an inherent (small) TOCTOU window
 * between the probe close and the server's bind, but on a loopback test host the
 * kernel does not immediately recycle the port, so this is dramatically more
 * robust than fixed magic ports under parallel CTest.
 *
 * @param host IPv4 bind address for the probe (default "127.0.0.1").
 * @return A kernel-assigned ephemeral port number.
 * @throws std::runtime_error if the probe listener cannot bind.
 */
inline std::uint16_t
ephemeral_port(const std::string &host = "127.0.0.1") {
    qb::io::tcp::listener probe;
    if (probe.listen_v4(0, host) != 0) {
        throw std::runtime_error("ephemeral_port: failed to bind probe listener on " + host + ":0");
    }
    const std::uint16_t port = probe.local_endpoint().port();
    probe.close();
    if (port == 0) {
        throw std::runtime_error("ephemeral_port: kernel returned port 0 after bind");
    }
    return port;
}

/**
 * @brief RAII wrapper that runs a qbm-http server on its own worker thread.
 *
 * Lifecycle on construction:
 *   1. The caller-supplied @p configure callback is invoked on the WORKER thread
 *      (after `qb::io::async::init()`), so the server object — its router, routes,
 *      middleware, transport/TLS init — is built and listens on the same thread
 *      that will pump it. @p configure must call `server.transport().listen_v4(port)`
 *      (or `listen(...)`) and `server.start()`; it returns true on success.
 *   2. The constructor blocks (on a condition variable, NOT a sleep) until the
 *      worker signals readiness, then returns. If `configure` fails or throws,
 *      construction reports the failure via @ref ready().
 *
 * Lifecycle on destruction (or @ref stop()):
 *   - Signals the worker loop to exit and joins the thread; the server object is
 *     destroyed on the worker thread it lived on.
 *
 * @tparam ServerT The qbm-http server type (e.g. `qb::http::Server<>`,
 *                 `qb::http::ssl::Server<>`, `qb::http2::Server<>`, a custom
 *                 `qb::http::use<...>::server<...>` subclass, or a WS server).
 */
template <typename ServerT>
class ServerThread {
public:
    /**
     * @brief Configure callback type.
     * @param server Reference to the freshly-constructed server (on the worker thread).
     * @return true if the server was set up and is listening; false to abort startup.
     */
    using ConfigureFn = std::function<bool(ServerT &)>;

    /**
     * @brief Construct, start, and wait until the server is ready.
     *
     * @param configure Sets up routes/transport and starts listening. Runs on the
     *                  worker thread. Must call `server.transport().listen_v4(port)`
     *                  and `server.start()`.
     * @param ready_budget Maximum wall time to wait for readiness before giving up.
     */
    explicit ServerThread(ConfigureFn configure,
                          std::chrono::milliseconds ready_budget = std::chrono::seconds(5))
        : _configure(std::move(configure)) {
        _thread = std::thread([this] { worker_main(); });

        std::unique_lock<std::mutex> lock(_mutex);
        const bool                   signalled =
            _cv.wait_for(lock, ready_budget, [this] { return _ready.load() || _failed.load(); });
        if (!signalled) {
            ADD_FAILURE() << "ServerThread: server did not become ready within "
                          << ready_budget.count() << "ms";
        } else if (_failed.load()) {
            ADD_FAILURE() << "ServerThread: configure callback failed or threw during startup";
        }
    }

    ServerThread(const ServerThread &)            = delete;
    ServerThread &operator=(const ServerThread &) = delete;
    ServerThread(ServerThread &&)                 = delete;
    ServerThread &operator=(ServerThread &&)      = delete;

    ~ServerThread() {
        stop();
    }

    /** @brief True if the server reached the listening/started state. */
    [[nodiscard]] bool
    ready() const noexcept {
        return _ready.load();
    }

    /** @brief Signal the worker loop to exit and join the thread (idempotent). */
    void
    stop() {
        _running.store(false, std::memory_order_release);
        if (_thread.joinable()) {
            _thread.join();
        }
    }

    /**
     * @brief Access the live server object.
     *
     * Valid for the lifetime of this ServerThread. Note the server is owned by,
     * and runs on, the worker thread; touching its state from the test thread is
     * only safe for atomics or read-only inspection that the server itself does
     * not mutate concurrently.
     *
     * @return Reference to the server (asserts in debug if not yet constructed).
     */
    ServerT &
    server() {
        return *_server;
    }

    /**
     * @brief Pump the CALLER's event loop until @p pred holds or @p budget elapses.
     *
     * Drives `qb::io::async::run(EVRUN_NOWAIT)` on the calling (test) thread,
     * checking @p pred between passes. This is the readiness/completion barrier
     * for client-side work issued from the test body. It NEVER blocks
     * indefinitely: on timeout it records a non-fatal gtest failure and returns
     * false, so a stuck condition surfaces as a test failure instead of a hang.
     *
     * @tparam Pred Nullary predicate convertible to bool.
     * @param pred   Condition to wait for.
     * @param budget Maximum wall time to pump before failing.
     * @return true if @p pred became true within @p budget; false (with an
     *         ADD_FAILURE) on timeout.
     */
    template <typename Pred>
    static bool
    pump_until(Pred &&pred, std::chrono::milliseconds budget = std::chrono::seconds(5)) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (!pred()) {
            if (std::chrono::steady_clock::now() >= deadline) {
                ADD_FAILURE() << "pump_until: predicate not satisfied within " << budget.count()
                              << "ms (event loop pumped to timeout)";
                return false;
            }
            qb::io::async::run(EVRUN_NOWAIT);
        }
        return true;
    }

private:
    void
    worker_main() {
        qb::io::async::init();

        bool ok = false;
        try {
            _server = std::make_unique<ServerT>();
            ok      = _configure ? _configure(*_server) : false;
        } catch (...) {
            ok = false;
        }

        {
            std::lock_guard<std::mutex> lock(_mutex);
            if (ok) {
                _ready.store(true);
            } else {
                _failed.store(true);
            }
        }
        _cv.notify_all();

        if (!ok) {
            return; // Startup failed; nothing to pump. Destructor will join.
        }

        // Pump the server's own loop until asked to stop. EVRUN_NOWAIT + a short
        // back-off avoids a busy spin while keeping shutdown latency low.
        while (_running.load(std::memory_order_acquire)) {
            if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }

        _server.reset(); // Destroy the server on the thread it lived on.
    }

    ConfigureFn                _configure;
    std::unique_ptr<ServerT>   _server;
    std::thread                _thread;
    std::atomic<bool>          _running{true};
    std::atomic<bool>          _ready{false};
    std::atomic<bool>          _failed{false};
    std::mutex                 _mutex;
    std::condition_variable    _cv;
};

} // namespace qb::http::test

#endif // QBM_HTTP_TESTS_SHARED_LOOPBACK_SERVER_H
