/**
 * @file qbm/http/detail/drain.h
 * @brief The bookkeeping the HTTP/1.1, HTTP/2 and HTTP/3 servers' drains share (Huly QB-167, QB-91).
 *
 * Every server drains with one contract -- `drain(deadline, on_drained)` begins once and reports once,
 * `qb::http::drain_outcome::drained` or `qb::http::drain_outcome::deadline`, on the server's loop -- and keeps
 * its state here: whether a drain began, whether it was reported, the callback, and the deadline's timer. What a
 * drain does to a connection is each protocol's own. Not part of the public API.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <exception>
#include <functional>
#include <memory>
#include <string_view>
#include <utility>

#include <qb/io/async.h>

#include "../logger.h"
#include "../types.h"

namespace qb::http::detail {

/// Cold shutdown capability of a protocol upgraded in place. No hook runs during ordinary HTTP traffic.
class websocket_drain {
public:
    virtual void begin_server_drain() noexcept = 0;

protected:
    ~websocket_drain() = default;
};

/**
 * @brief A one-shot timer of the loop the creating thread runs: its action runs once, when the time given has
 *        passed.
 *
 * Created on the server's loop. Its owner keeps it; its action may stop it, never release it.
 */
class loop_timer : public qb::io::async::with_timeout<loop_timer> {
    std::function<void()> _action;

public:
    /**
     * @param after  How long from now.
     * @param action What runs then; must not throw.
     */
    loop_timer(qb::duration after, std::function<void()> action)
        : qb::io::async::with_timeout<loop_timer>(after)
        , _action(std::move(action)) {}

    /// Stops the timer: its action will not run.
    void
    stop() noexcept {
        this->setTimeout(qb::duration::zero());
    }

    /// Arms the timer again: its action runs once @p after has passed (zero or less stops it).
    void
    restart(qb::duration after) noexcept {
        this->setTimeout(after);
    }

    /// The timer expired: runs the action.
    void
    on(qb::io::async::event::timer const &) noexcept {
        if (_action)
            _action();
    }
};

/**
 * @brief A server's drain: begun once, reported once.
 */
class drain_state {
    bool                                         _started  = false;
    bool                                         _reported = false;
    std::function<void(qb::http::drain_outcome)> _on_drained;
    std::unique_ptr<loop_timer>                  _deadline;

public:
    /**
     * @brief Begins the drain.
     * @param on_drained Told how the drain ended; may be empty.
     * @return False, and nothing changes, when a drain already began.
     */
    [[nodiscard]] bool
    begin(std::function<void(qb::http::drain_outcome)> on_drained) {
        if (_started)
            return false;
        _started    = true;
        _on_drained = std::move(on_drained);
        return true;
    }

    /**
     * @brief Runs @p on_deadline once @p after has passed, unless the drain is reported first.
     * @param after       How long from now.
     * @param on_deadline What runs then; must not throw.
     */
    void
    arm_deadline(qb::duration after, std::function<void()> on_deadline) {
        _deadline = std::make_unique<loop_timer>(after, std::move(on_deadline));
    }

    /// Whether a drain began (it may be over).
    [[nodiscard]] bool
    started() const noexcept {
        return _started;
    }

    /// Whether a drain began and is not reported yet.
    [[nodiscard]] bool
    pending() const noexcept {
        return _started && !_reported;
    }

    /**
     * @brief Reports the drain, once: stops the deadline -- this may run from its own action -- then runs the
     *        callback, whose exception is contained and logged.
     * @param outcome How the drain ended.
     * @param server  The server's name, for the log.
     */
    void
    report(qb::http::drain_outcome outcome, std::string_view server) noexcept {
        if (!pending())
            return;
        _reported = true;
        if (_deadline)
            _deadline->stop();
        auto on_drained = std::move(_on_drained);
        _on_drained     = nullptr;
        if (!on_drained)
            return;
        try {
            on_drained(outcome);
        } catch (const std::exception &e) {
            LOG_HTTP_ERROR(server << " drain callback threw: " << e.what());
        } catch (...) {
            LOG_HTTP_ERROR(server << " drain callback threw an unknown exception");
        }
    }
};

} // namespace qb::http::detail
