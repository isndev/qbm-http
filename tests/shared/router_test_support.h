/**
 * @file qbm/http/tests/shared/router_test_support.h
 * @brief Shared router-test scaffolding: a synchronous deferred-task pump,
 *        an error-signaling middleware, and a base trace-middleware family.
 *
 * The qb-http routing pipeline is fully asynchronous: an @ref qb::http::IAsyncTask
 * (middleware or handler) may defer its `ctx->complete(...)` to a later turn of the
 * event loop. Unit tests do not run a real loop, so they substitute a manual pump
 * — @ref qb::http::test::TaskExecutor — that collects deferred continuations and
 * runs them on demand. This makes otherwise-async control flow deterministic and
 * step-able from a test body.
 *
 * Reconciled, canonical helpers (previously copy-pasted across the routing tests):
 *   - @ref qb::http::test::TaskExecutor — addTask / processAllTasks /
 *     getPendingTaskCount / hasTasks. `processAllTasks` drains a *snapshot* of the
 *     queue: tasks enqueued *by* the running tasks are left for the next call, so a
 *     test can advance the pipeline one "tick" at a time.
 *   - @ref qb::http::test::ErrorSignalerTask — an @ref qb::http::IMiddleware that
 *     fails the chain with @ref qb::http::AsyncTaskResult::ERROR and a chosen status,
 *     either synchronously or via a TaskExecutor.
 *   - @ref qb::http::test::TraceMiddleware / SyncTraceMiddleware / AsyncTraceMiddleware
 *     — the base trace family. Each records its id into a shared ordered vector
 *     (NOT a string-marker concat) so tests assert execution *order* structurally.
 *
 * Header-only; classes are templated on `SessionType` and free helpers are `inline`,
 * so the header is safe to include from any number of gtest translation units.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#ifndef QB_HTTP_TESTS_SHARED_ROUTER_TEST_SUPPORT_H
#define QB_HTTP_TESTS_SHARED_ROUTER_TEST_SUPPORT_H

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <qbm/http/http.h> // qb::http::Router, Context, IMiddleware, AsyncTaskResult, status

namespace qb::http::test {

/**
 * @brief Synchronous, manually-driven pump for deferred routing continuations.
 *
 * Tasks (typically a captured `ctx->complete(...)` closure) are enqueued with
 * @ref addTask and executed by @ref processAllTasks. The pump intentionally runs
 * only a *snapshot* of the queue per call: any task enqueued by a running task is
 * collected into a fresh queue and executed by the *next* @ref processAllTasks
 * call. This lets a test step a multi-hop async chain one tick at a time, while
 * still allowing a "drain everything" loop:
 *
 * @code
 * while (executor.hasTasks()) executor.processAllTasks();
 * @endcode
 *
 * Single-threaded by design — matches the qb single-threaded listener model.
 */
class TaskExecutor {
public:
    /** @brief Enqueues a continuation to be run on a subsequent @ref processAllTasks call. */
    void
    addTask(std::function<void()> task) {
        _tasks.push_back(std::move(task));
    }

    /**
     * @brief Runs every task currently queued (a snapshot taken at call entry).
     *
     * The queue is cleared before execution, so tasks enqueued *during* this call
     * accumulate in a fresh queue and are deferred to the next invocation. Run this
     * in a `while (hasTasks())` loop to fully drain a multi-hop chain.
     */
    void
    processAllTasks() {
        std::vector<std::function<void()>> snapshot = std::move(_tasks);
        _tasks.clear();
        for (auto &task : snapshot) {
            if (task) {
                task();
            }
        }
    }

    /** @brief True if any task is currently queued. */
    [[nodiscard]] bool
    hasTasks() const noexcept {
        return !_tasks.empty();
    }

    /** @brief Number of tasks currently queued (not yet processed). */
    [[nodiscard]] std::size_t
    getPendingTaskCount() const noexcept {
        return _tasks.size();
    }

    /** @brief Discards all queued tasks without running them. */
    void
    clearTasks() noexcept {
        _tasks.clear();
    }

private:
    std::vector<std::function<void()>> _tasks;
};

/**
 * @brief Middleware that fails the routing chain with a chosen status.
 *
 * Records its name into a shared order log (if one is supplied), sets the response
 * status to the configured value, then completes the context with
 * @ref qb::http::AsyncTaskResult::ERROR — routing it into the configured error
 * chain (or a generic 500 if none is set). When a @ref TaskExecutor is supplied the
 * error signal is deferred onto the pump (exercising the async error path);
 * otherwise it is signaled synchronously.
 *
 * @tparam SessionType The session type carried by the request context.
 */
template <typename SessionType>
class ErrorSignalerTask : public qb::http::IMiddleware<SessionType> {
public:
    /**
     * @brief Constructs an error-signaling middleware.
     * @param name      Identifier used by name() and recorded into @p order_log.
     * @param status    The status to set on the response before signaling ERROR.
     *                  Defaults to 500 Internal Server Error.
     * @param executor  Optional pump; when non-null the ERROR signal is deferred.
     * @param order_log Optional shared vector to append @p name to on execution.
     */
    explicit ErrorSignalerTask(std::string name, qb::http::status status = qb::http::status::INTERNAL_SERVER_ERROR,
                               TaskExecutor *executor = nullptr, std::shared_ptr<std::vector<std::string>> order_log = nullptr)
        : _name(std::move(name))
        , _status(status)
        , _executor(executor)
        , _order_log(std::move(order_log)) {}

    void
    process(std::shared_ptr<qb::http::Context<SessionType>> ctx) override {
        if (_order_log) {
            _order_log->push_back(_name);
        }
        const auto status = _status;
        if (_executor) {
            _executor->addTask([ctx, status]() {
                ctx->response().status() = status;
                ctx->complete(qb::http::AsyncTaskResult::ERROR);
            });
        } else {
            ctx->response().status() = status;
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        }
    }

    [[nodiscard]] std::string
    name() const override {
        return _name;
    }

    void
    cancel() override {}

private:
    std::string                               _name;
    qb::http::status                          _status;
    TaskExecutor                             *_executor;
    std::shared_ptr<std::vector<std::string>> _order_log;
};

/**
 * @brief Base of the trace-middleware family: records execution order into a vector.
 *
 * Each instance carries an id and a shared ordered log. On execution it appends its
 * id to the log, giving tests a structural record of *which middleware ran in what
 * order* — preferred over the legacy string-marker concatenation because it is
 * trivially comparable to an expected `std::vector<std::string>`.
 *
 * Concrete subclasses decide *when* to continue the chain (synchronously vs. via a
 * @ref TaskExecutor). This base supplies the id, name(), the shared log, a no-op
 * cancel(), and the @ref record helper.
 *
 * @tparam SessionType The session type carried by the request context.
 */
template <typename SessionType>
class TraceMiddleware : public qb::http::IMiddleware<SessionType> {
public:
    /**
     * @param id        Identifier appended to @p order_log on execution / returned by name().
     * @param order_log Shared vector into which execution order is recorded; must not be null.
     */
    TraceMiddleware(std::string id, std::shared_ptr<std::vector<std::string>> order_log)
        : _id(std::move(id))
        , _order_log(std::move(order_log)) {}

    [[nodiscard]] std::string
    name() const override {
        return _id;
    }

    void
    cancel() override {}

protected:
    /** @brief Appends @p marker (defaulting to this middleware's id) to the order log. */
    void
    record(const std::string &marker) const {
        if (_order_log) {
            _order_log->push_back(marker);
        }
    }

    /** @brief Appends this middleware's id to the order log. */
    void
    record() const {
        record(_id);
    }

    std::string                               _id;        ///< This middleware's identifier.
    std::shared_ptr<std::vector<std::string>> _order_log; ///< Shared execution-order log.
};

/**
 * @brief Trace middleware that records its id and continues the chain synchronously.
 *
 * Appends its id to the order log, then immediately completes with
 * @ref qb::http::AsyncTaskResult::CONTINUE.
 *
 * @tparam SessionType The session type carried by the request context.
 */
template <typename SessionType>
class SyncTraceMiddleware : public TraceMiddleware<SessionType> {
public:
    using TraceMiddleware<SessionType>::TraceMiddleware;

    void
    process(std::shared_ptr<qb::http::Context<SessionType>> ctx) override {
        this->record();
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }
};

/**
 * @brief Trace middleware that records its id and continues via a @ref TaskExecutor.
 *
 * Appends its id to the order log immediately, then defers the
 * @ref qb::http::AsyncTaskResult::CONTINUE completion onto the supplied pump,
 * exercising the asynchronous middleware path. If the context is cancelled before
 * the deferred continuation runs, it appends `"<id>_cancelled"` and does not
 * complete (the context is already finalizing).
 *
 * @tparam SessionType The session type carried by the request context.
 */
template <typename SessionType>
class AsyncTraceMiddleware : public TraceMiddleware<SessionType> {
public:
    /**
     * @param id        Identifier recorded / returned by name().
     * @param order_log Shared execution-order log.
     * @param executor  Pump onto which the CONTINUE completion is deferred; must not be null.
     */
    AsyncTraceMiddleware(std::string id, std::shared_ptr<std::vector<std::string>> order_log, TaskExecutor *executor)
        : TraceMiddleware<SessionType>(std::move(id), std::move(order_log))
        , _executor(executor) {}

    void
    process(std::shared_ptr<qb::http::Context<SessionType>> ctx) override {
        this->record();
        if (!_executor) {
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
            return;
        }
        const std::string id = this->_id;
        _executor->addTask([this, ctx, id]() {
            if (ctx->is_cancelled()) {
                this->record(id + "_cancelled");
                return;
            }
            ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
        });
    }

private:
    TaskExecutor *_executor;
};

} // namespace qb::http::test

#endif // QB_HTTP_TESTS_SHARED_ROUTER_TEST_SUPPORT_H
