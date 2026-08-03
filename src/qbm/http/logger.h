/**
 * @file qbm/http/logger.h
 * @brief Logging macros for the qbm-http module.
 *
 * This header defines a family of @c LOG_HTTP_* preprocessor macros used
 * throughout the qbm-http module for diagnostic logging. Each macro resolves to
 * one of three backends, selected at compile time:
 *   - @c QB_WITH_LOGGING defined: routes to qb's nanolog asynchronous logger,
 *     gated by @c nanolog::is_logged so disabled levels incur no formatting cost.
 *   - @c QB_STDOUT_LOGGING defined (and @c QB_WITH_LOGGING not): writes to
 *     @c qb::io::cout() / @c qb::io::cerr().
 *   - neither defined: expands to a no-op @c do/while(false) statement.
 *
 * Every emitted line is prefixed with @ref QBM_HTTP_LOG_PREFIX so qbm-http logs
 * can be easily filtered. The @c _PA ("Per Actor/Stream") variants additionally
 * embed a stream identifier in the form @c "S-<id>" for protocol-aware tracing.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#ifndef QB_MODULE_HTTP_LOGGER_H_
#define QB_MODULE_HTTP_LOGGER_H_

#include <qb/io.h> // This should include nanolog.h if QB_WITH_LOGGING is defined

/**
 * @def QBM_HTTP_LOG_PREFIX
 * @brief Common textual prefix prepended to every qbm-http log line.
 *
 * Used by all @c LOG_HTTP_* macros to make module log output easy to identify
 * and filter.
 */
#define QBM_HTTP_LOG_PREFIX "[qbm-http] "

#ifdef QB_WITH_LOGGING

/**
 * @name nanolog logging backend
 * @brief @c LOG_HTTP_* macros routed to qb's asynchronous nanolog logger.
 *
 * Each macro is short-circuit guarded by @c nanolog::is_logged(level), so the
 * message expression @p X is only formatted when the corresponding level is
 * enabled. The whole expression is cast to @c void to be safely usable as a
 * statement.
 *
 * Level mapping notes: @c TRACE and @c DEBUG both map to @c LogLevel::DEBUG, and
 * @c ERROR maps to @c LogLevel::WARN (nanolog exposes no dedicated ERROR level);
 * the textual tag in the emitted line still distinguishes them.
 * @{
 */

// HTTP-specific TRACE (maps to DEBUG for nanolog, could be made more distinct if nanolog supported more levels easily)
#define LOG_HTTP_TRACE(X) \
    (void) (nanolog::is_logged(nanolog::LogLevel::DEBUG) && NANO_LOG(nanolog::LogLevel::DEBUG) << QBM_HTTP_LOG_PREFIX << "TRACE: " << X)

#define LOG_HTTP_DEBUG(X) \
    (void) (nanolog::is_logged(nanolog::LogLevel::DEBUG) && NANO_LOG(nanolog::LogLevel::DEBUG) << QBM_HTTP_LOG_PREFIX << "DEBUG: " << X)

#define LOG_HTTP_VERBOSE(X) \
    (void) (nanolog::is_logged(nanolog::LogLevel::VERBOSE) && NANO_LOG(nanolog::LogLevel::VERBOSE) << QBM_HTTP_LOG_PREFIX << "VERBOSE: " << X)

#define LOG_HTTP_INFO(X) \
    (void) (nanolog::is_logged(nanolog::LogLevel::INFO) && NANO_LOG(nanolog::LogLevel::INFO) << QBM_HTTP_LOG_PREFIX << "INFO: " << X)

#define LOG_HTTP_WARN(X) \
    (void) (nanolog::is_logged(nanolog::LogLevel::WARN) && NANO_LOG(nanolog::LogLevel::WARN) << QBM_HTTP_LOG_PREFIX << "WARN: " << X)

#define LOG_HTTP_ERROR(X) \
    (void) (nanolog::is_logged(nanolog::LogLevel::WARN) && NANO_LOG(nanolog::LogLevel::WARN) << QBM_HTTP_LOG_PREFIX << "ERROR: " << X)

#define LOG_HTTP_CRIT(X) \
    (void) (nanolog::is_logged(nanolog::LogLevel::CRIT) && NANO_LOG(nanolog::LogLevel::CRIT) << QBM_HTTP_LOG_PREFIX << "CRITICAL: " << X)

// Version with stream ID context (PA for Protocol Aware or Per Actor/Stream)
#define LOG_HTTP_TRACE_PA(STREAM_ID, X)                  \
    (void) (nanolog::is_logged(nanolog::LogLevel::DEBUG) \
            && NANO_LOG(nanolog::LogLevel::DEBUG) << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " TRACE: " << X)

#define LOG_HTTP_DEBUG_PA(STREAM_ID, X)                  \
    (void) (nanolog::is_logged(nanolog::LogLevel::DEBUG) \
            && NANO_LOG(nanolog::LogLevel::DEBUG) << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " DEBUG: " << X)

#define LOG_HTTP_INFO_PA(STREAM_ID, X)                  \
    (void) (nanolog::is_logged(nanolog::LogLevel::INFO) \
            && NANO_LOG(nanolog::LogLevel::INFO) << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " INFO: " << X)

#define LOG_HTTP_WARN_PA(STREAM_ID, X)                  \
    (void) (nanolog::is_logged(nanolog::LogLevel::WARN) \
            && NANO_LOG(nanolog::LogLevel::WARN) << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " WARN: " << X)

#define LOG_HTTP_ERROR_PA(STREAM_ID, X)                 \
    (void) (nanolog::is_logged(nanolog::LogLevel::WARN) \
            && NANO_LOG(nanolog::LogLevel::WARN) << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " ERROR: " << X)

#define LOG_HTTP_CRIT_PA(STREAM_ID, X)                  \
    (void) (nanolog::is_logged(nanolog::LogLevel::CRIT) \
            && NANO_LOG(nanolog::LogLevel::CRIT) << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " CRITICAL: " << X)

/** @} */ // end of nanolog logging backend

#else // QB_WITH_LOGGING not defined, fallback to QB_STDOUT_LOGGING or no-op

#ifdef QB_STDOUT_LOGGING

/**
 * @name stdout/stderr logging backend
 * @brief Fallback @c LOG_HTTP_* macros writing directly to standard streams.
 *
 * Used when @c QB_WITH_LOGGING is not defined but @c QB_STDOUT_LOGGING is.
 * Informational levels are written to @c qb::io::cout(); @c ERROR and
 * @c CRITICAL are written to @c qb::io::cerr(). Each line is terminated with
 * @c std::endl. Unlike the nanolog backend, these macros are unconditional and
 * always evaluate @p X.
 * @{
 */
#define LOG_HTTP_TRACE(X) qb::io::cout() << QBM_HTTP_LOG_PREFIX << "TRACE: " << X << std::endl
#define LOG_HTTP_DEBUG(X) qb::io::cout() << QBM_HTTP_LOG_PREFIX << "DEBUG: " << X << std::endl
#define LOG_HTTP_VERBOSE(X) qb::io::cout() << QBM_HTTP_LOG_PREFIX << "VERBOSE: " << X << std::endl
#define LOG_HTTP_INFO(X) qb::io::cout() << QBM_HTTP_LOG_PREFIX << "INFO: " << X << std::endl
#define LOG_HTTP_WARN(X) qb::io::cout() << QBM_HTTP_LOG_PREFIX << "WARN: " << X << std::endl
#define LOG_HTTP_ERROR(X) qb::io::cerr() << QBM_HTTP_LOG_PREFIX << "ERROR: " << X << std::endl
#define LOG_HTTP_CRIT(X) qb::io::cerr() << QBM_HTTP_LOG_PREFIX << "CRITICAL: " << X << std::endl

#define LOG_HTTP_TRACE_PA(STREAM_ID, X) qb::io::cout() << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " TRACE: " << X << std::endl
#define LOG_HTTP_DEBUG_PA(STREAM_ID, X) qb::io::cout() << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " DEBUG: " << X << std::endl
#define LOG_HTTP_INFO_PA(STREAM_ID, X) qb::io::cout() << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " INFO: " << X << std::endl
#define LOG_HTTP_WARN_PA(STREAM_ID, X) qb::io::cout() << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " WARN: " << X << std::endl
#define LOG_HTTP_ERROR_PA(STREAM_ID, X) qb::io::cerr() << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " ERROR: " << X << std::endl
#define LOG_HTTP_CRIT_PA(STREAM_ID, X) qb::io::cerr() << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " CRITICAL: " << X << std::endl

/** @} */ // end of stdout/stderr logging backend

#else // QB_STDOUT_LOGGING not defined, logs are no-ops

/**
 * @name No-op logging backend
 * @brief Fallback @c LOG_HTTP_* macros that compile to nothing.
 *
 * Used when neither @c QB_WITH_LOGGING nor @c QB_STDOUT_LOGGING is defined. Each
 * macro expands to an empty @c do/while(false) statement so call sites remain
 * valid statements while the message expression @p X is not evaluated.
 * @{
 */
#define LOG_HTTP_TRACE(X) \
    do {                  \
    } while (false)
#define LOG_HTTP_DEBUG(X) \
    do {                  \
    } while (false)
#define LOG_HTTP_VERBOSE(X) \
    do {                    \
    } while (false)
#define LOG_HTTP_INFO(X) \
    do {                 \
    } while (false)
#define LOG_HTTP_WARN(X) \
    do {                 \
    } while (false)
#define LOG_HTTP_ERROR(X) \
    do {                  \
    } while (false)
#define LOG_HTTP_CRIT(X) \
    do {                 \
    } while (false)

#define LOG_HTTP_TRACE_PA(STREAM_ID, X) \
    do {                                \
    } while (false)
#define LOG_HTTP_DEBUG_PA(STREAM_ID, X) \
    do {                                \
    } while (false)
#define LOG_HTTP_INFO_PA(STREAM_ID, X) \
    do {                               \
    } while (false)
#define LOG_HTTP_WARN_PA(STREAM_ID, X) \
    do {                               \
    } while (false)
#define LOG_HTTP_ERROR_PA(STREAM_ID, X) \
    do {                                \
    } while (false)
#define LOG_HTTP_CRIT_PA(STREAM_ID, X) \
    do {                               \
    } while (false)

/** @} */ // end of No-op logging backend

#endif // QB_STDOUT_LOGGING
#endif // QB_WITH_LOGGING

#endif // QB_MODULE_HTTP_LOGGER_H_