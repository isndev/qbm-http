#ifndef QB_MODULE_HTTP_LOGGER_H_
#define QB_MODULE_HTTP_LOGGER_H_

#include <qb/io.h> // This should include nanolog.h if QB_LOGGER is defined

// Define a common prefix for all qbm-http logs to easily identify them.
#define QBM_HTTP_LOG_PREFIX "[qbm-http] "

#ifdef QB_LOGGER

// HTTP-specific TRACE (maps to DEBUG for nanolog, could be made more distinct if nanolog supported more levels easily)
#define LOG_HTTP_TRACE(X) \
    (void)(nanolog::is_logged(nanolog::LogLevel::DEBUG) && \
           NANO_LOG(nanolog::LogLevel::DEBUG) << QBM_HTTP_LOG_PREFIX << "TRACE: " << X)

#define LOG_HTTP_DEBUG(X) \
    (void)(nanolog::is_logged(nanolog::LogLevel::DEBUG) && \
           NANO_LOG(nanolog::LogLevel::DEBUG) << QBM_HTTP_LOG_PREFIX << "DEBUG: " << X)

#define LOG_HTTP_VERBOSE(X) \
    (void)(nanolog::is_logged(nanolog::LogLevel::VERBOSE) && \
           NANO_LOG(nanolog::LogLevel::VERBOSE) << QBM_HTTP_LOG_PREFIX << "VERBOSE: " << X)

#define LOG_HTTP_INFO(X) \
    (void)(nanolog::is_logged(nanolog::LogLevel::INFO) && \
           NANO_LOG(nanolog::LogLevel::INFO) << QBM_HTTP_LOG_PREFIX << "INFO: " << X)

#define LOG_HTTP_WARN(X) \
    (void)(nanolog::is_logged(nanolog::LogLevel::WARN) && \
           NANO_LOG(nanolog::LogLevel::WARN) << QBM_HTTP_LOG_PREFIX << "WARN: " << X)

#define LOG_HTTP_ERROR(X) \
    (void)(nanolog::is_logged(nanolog::LogLevel::CRIT) && \
           NANO_LOG(nanolog::LogLevel::CRIT) << QBM_HTTP_LOG_PREFIX << "ERROR: " << X) // Map ERROR to CRIT for higher visibility

#define LOG_HTTP_CRIT(X) \
    (void)(nanolog::is_logged(nanolog::LogLevel::CRIT) && \
           NANO_LOG(nanolog::LogLevel::CRIT) << QBM_HTTP_LOG_PREFIX << "CRITICAL: " << X)

// Version with stream ID context (PA for Protocol Aware or Per Actor/Stream)
#define LOG_HTTP_TRACE_PA(STREAM_ID, X) \
    (void)(nanolog::is_logged(nanolog::LogLevel::DEBUG) && \
           NANO_LOG(nanolog::LogLevel::DEBUG) << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " TRACE: " << X)

#define LOG_HTTP_DEBUG_PA(STREAM_ID, X) \
    (void)(nanolog::is_logged(nanolog::LogLevel::DEBUG) && \
           NANO_LOG(nanolog::LogLevel::DEBUG) << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " DEBUG: " << X)

#define LOG_HTTP_INFO_PA(STREAM_ID, X) \
    (void)(nanolog::is_logged(nanolog::LogLevel::INFO) && \
           NANO_LOG(nanolog::LogLevel::INFO) << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " INFO: " << X)

#define LOG_HTTP_WARN_PA(STREAM_ID, X) \
    (void)(nanolog::is_logged(nanolog::LogLevel::WARN) && \
           NANO_LOG(nanolog::LogLevel::WARN) << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " WARN: " << X)
           
#define LOG_HTTP_ERROR_PA(STREAM_ID, X) \
    (void)(nanolog::is_logged(nanolog::LogLevel::CRIT) && \
           NANO_LOG(nanolog::LogLevel::CRIT) << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " ERROR: " << X)

#define LOG_HTTP_CRIT_PA(STREAM_ID, X) \
    (void)(nanolog::is_logged(nanolog::LogLevel::CRIT) && \
           NANO_LOG(nanolog::LogLevel::CRIT) << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " CRITICAL: " << X)

#else // QB_LOGGER not defined, fallback to QB_STDOUT_LOG or no-op

#ifdef QB_STDOUT_LOG
#define LOG_HTTP_TRACE(X) qb::io::cout() << QBM_HTTP_LOG_PREFIX << "TRACE: " << X << std::endl
#define LOG_HTTP_DEBUG(X) qb::io::cout() << QBM_HTTP_LOG_PREFIX << "DEBUG: " << X << std::endl
#define LOG_HTTP_VERBOSE(X) qb::io::cout() << QBM_HTTP_LOG_PREFIX << "VERBOSE: " << X << std::endl
#define LOG_HTTP_INFO(X)  qb::io::cout() << QBM_HTTP_LOG_PREFIX << "INFO: " << X << std::endl
#define LOG_HTTP_WARN(X)  qb::io::cout() << QBM_HTTP_LOG_PREFIX << "WARN: " << X << std::endl
#define LOG_HTTP_ERROR(X) qb::io::cerr() << QBM_HTTP_LOG_PREFIX << "ERROR: " << X << std::endl
#define LOG_HTTP_CRIT(X)  qb::io::cerr() << QBM_HTTP_LOG_PREFIX << "CRITICAL: " << X << std::endl

#define LOG_HTTP_TRACE_PA(STREAM_ID, X) qb::io::cout() << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " TRACE: " << X << std::endl
#define LOG_HTTP_DEBUG_PA(STREAM_ID, X) qb::io::cout() << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " DEBUG: " << X << std::endl
#define LOG_HTTP_INFO_PA(STREAM_ID, X)  qb::io::cout() << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " INFO: " << X << std::endl
#define LOG_HTTP_WARN_PA(STREAM_ID, X)  qb::io::cout() << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " WARN: " << X << std::endl
#define LOG_HTTP_ERROR_PA(STREAM_ID, X) qb::io::cerr() << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " ERROR: " << X << std::endl
#define LOG_HTTP_CRIT_PA(STREAM_ID, X)  qb::io::cerr() << QBM_HTTP_LOG_PREFIX << "S-" << STREAM_ID << " CRITICAL: " << X << std::endl

#else // QB_STDOUT_LOG not defined, logs are no-ops

#define LOG_HTTP_TRACE(X) do {} while (false)
#define LOG_HTTP_DEBUG(X) do {} while (false)
#define LOG_HTTP_VERBOSE(X) do {} while (false)
#define LOG_HTTP_INFO(X)  do {} while (false)
#define LOG_HTTP_WARN(X)  do {} while (false)
#define LOG_HTTP_ERROR(X) do {} while (false)
#define LOG_HTTP_CRIT(X)  do {} while (false)

#define LOG_HTTP_TRACE_PA(STREAM_ID, X) do {} while (false)
#define LOG_HTTP_DEBUG_PA(STREAM_ID, X) do {} while (false)
#define LOG_HTTP_INFO_PA(STREAM_ID, X)  do {} while (false)
#define LOG_HTTP_WARN_PA(STREAM_ID, X)  do {} while (false)
#define LOG_HTTP_ERROR_PA(STREAM_ID, X) do {} while (false)
#define LOG_HTTP_CRIT_PA(STREAM_ID, X) do {} while (false)

#endif // QB_STDOUT_LOG
#endif // QB_LOGGER

#endif // QB_MODULE_HTTP_LOGGER_H_ 