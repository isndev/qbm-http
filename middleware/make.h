/**
 * @file qbm/http/middleware/make.h
 * @brief Unified factory entry point for standard HTTP middleware.
 *
 * Historically, each middleware shipped its own set of free factory helpers
 * (`create_auth_middleware`, `cors_middleware`, `rate_limit_dev_middleware`,
 * &hellip;). The names and argument conventions drifted over time, which made it
 * hard to discover the canonical way to build a middleware for a given purpose.
 *
 * This header consolidates every factory under a single generic entry point:
 *
 * @code
 *   using qb::http::middleware::tags;
 *   auto cors = qb::http::middleware::make<tags::cors_secure, MySession>();
 *   auto auth = qb::http::middleware::make<tags::jwt_auth, MySession>(
 *                   secret, "HS256", "MyAuth");
 * @endcode
 *
 * Tag types are light-weight structs that select the target middleware family
 * at compile time, while the variadic `make<Tag, Session>(Args...)` entry point
 * perfect-forwards to the existing per-middleware factory. The existing factory
 * helpers remain available for source compatibility and are the implementation
 * detail consumed by `make<>`.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Middleware
 */
#pragma once

#include <utility>

#include "./auth.h"
#include "./compression.h"
#include "./conditional.h"
#include "./cors.h"
#include "./error_handling.h"
#include "./jwt.h"
#include "./logging.h"
#include "./rate_limit.h"
#include "./security_headers.h"
#include "./static_files.h"
#include "./timing.h"
#include "./transform.h"

#ifdef QB_HTTP_HAS_RECAPTCHA_MIDDLEWARE
#include "./recaptcha.h"
#endif

namespace qb::http::middleware {
    /**
     * @brief Strongly-typed tags selecting a middleware family for `make<>()`.
     *
     * Each tag maps to exactly one factory in the corresponding middleware
     * header. Tags are empty types; they are only used as compile-time
     * discriminators and never carry runtime state.
     */
    namespace tags {
        // --- Authentication / Authorisation -----------------------------------
        struct auth {};             ///< Full-featured auth middleware (token + roles).
        struct jwt_auth {};         ///< Convenience JWT auth (secret or public key + algorithm).
        struct role_auth {};        ///< Role-based access check assuming user already in context.
        struct optional_auth {};    ///< Auth accepted but not required.

        // --- CORS -------------------------------------------------------------
        struct cors {};             ///< Configurable CORS middleware.
        struct cors_dev {};         ///< Permissive CORS preset for local development.
        struct cors_secure {};      ///< Hardened CORS preset for production.

        // --- Compression ------------------------------------------------------
        struct compression {};      ///< Negotiated compression (gzip/deflate/br).
        struct compression_fast {}; ///< Compression preset favouring throughput.
        struct compression_max {};  ///< Compression preset favouring size.

        // --- Observability ----------------------------------------------------
        struct logging {};          ///< Request/response logging.
        struct timing {};           ///< Request duration timing headers.

        // --- Rate limiting ----------------------------------------------------
        struct rate_limit {};       ///< Configurable rate limiter.
        struct rate_limit_dev {};   ///< Loose rate limiter preset for development.
        struct rate_limit_secure {};///< Strict rate limiter preset for production.

        // --- Security & delivery ---------------------------------------------
        struct security_headers {}; ///< Security-related response headers.
        struct static_files {};     ///< Static file serving.

        // --- Structural middleware -------------------------------------------
        struct transform {};        ///< Request/response transformer.
        struct conditional {};      ///< Branching middleware (if/else on predicate).
        struct error_handling {};   ///< Centralised error-to-response translation.

        // --- JWT (raw) --------------------------------------------------------
        struct jwt {};              ///< Low-level JWT verification middleware.

#ifdef QB_HTTP_HAS_RECAPTCHA_MIDDLEWARE
        struct recaptcha {};        ///< Google reCAPTCHA v2/v3 verification.
        struct recaptcha_v3 {};     ///< reCAPTCHA v3 preset.
        struct recaptcha_strict {}; ///< Strict reCAPTCHA preset.
#endif
    }

    /// Maps a middleware tag to the factory function that produces it.
    /// Overloads are provided per-tag; `make<Tag, Session>(args...)` forwards
    /// through this dispatcher so every middleware shares a single call shape.
    namespace detail {
        // --- Auth family ------------------------------------------------------
        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::auth, Args &&... args) {
            return qb::http::create_auth_middleware<SessionType>(std::forward<Args>(args)...);
        }

        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::jwt_auth, Args &&... args) {
            return qb::http::create_jwt_auth_middleware<SessionType>(std::forward<Args>(args)...);
        }

        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::role_auth, Args &&... args) {
            return qb::http::create_role_auth_middleware<SessionType>(std::forward<Args>(args)...);
        }

        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::optional_auth, Args &&... args) {
            return qb::http::create_optional_auth_middleware<SessionType>(std::forward<Args>(args)...);
        }

        // --- CORS -------------------------------------------------------------
        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::cors, Args &&... args) {
            return qb::http::cors_middleware<SessionType>(std::forward<Args>(args)...);
        }

        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::cors_dev, Args &&... args) {
            return qb::http::cors_dev_middleware<SessionType>(std::forward<Args>(args)...);
        }

        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::cors_secure, Args &&... args) {
            return qb::http::cors_secure_middleware<SessionType>(std::forward<Args>(args)...);
        }

        // --- Compression ------------------------------------------------------
        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::compression, Args &&... args) {
            return qb::http::compression_middleware<SessionType>(std::forward<Args>(args)...);
        }

        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::compression_fast, Args &&... args) {
            return qb::http::fast_compression_middleware<SessionType>(std::forward<Args>(args)...);
        }

        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::compression_max, Args &&... args) {
            return qb::http::max_compression_middleware<SessionType>(std::forward<Args>(args)...);
        }

        // --- Observability ----------------------------------------------------
        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::logging, Args &&... args) {
            return qb::http::logging_middleware<SessionType>(std::forward<Args>(args)...);
        }

        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::timing, Args &&... args) {
            return qb::http::timing_middleware<SessionType>(std::forward<Args>(args)...);
        }

        // --- Rate limit -------------------------------------------------------
        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::rate_limit, Args &&... args) {
            return qb::http::rate_limit_middleware<SessionType>(std::forward<Args>(args)...);
        }

        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::rate_limit_dev, Args &&... args) {
            return qb::http::rate_limit_dev_middleware<SessionType>(std::forward<Args>(args)...);
        }

        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::rate_limit_secure, Args &&... args) {
            return qb::http::rate_limit_secure_middleware<SessionType>(std::forward<Args>(args)...);
        }

        // --- Security / delivery ---------------------------------------------
        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::security_headers, Args &&... args) {
            return qb::http::security_headers_middleware<SessionType>(std::forward<Args>(args)...);
        }

        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::static_files, Args &&... args) {
            return qb::http::static_files_middleware<SessionType>(std::forward<Args>(args)...);
        }

        // --- Structural -------------------------------------------------------
        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::transform, Args &&... args) {
            return qb::http::transform_middleware<SessionType>(std::forward<Args>(args)...);
        }

        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::conditional, Args &&... args) {
            return qb::http::conditional_middleware<SessionType>(std::forward<Args>(args)...);
        }

        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::error_handling, Args &&... args) {
            return qb::http::error_handling_middleware<SessionType>(std::forward<Args>(args)...);
        }

        // --- JWT (raw) --------------------------------------------------------
        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::jwt, Args &&... args) {
            return qb::http::jwt_middleware<SessionType>(std::forward<Args>(args)...);
        }

#ifdef QB_HTTP_HAS_RECAPTCHA_MIDDLEWARE
        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::recaptcha, Args &&... args) {
            return qb::http::recaptcha_middleware<SessionType>(std::forward<Args>(args)...);
        }

        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::recaptcha_v3, Args &&... args) {
            return qb::http::recaptcha_v3_middleware<SessionType>(std::forward<Args>(args)...);
        }

        template<typename SessionType, typename... Args>
        [[nodiscard]] auto make_dispatch(tags::recaptcha_strict, Args &&... args) {
            return qb::http::recaptcha_strict_middleware<SessionType>(std::forward<Args>(args)...);
        }
#endif
    } // namespace detail

    /**
     * @brief Construct a middleware identified by `Tag` for the session `SessionType`.
     *
     * @tparam Tag         A middleware tag defined in `qb::http::middleware::tags`.
     * @tparam SessionType The router session type (`DefaultSession` for server-side,
     *                     custom types for richer contexts).
     * @param args         Arguments forwarded verbatim to the underlying factory.
     * @return The `std::shared_ptr<...>` produced by the selected factory.
     *
     * Selecting an unknown tag fails at compile time with a clear diagnostic.
     */
    template<typename Tag, typename SessionType, typename... Args>
    [[nodiscard]] auto make(Args &&... args) {
        return detail::make_dispatch<SessionType>(Tag{}, std::forward<Args>(args)...);
    }
} // namespace qb::http::middleware
