/**
 * @file qbm/http/tests/shared/auth_test_helpers.h
 * @brief Shared JWT / auth fixtures for the qbm-http test suite.
 *
 * Reconciles the inline token-forging and options/user builders that were
 * duplicated across the auth and JWT-middleware test translation units into a
 * single canonical set of free helpers, all operating on the real framework
 * types (@c qb::http::auth::{Options,User} and @c qb::jwt).
 *
 * Reconciled from:
 *   - tests/unit/auth/auth-manager.cpp        (now_epoch, hmac_options, make_user,
 *                                              forge_token, forge_token_raw_payload,
 *                                              kSecret)
 *   - tests/unit/middleware/middleware-jwt.cpp (claim-map token generation; the
 *                                              fixture-local generate_token there is
 *                                              JwtOptions-driven and stays inline, but
 *                                              its raw qb::jwt::create claim-map shape
 *                                              is captured by forge_token/forge_claims_token)
 *
 * Token-wire-format note (matches production qb::http::auth::Manager):
 *   qb::jwt::create() takes a std::map<string,string> claim set. Non-string JSON
 *   values are therefore stringified (numbers -> their decimal text, arrays/objects
 *   -> their compact dump). @ref forge_token mirrors that mapping. When a claim must
 *   reach the verifier as a NATIVE JSON type (e.g. an array `aud`, or a non-object
 *   top-level payload), use @ref forge_token_raw_payload, which hand-builds the JWT
 *   so the payload segment decodes verbatim.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#ifndef QBM_HTTP_TESTS_SHARED_AUTH_TEST_HELPERS_H
#define QBM_HTTP_TESTS_SHARED_AUTH_TEST_HELPERS_H

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <qb/io/crypto.h>     // qb::crypto::base64url_encode
#include <qb/io/crypto_jwt.h> // qb::jwt::{create, CreateOptions, Algorithm}
#include <qb/json.h>          // qb::json

#include "../../auth.h" // qb::http::auth::{Options, User}

namespace qb::http::test {

/**
 * @brief Default HMAC secret used by the shared auth helpers.
 *
 * A long, non-trivial string so that signature-verification tests exercise a
 * realistic key. Individual tests may pass their own secret to override it.
 */
inline constexpr char kDefaultSecret[] = "unit_test_secret_key_for_auth_manager_!@#$%";

/**
 * @brief Current UNIX epoch time, in whole seconds, as an unsigned 64-bit value.
 *
 * Used to stamp / bound `iat`, `exp`, `nbf` claims in forged tokens and to
 * assert generated-token time windows.
 */
inline std::uint64_t
now_epoch() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

/**
 * @brief Build an HMAC @c auth::Options pre-loaded with a secret key.
 *
 * Leaves every other policy at its framework default (HS256, verify exp/nbf,
 * 1h expiry, "Authorization"/"Bearer" extraction). Tests chain further fluent
 * setters on the returned value.
 *
 * @param secret HMAC secret (defaults to @ref kDefaultSecret).
 */
inline qb::http::auth::Options
hmac_options(const std::string &secret = kDefaultSecret) {
    qb::http::auth::Options opts;
    opts.secret_key(secret);
    return opts;
}

/**
 * @brief Build a representative authenticated @c auth::User.
 *
 * Carries an id, username, two roles, and two metadata entries — enough to
 * exercise the full claim-mapping path (sub/username/roles/metadata) of the
 * auth Manager round-trip.
 */
inline qb::http::auth::User
make_user() {
    qb::http::auth::User u;
    u.id       = "user-42";
    u.username = "alice";
    u.roles    = {"admin", "user"};
    u.metadata = {{"dept", "eng"}, {"tier", "gold"}};
    return u;
}

/**
 * @brief Forge a signed JWT from a JSON payload, mirroring production claim mapping.
 *
 * Each top-level key of @p payload becomes a claim: string values pass through
 * unchanged, every other JSON type is serialized via @c dump() (numbers ->
 * decimal text, arrays/objects -> compact JSON text). This is exactly how
 * @c qb::http::auth::Manager projects a payload onto the
 * @c std::map<string,string> claim set that @c qb::jwt::create() consumes, so a
 * forged token is wire-indistinguishable from a Manager-issued one.
 *
 * @param payload Top-level JSON object of claims.
 * @param secret  HMAC signing secret (defaults to @ref kDefaultSecret).
 * @param algo    JWT algorithm (defaults to HS256).
 * @return The compact-serialized JWT string.
 */
inline std::string
forge_token(const qb::json &payload, const std::string &secret = kDefaultSecret,
            qb::jwt::Algorithm algo = qb::jwt::Algorithm::HS256) {
    std::map<std::string, std::string> claims;
    for (auto it = payload.begin(); it != payload.end(); ++it) {
        claims[it.key()] = it.value().is_string() ? it.value().get<std::string>() : it.value().dump();
    }
    qb::jwt::CreateOptions create_opts;
    create_opts.algorithm = algo;
    create_opts.key       = secret;
    return qb::jwt::create(claims, create_opts);
}

/**
 * @brief Forge a signed JWT directly from a pre-built string claim map.
 *
 * Convenience for tests that already think in terms of the
 * @c std::map<string,string> wire form (the shape the JWT-middleware fixture
 * uses). No JSON-to-claim projection is applied.
 *
 * @param claims Claim map (values are taken verbatim).
 * @param secret HMAC signing secret (defaults to @ref kDefaultSecret).
 * @param algo   JWT algorithm (defaults to HS256).
 */
inline std::string
forge_claims_token(const std::map<std::string, std::string> &claims, const std::string &secret = kDefaultSecret,
                   qb::jwt::Algorithm algo = qb::jwt::Algorithm::HS256) {
    qb::jwt::CreateOptions create_opts;
    create_opts.algorithm = algo;
    create_opts.key       = secret;
    return qb::jwt::create(claims, create_opts);
}

/**
 * @brief Hand-craft a JWT whose payload segment decodes to @p payload_obj verbatim.
 *
 * Needed when a claim must reach the unverified-decode path as a NATIVE JSON
 * type — e.g. an array `aud`, or a structurally-valid-but-non-object payload —
 * which @ref forge_token / @c qb::jwt::create() would otherwise stringify.
 *
 * The signature segment is a fixed placeholder (base64url of "sig"); this helper
 * is only meaningful on verifier paths that do NOT check the signature
 * (`require_signature_verification(false)`).
 *
 * @param payload_obj The exact JSON value to encode as the payload segment
 *                    (may be an object, array, or scalar).
 * @return A three-segment `header.payload.signature` JWT string.
 */
inline std::string
forge_token_raw_payload(const qb::json &payload_obj) {
    const auto b64url = [](const std::string &s) {
        return qb::crypto::base64url_encode(std::vector<unsigned char>(s.begin(), s.end()));
    };
    const std::string header_b64    = b64url(R"({"alg":"HS256","typ":"JWT"})");
    const std::string payload_b64   = b64url(payload_obj.dump());
    const std::string signature_b64 = b64url("sig"); // unchecked on the unverified path
    return header_b64 + "." + payload_b64 + "." + signature_b64;
}

} // namespace qb::http::test

#endif // QBM_HTTP_TESTS_SHARED_AUTH_TEST_HELPERS_H
