/**
 * @file qbm/http/tests/test-auth-manager.cpp
 * @brief Unit tests for the qb::http::auth::Manager API (JWT issue/verify, token payload).
 *
 * These tests exercise the Manager class directly (not through the AuthMiddleware),
 * targeting the previously-uncovered code paths in qbm/http/auth/manager.cpp:
 *   - generate_token / generate_token_payload (claim construction: sub, iat, exp,
 *     iss, aud, username, roles, metadata)
 *   - verify_token round-trip (HMAC HS256/HS384/HS512) including the
 *     signature-verified path and the unverified (require_signature_verification(false))
 *     path, which routes through decode_unverified_payload + parse_time_claim_as_int64
 *   - current_timestamp (exercised transitively via iat/exp generation)
 *   - extract_token_from_header edge cases
 *
 * No network is required; everything operates on in-memory tokens.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include "../auth.h" // qb::http::auth::{Manager, Options, User}

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <qb/io/crypto_jwt.h> // qb::jwt::create for forged/foreign tokens
#include <qb/json.h>          // qb::json

namespace {

using qb::http::auth::Manager;
using qb::http::auth::Options;
using qb::http::auth::User;

constexpr char kSecret[] = "unit_test_secret_key_for_auth_manager_!@#$%";

uint64_t
now_epoch() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

Options
hmac_options(const std::string &secret = kSecret) {
    Options opts;
    opts.secret_key(secret);
    return opts;
}

User
make_user() {
    User u;
    u.id       = "user-42";
    u.username = "alice";
    u.roles    = {"admin", "user"};
    u.metadata = {{"dept", "eng"}, {"tier", "gold"}};
    return u;
}

// Build a raw HS256 token directly from a JSON payload, mirroring how the
// production code maps payload values into the std::map<string,string> JWT
// claim set (string values pass through, everything else is dumped).
std::string
forge_token(const qb::json &payload, const std::string &secret = kSecret, qb::jwt::Algorithm algo = qb::jwt::Algorithm::HS256) {
    std::map<std::string, std::string> claims;
    for (auto it = payload.begin(); it != payload.end(); ++it) {
        claims[it.key()] = it.value().is_string() ? it.value().get<std::string>() : it.value().dump();
    }
    qb::jwt::CreateOptions create_opts;
    create_opts.algorithm = algo;
    create_opts.key       = secret;
    return qb::jwt::create(claims, create_opts);
}

// ---------------------------------------------------------------------------
// generate_token_payload (public: unsigned claims JSON)
// ---------------------------------------------------------------------------

TEST(AuthManagerPayload, ContainsStandardAndUserClaims) {
    Manager     mgr(hmac_options());
    const User  user        = make_user();
    const auto  before      = now_epoch();
    std::string payload_str = mgr.generate_token_payload(user);
    const auto  after       = now_epoch();

    ASSERT_FALSE(payload_str.empty());
    qb::json payload = qb::json::parse(payload_str);

    EXPECT_EQ(payload.at("sub").get<std::string>(), "user-42");
    EXPECT_EQ(payload.at("username").get<std::string>(), "alice");

    ASSERT_TRUE(payload.at("roles").is_array());
    ASSERT_EQ(payload.at("roles").size(), 2u);
    EXPECT_EQ(payload.at("roles")[0].get<std::string>(), "admin");
    EXPECT_EQ(payload.at("roles")[1].get<std::string>(), "user");

    // iat is bounded by the wall-clock window around generation.
    ASSERT_TRUE(payload.contains("iat"));
    const auto iat = payload.at("iat").get<uint64_t>();
    EXPECT_GE(iat, before);
    EXPECT_LE(iat, after);

    // Default options enable expiration verification -> exp present and in the future.
    ASSERT_TRUE(payload.contains("exp"));
    EXPECT_GT(payload.at("exp").get<uint64_t>(), iat);
    EXPECT_EQ(payload.at("exp").get<uint64_t>(), iat + 3600u);

    // Metadata is serialized as a nested object.
    ASSERT_TRUE(payload.contains("metadata"));
    ASSERT_TRUE(payload.at("metadata").is_object());
    EXPECT_EQ(payload.at("metadata").at("dept").get<std::string>(), "eng");
    EXPECT_EQ(payload.at("metadata").at("tier").get<std::string>(), "gold");

    // Issuer/audience are off by default.
    EXPECT_FALSE(payload.contains("iss"));
    EXPECT_FALSE(payload.contains("aud"));
}

TEST(AuthManagerPayload, OmitsExpWhenVerificationDisabledAndIncludesIssAud) {
    Options opts = hmac_options();
    opts.verify_expiration(false);
    opts.token_issuer("issuer-x"); // also enables verify_issuer
    opts.token_audience("aud-y");  // also enables verify_audience
    Manager mgr(opts);

    User u;
    u.id       = "no-meta";
    u.username = "bob";
    // No metadata -> "metadata" key must be omitted.

    qb::json payload = qb::json::parse(mgr.generate_token_payload(u));

    EXPECT_FALSE(payload.contains("exp"));
    EXPECT_FALSE(payload.contains("metadata"));
    ASSERT_TRUE(payload.contains("iss"));
    EXPECT_EQ(payload.at("iss").get<std::string>(), "issuer-x");
    ASSERT_TRUE(payload.contains("aud"));
    EXPECT_EQ(payload.at("aud").get<std::string>(), "aud-y");
}

// ---------------------------------------------------------------------------
// generate_token + verify_token round-trip (signature-verified path)
// ---------------------------------------------------------------------------

TEST(AuthManagerRoundTrip, ValidHmacTokenRoundTrips) {
    Manager     mgr(hmac_options());
    const User  user  = make_user();
    std::string token = mgr.generate_token(user);
    ASSERT_FALSE(token.empty());

    auto out = mgr.verify_token(token);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->id, "user-42");
    EXPECT_EQ(out->username, "alice");
    EXPECT_TRUE(out->has_role("admin"));
    EXPECT_TRUE(out->has_role("user"));
    EXPECT_FALSE(out->has_role("superadmin"));
    EXPECT_EQ(out->metadata.at("dept"), "eng");
    EXPECT_EQ(out->metadata.at("tier"), "gold");
}

TEST(AuthManagerRoundTrip, HmacSha384AndSha512RoundTrip) {
    for (auto algo : {Options::Algorithm::HMAC_SHA384, Options::Algorithm::HMAC_SHA512}) {
        Options opts = hmac_options();
        opts.algorithm(algo);
        Manager     mgr(opts);
        const User  user  = make_user();
        std::string token = mgr.generate_token(user);
        ASSERT_FALSE(token.empty());

        auto out = mgr.verify_token(token);
        ASSERT_TRUE(out.has_value()) << "algorithm index " << static_cast<int>(algo);
        EXPECT_EQ(out->id, "user-42");
        EXPECT_TRUE(out->has_role("admin"));
    }
}

TEST(AuthManagerRoundTrip, IssuerAndAudienceRoundTrip) {
    Options opts = hmac_options();
    opts.token_issuer("my-issuer");
    opts.token_audience("my-audience");
    Manager mgr(opts);

    std::string token = mgr.generate_token(make_user());
    auto        out   = mgr.verify_token(token);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->id, "user-42");
}

// ---------------------------------------------------------------------------
// verify_token rejection paths (signature-verified)
// ---------------------------------------------------------------------------

TEST(AuthManagerVerify, WrongSecretIsRejected) {
    Manager     issuer(hmac_options());
    std::string token = issuer.generate_token(make_user());

    Manager verifier(hmac_options("a_totally_different_secret"));
    EXPECT_FALSE(verifier.verify_token(token).has_value());
}

TEST(AuthManagerVerify, TamperedTokenIsRejected) {
    Manager     mgr(hmac_options());
    std::string token = mgr.generate_token(make_user());

    // Flip a byte inside the payload segment to break the signature.
    const auto first_dot = token.find('.');
    ASSERT_NE(first_dot, std::string::npos);
    const auto second_dot = token.find('.', first_dot + 1);
    ASSERT_NE(second_dot, std::string::npos);
    std::string tampered    = token;
    tampered[first_dot + 1] = (tampered[first_dot + 1] == 'A' ? 'B' : 'A');

    EXPECT_FALSE(mgr.verify_token(tampered).has_value());
}

TEST(AuthManagerVerify, MalformedTokenIsRejected) {
    Manager mgr(hmac_options());
    EXPECT_FALSE(mgr.verify_token("not-a-jwt").has_value());
    EXPECT_FALSE(mgr.verify_token("").has_value());
    EXPECT_FALSE(mgr.verify_token("a.b.c").has_value());
}

TEST(AuthManagerVerify, ExpiredTokenIsRejected) {
    Options opts = hmac_options();
    opts.token_expiration(std::chrono::seconds(-3600)); // already expired
    Manager     mgr(opts);
    std::string token = mgr.generate_token(make_user());

    EXPECT_FALSE(mgr.verify_token(token).has_value());
}

TEST(AuthManagerVerify, WrongIssuerIsRejected) {
    Options sign_opts = hmac_options();
    sign_opts.token_issuer("issuer-A");
    Manager     signer(sign_opts);
    std::string token = signer.generate_token(make_user());

    Options verify_opts = hmac_options();
    verify_opts.token_issuer("issuer-B");
    Manager verifier(verify_opts);
    EXPECT_FALSE(verifier.verify_token(token).has_value());
}

TEST(AuthManagerVerify, WrongAudienceIsRejected) {
    Options sign_opts = hmac_options();
    sign_opts.token_audience("aud-A");
    Manager     signer(sign_opts);
    std::string token = signer.generate_token(make_user());

    Options verify_opts = hmac_options();
    verify_opts.token_audience("aud-B");
    Manager verifier(verify_opts);
    EXPECT_FALSE(verifier.verify_token(token).has_value());
}

TEST(AuthManagerVerify, TokenWithoutSubjectOrUsernameIsRejected) {
    // Forge a signature-valid token that carries neither sub nor username.
    qb::json payload;
    payload["roles"]  = qb::json::array({"user"});
    payload["iat"]    = now_epoch();
    payload["exp"]    = now_epoch() + 3600;
    std::string token = forge_token(payload);

    Manager mgr(hmac_options());
    EXPECT_FALSE(mgr.verify_token(token).has_value());
}

// ---------------------------------------------------------------------------
// Unverified path: require_signature_verification(false)
//   -> decode_unverified_payload + parse_time_claim_as_int64 + claim checks
// ---------------------------------------------------------------------------

TEST(AuthManagerUnverified, AcceptsValidPayloadWithoutSignatureCheck) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    Manager mgr(opts);

    // Token signed with a DIFFERENT secret: signature would fail, but it is not checked.
    qb::json payload;
    payload["sub"]      = "ghost";
    payload["username"] = "ghostuser";
    payload["roles"]    = qb::json::array({"reader"});
    payload["iat"]      = now_epoch();
    payload["exp"]      = now_epoch() + 3600;
    std::string token   = forge_token(payload, "some_other_secret");

    auto out = mgr.verify_token(token);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->id, "ghost");
    EXPECT_EQ(out->username, "ghostuser");
    EXPECT_TRUE(out->has_role("reader"));
}

TEST(AuthManagerUnverified, ExpiredPayloadRejectedEvenWithoutSignatureCheck) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    Manager mgr(opts);

    qb::json payload;
    payload["sub"]    = "expired";
    payload["exp"]    = now_epoch() - 100; // expired, no skew tolerance
    std::string token = forge_token(payload, "irrelevant_secret");

    EXPECT_FALSE(mgr.verify_token(token).has_value());
}

TEST(AuthManagerUnverified, StringExpClaimIsParsedAsInt64) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    Manager mgr(opts);

    // exp delivered as a numeric string -> parse_time_claim_as_int64 string branch.
    qb::json payload;
    payload["sub"]    = "strexp";
    payload["exp"]    = std::to_string(now_epoch() + 3600);
    std::string token = forge_token(payload, "irrelevant_secret");

    auto out = mgr.verify_token(token);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->id, "strexp");
}

TEST(AuthManagerUnverified, NonNumericExpClaimIsRejected) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    Manager mgr(opts);

    qb::json payload;
    payload["sub"]    = "badexp";
    payload["exp"]    = "not-a-number"; // parse_time_claim_as_int64 returns nullopt
    std::string token = forge_token(payload, "irrelevant_secret");

    EXPECT_FALSE(mgr.verify_token(token).has_value());
}

TEST(AuthManagerUnverified, NotYetValidNbfIsRejected) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    opts.verify_not_before(true);
    Manager mgr(opts);

    qb::json payload;
    payload["sub"]    = "future";
    payload["nbf"]    = now_epoch() + 3600; // not valid yet, no skew tolerance
    std::string token = forge_token(payload, "irrelevant_secret");

    EXPECT_FALSE(mgr.verify_token(token).has_value());
}

TEST(AuthManagerUnverified, ClockSkewToleratesRecentlyExpiredToken) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    opts.clock_skew_tolerance(std::chrono::seconds(120));
    Manager mgr(opts);

    qb::json payload;
    payload["sub"]    = "skewed";
    payload["exp"]    = now_epoch() - 10; // expired 10s ago, within 120s tolerance
    std::string token = forge_token(payload, "irrelevant_secret");

    auto out = mgr.verify_token(token);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->id, "skewed");
}

TEST(AuthManagerUnverified, IssuerMismatchRejectedWithoutSignatureCheck) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    opts.token_issuer("expected-iss");
    Manager mgr(opts);

    qb::json payload;
    payload["sub"]    = "u";
    payload["iss"]    = "other-iss";
    std::string token = forge_token(payload, "irrelevant_secret");
    EXPECT_FALSE(mgr.verify_token(token).has_value());

    // Missing iss entirely is also rejected.
    qb::json no_iss;
    no_iss["sub"] = "u";
    EXPECT_FALSE(mgr.verify_token(forge_token(no_iss, "irrelevant_secret")).has_value());
}

// Hand-craft a JWT whose payload JSON is `payload_obj` verbatim. Needed when a
// claim must reach decode_unverified_payload() as a NATIVE JSON type (e.g. an
// array `aud`); qb::jwt::create() would stringify non-string claim values.
std::string
forge_token_raw_payload(const qb::json &payload_obj) {
    auto b64url = [](const std::string &s) {
        return qb::crypto::base64url_encode(std::vector<unsigned char>(s.begin(), s.end()));
    };
    const std::string header_b64    = b64url(R"({"alg":"HS256","typ":"JWT"})");
    const std::string payload_b64   = b64url(payload_obj.dump());
    const std::string signature_b64 = b64url("sig"); // unchecked on the unverified path
    return header_b64 + "." + payload_b64 + "." + signature_b64;
}

TEST(AuthManagerUnverified, AudienceAsArrayIsMatched) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    opts.token_audience("svc-b");
    Manager mgr(opts);

    // aud as a native JSON array containing the expected audience -> array branch.
    qb::json payload;
    payload["sub"]    = "u";
    payload["aud"]    = qb::json::array({"svc-a", "svc-b", "svc-c"});
    std::string token = forge_token_raw_payload(payload);

    auto out = mgr.verify_token(token);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->id, "u");
}

TEST(AuthManagerUnverified, AudienceArrayWithoutMatchIsRejected) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    opts.token_audience("svc-z");
    Manager mgr(opts);

    qb::json payload;
    payload["sub"]    = "u";
    payload["aud"]    = qb::json::array({"svc-a", "svc-b"});
    std::string token = forge_token_raw_payload(payload);

    EXPECT_FALSE(mgr.verify_token(token).has_value());
}

TEST(AuthManagerUnverified, RolesAsJsonStringArrayAreParsed) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    Manager mgr(opts);

    // roles delivered as a stringified JSON array (the qb::jwt::create wire form).
    qb::json payload;
    payload["sub"]    = "u";
    payload["roles"]  = qb::json::array({"editor", "viewer"}).dump(); // string value
    std::string token = forge_token(payload, "irrelevant_secret");

    auto out = mgr.verify_token(token);
    ASSERT_TRUE(out.has_value());
    EXPECT_TRUE(out->has_role("editor"));
    EXPECT_TRUE(out->has_role("viewer"));
}

TEST(AuthManagerUnverified, MetadataAsStringObjectIsParsed) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    Manager mgr(opts);

    qb::json meta;
    meta["region"] = "eu";
    qb::json payload;
    payload["sub"]      = "u";
    payload["metadata"] = meta.dump(); // string value -> parsed back
    std::string token   = forge_token(payload, "irrelevant_secret");

    auto out = mgr.verify_token(token);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->metadata.at("region"), "eu");
}

TEST(AuthManagerUnverified, NonObjectPayloadIsRejected) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    Manager mgr(opts);

    // Hand-craft a structurally valid JWT whose payload segment decodes to a
    // JSON array instead of an object -> verify_token's `!is_object()` branch.
    auto b64url = [](const std::string &s) {
        return qb::crypto::base64url_encode(std::vector<unsigned char>(s.begin(), s.end()));
    };
    const std::string header_b64    = b64url(R"({"alg":"HS256","typ":"JWT"})");
    const std::string payload_b64   = b64url(R"([1,2,3])"); // valid JSON, not an object
    const std::string signature_b64 = b64url("sig");        // unchecked on this path
    const std::string token         = header_b64 + "." + payload_b64 + "." + signature_b64;

    EXPECT_FALSE(mgr.verify_token(token).has_value());
}

// ---------------------------------------------------------------------------
// extract_token_from_header
// ---------------------------------------------------------------------------

TEST(AuthManagerExtract, ExtractsBearerToken) {
    Manager mgr(hmac_options());
    EXPECT_EQ(mgr.extract_token_from_header("Bearer abc.def.ghi"), "abc.def.ghi");
    // Case-insensitive scheme + surrounding whitespace tolerance.
    EXPECT_EQ(mgr.extract_token_from_header("  bearer   abc.def.ghi  "), "abc.def.ghi");
}

TEST(AuthManagerExtract, RejectsBadHeaders) {
    Manager mgr(hmac_options());
    EXPECT_TRUE(mgr.extract_token_from_header("").empty());
    EXPECT_TRUE(mgr.extract_token_from_header("   \t  ").empty());
    EXPECT_TRUE(mgr.extract_token_from_header("Basic abc.def.ghi").empty());
    EXPECT_TRUE(mgr.extract_token_from_header("Bearerabc").empty()); // no space after scheme
    EXPECT_TRUE(mgr.extract_token_from_header("Bearer   ").empty()); // scheme but no token
}

TEST(AuthManagerExtract, CustomScheme) {
    Options opts = hmac_options();
    opts.auth_scheme("Token");
    Manager mgr(opts);
    EXPECT_EQ(mgr.extract_token_from_header("Token xyz"), "xyz");
    EXPECT_TRUE(mgr.extract_token_from_header("Bearer xyz").empty());
}

// ---------------------------------------------------------------------------
// Manager option accessors / mutation
// ---------------------------------------------------------------------------

TEST(AuthManagerOptions, GetAndSetOptions) {
    Manager mgr;
    EXPECT_TRUE(mgr.get_options().get_secret_key().empty());

    Options opts = hmac_options();
    opts.token_issuer("issX");
    mgr.set_options(opts);
    EXPECT_FALSE(mgr.get_options().get_secret_key().empty());
    EXPECT_EQ(mgr.get_options().get_token_issuer(), "issX");
    EXPECT_TRUE(mgr.get_options().get_verify_issuer());
}

} // namespace
