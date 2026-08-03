/**
 * @file qbm/http/tests/unit/auth/auth-manager.cpp
 * @brief Unit tests for the qb::http::auth::Manager API (JWT issue/verify, token payload).
 *
 * These tests exercise the `Manager` class directly (not through the
 * `AuthMiddleware`), targeting the code paths in `qbm/http/auth/manager.cpp`:
 *   - `generate_token` / `generate_token_payload` (claim construction: sub, iat,
 *     exp, iss, aud, username, roles, metadata)
 *   - `verify_token` round-trip (HMAC HS256/HS384/HS512) including the
 *     signature-verified path and the unverified
 *     (`require_signature_verification(false)`) path, which routes through
 *     `decode_unverified_payload` + `parse_time_claim_as_int64`
 *   - `current_timestamp` (exercised transitively via iat/exp generation)
 *   - `extract_token_from_header` edge cases
 *
 * Tier: **unit** with a real `ssl` build dependency — `qb/io/crypto.h` `#error`s
 * without OpenSSL, so HMAC/JWT genuinely cannot link without it. No network,
 * engine, socket, or event loop is involved; everything operates on in-memory
 * tokens via synchronous `Manager` calls.
 *
 * Token-forging helpers (`forge_token`, `forge_token_raw_payload`, `now_epoch`,
 * `hmac_options`, `make_user`) come from the shared
 * `shared/auth_test_helpers.h`, deduplicated against `middleware-jwt.cpp` and the
 * auth benchmark.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <chrono>
#include <cstdint>
#include <string>

#include <gtest/gtest.h>

#include <qb/io/crypto.h> // qb::crypto::generate_{rsa,ec,ed25519}_keypair
#include <qb/json.h>      // qb::json

#include "../../shared/auth_test_helpers.h" // forge_token, forge_token_raw_payload, now_epoch, hmac_options, make_user
#include <qbm/http/auth.h>                        // qb::http::auth::{Manager, Options, User}

namespace {

using qb::http::auth::Manager;
using qb::http::auth::Options;
using qb::http::auth::User;

using qb::http::test::forge_token;
using qb::http::test::forge_token_raw_payload;
using qb::http::test::hmac_options;
using qb::http::test::kDefaultSecret;
using qb::http::test::make_user;
using qb::http::test::now_epoch;

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
    const auto iat = payload.at("iat").get<std::uint64_t>();
    EXPECT_GE(iat, before);
    EXPECT_LE(iat, after);

    // Default options enable expiration verification -> exp present and in the future.
    // manager.cpp reads the wall clock TWICE (once for iat, once for exp = now()+3600),
    // so a one-second boundary straddle between the two reads makes exp == iat+3601
    // legitimately. Assert exp - iat is the expected 3600 +/- the 1s straddle window
    // rather than pinning the exact value (which would flake at a second rollover).
    ASSERT_TRUE(payload.contains("exp"));
    const auto exp = payload.at("exp").get<std::uint64_t>();
    EXPECT_GT(exp, iat);
    EXPECT_GE(exp - iat, 3600u);
    EXPECT_LE(exp - iat, 3601u);

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

// ---------------------------------------------------------------------------
// Asymmetric round-trips (RSA RS384/RS512, ECDSA ES384/ES512, EdDSA)
//
// The HMAC tests above cover the symmetric algorithm branches; these drive the asymmetric
// algorithm-mapping switches (both the sign and the verify path in auth::Manager) and the
// public/private-key handling, using freshly generated keypairs (no checked-in PEM material).
// RS256 / ES256 are already exercised by the middleware-auth suite; here we close the 384/512 +
// EdDSA branches. Each test mints a token with the private key and verifies it with the public key,
// proving a real end-to-end sign+verify per algorithm — not just an enum mapping.
// ---------------------------------------------------------------------------

namespace {
void
expect_asymmetric_roundtrip(Options::Algorithm algo, const std::string &priv, const std::string &pub) {
    Options sign_opts;
    sign_opts.algorithm(algo).private_key(priv).secret_key("");
    Options verify_opts;
    verify_opts.algorithm(algo).public_key(pub).secret_key("");

    const User  user  = make_user();
    std::string token = Manager(sign_opts).generate_token(user);
    ASSERT_FALSE(token.empty()) << "sign failed for algorithm index " << static_cast<int>(algo);

    auto out = Manager(verify_opts).verify_token(token);
    ASSERT_TRUE(out.has_value()) << "verify failed for algorithm index " << static_cast<int>(algo);
    EXPECT_EQ(out->id, "user-42");
    EXPECT_TRUE(out->has_role("admin"));
}
} // namespace

TEST(AuthManagerRoundTrip, RsaSha384AndSha512RoundTrip) {
    auto [priv, pub] = qb::crypto::generate_rsa_keypair(2048); // {private, public}
    ASSERT_FALSE(priv.empty());
    ASSERT_FALSE(pub.empty());
    expect_asymmetric_roundtrip(Options::Algorithm::RSA_SHA384, priv, pub);
    expect_asymmetric_roundtrip(Options::Algorithm::RSA_SHA512, priv, pub);
}

TEST(AuthManagerRoundTrip, EcdsaSha384RoundTrip) {
    auto [priv, pub] = qb::crypto::generate_ec_keypair("secp384r1"); // P-384 for ES384
    ASSERT_FALSE(priv.empty());
    expect_asymmetric_roundtrip(Options::Algorithm::ECDSA_SHA384, priv, pub);
}

TEST(AuthManagerRoundTrip, EcdsaSha512RoundTrip) {
    auto [priv, pub] = qb::crypto::generate_ec_keypair("secp521r1"); // P-521 for ES512
    ASSERT_FALSE(priv.empty());
    expect_asymmetric_roundtrip(Options::Algorithm::ECDSA_SHA512, priv, pub);
}

TEST(AuthManagerRoundTrip, Ed25519RoundTrip) {
    auto [priv, pub] = qb::crypto::generate_ed25519_keypair();
    ASSERT_FALSE(priv.empty());
    expect_asymmetric_roundtrip(Options::Algorithm::ED25519, priv, pub);
}

// ---------------------------------------------------------------------------
// Malformed-claim robustness (security): a signature-valid token with a bad claim shape must
// degrade gracefully, never crash. exp verification is disabled so the forged (exp-less) token
// reaches the claim-extraction path.
// ---------------------------------------------------------------------------

// A "roles" claim whose string value is not parseable JSON must verify (signature is valid) but
// leave roles empty — the parse failure is caught + logged, not fatal. Drives the roles-parse
// catch branch in auth::Manager.
TEST(AuthManagerRoundTrip, MalformedRolesClaimDegradesToEmpty) {
    Options opts = hmac_options();
    opts.verify_expiration(false);
    Manager mgr(opts);

    qb::json payload;
    payload["sub"]    = "user-x";
    payload["roles"]  = "this is not valid json {";           // a string that fails json::parse
    std::string token = qb::http::test::forge_token(payload); // signed with the default secret

    auto out = mgr.verify_token(token);
    ASSERT_TRUE(out.has_value()) << "a malformed roles claim must not fail verification";
    EXPECT_EQ(out->id, "user-x");
    EXPECT_TRUE(out->roles.empty()) << "an unparseable roles claim must degrade to empty, not crash";
}

// Metadata with non-string values must be stringified to their JSON text (not dropped). Drives the
// metadata `it.value().dump()` else-branch.
TEST(AuthManagerRoundTrip, NonStringMetadataValuesAreStringified) {
    Options opts = hmac_options();
    opts.verify_expiration(false);
    Manager mgr(opts);

    qb::json payload;
    payload["sub"]      = "user-y";
    payload["metadata"] = qb::json{{"count", 5}, {"active", true}}; // numeric + bool values
    std::string token   = qb::http::test::forge_token(payload);

    auto out = mgr.verify_token(token);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->metadata.at("count"), "5") << "a numeric metadata value must be dumped to its JSON text";
    EXPECT_EQ(out->metadata.at("active"), "true");
}

// IssuerAndAudienceRoundTrip: the previous version only re-asserted out->id and
// dropped the iss/aud claims it had just round-tripped. A correct token is now
// proven to survive verification AND to carry the configured iss/aud back to the
// caller via the decoded payload, while a wrong-issuer / wrong-audience token
// minted with the SAME signing key is rejected (so rejection is attributable to
// the claim mismatch, not the signature).
TEST(AuthManagerRoundTrip, IssuerAndAudienceRoundTrip) {
    Options opts = hmac_options();
    opts.token_issuer("my-issuer");
    opts.token_audience("my-audience");
    Manager mgr(opts);

    std::string token = mgr.generate_token(make_user());
    auto        out   = mgr.verify_token(token);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->id, "user-42");

    // The generated payload must carry the exact iss/aud the options requested.
    qb::json payload = qb::json::parse(mgr.generate_token_payload(make_user()));
    ASSERT_TRUE(payload.contains("iss"));
    EXPECT_EQ(payload.at("iss").get<std::string>(), "my-issuer");
    ASSERT_TRUE(payload.contains("aud"));
    EXPECT_EQ(payload.at("aud").get<std::string>(), "my-audience");

    // Same secret, but a verifier expecting a different issuer rejects the token:
    // the failure is the claim mismatch, not a signature failure.
    Options wrong_iss = hmac_options();
    wrong_iss.token_issuer("not-my-issuer");
    wrong_iss.token_audience("my-audience");
    EXPECT_FALSE(Manager(wrong_iss).verify_token(token).has_value());

    Options wrong_aud = hmac_options();
    wrong_aud.token_issuer("my-issuer");
    wrong_aud.token_audience("not-my-audience");
    EXPECT_FALSE(Manager(wrong_aud).verify_token(token).has_value());
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

// ADDED (spec): fractional NumericDate exp. RFC 7519 declares NumericDate as a
// JSON number that MAY be non-integer, but Manager's parse_time_claim_as_int64
// only accepts integers and integer-shaped strings (no is_number_float branch).
// A native floating-point exp therefore fails to parse and the token is rejected
// even though the instant is comfortably in the future. This pins that contract
// (reject, do NOT crash, do NOT accept) so a future float-tolerant change is a
// deliberate decision rather than a silent regression.
TEST(AuthManagerUnverified, FractionalNumericDateExpIsRejected) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    Manager mgr(opts);

    // exp as a native JSON float (sub-second precision), far in the future.
    qb::json payload;
    payload["sub"]    = "frac";
    payload["exp"]    = static_cast<double>(now_epoch() + 3600) + 0.5;
    std::string token = forge_token_raw_payload(payload); // keep float native, not stringified

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

// ADDED (spec): far-future iat. The Manager validates exp/nbf/iss/aud on the
// unverified path but does NOT reject an issued-in-the-future `iat`. A token
// whose iat is years ahead is therefore accepted (only sub/identity matters).
// This pins the current "iat is informational, not enforced by Manager"
// contract — distinct from JwtMiddleware, which DOES reject a future iat.
TEST(AuthManagerUnverified, FarFutureIatIsAcceptedByManager) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    Manager mgr(opts);

    qb::json payload;
    payload["sub"]    = "timetraveler";
    payload["iat"]    = now_epoch() + 10ull * 365 * 24 * 3600; // ~10 years ahead
    payload["exp"]    = now_epoch() + 11ull * 365 * 24 * 3600;
    std::string token = forge_token(payload, "irrelevant_secret");

    auto out = mgr.verify_token(token);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->id, "timetraveler");
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

// ADDED (spec): single-string aud. The `aud` claim may be a single JSON string
// (not an array). Manager's is_string() branch compares it directly against the
// configured audience: an exact match passes, a non-match is rejected.
TEST(AuthManagerUnverified, AudienceAsSingleStringIsMatched) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    opts.token_audience("the-one-svc");
    Manager mgr(opts);

    qb::json payload;
    payload["sub"]    = "u";
    payload["aud"]    = "the-one-svc"; // single string, exact match
    std::string token = forge_token_raw_payload(payload);

    auto out = mgr.verify_token(token);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->id, "u");
}

TEST(AuthManagerUnverified, AudienceAsSingleStringMismatchIsRejected) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    opts.token_audience("expected-svc");
    Manager mgr(opts);

    qb::json payload;
    payload["sub"]    = "u";
    payload["aud"]    = "different-svc"; // single string, no match
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

    // A structurally valid JWT whose payload segment decodes to a JSON array
    // instead of an object -> verify_token's `!is_object()` branch.
    const std::string token = forge_token_raw_payload(qb::json::array({1, 2, 3}));

    EXPECT_FALSE(mgr.verify_token(token).has_value());
}

// verify_audience(true) but the token carries NO `aud` claim at all: the
// `!contains("aud")` guard rejects it. Every other audience test presents an aud
// that mismatches or matches; none exercises the missing-claim arm.
TEST(AuthManagerUnverified, MissingAudienceWhenRequiredIsRejected) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    opts.token_audience("required-svc"); // also enables verify_audience
    Manager mgr(opts);

    qb::json payload;
    payload["sub"] = "u";
    // No "aud" claim.
    std::string token = forge_token(payload, "irrelevant_secret");

    EXPECT_FALSE(mgr.verify_token(token).has_value());
}

// An `aud` claim that is neither a string nor an array (here a native JSON number)
// is malformed: the final `else` of the audience check rejects it. A raw payload
// keeps the number NATIVE — forge_token would stringify it into the is_string()
// arm instead, which is the wrong branch.
TEST(AuthManagerUnverified, AudienceOfWrongJsonTypeIsRejected) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    opts.token_audience("required-svc");
    Manager mgr(opts);

    qb::json payload;
    payload["sub"] = "u";
    payload["aud"] = 1234; // native JSON number: not string, not array
    std::string token = forge_token_raw_payload(payload);

    EXPECT_FALSE(mgr.verify_token(token).has_value());
}

// verify_not_before(true) with a non-numeric `nbf`: parse_time_claim_as_int64
// fails to parse the string and the nbf branch rejects the token. The existing
// NotYetValidNbfIsRejected drives a well-formed FUTURE nbf (parses, then now < nbf);
// this closes the parse-FAILURE arm of the nbf path instead.
TEST(AuthManagerUnverified, NonNumericNbfIsRejected) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    opts.verify_not_before(true); // default is already true; explicit for intent
    Manager mgr(opts);

    qb::json payload;
    payload["sub"] = "u";
    payload["nbf"] = "not-a-number"; // parse_time_claim_as_int64 -> nullopt
    std::string token = forge_token(payload, "irrelevant_secret");

    EXPECT_FALSE(mgr.verify_token(token).has_value());
}

// A NATIVE integer `exp` drives the is_number_integer() arm of
// parse_time_claim_as_int64 — distinct from the stringified exp qb::jwt::create
// emits (is_string arm) and the float exp covered elsewhere (rejected). A future
// integer exp parses cleanly and the token is accepted, pinning the integer-claim
// path the other exp tests never reach.
//
// NOTE: the sibling `is_number_unsigned() && > INT64_MAX` block in
// parse_time_claim_as_int64 is dead code — nlohmann's is_number_integer() already
// returns true for unsigned values, so an unsigned claim is consumed by the arm
// above before the unsigned branch is ever reached. There is therefore no input
// that exercises it, and no test is written for it.
TEST(AuthManagerUnverified, NativeIntegerExpClaimIsAccepted) {
    Options opts = hmac_options();
    opts.require_signature_verification(false);
    Manager mgr(opts);

    qb::json payload;
    payload["sub"] = "u";
    payload["exp"] = now_epoch() + 3600; // native JSON integer, well in the future
    std::string token = forge_token_raw_payload(payload);

    auto out = mgr.verify_token(token);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->id, "u");
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

// A header whose whitespace-trimmed length is below scheme.length()+2 (the scheme
// plus its separator plus at least one token char) is rejected up front by the
// length guard, before any scheme comparison. The RejectsBadHeaders cases are all
// at least that long (or whitespace-only, caught earlier); these are genuinely
// shorter and drive the length-guard arm.
TEST(AuthManagerExtract, HeaderShorterThanSchemePlusTwoIsRejected) {
    Manager mgr(hmac_options()); // default scheme "Bearer" (len 6) -> minimum length 8

    EXPECT_TRUE(mgr.extract_token_from_header("Bear").empty());   // 4 < 8
    EXPECT_TRUE(mgr.extract_token_from_header("Bearer").empty()); // 6 < 8 (scheme alone, no token)
    EXPECT_TRUE(mgr.extract_token_from_header("x").empty());      // 1 < 8
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
