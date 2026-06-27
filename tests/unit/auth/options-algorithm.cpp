/**
 * @file qbm/http/tests/unit/auth/options-algorithm.cpp
 * @brief Unit tests for qb::http::auth::Options::algorithm_from_string.
 *
 * Resolves a textual JWT `alg` identifier (HS256.., RS256.., ES256.., EdDSA) to the
 * Options::Algorithm enum, case-insensitively, and returns std::nullopt for anything
 * unrecognised. Pure logic — no daemon, no event loop, parallel-safe.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <optional>
#include <string_view>
#include <gtest/gtest.h>

#include "../auth.h" // qb::http::auth::Options

using Algorithm = qb::http::auth::Options::Algorithm;
using qb::http::auth::Options;

// Every canonical JWT `alg` value maps to its enum.
TEST(AuthOptionsAlgorithm, MapsEveryCanonicalIdentifier) {
    EXPECT_EQ(Options::algorithm_from_string("HS256"), Algorithm::HMAC_SHA256);
    EXPECT_EQ(Options::algorithm_from_string("HS384"), Algorithm::HMAC_SHA384);
    EXPECT_EQ(Options::algorithm_from_string("HS512"), Algorithm::HMAC_SHA512);
    EXPECT_EQ(Options::algorithm_from_string("RS256"), Algorithm::RSA_SHA256);
    EXPECT_EQ(Options::algorithm_from_string("RS384"), Algorithm::RSA_SHA384);
    EXPECT_EQ(Options::algorithm_from_string("RS512"), Algorithm::RSA_SHA512);
    EXPECT_EQ(Options::algorithm_from_string("ES256"), Algorithm::ECDSA_SHA256);
    EXPECT_EQ(Options::algorithm_from_string("ES384"), Algorithm::ECDSA_SHA384);
    EXPECT_EQ(Options::algorithm_from_string("ES512"), Algorithm::ECDSA_SHA512);
    EXPECT_EQ(Options::algorithm_from_string("EdDSA"), Algorithm::ED25519);
}

// Resolution is case-insensitive (iequals).
TEST(AuthOptionsAlgorithm, IsCaseInsensitive) {
    EXPECT_EQ(Options::algorithm_from_string("hs256"), Algorithm::HMAC_SHA256);
    EXPECT_EQ(Options::algorithm_from_string("Hs256"), Algorithm::HMAC_SHA256);
    EXPECT_EQ(Options::algorithm_from_string("rs512"), Algorithm::RSA_SHA512);
    EXPECT_EQ(Options::algorithm_from_string("eS384"), Algorithm::ECDSA_SHA384);
    EXPECT_EQ(Options::algorithm_from_string("eddsa"), Algorithm::ED25519);
    EXPECT_EQ(Options::algorithm_from_string("EDDSA"), Algorithm::ED25519);
}

// Anything not in the table resolves to std::nullopt.
TEST(AuthOptionsAlgorithm, UnknownResolvesToNullopt) {
    for (std::string_view bad : {"", "HS", "HS999", "RS25", "none", "NONE", "PS256", "HS2560", " HS256", "HS256 "}) {
        EXPECT_FALSE(Options::algorithm_from_string(bad).has_value()) << "unexpectedly mapped: [" << bad << "]";
    }
}

int
main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
