/**
 * @file qbm/http/tests/unit/routing/routing-compile.cpp
 * @brief Route-pattern ambiguity validation at compile() time and recoverability.
 *
 * One of the four focused unit files carved out of the legacy `test-router.cpp`
 * monolith. Route patterns are validated when @ref qb::http::Router::compile() walks
 * the registered routes into the radix tree (see `routing/radix_tree.h`): a malformed
 * or ambiguous pattern throws `std::invalid_argument`. This file pins those throws and
 * — critically — that the router *recovers*: after a failed compile, a fresh router
 * (the documented reset idiom) compiles and serves valid routes normally.
 *
 * Adopts shared @ref qb::http::test::MockSession / create_request.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include "../http.h"
#include "../../shared/mock_session.h"

using qb::http::test::create_request;
using qb::http::test::MockSession;

namespace {

class RoutingCompileTest : public ::testing::Test {
protected:
    std::shared_ptr<MockSession>  session = std::make_shared<MockSession>();
    qb::http::Router<MockSession> router;

    static void
    noop_handler(std::shared_ptr<qb::http::Context<MockSession>> ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    }
};

// --------------------------------------------------------------------------
// Ambiguity validation
// --------------------------------------------------------------------------

TEST_F(RoutingCompileTest, DuplicateParameterNameThrows) {
    // Two segments capturing the same name (:id/:id) is ambiguous.
    router.get("/test/:id/:id", &RoutingCompileTest::noop_handler);

    EXPECT_THROW(router.compile(), std::invalid_argument);
}

TEST_F(RoutingCompileTest, ConflictingParameterAndWildcardNameThrows) {
    // A parameter and a wildcard sharing one capture name (:name/*name) is ambiguous.
    router.get("/other/:name/*name", &RoutingCompileTest::noop_handler);

    EXPECT_THROW(router.compile(), std::invalid_argument);
}

TEST_F(RoutingCompileTest, UnnamedWildcardThrows) {
    // A wildcard must be named (e.g. *rest); a bare '*' is rejected.
    router.get("/files/*", &RoutingCompileTest::noop_handler);

    EXPECT_THROW(router.compile(), std::invalid_argument);
}

TEST_F(RoutingCompileTest, UnnamedParameterThrows) {
    // A parameter must be named (e.g. :id); a bare ':' is rejected.
    router.get("/users/:/profile", &RoutingCompileTest::noop_handler);

    EXPECT_THROW(router.compile(), std::invalid_argument);
}

TEST_F(RoutingCompileTest, WildcardNotLastSegmentThrows) {
    // A wildcard must be the terminal segment; anything after it is illegal.
    router.get("/files/*rest/more", &RoutingCompileTest::noop_handler);

    EXPECT_THROW(router.compile(), std::invalid_argument);
}

TEST_F(RoutingCompileTest, ConflictingWildcardNamesAtSameLevelThrows) {
    // Two routes whose wildcard captures share a level but use different names
    // (*a vs *b) collide when the second is woven into the tree.
    router.get("/dl/*a", &RoutingCompileTest::noop_handler);
    router.post("/dl/*b", &RoutingCompileTest::noop_handler);

    EXPECT_THROW(router.compile(), std::invalid_argument);
}

TEST_F(RoutingCompileTest, ConflictingParameterNamesAtSameLevelThrows) {
    // Two routes that put a parameter at the same level but name it differently
    // (:x vs :y) are ambiguous — the radix node can hold only one param name.
    router.get("/api/:x/edit", &RoutingCompileTest::noop_handler);
    router.post("/api/:y/view", &RoutingCompileTest::noop_handler);

    EXPECT_THROW(router.compile(), std::invalid_argument);
}

// --------------------------------------------------------------------------
// Duplicate-route registration: last definition wins (not an error)
// --------------------------------------------------------------------------

TEST_F(RoutingCompileTest, DuplicateRouteSamePathMethodCompilesAndLastWins) {
    router.get("/dup", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "first";
        ctx->complete();
    });
    router.get("/dup", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "second";
        ctx->complete();
    });

    ASSERT_NO_THROW(router.compile());

    router.route(session, create_request(qb::http::method::GET, "/dup"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "second");
    EXPECT_EQ(session->response_write_count(), 1u);
}

// --------------------------------------------------------------------------
// Recoverability: a fresh router serves valid routes after a failed compile
// --------------------------------------------------------------------------

TEST_F(RoutingCompileTest, RouterRecoversAfterAmbiguousCompile) {
    router.get("/test/:id/:id", &RoutingCompileTest::noop_handler);
    ASSERT_THROW(router.compile(), std::invalid_argument);

    // Documented reset idiom: re-initialize the router after a throwing compile.
    router = qb::http::Router<MockSession>();
    router.get("/good/route", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "good";
        ctx->complete();
    });

    ASSERT_NO_THROW(router.compile());

    router.route(session, create_request(qb::http::method::GET, "/good/route"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "good");
    EXPECT_EQ(session->response_write_count(), 1u);
}

// --------------------------------------------------------------------------
// Valid complex patterns compile without error
// --------------------------------------------------------------------------

TEST_F(RoutingCompileTest, ValidMixedPatternsCompileCleanly) {
    auto ok = [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    };
    router.get("/", ok);
    router.get("/users/:id", ok);
    router.get("/users/:id/items/:itemId", ok);
    router.get("/static/specific", ok);
    router.get("/static/*rest", ok);

    EXPECT_NO_THROW(router.compile());
}

} // namespace
