/**
 * @file qbm/http/tests/unit/routing/routing-methods.cpp
 * @brief Per-verb dispatch, route overwrite, HEAD / 204 empty-body, and the
 *        405 Method-Not-Allowed + `Allow` header path.
 *
 * One of the four focused unit files carved out of the legacy `test-router.cpp`
 * monolith. It pins how a compiled @ref qb::http::Router dispatches each HTTP verb
 * to its handler, that re-registering a path/method overwrites the earlier handler,
 * that HEAD and 204 produce empty bodies, and — newly added per the binding spec —
 * that requesting an *unregistered method on a registered path* produces a 405 with
 * a correct RFC `Allow` header (emitted by the router itself, see
 * `routing/router_core.h::route`).
 *
 * The per-verb dispatch matrix is a `TEST_P` table so each verb is an independently
 * reported case. Adopts shared @ref qb::http::test::MockSession / create_request.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "../http.h"
#include "../../shared/mock_session.h"

using qb::http::test::create_request;
using qb::http::test::MockSession;

namespace {

// --------------------------------------------------------------------------
// Per-verb dispatch (TEST_P table)
// --------------------------------------------------------------------------

struct VerbCase {
    qb::http::method method;       ///< Verb to register and request.
    const char      *verb_name;    ///< Human label for the test name.
    qb::http::status status;       ///< Status the handler returns.
    const char      *body;         ///< Body the handler returns (empty for body-less verbs).
    bool             expect_body;  ///< Whether the response is expected to carry a body.
};

class RoutingVerbDispatchTest : public ::testing::TestWithParam<VerbCase> {
protected:
    std::shared_ptr<MockSession>  session = std::make_shared<MockSession>();
    qb::http::Router<MockSession> router;
};

TEST_P(RoutingVerbDispatchTest, DispatchesToRegisteredVerbHandler) {
    const auto &tc = GetParam();

    auto handler = [tc](auto ctx) {
        ctx->response().status() = tc.status;
        if (tc.expect_body) {
            ctx->response().body() = std::string(tc.body);
        }
        ctx->complete();
    };

    switch (static_cast<qb::http::method::Value>(tc.method)) {
        case qb::http::method::GET: router.get("/resource", handler); break;
        case qb::http::method::POST: router.post("/resource", handler); break;
        case qb::http::method::PUT: router.put("/resource", handler); break;
        case qb::http::method::DEL: router.del("/resource", handler); break;
        case qb::http::method::PATCH: router.patch("/resource", handler); break;
        case qb::http::method::OPTIONS: router.options("/resource", handler); break;
        case qb::http::method::HEAD: router.head("/resource", handler); break;
        default: FAIL() << "unhandled verb in test table"; return;
    }

    router.compile();
    router.route(session, create_request(tc.method, "/resource"));

    EXPECT_EQ(session->_response.status(), tc.status) << "verb: " << tc.verb_name;
    EXPECT_EQ(session->response_write_count(), 1u) << "verb: " << tc.verb_name;
    if (tc.expect_body) {
        EXPECT_EQ(session->_response.body().template as<std::string>(), tc.body) << "verb: " << tc.verb_name;
    } else {
        EXPECT_TRUE(session->_response.body().raw().empty()) << "verb: " << tc.verb_name;
    }
}

INSTANTIATE_TEST_SUITE_P(
    AllVerbs, RoutingVerbDispatchTest,
    ::testing::Values(VerbCase{qb::http::method::GET, "GET", qb::http::status::OK, "got", true},
                      VerbCase{qb::http::method::POST, "POST", qb::http::status::CREATED, "created", true},
                      VerbCase{qb::http::method::PUT, "PUT", qb::http::status::OK, "updated", true},
                      VerbCase{qb::http::method::DEL, "DELETE", qb::http::status::NO_CONTENT, "", false},
                      VerbCase{qb::http::method::PATCH, "PATCH", qb::http::status::OK, "patched", true},
                      VerbCase{qb::http::method::OPTIONS, "OPTIONS", qb::http::status::OK, "opts", true},
                      VerbCase{qb::http::method::HEAD, "HEAD", qb::http::status::OK, "", false}),
    [](const ::testing::TestParamInfo<VerbCase> &info) { return info.param.verb_name; });

// --------------------------------------------------------------------------
// Standalone method behaviours
// --------------------------------------------------------------------------

class RoutingMethodsTest : public ::testing::Test {
protected:
    std::shared_ptr<MockSession>  session = std::make_shared<MockSession>();
    qb::http::Router<MockSession> router;
};

TEST_F(RoutingMethodsTest, ReRegisteringSamePathMethodOverwritesHandler) {
    router.get("/overwrite", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "first";
        ctx->complete();
    });
    router.get("/overwrite", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "second";
        ctx->complete();
    });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/overwrite"));

    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "second");
    EXPECT_EQ(session->response_write_count(), 1u);
}

TEST_F(RoutingMethodsTest, HeadRouteCarriesHeadersButNoBody) {
    router.head("/info", [](auto ctx) {
        ctx->response().set_header("X-Info-Detail", "SomeDetail");
        ctx->response().status() = qb::http::status::OK;
        // Intentionally no body for HEAD.
        ctx->complete();
    });
    router.compile();

    router.route(session, create_request(qb::http::method::HEAD, "/info"));

    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    ASSERT_TRUE(session->_response.has_header("X-Info-Detail"));
    EXPECT_EQ(session->_response.header("X-Info-Detail", 0), "SomeDetail");
    EXPECT_TRUE(session->_response.body().raw().empty());
    EXPECT_EQ(session->response_write_count(), 1u);
}

TEST_F(RoutingMethodsTest, DeleteRoute204HasEmptyBody) {
    router.del("/resource/456", [](auto ctx) {
        ctx->response().status() = qb::http::status::NO_CONTENT;
        ctx->complete();
    });
    router.compile();

    router.route(session, create_request(qb::http::method::DEL, "/resource/456"));

    EXPECT_EQ(session->_response.status(), qb::http::status::NO_CONTENT);
    EXPECT_TRUE(session->_response.body().raw().empty());
    EXPECT_EQ(session->response_write_count(), 1u);
}

TEST_F(RoutingMethodsTest, DistinctVerbsOnSamePathAreIndependent) {
    router.get("/multi", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "got";
        ctx->complete();
    });
    router.post("/multi", [](auto ctx) {
        ctx->response().status() = qb::http::status::CREATED;
        ctx->response().body()   = "made";
        ctx->complete();
    });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/multi"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "got");

    session->reset();

    router.route(session, create_request(qb::http::method::POST, "/multi"));
    EXPECT_EQ(session->_response.status(), qb::http::status::CREATED);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "made");
}

// --------------------------------------------------------------------------
// 405 Method Not Allowed + Allow header (router-emitted)
// --------------------------------------------------------------------------

/**
 * @brief A registered path requested with an unregistered method yields 405.
 *
 * The router matches the *path* via the radix tree's allowed-methods lookup, sets
 * status 405, and emits an `Allow` header listing the methods that *are* registered
 * on that path — without invoking any route handler.
 */
TEST_F(RoutingMethodsTest, UnregisteredMethodOnKnownPathYields405WithAllow) {
    bool handler_ran = false;
    router.get("/only-get", [&handler_ran](auto ctx) {
        handler_ran            = true;
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    router.compile();

    router.route(session, create_request(qb::http::method::POST, "/only-get"));

    EXPECT_EQ(session->_response.status(), qb::http::status::METHOD_NOT_ALLOWED);
    EXPECT_FALSE(handler_ran) << "no route handler should run on a 405";
    ASSERT_TRUE(session->_response.has_header("Allow"));
    const std::string allow = session->_response.header("Allow", 0);
    EXPECT_NE(allow.find("GET"), std::string::npos) << "Allow was: " << allow;
    EXPECT_EQ(allow.find("POST"), std::string::npos) << "Allow must not list the rejected method; was: " << allow;
    EXPECT_EQ(session->response_write_count(), 1u);
}

TEST_F(RoutingMethodsTest, AllowHeaderListsEveryRegisteredMethodOnPath) {
    auto ok = [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    };
    router.get("/multi", ok);
    router.put("/multi", ok);
    router.del("/multi", ok);
    router.compile();

    // PATCH is not registered -> 405, Allow must enumerate GET/PUT/DELETE.
    router.route(session, create_request(qb::http::method::PATCH, "/multi"));

    EXPECT_EQ(session->_response.status(), qb::http::status::METHOD_NOT_ALLOWED);
    ASSERT_TRUE(session->_response.has_header("Allow"));
    const std::string allow = session->_response.header("Allow", 0);
    EXPECT_NE(allow.find("GET"), std::string::npos) << allow;
    EXPECT_NE(allow.find("PUT"), std::string::npos) << allow;
    EXPECT_NE(allow.find("DELETE"), std::string::npos) << allow;
}

TEST_F(RoutingMethodsTest, UnknownPathYields404Not405) {
    router.get("/known", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    router.compile();

    // Path itself does not exist -> 404 (no Allow header), distinct from 405.
    router.route(session, create_request(qb::http::method::POST, "/does-not-exist"));

    EXPECT_EQ(session->_response.status(), qb::http::status::NOT_FOUND);
    EXPECT_FALSE(session->_response.has_header("Allow"));
    EXPECT_EQ(session->response_write_count(), 1u);
}

} // namespace
