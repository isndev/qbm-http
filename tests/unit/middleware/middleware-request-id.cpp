/**
 * @file qbm/http/tests/unit/middleware/middleware-request-id.cpp
 * @brief Unit tests for qb::http::RequestIdMiddleware (Huly QB-166).
 *
 * The middleware gives each request an id -- a fresh UUID v4, or the client's when trusted and valid -- stores
 * it under `request_id_slot` and answers it in the response header. These tests pin: the UUID shape, the
 * header and the slot carrying the same id, the client's id ignored by default, adopted only when trusted AND
 * valid (1..128 of [A-Za-z0-9._-]) and never echoed otherwise, a custom header name, one id per request, the
 * 404 answer carrying it, the `make<tags::request_id>` entry, and the empty-header-name refusal.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <qbm/http/http.h>
#include <qbm/http/middleware/all.h>
#include <qbm/http/middleware/request_id.h>

#include "../../shared/middleware_test_fixture.h"

namespace middleware_request_id_test {

using Session = qb::http::test::MockMiddlewareSession;
using Ctx     = qb::http::Context<Session>;

/** @brief Whether `s` is the 36-character text form of a version-4, RFC 4122-variant UUID. */
bool
is_uuid_v4(std::string const &s) {
    if (s.size() != 36)
        return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-')
                return false;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return s[14] == '4' && (s[19] == '8' || s[19] == '9' || s[19] == 'a' || s[19] == 'b');
}

class RequestIdMiddlewareTest : public qb::http::test::MiddlewareTestFixture<Session> {
protected:
    std::string _slot_seen; ///< what the handler read from request_id_slot
    bool        _slot_was_set = false;

    /** @brief Mounts `mw` then a handler that records the slot, on GET /rid; routes `request`. */
    void
    run(std::shared_ptr<qb::http::IMiddleware<Session>> mw, qb::http::Request request) {
        _router = std::make_unique<qb::http::Router<Session>>();
        _router->use(std::move(mw));
        _router->get("/rid", [this](std::shared_ptr<Ctx> ctx) {
            _session->_final_handler_called = true;
            if (const std::string *id = ctx->get_if(qb::http::request_id_slot)) {
                _slot_was_set = true;
                _slot_seen    = *id;
            }
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });
        _router->compile();
        _session->reset();
        _slot_seen.clear();
        _slot_was_set = false;
        _router->route(_session, std::move(request));
    }

    qb::http::Request
    request_with(std::string const &header, std::string const &value) {
        auto req = create_request(qb::http::method::GET, "/rid");
        req.set_header(header, value);
        return req;
    }
};

TEST_F(RequestIdMiddlewareTest, GeneratesAUuidV4InTheHeaderAndTheSlot) {
    run(qb::http::request_id_middleware<Session>(), create_request(qb::http::method::GET, "/rid"));

    ASSERT_TRUE(_session->_final_handler_called);
    const std::string &header = _session->_response.header("X-Request-ID");
    EXPECT_TRUE(is_uuid_v4(header)) << header;
    ASSERT_TRUE(_slot_was_set);
    EXPECT_EQ(_slot_seen, header);
}

TEST_F(RequestIdMiddlewareTest, TheClientsIdIsIgnoredByDefault) {
    run(qb::http::request_id_middleware<Session>(), request_with("X-Request-ID", "client-chosen-1"));

    const std::string &header = _session->_response.header("X-Request-ID");
    EXPECT_NE(header, "client-chosen-1");
    EXPECT_TRUE(is_uuid_v4(header)) << header;
    EXPECT_EQ(_slot_seen, header);
}

TEST_F(RequestIdMiddlewareTest, ATrustedValidIdIsPropagated) {
    const std::string incoming = "Abc.def_0-9";
    run(qb::http::request_id_middleware<Session>(qb::http::RequestIdOptions{}.trust_incoming_id()), request_with("x-request-id", incoming));

    EXPECT_EQ(_session->_response.header("X-Request-ID"), incoming);
    EXPECT_EQ(_slot_seen, incoming);
}

TEST_F(RequestIdMiddlewareTest, ATrustedIdOfExactly128CharactersIsPropagated) {
    const std::string incoming(qb::http::max_request_id_length, 'z');
    run(qb::http::request_id_middleware<Session>(qb::http::RequestIdOptions{}.trust_incoming_id()), request_with("X-Request-ID", incoming));

    EXPECT_EQ(_session->_response.header("X-Request-ID"), incoming);
}

TEST_F(RequestIdMiddlewareTest, ATrustedInvalidIdIsReplacedAndNeverEchoed) {
    const std::vector<std::string> invalid = {
        std::string(qb::http::max_request_id_length + 1, 'z'), // one past the cap
        "two words",                                           // a space
        "quote\"d",                                            // a quote: log injection
        "line\nbreak",                                         // a control byte
        "caf\xc3\xa9",                                         // a non-ASCII byte
        "slash/es",                                            // a character outside the set
    };
    for (auto const &bad : invalid) {
        run(qb::http::request_id_middleware<Session>(qb::http::RequestIdOptions{}.trust_incoming_id()), request_with("X-Request-ID", bad));
        const std::string &header = _session->_response.header("X-Request-ID");
        EXPECT_NE(header, bad);
        EXPECT_TRUE(is_uuid_v4(header)) << "for incoming '" << bad << "': " << header;
        EXPECT_EQ(_slot_seen, header);
    }
}

TEST_F(RequestIdMiddlewareTest, ATrustedButAbsentIdIsGenerated) {
    run(qb::http::request_id_middleware<Session>(qb::http::RequestIdOptions{}.trust_incoming_id()),
        create_request(qb::http::method::GET, "/rid"));

    EXPECT_TRUE(is_uuid_v4(_session->_response.header("X-Request-ID")));
}

TEST_F(RequestIdMiddlewareTest, ACustomHeaderNameIsReadAndWritten) {
    auto options = qb::http::RequestIdOptions{}.header("X-Correlation-ID").trust_incoming_id();
    run(qb::http::request_id_middleware<Session>(options), request_with("X-Correlation-ID", "corr-42"));

    EXPECT_EQ(_session->_response.header("X-Correlation-ID"), "corr-42");
    EXPECT_FALSE(_session->_response.has_header("X-Request-ID"));
    EXPECT_EQ(_slot_seen, "corr-42");
}

TEST_F(RequestIdMiddlewareTest, EveryRequestGetsItsOwnId) {
    auto                  mw = qb::http::request_id_middleware<Session>(); // one instance, shared by every request
    std::set<std::string> seen;
    constexpr int         requests = 200;
    for (int i = 0; i < requests; ++i) {
        run(mw, create_request(qb::http::method::GET, "/rid"));
        seen.insert(_session->_response.header("X-Request-ID"));
    }
    EXPECT_EQ(seen.size(), static_cast<std::size_t>(requests));
}

TEST_F(RequestIdMiddlewareTest, TheNotFoundAnswerCarriesAnId) {
    // Global middleware is prepended to the 404 chain: an unrouted request is answered with its id too.
    run(qb::http::request_id_middleware<Session>(), create_request(qb::http::method::GET, "/nowhere"));

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_FOUND);
    EXPECT_TRUE(is_uuid_v4(_session->_response.header("X-Request-ID")));
}

TEST_F(RequestIdMiddlewareTest, TheMakeEntryBuildsIt) {
    auto mw = qb::http::middleware::make<qb::http::middleware::tags::request_id, Session>();
    EXPECT_EQ(mw->name(), "RequestIdMiddleware");
    run(mw, create_request(qb::http::method::GET, "/rid"));
    EXPECT_TRUE(is_uuid_v4(_session->_response.header("X-Request-ID")));
}

TEST_F(RequestIdMiddlewareTest, AnEmptyHeaderNameIsRefused) {
    EXPECT_THROW((void) qb::http::request_id_middleware<Session>(qb::http::RequestIdOptions{}.header("")), std::invalid_argument);
}

TEST(RequestIdValidation, TheAcceptedAlphabetAndLength) {
    static_assert(qb::http::is_valid_request_id("a"));
    static_assert(qb::http::is_valid_request_id("AZaz09._-"));
    static_assert(!qb::http::is_valid_request_id(""));
    static_assert(!qb::http::is_valid_request_id("a b"));
    static_assert(!qb::http::is_valid_request_id("a:b"));
    EXPECT_TRUE(qb::http::is_valid_request_id(std::string(128, '0')));
    EXPECT_FALSE(qb::http::is_valid_request_id(std::string(129, '0')));
}

} // namespace middleware_request_id_test
