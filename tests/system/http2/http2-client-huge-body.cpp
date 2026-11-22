/**
 * @file qbm/http/tests/system/http2/http2-client-huge-body.cpp
 * @brief What crosses the HTTP/2 client's reset of a response past MAX_BODY_SIZE, over real TLS sockets (Huly QB-1270):
 *        100 MiB on the wire, so a binary of its own, labelled huge-body (`ctest -LE huge-body` drops it).
 *
 * A legitimate server streams a body past MAX_BODY_SIZE on stream 1 while the client's other request waits on stream 3.
 * The client resets stream 1 at the frame that passes the limit; the server had already written the next DATA of that
 * stream and its trailers, then the response to stream 3. The DATA closed the connection with GOAWAY(PROTOCOL_ERROR),
 * « DATA for unknown client stream », and the request on stream 3 failed with it -- every other request of the
 * connection did. It is discarded now (RFC 9113 §5.1). The same with a body past its content-length is a case of
 * http2-client.cpp, which every run builds.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include <gtest/gtest.h>

#include "../../shared/http2_planned_peer.h"
#include "../../shared/ssl_test_resource.h"

#include <qbm/http/2/client.h>

using namespace std::chrono_literals;
using qb::http::test::Http2PlannedPeer;

namespace http2_client_huge_body_test {

template <typename Pred>
[[nodiscard]] bool
pump_until(Pred &&pred, std::chrono::milliseconds budget) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            return false;
        }
        qb::io::async::run(EVRUN_NOWAIT);
    }
    return true;
}

// The request on stream 3 is answered on the same connection, its header named by an index the discarded trailers put
// in the HPACK table; the request on stream 1 fails with the limit; the client sent one reset, of stream 1
// (ENHANCE_YOUR_CALM), and its only GOAWAY is the NO_ERROR of the test's disconnect(). Every bound is under the system
// tier's timeout: 0.2 s in Release on a workstation, the 100 MiB copied twice by the client.
TEST(Http2ClientHugeBody, ADataCrossingTheResetOfABodyPastTheLimitLeavesTheOtherRequestServed) {
    ASSERT_TRUE(qb::http::test::certs_available()) << "the HTTP/2 client system suite REQUIRES the TLS test certificates";
    qb::io::async::init();
    Http2PlannedPeer peer(Http2PlannedPeer::Plan::body_past_the_limit, std::chrono::seconds(90));
    ASSERT_NE(peer.port(), 0);
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(peer.port()));
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);
    client->set_request_timeout(90s); // a request ends with its response or with the connection, not on its own
    client->disable_auto_reconnect();
    bool connected = false;
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(pump_until([&] { return connected; }, 10s)) << "the client did not connect";

    std::optional<qb::http::Response> large, other;
    qb::http::Request                 first, second;
    first.method()  = qb::http::Method::GET;
    first.uri()     = qb::io::uri("/large");
    second.method() = qb::http::Method::GET;
    second.uri()    = qb::io::uri("/other");
    ASSERT_TRUE(client->push_request(first, [&](qb::http::Response r) { large = std::move(r); }));
    ASSERT_TRUE(client->push_request(second, [&](qb::http::Response r) { other = std::move(r); }));
    ASSERT_TRUE(pump_until([&] { return (large.has_value() && other.has_value()) || peer.eof(); }, 75s))
        << "neither the responses nor the end of the connection came";
    ASSERT_TRUE(large.has_value()) << "the response past the limit was not refused";
    EXPECT_NE(large->status(), qb::http::status::OK);
    EXPECT_NE(large->body().as<std::string>().find("exceeds the client's limit of 104857600 bytes"), std::string::npos)
        << large->body().as<std::string>();
    ASSERT_TRUE(other.has_value()) << "the connection ended before the other request was answered";
    EXPECT_EQ(other->status(), qb::http::status::OK) << other->body().as<std::string>();
    EXPECT_EQ(other->body().as<std::string>(), "three");
    EXPECT_EQ(other->header("x-crossed"), "one");
    EXPECT_TRUE(client->is_connected());

    client->disconnect(); // GOAWAY(NO_ERROR) behind everything the client wrote: the peer reads it all
    ASSERT_TRUE(pump_until([&] { return peer.eof(); }, 10s)) << "the peer did not see the connection end";
    const auto resets = peer.resets();
    ASSERT_EQ(resets.size(), 1u) << "what crossed the reset was answered";
    EXPECT_EQ(resets.front().first, 1u);
    EXPECT_EQ(resets.front().second, 0xBu) << "ENHANCE_YOUR_CALM";
    ASSERT_TRUE(peer.goaway());
    const auto [code, debug] = peer.first_goaway();
    EXPECT_EQ(code, 0u) << "the client closed the connection: " << debug;
}

// The same body under a limit of none (Huly QB-1248): `set_max_body_size(0)` reads all of it -- the 100 MiB, the frame
// past them and the DATA behind it, then its trailers -- and the request on stream 3 is answered; the client resets nothing.
TEST(Http2ClientHugeBody, UnderALimitOfNoneABodyPastTheDefaultIsDelivered) {
    ASSERT_TRUE(qb::http::test::certs_available()) << "the HTTP/2 client system suite REQUIRES the TLS test certificates";
    qb::io::async::init();
    Http2PlannedPeer peer(Http2PlannedPeer::Plan::body_past_the_limit, std::chrono::seconds(90));
    ASSERT_NE(peer.port(), 0);
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(peer.port()));
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);
    client->set_request_timeout(90s);
    client->disable_auto_reconnect();
    client->set_max_body_size(0);
    bool connected = false;
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(pump_until([&] { return connected; }, 10s)) << "the client did not connect";

    std::optional<qb::http::Response> large, other;
    qb::http::Request                 first, second;
    first.method()  = qb::http::Method::GET;
    first.uri()     = qb::io::uri("/large");
    second.method() = qb::http::Method::GET;
    second.uri()    = qb::io::uri("/other");
    ASSERT_TRUE(client->push_request(first, [&](qb::http::Response r) { large = std::move(r); }));
    ASSERT_TRUE(client->push_request(second, [&](qb::http::Response r) { other = std::move(r); }));
    ASSERT_TRUE(pump_until([&] { return (large.has_value() && other.has_value()) || peer.eof(); }, 75s))
        << "neither the responses nor the end of the connection came";
    ASSERT_TRUE(large.has_value());
    EXPECT_EQ(large->status(), qb::http::status::OK) << large->body().as<std::string>().substr(0, 200);
    EXPECT_EQ(large->body().size(), qb::http::protocol_limits::MAX_BODY_SIZE + 16384 + 8192);
    ASSERT_TRUE(other.has_value());
    EXPECT_EQ(other->status(), qb::http::status::OK);
    EXPECT_EQ(other->body().as<std::string>(), "three");
    client->disconnect();
    ASSERT_TRUE(pump_until([&] { return peer.eof(); }, 10s)) << "the peer did not see the connection end";
    EXPECT_TRUE(peer.resets().empty()) << "the client reset a stream under a limit of none";
}

} // namespace http2_client_huge_body_test
