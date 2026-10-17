/**
 * @file qbm/http/tests/system/server/make-server-factory-huge-body.cpp
 * @brief A request body exactly at the default cap is served by `qb::http::make_server()` (Huly QB-168).
 *
 * Its message -- the header section plus `protocol_limits::MAX_BODY_SIZE` (100 MiB) of body -- is past
 * the transport's generic message cap (`QB_MAX_MESSAGE_SIZE`, also 100 MiB), which cut it with no
 * answer at all: the HTTP/1.1 session now leaves the bounds to the protocol, which states them and
 * answers a breach. The case holds ~200 MiB of server memory, so it is its own binary, labelled
 * `huge-body`: `ctest -LE huge-body` drops it on a runner short of memory, and nothing else in the
 * suite pays for it. Its `REQUIRES live` lock keeps it apart from the other loopback tests.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

#include <qb/io/async.h>
#include <qb/io/tcp/socket.h>

#include <qbm/http/http.h>

#include "../../shared/loopback_server.h"

using namespace std::chrono_literals;

namespace {

using PlainServer       = qb::http::Server<>;
using PlainServerThread = qb::http::test::ServerThread<PlainServer>;

/// Sends all of @p size bytes at @p data on a blocking socket; false once a send fails (a reset).
bool
send_all(qb::io::tcp::socket &sock, char const *data, std::size_t size) {
    while (size) {
        const int written = sock.write(data, size);
        if (written <= 0)
            return false;
        data += written;
        size -= static_cast<std::size_t>(written);
    }
    return true;
}

TEST(HttpServerHugeBody, ABodyAtTheDefaultCapIsServed) {
    qb::io::async::init();
    PlainServerThread server([] { return qb::http::make_server(); },
                             [](PlainServer &srv) -> bool {
                                 srv.router().post("/size", [](std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) {
                                     ctx->text(std::to_string(ctx->request().body().size()));
                                 });
                                 srv.router().compile();
                                 if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                                     return false;
                                 srv.start();
                                 return true;
                             });
    ASSERT_TRUE(server.ready()) << "plaintext HTTP/1.1 loopback server failed to start";
    const auto port = server.server().transport().local_endpoint().port();

    qb::io::tcp::socket sock;
    ASSERT_EQ(sock.connect_v4("127.0.0.1", port), 0) << "the raw client could not connect";
    constexpr std::size_t body = qb::http::protocol_limits::MAX_BODY_SIZE;
    const std::string     head = "POST /size HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + std::to_string(body) + "\r\n\r\n";
    const std::string     chunk(1024 * 1024, 'b');
    bool                  sent = send_all(sock, head.data(), head.size());
    for (std::size_t left = body; sent && left; left -= std::min(left, chunk.size()))
        sent = send_all(sock, chunk.data(), std::min(left, chunk.size()));
    EXPECT_TRUE(sent) << "the server ended the connection during the upload (error " << qb::io::socket::get_last_errno() << ")";

    // The answer: a 200 whose body is the size the handler saw. Read until it is whole, the connection
    // ends, or the budget runs out.
    (void) sock.set_nonblocking(true);
    const std::string expected = std::to_string(body);
    std::string       received;
    char              buffer[4096];
    const auto        deadline = std::chrono::steady_clock::now() + 60s;
    while (std::chrono::steady_clock::now() < deadline && received.find("\r\n\r\n" + expected) == std::string::npos) {
        const int got = sock.read(buffer, sizeof(buffer));
        if (got > 0) {
            received.append(buffer, static_cast<std::size_t>(got));
            continue;
        }
        // tcp::socket::read() answers -1 at EOF too, with the error cleared to 0.
        if (const int error = got == 0 ? 0 : qb::io::socket::get_last_errno(); error == 0 || !qb::io::socket::not_recv_error(error))
            break;
        std::this_thread::sleep_for(1ms);
    }
    sock.close();
    EXPECT_EQ(received.rfind("HTTP/1.1 200 ", 0), 0u) << "no answer: [" << received.substr(0, 200) << "]";
    EXPECT_NE(received.find("\r\n\r\n" + expected), std::string::npos) << received.substr(0, 400);
}

} // namespace
