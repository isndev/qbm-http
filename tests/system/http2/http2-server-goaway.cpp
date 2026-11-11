/**
 * @file qbm/http/tests/system/http2/http2-server-goaway.cpp
 * @brief The GOAWAY the HTTP/2 server owes a connection error, over real TLS sockets, and how its session logs it (Huly
 *        QB-1270, part 6: the maintainer's « Yes, as recommended » of 2026-11-11).
 *
 * The client is the raw HTTP/2 client of `shared/http2_raw_client.h`: it sends the frames a server must refuse, which no
 * well-behaved client writes, and reads what the server answers. Each case runs on a connection of its own.
 *
 *   - Three checks the frame layer makes on a frame's header alone, before it dispatches the frame -- a SETTINGS, a PING
 *     or a GOAWAY on a stream other than 0, a frame longer than SETTINGS_MAX_FRAME_SIZE -- are connection errors (RFC
 *     9113 §6.5, §6.7, §6.8, §4.2). The server closed the connection without a GOAWAY; it sends the GOAWAY it owes now
 *     (§5.4.1), its code and the reason as debug data.
 *   - A connection error the frame layer finds in a frame on a stream other than 0 -- a RST_STREAM or a WINDOW_UPDATE of
 *     the wrong size, a padding past its payload, a DATA where a CONTINUATION is due (§6.4, §6.9, §6.1, §6.10) -- was
 *     answered with a RST_STREAM of that stream, an idle one's included, and no GOAWAY. It ends the connection with its
 *     GOAWAY now, and resets nothing.
 *   - The session logged the GOAWAY the server sent as one received from the client, « Received GOAWAY from client ...
 *     Debug: GOAWAY sent by server: ... ». It logs « Sent GOAWAY to client » for its own now, told by
 *     `Http2GoAwayEvent::sent`, and « Received GOAWAY from client » for the client's alone.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

#include "../../shared/http2_raw_client.h"
#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

#include <qb/io.h>
#include <qbm/http/http.h>

using namespace std::chrono_literals;
using qb::http::test::Http2RawClient;
using qb::http::test::ServerThread;

namespace http2_server_goaway_test {

class GoawayServer;

class GoawaySession : public qb::http2::use<GoawaySession>::session<GoawayServer> {
public:
    explicit GoawaySession(GoawayServer &server)
        : session(server) {}
};

/// One route, answered at once and without a body.
class GoawayServer : public qb::http2::use<GoawayServer>::server<GoawaySession> {
public:
    GoawayServer() {
        router().get("/served", [](auto ctx) {
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });
        router().compile();
    }
};

/// A server listening on an ephemeral port of the loopback, on its own thread.
[[nodiscard]] std::unique_ptr<ServerThread<GoawayServer>>
start_server() {
    const std::string cert = qb::http::test::ssl_cert_path().string();
    const std::string key  = qb::http::test::ssl_key_path().string();
    return std::make_unique<ServerThread<GoawayServer>>([cert, key](GoawayServer &srv) -> bool {
        srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2"}));
        if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        srv.start();
        return true;
    });
}

/// A frame the server must refuse, sent once the connection is up -- behind a request it serves when
/// @p after_a_request -- and the GOAWAY it owes.
struct refused_frame {
    const char          *name;
    std::uint8_t         type;
    std::uint8_t         flags;
    std::uint32_t        sid;
    std::vector<uint8_t> payload;
    std::uint32_t        code;
    std::string          debug;
    bool                 after_a_request = false;
    /// Frames sent first, in the same write as nothing else: a HEADERS whose block a CONTINUATION must end, say.
    std::vector<std::pair<std::uint8_t, std::uint32_t>> lead = {};
    /// Non-zero: send only the frame's header, declaring this length (a frame refused on its header alone).
    std::uint32_t declared = 0;
};

constexpr std::uint8_t kPadded = 0x8;

class Http2ServerGoawayWireTest : public ::testing::Test {
protected:
    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available()) << "Missing TLS test certificates (" << qb::http::test::ssl_cert_path() << ")";
        qb::io::async::init();
    }

    /// Each of @p frames on a connection of its own: the server's last frame is a GOAWAY of its code and debug data, and
    /// it resets no stream.
    static void
    each_ends_the_connection_with_its_goaway(const std::vector<refused_frame> &frames) {
        for (const auto &frame : frames) {
            ends_the_connection_with_its_goaway(frame); // a fatal failure ends that frame's case, not the others
        }
    }

    static void
    ends_the_connection_with_its_goaway(const refused_frame &frame) {
        SCOPED_TRACE(frame.name);
        auto server = start_server();
        ASSERT_TRUE(server->ready());
        Http2RawClient client;
        ASSERT_TRUE(client.connect(server->port()));
        ASSERT_TRUE(client.read_until([&] { return client.settings_acked; })) << "the server never acknowledged the SETTINGS";
        if (frame.after_a_request) {
            const auto sid = client.request("/served");
            ASSERT_NE(sid, 0u);
            ASSERT_TRUE(client.read_until([&] { return client.stream(sid).end_stream; })) << "the request was not served";
        }
        for (const auto &[type, sid] : frame.lead) {
            ASSERT_TRUE(client.frame(type, 0, sid, {0x82})); // `:method: GET`, its block left open: no END_HEADERS
        }
        if (frame.declared != 0) {
            ASSERT_TRUE(client.frame_header(frame.type, frame.flags, frame.sid, frame.declared));
        } else {
            ASSERT_TRUE(client.frame(frame.type, frame.flags, frame.sid, frame.payload));
        }
        ASSERT_TRUE(client.read_until([&] { return client.eof; }, 10s)) << "the server did not close the connection";
        ASSERT_TRUE(client.goaway_seen) << "the server closed the connection without a GOAWAY";
        EXPECT_EQ(client.goaway_code, frame.code);
        EXPECT_EQ(client.goaway_debug, frame.debug);
        EXPECT_EQ(client.resets, 0u) << "a connection error reset a stream";
        if (!client.frames.empty()) {
            EXPECT_EQ(client.frames.back().type, Http2RawClient::GOAWAY) << "a frame followed the GOAWAY";
        }
    }
};

} // namespace http2_server_goaway_test

using namespace http2_server_goaway_test;

// A SETTINGS, a PING or a GOAWAY on stream 1, and a DATA one octet past the server's SETTINGS_MAX_FRAME_SIZE: refused
// on the frame's header alone, before its dispatch -- the DATA is sent as its header only, so the server cannot have
// waited for its payload, and closes with nothing of it unread. The server closed the connection without a GOAWAY.
TEST_F(Http2ServerGoawayWireTest, ACheckOnAFramesHeaderAloneEndsTheConnectionWithItsGoaway) {
    each_ends_the_connection_with_its_goaway({
        {"a SETTINGS on stream 1", Http2RawClient::SETTINGS, 0, 1, {}, 0x1, "SETTINGS frame on non-zero stream_id"},
        {"a PING on stream 1", Http2RawClient::PING, 0, 1, {1, 2, 3, 4, 5, 6, 7, 8}, 0x1, "PING frame on non-zero stream_id"},
        {"a GOAWAY on stream 1", Http2RawClient::GOAWAY, 0, 1, {0, 0, 0, 0, 0, 0, 0, 0}, 0x1, "GOAWAY frame on non-zero stream_id"},
        {"the header of a DATA past SETTINGS_MAX_FRAME_SIZE",
         Http2RawClient::DATA,
         0,
         1,
         {},
         0x6,
         "Frame size 16385 exceeds SETTINGS_MAX_FRAME_SIZE 16384",
         false,
         {},
         16385},
    });
}

// A connection error the frame layer finds in a frame on a stream other than 0: the server answered it with a
// RST_STREAM of that stream -- an idle one's included -- and closed the connection without a GOAWAY.
TEST_F(Http2ServerGoawayWireTest, AConnectionErrorTheFrameLayerFindsOnAStreamEndsTheConnectionWithItsGoaway) {
    each_ends_the_connection_with_its_goaway({
        {"a RST_STREAM of 3 octets on a stream served",
         Http2RawClient::RST_STREAM,
         0,
         1,
         {0, 0, 8},
         0x6,
         "RST_STREAM frame payload incorrect size.",
         true},
        {"a WINDOW_UPDATE of 5 octets on a stream served",
         Http2RawClient::WINDOW_UPDATE,
         0,
         1,
         {0, 0, 0, 1, 0},
         0x6,
         "WINDOW_UPDATE frame payload incorrect size.",
         true},
        {"a DATA whose padding passes its payload",
         Http2RawClient::DATA,
         kPadded,
         1,
         {5, 'x'},
         0x1,
         "Pad Length in DATA frame exceeds payload size.",
         true},
        {"a RST_STREAM of 3 octets on an idle stream",
         Http2RawClient::RST_STREAM,
         0,
         9,
         {0, 0, 8},
         0x6,
         "RST_STREAM frame payload incorrect size."},
        {"a DATA where the CONTINUATION of stream 3 is due",
         Http2RawClient::DATA,
         Http2RawClient::END_STREAM,
         3,
         {'x'},
         0x1,
         "Expected CONTINUATION frame for stream 3",
         false,
         {{Http2RawClient::HEADERS, 3u}}},
    });
}

#ifdef QB_WITH_LOGGING
namespace http2_server_goaway_test {

/// What the process logged while @p body ran: a log of its own, closed and drained by the next qb::io::log::init()
/// before that returns (the capture of qbm-redis's consumer-unknown-push.cpp), then the process's own file again
/// (LogInitializer's "./qb", 512 MB). Nothing else logs meanwhile: the server's thread starts and ends inside @p body.
[[nodiscard]] std::string
log_of(const std::function<void()> &body) {
    const auto      dir = std::filesystem::temp_directory_path() / ("qbm-http-h2-server-log-" + std::to_string(std::random_device{}()));
    std::error_code ec;
    EXPECT_TRUE(std::filesystem::create_directory(dir, ec)) << ec.message();
    const auto base = dir / "capture";
    qb::io::log::init(base.string(), 64);
    EXPECT_TRUE(nanolog::log_file_opened());
    EXPECT_TRUE(nanolog::is_logged(qb::io::log::Level::WARN));
    body();
    qb::io::log::init("./qb", 512);
    std::string content;
    {
        std::ifstream      in(base.string() + ".1.log", std::ios::binary);
        std::ostringstream bytes;
        bytes << in.rdbuf();
        content = bytes.str();
    }
    std::filesystem::remove_all(dir, ec);
    return content;
}

[[nodiscard]] std::size_t
occurrences(const std::string &text, std::string_view needle) {
    std::size_t n = 0;
    for (std::size_t at = text.find(needle); at != std::string::npos; at = text.find(needle, at + needle.size())) {
        ++n;
    }
    return n;
}

} // namespace http2_server_goaway_test

// The session logs the GOAWAY its protocol sent -- a HEADERS on stream 0, a connection error -- as sent, and the
// client's GOAWAY as received. It logged both as received from the client, the server's own with its reason behind
// « GOAWAY sent by server: ».
TEST_F(Http2ServerGoawayWireTest, TheSessionLogsItsOwnGoawayAsSentAndTheClientsAsReceived) {
    const std::string log = log_of([] {
        auto server = start_server();
        ASSERT_TRUE(server->ready());
        {
            Http2RawClient client;
            ASSERT_TRUE(client.connect(server->port()));
            ASSERT_TRUE(client.read_until([&] { return client.settings_acked; }));
            ASSERT_TRUE(client.frame(Http2RawClient::HEADERS, Http2RawClient::END_STREAM | Http2RawClient::END_HEADERS, 0, {0x82}));
            ASSERT_TRUE(client.read_until([&] { return client.eof; }, 10s));
            ASSERT_TRUE(client.goaway_seen);
            EXPECT_EQ(client.goaway_debug, "HEADERS frame on stream 0");
        }
        {
            Http2RawClient client;
            ASSERT_TRUE(client.connect(server->port()));
            ASSERT_TRUE(client.read_until([&] { return client.settings_acked; }));
            std::vector<uint8_t> payload{0, 0, 0, 0, 0, 0, 0, 0x1};
            for (const char c : std::string_view("the client's reason"))
                payload.push_back(static_cast<uint8_t>(c));
            ASSERT_TRUE(client.frame(Http2RawClient::GOAWAY, 0, 0, payload));
            ASSERT_TRUE(client.read_until([&] { return client.eof; }, 10s)) << "the server kept the connection after a GOAWAY with an error";
        }
        server.reset(); // the server's thread ends before the capture does
    });
    EXPECT_EQ(occurrences(log, "Sent GOAWAY to client"), 1u) << "the server's own GOAWAY is not logged as sent";
    EXPECT_EQ(occurrences(log, "Sent GOAWAY to client. Last Stream ID: 0, Code: 1, Debug: HEADERS frame on stream 0"), 1u);
    EXPECT_EQ(occurrences(log, "Received GOAWAY from client"), 1u) << "the server's own GOAWAY is logged as received from the client";
    EXPECT_EQ(occurrences(log, "Received GOAWAY from client. Last Stream ID: 0, Code: 1, Debug: the client's reason"), 1u);
    EXPECT_EQ(occurrences(log, "GOAWAY sent by server"), 0u);
}
#endif // QB_WITH_LOGGING
