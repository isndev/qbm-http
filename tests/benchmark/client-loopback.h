#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <thread>
#include <utility>

#include <qb/io/async.h>
#include <qb/io/udp/socket.h>

namespace http_client_bench {

inline std::pair<std::filesystem::path, std::filesystem::path>
certificates() {
    // The benchmark source lives at qbm/http/tests/benchmark/ in both trees.
    const auto root      = std::filesystem::path(__FILE__)
                               .lexically_normal()
                               .parent_path()  // benchmark
                               .parent_path()  // tests
                               .parent_path()  // http
                               .parent_path()  // qbm
                               .parent_path(); // superproject
    const auto directory = root / "qb" / "resources" / "ssl";
    return {directory / "cert.pem", directory / "key.pem"};
}

template <typename Predicate>
bool
pump_until(Predicate &&done, std::chrono::steady_clock::duration budget = std::chrono::seconds(5)) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!done()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            return false;
        }
        if (!qb::io::async::run(EVRUN_NOWAIT)) {
            std::this_thread::yield();
        }
    }
    return true;
}

inline std::uint16_t
free_udp_port() {
    qb::io::udp::socket probe;
    if (!probe.init(AF_INET) || probe.bind_v4(0, "127.0.0.1") != 0) {
        return 0;
    }
    const auto port = probe.local_endpoint().port();
    probe.close();
    return port;
}

} // namespace http_client_bench
