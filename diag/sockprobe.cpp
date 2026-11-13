// SCRATCH (lot T7-H2MAC, Huly QB-1270), never to merge: does a loopback TCP socket filled by a peer that reads nothing
// stay full? A sender writes (non-blocking) until the socket refuses, then, after a pause, tries again and counts what
// the socket took after it had refused. Configurations: the receiver's SO_RCVBUF set before connect(), after it, or not;
// the sender's SO_SNDBUF set or not (on the listening socket, inherited, or on the accepted one). Each prints the
// buffer sizes the system reports at each step.
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {
int
opt(int fd, int name) {
    int       v   = -1;
    socklen_t len = sizeof v;
    if (getsockopt(fd, SOL_SOCKET, name, &v, &len) != 0)
        return -errno;
    return v;
}
void
set(int fd, int name, int v) {
    if (v > 0 && setsockopt(fd, SOL_SOCKET, name, &v, sizeof v) != 0)
        std::printf("  setsockopt(%d, %d) failed: %s\n", name, v, std::strerror(errno));
}
// Write until the socket refuses: the bytes taken, and the errno that stopped it.
std::size_t
fill(int fd, int &stop) {
    static std::vector<char> chunk(65536, 'x');
    std::size_t              total = 0;
    for (;;) {
        const ssize_t n = ::send(fd, chunk.data(), chunk.size(), 0);
        if (n > 0) {
            total += static_cast<std::size_t>(n);
            continue;
        }
        stop = n < 0 ? errno : 0;
        return total;
    }
}
struct config {
    const char *name;
    int         rcv_before; // the receiver's SO_RCVBUF before connect()
    int         rcv_after;  // ... after connect()
    int         snd_listen; // the sender's SO_SNDBUF on the listening socket (inherited)
    int         snd_accept; // ... on the accepted socket
};
} // namespace

int
main(int argc, char **argv) {
    const int    trials    = argc > 1 ? std::atoi(argv[1]) : 10;
    const config configs[] = {
        {"defaults", 0, 0, 0, 0},
        {"rcv 4096 before connect", 4096, 0, 0, 0},
        {"rcv 4096 after connect", 0, 4096, 0, 0},
        {"rcv 4096 before, snd 16384 on the listener", 4096, 0, 16384, 0},
        {"rcv 4096 before, snd 16384 on the accepted socket", 4096, 0, 0, 16384},
        {"rcv 4096 after, snd 16384 on the accepted socket", 0, 4096, 0, 16384},
        {"snd 16384 on the accepted socket only", 0, 0, 0, 16384},
    };
    const int pauses_ms[] = {0, 1, 5, 50};
    for (auto const &c : configs) {
        std::printf("=== %s\n", c.name);
        for (int pause : pauses_ms) {
            std::size_t took_after_max = 0, took_after_sum = 0, nonzero = 0, filled_sum = 0;
            int         rcv_connect = 0, rcv_end = 0, snd_end = 0, stop = 0;
            for (int t = 0; t < trials; ++t) {
                const int l   = ::socket(AF_INET, SOCK_STREAM, 0);
                int       one = 1;
                setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
                set(l, SO_SNDBUF, c.snd_listen);
                sockaddr_in a{};
                a.sin_family      = AF_INET;
                a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                a.sin_port        = 0;
                ::bind(l, reinterpret_cast<sockaddr *>(&a), sizeof a);
                ::listen(l, 1);
                socklen_t len = sizeof a;
                ::getsockname(l, reinterpret_cast<sockaddr *>(&a), &len);
                const int r = ::socket(AF_INET, SOCK_STREAM, 0); // the receiver: reads nothing
                set(r, SO_RCVBUF, c.rcv_before);
                if (::connect(r, reinterpret_cast<sockaddr *>(&a), sizeof a) != 0) {
                    std::printf("connect: %s\n", std::strerror(errno));
                    return 1;
                }
                set(r, SO_RCVBUF, c.rcv_after);
                const int s = ::accept(l, nullptr, nullptr); // the sender
                set(s, SO_SNDBUF, c.snd_accept);
                ::fcntl(s, F_SETFL, ::fcntl(s, F_GETFL) | O_NONBLOCK);
                rcv_connect            = opt(r, SO_RCVBUF);
                const std::size_t full = fill(s, stop);
                std::this_thread::sleep_for(std::chrono::milliseconds(pause));
                int               stop2 = 0;
                const std::size_t more  = fill(s, stop2);
                filled_sum += full;
                took_after_sum += more;
                took_after_max = std::max(took_after_max, more);
                nonzero += more != 0;
                rcv_end = opt(r, SO_RCVBUF);
                snd_end = opt(s, SO_SNDBUF);
                ::close(s);
                ::close(r);
                ::close(l);
            }
            std::printf("  pause %2d ms: filled %zu avg, then took more in %zu of %d (max %zu, avg %zu); rcvbuf at connect %d, at "
                        "end %d; sndbuf at end %d; first stop errno %d (%s)\n",
                        pause, filled_sum / trials, nonzero, trials, took_after_max, took_after_sum / trials, rcv_connect, rcv_end, snd_end,
                        stop, std::strerror(stop));
        }
    }
    return 0;
}
