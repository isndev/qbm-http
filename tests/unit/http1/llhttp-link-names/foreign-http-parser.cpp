/**
 * @file qbm/http/tests/unit/http1/llhttp-link-names/foreign-http-parser.cpp
 * @brief Node's older http_parser in the same program: its own link names, its own answers.
 *
 * The stand-in for a library that carries http_parser (Huly QB-1139). http_parser and qbm-http's
 * llhttp fork share two C names outright, with other signatures -- `http_should_keep_alive` and
 * `http_errno_name` -- and this object defines both under those names. It includes nothing of
 * qbm-http, so here they are the plain C names. Its `http_should_keep_alive` answers "keep alive"
 * for every message: if qbm-http's parser ever reached it, a `Connection: close` request would
 * come out keep-alive, which is how the witness sees it.
 *
 * One object on purpose: the witness references `foreign_marker()`, so the linker loads this
 * object beside the fork's whatever the order -- two `http_should_keep_alive`, unless the fork's
 * link names are its own.
 */

#include <cstdint>

namespace llhttp_link_names_test {
std::uint32_t g_foreign_calls = 0;
} // namespace llhttp_link_names_test

struct http_parser;

extern "C" {

int
http_should_keep_alive(const struct http_parser *) {
    ++llhttp_link_names_test::g_foreign_calls;
    return 0x5eed;
}

const char *
http_errno_name(int) {
    ++llhttp_link_names_test::g_foreign_calls;
    return "FOREIGN_HTTP_PARSER";
}

} // extern "C"

namespace llhttp_link_names_test {

int
foreign_marker() {
    return 0x5eed;
}

std::uint32_t
foreign_calls() {
    return g_foreign_calls;
}

void const *
foreign_keep_alive_address() {
    return reinterpret_cast<void const *>(&http_should_keep_alive);
}

} // namespace llhttp_link_names_test
