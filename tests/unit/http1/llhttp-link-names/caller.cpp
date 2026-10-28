/**
 * @file qbm/http/tests/unit/http1/llhttp-link-names/caller.cpp
 * @brief A translation unit of the program that uses http_parser and includes nothing of qbm-http.
 *
 * Its `http_should_keep_alive` and `http_errno_name` are resolved by the linker, not by qbm-http's
 * headers: with the llhttp fork linked under its own names, they reach the http_parser stand-in
 * (foreign-http-parser.cpp), proving that copy is really in the program beside the fork.
 */

struct http_parser;
extern "C" int         http_should_keep_alive(const struct http_parser *);
extern "C" const char *http_errno_name(int);

namespace llhttp_link_names_test {

int
call_foreign_keep_alive() {
    return http_should_keep_alive(nullptr);
}

const char *
call_foreign_errno_name() {
    return http_errno_name(0);
}

} // namespace llhttp_link_names_test
