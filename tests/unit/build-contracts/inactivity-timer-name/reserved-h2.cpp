/*
 * qb - C++ Actor Framework
 * Copyright (c) 2011-2026 qb - isndev (cpp.actor). All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * See the License for the specific terms.
 */

/**
 * @file unit/build-contracts/inactivity-timer-name/reserved-h2.cpp
 * @brief An HTTP/2 server session type that declares an `inactivity_timer_t` of its own does not compile (Huly
 *        QB-1248).
 *
 * The name is the session's: qb-io's `io_handler::extractSession()` reads it for the inactivity timer it stops. A
 * session type's own declaration hid it, and the extraction stopped another timer -- the session, held past its
 * extraction, was timed out on a connection its next owner has. The session's constructor refuses it with a
 * static_assert. This unit is built on demand by the ctest entry `qbm-http-test-unit-inactivity-timer-name-h2`, which
 * passes when the build fails with the static_assert's message as its only error. Built with
 * `QBM_HTTP_CONTRACT_CONTROL`, the declaration is gone: that unit is the target of the entry's name, built and linked
 * with the suite.
 */

#include <qbm/http/2/http2.h>

namespace inactivity_timer_name_contract {
class Server;

class Session : public qb::http2::use<Session>::session<Server> {
public:
#ifndef QBM_HTTP_CONTRACT_CONTROL
    using inactivity_timer_t = int; // hides the session's name: refused
#endif
    explicit Session(Server &server);
};

class Server : public qb::http2::use<Server>::server<Session> {};

Session::Session(Server &server)
    : session(server) {}
} // namespace inactivity_timer_name_contract

int
main() {
    return 0;
}
