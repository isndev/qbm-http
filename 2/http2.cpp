/**
 * @file qbm/http/2/http2.cpp
 * @brief HTTP/2 TLS server instantiation
 *
 * Explicit instantiation of the default HTTP/2 server configuration, so the
 * common case is compiled once here instead of in every consumer.
 *
 * This TU is SSL-ONLY (see qbm/http/CMakeLists.txt): qb::http2::Server derives
 * from qb::io::async::tcp::acceptor<..., qb::io::transport::saccept> and calls
 * qb::io::ssl::Context::server(), none of which exist at QB_HAS_SSL=OFF — h2 is
 * TLS+ALPN only here, there is no h2c upgrade path.
 *
 * Nothing transport-independent may live in this file. The frame serializers
 * (qb::allocator::pipe<char>::put<Http2FrameData<T>>) used to, which made the
 * entire HTTP/2 wire codec unlinkable in SSL-off builds; they now sit with the
 * rest of the codec in ./protocol/base.cpp, next to their declarations.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./http2.h"

namespace qb::http2 {
template class Server<DefaultSession>;
} // namespace qb::http2
