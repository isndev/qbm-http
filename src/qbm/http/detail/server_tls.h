/**
 * @file server_tls.h
 * @brief Cold TLS configuration shared by the HTTP/1.1 and HTTP/2 listeners.
 */
#pragma once

#ifdef QB_HAS_SSL
#include <qb/io/tcp/ssl/listener.h>

namespace qb::http::detail {

// Context copies share SSL_CTX. The caller supplies a fresh, unpublished context;
// this pins its ALPN before replacing the listener's reference on its owner thread.
[[nodiscard]] bool set_server_tls_context(qb::io::tcp::ssl::listener &listener, qb::io::ssl::Context context, bool http2);

} // namespace qb::http::detail
#endif
