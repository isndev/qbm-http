#include "server_tls.h"

#include <memory>
#include <utility>
#include <qb/io/tcp/ssl/socket.h>
#include "../logger.h"

namespace qb::http::detail {

bool
set_server_tls_context(qb::io::tcp::ssl::listener &listener, qb::io::ssl::Context context, bool http2) {
    if (!context) {
        LOG_HTTP_ERROR("Failed to configure SSL/TLS server context: " << context.error());
        return false;
    }
    {
        // Before set_connect_state/set_accept_state, OpenSSL reports server for a
        // server OR generic method, client for a client-only method. Validate this
        // on a short-lived SSL, without a handshake or publication to the listener.
        std::unique_ptr<SSL, decltype(&SSL_free)> probe{SSL_new(context.native()), SSL_free};
        if (!probe || !SSL_is_server(probe.get()) || SSL_is_dtls(probe.get())) {
            LOG_HTTP_ERROR("HTTP requires a TLS server or generic context, not a client or DTLS context.");
            return false;
        }
    }
    // Context::alpn chooses its role from qb's private state. adopt/share of a raw
    // context without that state defaults to client-role, even for TLS_server_method.
    // The explicit server helper installs the server selection callback in both cases.
    const bool configured = http2 ? qb::io::ssl::set_alpn_protos_server(context.native(), {"h2", "http/1.1"})
                                  : qb::io::ssl::set_alpn_protos_server(context.native(), {"http/1.1"});
    if (!configured) {
        LOG_HTTP_ERROR("Failed to configure the HTTP server's ALPN selection.");
        return false;
    }
    return listener.reload_context(std::move(context));
}

} // namespace qb::http::detail
