/**
 * @file qbm/http/3/client.cpp
 * @brief HTTP/3 client implementation.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "client.h"

#include <algorithm>
#include <exception>
#include <utility>

#include <nghttp3/nghttp3.h>

#include <qb/io/tcp/socket.h> // resolve_endpoints(), connect_attempt_budget(): the rules of the TCP connector

#include "../detail/client_callback.h"
#include "../origin.h"

namespace qb::http3 {

using qb::http::detail::notify; // a user callback's call: contained while the client is being destroyed (Huly QB-1246)

namespace {
// Endpoint dispatch continues after a derived callback returns. If user code
// releases the last external owner, defer the last reference until the next
// listener turn, after the endpoint's outer event handler has unwound.
struct EventLifetime {
    std::shared_ptr<Client> owner;

    explicit EventLifetime(Client &client)
        : owner(client.weak_from_this().lock()) {}

    ~EventLifetime() {
        if (owner && owner.use_count() == 1) {
            qb::io::async::listener::current.defer([hold = std::move(owner)] {});
        }
    }
};

/// Counts a failure while it runs the callbacks of what it ends, however it is left: what such a callback awaits of
/// connect() is answered at once (Huly QB-1246).
struct FailureScope {
    int &depth;
    explicit FailureScope(int &value) noexcept
        : depth(value) {
        ++depth;
    }
    FailureScope(FailureScope const &)            = delete;
    FailureScope &operator=(FailureScope const &) = delete;
    ~FailureScope() noexcept {
        --depth;
    }
};
} // namespace

Client::Client(std::string const &base_uri)
    : _client_id(qb::generate_random_uuid()) {
    initialize_from_uri(qb::io::uri(base_uri));
}

Client::Client(qb::io::uri const &uri)
    : _client_id(qb::generate_random_uuid()) {
    initialize_from_uri(uri);
}

Client::~Client() {
    // The destruction contract of the three HTTP clients (Huly QB-1246): every request in flight or queued hears once, every
    // connect() still waiting hears `false` once, and from `_destroying` on nothing is accepted, armed or connected -- a request
    // pushed from one of those callbacks is answered inside its push, a connect() refused by its return value alone. A client
    // with static storage is destroyed after its thread's event loop, where a timer or a connection asked stops the process.
    _destroying = true;
    try {
        (void) fail_all_requests("HTTP/3 client destroyed"); // what a callback throws is logged where it is thrown: notify()
    } catch (...) {
        // An allocation the pass makes for itself failed: nothing leaves a destructor. The close below still runs.
    }
    _deferred_close.reset(); // a close a read left half done is not this one: disconnect() below is the full close,
    qb::http::detail::contained("HTTP/3", [&] { disconnect(); }, "destructor's close"); // every connect() still waiting hears it
    qb::http::detail::contained("HTTP/3", [&] { run_late_answers(); }, "refusals still owed their turn"); // heard here, once
}

namespace {
/// Counts a refusal while it is answered inside its push, however that answer is left.
struct RefusalScope {
    int &depth;
    explicit RefusalScope(int &value) noexcept
        : depth(value) {
        ++depth;
    }
    RefusalScope(RefusalScope const &)            = delete;
    RefusalScope &operator=(RefusalScope const &) = delete;
    ~RefusalScope() noexcept {
        --depth;
    }
};
} // namespace

void
Client::refuse(std::function<void()> answer) {
    if (_refusal_depth == 0 || _destroying || weak_from_this().expired()) {
        const RefusalScope answering{_refusal_depth};
        answer(); // inside the push, as before: what the callback throws reaches the caller of the push
        return;
    }
    // Pushed from inside the answer of a refusal: answered there too, a callback that pushes its request back at every
    // refusal was called from inside its own push, one frame deeper each time, without end. Heard on the loop's next turn.
    _late_answers.push_back(std::move(answer));
    if (!_late_scheduled) {
        _late_scheduled = true;
        qb::io::async::defer([weak_self = weak_from_this()] {
            if (auto self = weak_self.lock()) {
                self->run_late_answers();
            }
        });
    }
}

void
Client::run_late_answers() {
    _late_scheduled = false;
    auto answers    = std::exchange(_late_answers, {}); // taken first: what one of them pushes is refused, or kept, anew
    for (auto &answer : answers) {
        qb::http::detail::contained("HTTP/3", answer); // no caller is left to hear what it throws
    }
}

void
Client::initialize_from_uri(qb::io::uri const &uri) {
    if (!qb::http::origin::scheme_eq(uri.scheme(), "https")) {
        throw std::invalid_argument("HTTP/3 client only supports https scheme");
    }
    _base_uri = uri;
    _host     = std::string(uri.host());
}

void
Client::set_verify_peer(bool value) noexcept {
    _verify_peer = value;
}

bool
Client::connect(ConnectionCallback callback) {
    if (_destroying) {
        return false; // refused, by the return value alone: the callback of a connect() that starts nothing is never called (QB-1246)
    }
    auto owner = weak_from_this().lock();
    if (_deferred_close && (_read_depth > 0 || _deferred_close->empty())) {
        // The old connection is still on nghttp3's stack, or its explicit close is notifying: a new handshake waits for that
        // teardown. The connect is queued and started once it has completed (start_deferred_connect()), so its callback hears the
        // attempt's own outcome -- it used to hear `false` here, inside the call, and a callback that dialled again on `false`
        // recursed without end (Huly QB-1246; the HTTP/2 client's `_connect_after_close` does the same). Two places complete
        // such a teardown: disconnect(), for an explicit close, and dispatch(stream_data) once its read has returned, for a
        // connection lost during that read. A close deferred by a submission alone queues nothing: no read is on the stack.
        if (callback) {
            _deferred_connects.push_back(std::move(callback));
        }
        _connect_after_close = true;
        return true;
    }
    if (_is_connected) {
        if (callback) {
            callback(true, {});
        }
        return true;
    }
    if (_is_connecting) {
        if (callback) {
            _connection_callbacks.push_back(std::move(callback));
        }
        return true;
    }
    // The host is resolved here, as the TCP connector of the two other clients resolves it (a blocking lookup, every address
    // of the family the URI names, in the resolver's order): the QUIC endpoint dials an address, as every QUIC stack's core
    // does, and until 3.4 this client handed it the name -- a host name never connected (Huly QB-1246). One connect timeout
    // covers the lookup and every address, stamped before the lookup.
    const auto                    began = std::chrono::steady_clock::now();
    std::vector<qb::io::endpoint> candidates;
    try {
        candidates = qb::io::tcp::resolve_endpoints(_base_uri.af(), _host, _base_uri.u_port());
    } catch (...) {
        // the lookup could not allocate its answer: no address
    }
    return dial(std::move(candidates), std::move(callback), began);
}

bool
Client::dial(std::vector<qb::io::endpoint> candidates, ConnectionCallback callback, std::chrono::steady_clock::time_point began) {
    auto       owner             = weak_from_this().lock();
    const bool heard_by_callback = static_cast<bool>(callback);
    if (heard_by_callback) {
        _connection_callbacks.push_back(std::move(callback));
    }
    const auto epoch    = ++_connect_epoch;
    _is_connecting      = true;
    _h3_ready           = false;
    _remote_shutdown    = false;
    _connect_deadline   = _connect_timeout > qb::duration::zero() ? began + _connect_timeout : std::chrono::steady_clock::time_point{};
    _connect_next       = 0;
    _connect_candidates = std::move(candidates);
    const char *failure = nullptr;
    if (_connect_candidates.empty()) {
        failure = "Unable to start QUIC connection";
        LOG_HTTP_WARN_PA(_client_id, "HTTP/3 connection to " << _host << " cannot start: the host resolves to no address");
    } else if (_connect_timeout > qb::duration::zero() && std::chrono::steady_clock::now() >= _connect_deadline) {
        failure = "HTTP/3 connection timeout"; // the lookup outlasted it: nothing is dialled
    } else if (!start_attempt()) {
        failure = "Unable to start QUIC connection";
        LOG_HTTP_WARN_PA(_client_id, "HTTP/3 connection to " << _host << " cannot start: no UDP socket opened and bound");
    }
    if (failure == nullptr) {
        arm_connect_timeout();
        return true;
    }
    if (!owner) {
        // No shared owner to hear for on a later turn (a plain object, not make_client()'s): the return value alone, and
        // its own callback dropped unheard. What was already waiting hears.
        if (heard_by_callback) {
            _connection_callbacks.pop_back();
        }
        close_failed_transport(failure);
        handle_connection_failure(failure);
        return false;
    }
    // An attempt that cannot start is a connection that failed, heard as one: through the callback, on a later turn of the
    // loop, as on the HTTP/1.1 and HTTP/2 clients, whose connector delivers it so. It answered this call by its return value
    // alone, and ran the failure of what was waiting from inside the call -- where a request whose callback pushes it back
    // dialled again, without end (Huly QB-1246).
    qb::io::async::defer([weak_self = weak_from_this(), epoch, error = std::string(failure)] {
        auto self = weak_self.lock();
        if (!self || self->_connect_epoch != epoch || !self->_is_connecting) {
            return; // a disconnect(), or a connection, since
        }
        self->close_failed_transport(error);
        self->handle_connection_failure(error);
    });
    return true;
}

bool
Client::start_attempt() {
    while (_connect_next < _connect_candidates.size()) {
        const auto &remote = _connect_candidates[_connect_next++];
        // The endpoint is given the address; the name stays the caller's, for SNI and for the certificate.
        qb::io::quic::tls_config tls;
        tls.server_name = _host;
        tls.verify_peer = _verify_peer;
        const auto dialed =
            "https://" + (remote.af() == AF_INET6 ? "[" + remote.ip() + "]" : remote.ip()) + ":" + std::to_string(remote.port());
        if (qb::io::async::quic::endpoint::connect(qb::io::uri(dialed), std::move(tls), {"h3"})) {
            ++_connect_attempt;
            // Its share of what is left, by the TCP connector's rule (connect_attempt_budget()). The last address has all of
            // it -- the connect timeout ends it --, and with no timeout no address is given up: QUIC has no refusal to hear.
            const std::size_t left = _connect_candidates.size() - _connect_next + 1;
            if (left > 1 && !_destroying && _connect_timeout > qb::duration::zero()) {
                const auto remaining = std::chrono::duration_cast<qb::duration>(_connect_deadline - std::chrono::steady_clock::now());
                qb::io::async::callback(
                    [weak_self = weak_from_this(), epoch = _connect_epoch, attempt = _connect_attempt] {
                        auto self = weak_self.lock();
                        if (self && self->_connect_epoch == epoch && self->_connect_attempt == attempt && self->_is_connecting) {
                            self->next_attempt();
                        }
                    },
                    qb::io::tcp::connect_attempt_budget(remaining, left));
            }
            return true;
        }
        close_failed_transport("HTTP/3 attempt could not start"); // what the endpoint opened before it gave up
    }
    return false;
}

void
Client::next_attempt() {
    LOG_HTTP_INFO_PA(_client_id, "HTTP/3 address " << _connect_next << " of " << _connect_candidates.size() << " for " << _host
                                                   << " did not answer in its share of the connect timeout: the next is dialled");
    close_failed_transport("HTTP/3 address did not answer"); // no failure: the connect() goes on
    if (!start_attempt()) {
        close_failed_transport("Unable to start QUIC connection");
        handle_connection_failure("Unable to start QUIC connection");
    }
}

void
Client::disconnect() {
    if (_deferred_close && _deferred_close->empty()) {
        give_up_deferred_connects(); // a connect() asked since then is given up: the last word is this disconnect()
        return;                      // an explicit close is already notifying its old requests
    }
    if (_read_depth > 0 || _submit_depth > 0) {
        // A pending callback may call disconnect from nghttp3_conn_read_stream2.
        // Keep _h3 alive until that native reader returns. An empty deferred
        // reason marks explicit intent and takes precedence over a transport
        // close, so the outer dispatch will not start an automatic reconnect.
        ++_connect_epoch;
        _is_connected    = false;
        _is_connecting   = false;
        _h3_ready        = false;
        _remote_shutdown = true;
        _deferred_close.emplace();
        give_up_deferred_connects(); // a connect() queued before this disconnect() hears `false` when the close runs
        return;
    }
    give_up_deferred_connects(); // and one queued while a lost connection was torn down hears `false` from this close
    complete_disconnect();
}

void
Client::complete_disconnect() {
    // The close itself: disconnect() with no read on the stack, and the end of a disconnect() that was deferred to the end of
    // a read or of a submission. A connect() queued when it starts is NOT given up here: after a deferred disconnect() it was
    // asked after it (disconnect() gave up the ones before), and it starts once this close has run. disconnect() gives up
    // every one first -- its caller's last word -- so a disconnect() from a failure callback of a lost connection never
    // starts the connect() asked of that connection (Huly QB-1246).
    // Mark the old connection unavailable before invoking failure callbacks.
    // They may call connect(), push_request(), or disconnect() again.
    auto owner = weak_from_this().lock();
    ++_connect_epoch;
    _is_connected    = false;
    _is_connecting   = false;
    _h3_ready        = false;
    _remote_shutdown = true;
    _deferred_close.emplace();
    // The mark goes with this close however it ends: left behind by an allocation the pass makes for itself -- the one thing
    // that can leave it before its end --, it would keep every later disconnect() out, the destructor's included.
    struct close_mark {
        Client &client;
        bool    held = true;
        ~close_mark() {
            if (held) {
                client._deferred_close.reset();
                client._remote_shutdown = false;
            }
        }
    } mark{*this};
    std::exception_ptr callback_error;
    const auto         capture = [&](auto &&call) {
        try {
            call();
        } catch (...) {
            if (!callback_error) {
                callback_error = std::current_exception();
            }
        }
    };
    const auto fail_connects = [&] {
        while (!_connection_callbacks.empty()) {
            auto callbacks = std::exchange(_connection_callbacks, {});
            for (auto &callback : callbacks) {
                if (callback) {
                    capture([&] { notify(_destroying, "HTTP/3", [&] { callback(false, "HTTP/3 client disconnect"); }); });
                }
            }
        }
    };
    fail_connects();
    if (auto error = fail_all_requests("HTTP/3 client disconnect"); error && !callback_error) {
        callback_error = error;
    }
    fail_connects(); // a connect() one of those callbacks asked, then gave up by a disconnect() of its own
    _h3.reset();
    capture([&] { qb::io::async::quic::endpoint::close(0, "HTTP/3 client disconnect"); });
    _deferred_close.reset();
    _remote_shutdown = false;
    mark.held        = false;
    capture([&] { start_deferred_connect(); }); // a connect() one of those callbacks asked: the close has completed
    if (callback_error) {
        std::rethrow_exception(callback_error);
    }
}

void
Client::give_up_deferred_connects() {
    for (auto &callback : _deferred_connects) {
        _connection_callbacks.push_back(std::move(callback)); // where the close, or the attempt, that answers them finds them
    }
    _deferred_connects.clear();
    _connect_after_close = false;
}

void
Client::start_deferred_connect() {
    if (_connect_after_close) {
        give_up_deferred_connects(); // not given up: their callbacks wait for the attempt started here, and hear its outcome
        (void) connect(nullptr);     // (an attempt that cannot start fails them with everything else that waits)
    }
}

void
Client::ensure_absolute_uri(qb::http::Request &request) {
    if (!request.uri().host().empty()) {
        return;
    }
    // The base authority as every protocol writes it: an IPv6 literal between brackets (Huly QB-572,
    // QB-1064).
    std::string absolute = "https://" + qb::http::origin::authority(_base_uri);
    absolute += request.uri().path().empty() ? "/" : std::string(request.uri().path());
    if (!request.uri().encoded_queries().empty()) {
        absolute.push_back('?');
        absolute += request.uri().encoded_queries();
    }
    request.uri() = qb::io::uri(absolute);
}

std::optional<qb::http::Response>
Client::prepare_request(qb::http::Request &request) {
    ensure_absolute_uri(request);
    if (request.uri().host().empty()) {
        return create_error_response(qb::http::status::BAD_REQUEST, "HTTP/3 request URI is missing a host");
    }
    if (!qb::http::origin::scheme_eq(request.uri().scheme(), "https")) {
        return create_error_response(qb::http::status::BAD_REQUEST, "HTTP/3 request URI must use https");
    }
    if (!qb::http::origin::same(request.uri(), _base_uri)) {
        return create_error_response(qb::http::status::BAD_REQUEST, "HTTP/3 persistent client only accepts same-origin requests");
    }
    return std::nullopt;
}

bool
Client::push_request(qb::http::Request request, ResponseCallback callback) {
    if (!callback) {
        return false;
    }
    // false when the pending bound refused the request, its callback already holding the 503, as
    // the HTTP/1.1 and HTTP/2 clients answer; an invalid request, or one refused after GOAWAY, is
    // answered through its callback and returns true, as there (Huly QB-499).
    bool refused_by_bound = false;
    (void) admit_request(std::move(request), std::move(callback), refused_by_bound);
    return !refused_by_bound;
}

request_id
Client::push_request_with_id(qb::http::Request request, ResponseCallback callback) {
    bool refused_by_bound = false;
    return admit_request(std::move(request), std::move(callback), refused_by_bound);
}

request_id
Client::admit_request(qb::http::Request request, ResponseCallback callback, bool &refused_by_bound) {
    if (!callback) {
        return 0;
    }
    ++_total_requests;
    if (_destroying) { // pushed from a callback the destructor runs: answered here, never queued, nothing armed (Huly QB-1246)
        ++_failed_requests;
        if (_refusal_depth != 0) {
            // Pushed from inside the answer of such a push: refused by the return value alone, as connect() is there, its
            // callback destroyed unheard. No later turn exists to hear it on, and answered here a callback that always pushes
            // again was called from inside its own push without end.
            refused_by_bound = true;
            return 0;
        }
        const RefusalScope answering{_refusal_depth};
        notify(_destroying, "HTTP/3",
               [&] { callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "HTTP/3 client disconnect")); });
        return 0;
    }
    if (auto error = prepare_request(request)) {
        ++_failed_requests;
        refuse([callback = std::move(callback), response = std::move(*error)]() mutable { callback(std::move(response)); });
        return 0;
    }
    if (_remote_shutdown) {
        ++_failed_requests;
        const auto *reason = _deferred_close && _deferred_close->empty() ? "HTTP/3 client disconnect" : "HTTP/3 server is shutting down";
        refuse([callback = std::move(callback), response = create_error_response(qb::http::status::SERVICE_UNAVAILABLE, reason)]() mutable {
            callback(std::move(response));
        });
        return 0;
    }
    if (_pending_requests.size() + _active_requests.size() >= _max_pending_requests) {
        ++_failed_requests;
        refused_by_bound = true;
        refuse([callback = std::move(callback), response = create_error_response(qb::http::status::SERVICE_UNAVAILABLE,
                                                                                 "HTTP/3 client pending request limit reached")]() mutable {
            callback(std::move(response));
        });
        return 0;
    }
    auto ctx              = std::make_unique<RequestContext>();
    ctx->request          = std::move(request);
    ctx->callback         = std::move(callback);
    ctx->created_at       = std::chrono::steady_clock::now();
    ctx->request_id       = _next_request_id++;
    const auto request_id = ctx->request_id;
    _pending_requests.push_back(std::move(ctx));
    arm_request_timeout(request_id);

    if (is_connected()) {
        process_pending_requests();
    } else if (!_is_connecting) {
        connect(nullptr);
    }
    return request_id;
}

bool
Client::cancel_request(request_id id, std::string const &reason) {
    auto pending =
        std::find_if(_pending_requests.begin(), _pending_requests.end(), [id](auto const &ctx) { return ctx && ctx->request_id == id; });
    if (pending != _pending_requests.end()) {
        auto ctx = std::move(*pending);
        _pending_requests.erase(pending);
        ++_failed_requests;
        ctx->callback(create_error_response(qb::http::status::CLIENT_CLOSED_REQUEST, reason));
        return true;
    }

    auto active = std::find_if(_active_requests.begin(), _active_requests.end(),
                               [id](auto const &entry) { return entry.second && entry.second->request_id == id; });
    if (active == _active_requests.end()) {
        return false;
    }
    const auto stream_id = active->first;
    auto       owner     = weak_from_this().lock(); // Keep alive through callback and RFC 9114 §4.1 stream reset.
    fail_request(stream_id, reason, qb::http::status::CLIENT_CLOSED_REQUEST);
    reset_stream(0, stream_id, NGHTTP3_H3_REQUEST_CANCELLED);
    process_pending_requests();
    return true;
}

bool
Client::push_requests(std::vector<qb::http::Request> requests, BatchResponseCallback callback) {
    if (requests.empty()) {
        if (callback) {
            notify(_destroying, "HTTP/3", [&] { callback({}); });
        }
        return true;
    }
    if (!callback) {
        return false;
    }
    if (_destroying || _remote_shutdown) { // while destroying: as push_request(), every member answered here (Huly QB-1246)
        const auto *reason =
            _destroying || (_deferred_close && _deferred_close->empty()) ? "HTTP/3 client disconnect" : "HTTP/3 server is shutting down";
        _total_requests += requests.size();
        _failed_requests += requests.size();
        if (_destroying && _refusal_depth != 0) {
            return false; // as push_request() there: refused by the return value alone, the batch's callback unheard
        }
        const auto answer = [this, count = requests.size(), reason](BatchResponseCallback const &heard) {
            std::vector<qb::http::Response> responses;
            responses.reserve(count);
            for (std::size_t i = 0; i < count; ++i) {
                responses.push_back(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, reason));
            }
            heard(std::move(responses));
        };
        if (_destroying) {
            const RefusalScope answering{_refusal_depth};
            notify(_destroying, "HTTP/3", [&] { answer(callback); });
        } else {
            refuse([answer, callback = std::move(callback)] { answer(callback); });
        }
        return true;
    }

    const auto batch_id = _next_batch_id++;
    auto       batch    = std::make_unique<BatchRequestContext>();
    batch->callback     = std::move(callback);
    batch->responses.resize(requests.size());
    batch->completed.assign(requests.size(), false);
    bool admitted_all = true; // false once the bound refuses a member, as push_request() answers

    _total_requests += requests.size();

    for (std::size_t i = 0; i < requests.size(); ++i) {
        if (auto error = prepare_request(requests[i])) {
            ++_failed_requests;
            batch->responses[i] = std::move(*error);
            batch->completed[i] = true;
            ++batch->completed_count;
            continue;
        }
        // The bound counts queued + active requests whatever queued them: each member is
        // admitted as push_request would admit it, BEFORE its context and timer exist, and a
        // member past the bound is answered 503 at its index (Huly QB-499).
        if (_pending_requests.size() + _active_requests.size() >= _max_pending_requests) {
            ++_failed_requests;
            batch->responses[i] = create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "HTTP/3 client pending request limit reached");
            batch->completed[i] = true;
            ++batch->completed_count;
            admitted_all = false;
            continue;
        }
        auto ctx              = std::make_unique<RequestContext>();
        ctx->request          = std::move(requests[i]);
        ctx->created_at       = std::chrono::steady_clock::now();
        ctx->request_id       = _next_request_id++;
        ctx->batch_id         = batch_id;
        const auto request_id = ctx->request_id;
        ctx->callback         = [this, batch_id, i](qb::http::Response response) {
            auto it = _active_batches.find(batch_id);
            if (it == _active_batches.end()) {
                return;
            }
            auto &batch_ctx        = *it->second;
            batch_ctx.responses[i] = std::move(response);
            batch_ctx.completed[i] = true;
            if (++batch_ctx.completed_count == batch_ctx.responses.size()) {
                auto done      = std::move(batch_ctx.callback);
                auto responses = std::move(batch_ctx.responses);
                _active_batches.erase(it);
                done(std::move(responses));
            }
        };
        _pending_requests.push_back(std::move(ctx));
        arm_request_timeout(request_id);
    }

    if (batch->completed_count == batch->responses.size()) {
        // Call through `batch->callback`, NOT `callback`: ownership moved to the batch above, so
        // `callback` is an empty std::function here and invoking it throws std::bad_function_call.
        // Reached whenever every request in the batch fails prepare_request synchronously (a batch
        // of malformed URIs), i.e. exactly when the caller most needs its error results.
        batch->callback(std::move(batch->responses));
        return admitted_all;
    }

    _active_batches.emplace(batch_id, std::move(batch));

    if (is_connected()) {
        process_pending_requests();
    } else if (!_is_connecting) {
        connect(nullptr);
    }
    return admitted_all;
}

void
Client::process_pending_requests() {
    auto owner = weak_from_this().lock();
    if (!_h3 || !is_connected() || _remote_shutdown) {
        return;
    }
    while (_h3 && is_connected() && !_remote_shutdown && !_pending_requests.empty() && _active_requests.size() < _max_concurrent_streams) {
        // A prior iteration's submit_request / reset_stream drains output; a >TX-cap send can
        // have reentrantly scheduled a connection teardown (deferred until the read unwinds —
        // see dispatch(stream_data)). Stop enqueuing onto a connection that is going away: the
        // deferred fail_all_requests will fail everything already in _active_requests. Checking
        // at the loop top covers BOTH the submit-success and the submit-failure (reset_stream)
        // paths below, either of which can set _deferred_close.
        if (_deferred_close) {
            return;
        }
        auto ctx = std::move(_pending_requests.front());
        _pending_requests.pop_front();

        auto stream              = open_bidirectional_stream(0);
        ctx->stream_id           = stream.id();
        const auto stream_id     = ctx->stream_id;
        const auto attempt_epoch = _connect_epoch;
        bool       submitted     = false;
        {
            struct SubmitGuard {
                int &depth;
                explicit SubmitGuard(int &value) noexcept
                    : depth(value) {
                    ++depth;
                }
                ~SubmitGuard() noexcept {
                    --depth;
                }
            } guard(_submit_depth);
            submitted = _h3->submit_request(stream_id, ctx->request);
        }
        std::exception_ptr transition_error;
        bool               closed_during_submit = false;
        if (_deferred_close && _read_depth == 0 && _submit_depth == 0) {
            closed_during_submit     = true;
            const std::string reason = std::move(*_deferred_close);
            _deferred_close.reset();
            try {
                if (reason.empty()) {
                    complete_disconnect(); // the disconnect() deferred to the end of this submission
                } else {
                    close_failed_transport("HTTP/3 connection closed");
                    handle_connection_failure(reason);
                    if (_auto_reconnect && has_pending_or_active_work()) {
                        connect(nullptr);
                    }
                }
            } catch (...) {
                transition_error = std::current_exception();
            }
        }
        if (closed_during_submit || attempt_epoch != _connect_epoch || !_h3 || !is_connected()) {
            const FailureScope failing{_failure_callbacks}; // the request of a connection that has just ended (Huly QB-1246)
            ++_failed_requests;
            try {
                // Through refuse(), as every refusal of a push: its callback may push the request back.
                refuse([shared   = std::shared_ptr<RequestContext>(std::move(ctx)),
                        response = create_error_response(qb::http::status::SERVICE_UNAVAILABLE,
                                                         "HTTP/3 connection closed during request submission")]() mutable {
                    shared->callback(std::move(response));
                });
            } catch (...) {
                if (!transition_error) {
                    transition_error = std::current_exception();
                }
            }
            if (transition_error) {
                std::rethrow_exception(transition_error);
            }
            return;
        }
        if (!submitted) {
            // Request never made it onto the wire; abandon the just-opened
            // stream the same way the client cancels any request (RFC 9114 §4.1).
            reset_stream(0, stream_id, NGHTTP3_H3_REQUEST_CANCELLED);
            ++_failed_requests;
            refuse([shared   = std::shared_ptr<RequestContext>(std::move(ctx)),
                    response = create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "Failed to submit HTTP/3 request")]() mutable {
                shared->callback(std::move(response));
            });
            continue;
        }
        _active_requests.emplace(stream_id, std::move(ctx));
    }
}

void
Client::handle_connection_success(std::string const &alpn) {
    ++_connect_epoch;
    _is_connected    = true;
    _is_connecting   = false;
    _h3_ready        = true;
    _remote_shutdown = false;
    _h3              = std::make_unique<h3_connection>(*this, 0, h3_connection::role::client);
    _h3->bind_local_streams();
    auto callbacks = std::move(_connection_callbacks);
    _connection_callbacks.clear();
    std::exception_ptr callback_error;
    for (auto &cb : callbacks) {
        if (cb) {
            try {
                cb(true, {});
            } catch (...) {
                if (!callback_error) {
                    callback_error = std::current_exception();
                }
            }
        }
    }
    process_pending_requests();
    LOG_HTTP_INFO_PA(_client_id, "HTTP/3 connected with ALPN " << alpn);
    if (callback_error) {
        std::rethrow_exception(callback_error);
    }
}

void
Client::handle_connection_failure(std::string const &error) {
    const FailureScope failing{_failure_callbacks};
    ++_connect_epoch;
    _is_connected    = false;
    _is_connecting   = false;
    _h3_ready        = false;
    _remote_shutdown = false;
    _h3.reset();
    auto callbacks = std::move(_connection_callbacks);
    _connection_callbacks.clear();
    // Retire old requests before connection callbacks can enqueue a new attempt.
    // fail_all_requests swaps its registries first, so work started by any of
    // its callbacks belongs to the next connection.
    auto callback_error = fail_all_requests(error);
    for (auto &cb : callbacks) {
        if (cb) {
            try {
                cb(false, error);
            } catch (...) {
                if (!callback_error) {
                    callback_error = std::current_exception();
                }
            }
        }
    }
    if (callback_error) {
        std::rethrow_exception(callback_error);
    }
}

void
Client::close_failed_transport(std::string_view reason) {
    struct CloseGuard {
        bool &flag;
        explicit CloseGuard(bool &value) noexcept
            : flag(value) {
            flag = true;
        }
        ~CloseGuard() noexcept {
            flag = false;
        }
    } guard(_closing_failed_attempt);
    qb::io::async::quic::endpoint::close(0, reason);
}

std::exception_ptr
Client::fail_all_requests(std::string const &error) {
    qb::unordered_map<std::uint64_t, std::unique_ptr<RequestContext>>      active;
    std::deque<std::unique_ptr<RequestContext>>                            pending;
    qb::unordered_map<std::uint64_t, std::unique_ptr<BatchRequestContext>> batches;
    active.swap(_active_requests);
    pending.swap(_pending_requests);
    batches.swap(_active_batches);
    std::exception_ptr callback_error;
    const auto         capture = [&](auto &&call) { // what `call` allocates for its answer is contained with it
        try {
            notify(_destroying, "HTTP/3", call);
        } catch (...) {
            if (!callback_error) {
                callback_error = std::current_exception();
            }
        }
    };

    for (auto &[id, ctx] : active) {
        (void) id;
        if (ctx->batch_id != 0) {
            continue;
        }
        ++_failed_requests;
        capture([&] { ctx->callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, error)); });
    }
    while (!pending.empty()) {
        auto ctx = std::move(pending.front());
        pending.pop_front();
        if (ctx->batch_id != 0) {
            continue;
        }
        ++_failed_requests;
        capture([&] { ctx->callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, error)); });
    }
    for (auto &[id, batch] : batches) {
        (void) id;
        capture([&] {
            for (std::size_t i = 0; i < batch->responses.size(); ++i) {
                if (i >= batch->completed.size() || !batch->completed[i]) {
                    ++_failed_requests;
                    batch->responses[i] = create_error_response(qb::http::status::SERVICE_UNAVAILABLE, error);
                }
            }
            batch->callback(std::move(batch->responses));
        });
    }
    return callback_error;
}

void
Client::fail_request(std::uint64_t stream_id, std::string const &error, qb::http::status status) {
    auto it = _active_requests.find(stream_id);
    if (it == _active_requests.end()) {
        return;
    }
    auto ctx = std::move(it->second);
    _active_requests.erase(it);
    ++_failed_requests;
    ctx->callback(create_error_response(status, error));
}

void
Client::fail_pending_request(std::uint64_t request_id, std::string const &error, qb::http::status status) {
    auto it = std::find_if(_pending_requests.begin(), _pending_requests.end(),
                           [request_id](auto const &ctx) { return ctx && ctx->request_id == request_id; });
    if (it == _pending_requests.end()) {
        return;
    }
    auto ctx = std::move(*it);
    _pending_requests.erase(it);
    ++_failed_requests;
    ctx->callback(create_error_response(status, error));
}

bool
Client::has_pending_or_active_work() const noexcept {
    return !_pending_requests.empty() || !_active_requests.empty() || !_active_batches.empty();
}

void
Client::arm_connect_timeout() {
    if (_destroying || _connect_timeout <= qb::duration::zero()) {
        return; // nothing is armed for a client being destroyed (Huly QB-1246)
    }
    auto       weak_self = weak_from_this();
    const auto epoch     = _connect_epoch;
    // What is left of the connect timeout: the lookup took its part (a microsecond at least: zero would arm nothing).
    const auto left = std::max(std::chrono::duration_cast<qb::duration>(_connect_deadline - std::chrono::steady_clock::now()),
                               qb::duration(std::chrono::microseconds(1)));
    qb::io::async::callback(
        [weak_self, epoch]() {
            auto self = weak_self.lock();
            if (!self || self->_connect_epoch != epoch || !self->_is_connecting || self->is_connected()) {
                return;
            }
            self->close_failed_transport("HTTP/3 connection timeout");
            self->handle_connection_failure("HTTP/3 connection timeout");
        },
        left);
}

void
Client::arm_request_timeout(std::uint64_t request_id) {
    if (_destroying || _request_timeout <= qb::duration::zero()) {
        return; // nothing is armed for a client being destroyed (Huly QB-1246)
    }
    schedule_request_timeout(request_id, _request_timeout);
}

void
Client::schedule_request_timeout(std::uint64_t request_id, qb::duration delay) {
    auto weak_self = weak_from_this();
    qb::io::async::callback(
        [weak_self, request_id]() {
            auto self = weak_self.lock();
            if (!self) {
                return;
            }
            const auto now = std::chrono::steady_clock::now();
            for (auto const &ctx : self->_pending_requests) {
                if (!ctx || ctx->request_id != request_id) {
                    continue;
                }
                const auto elapsed = std::chrono::duration_cast<qb::duration>(now - ctx->created_at);
                if (elapsed >= self->_request_timeout) {
                    self->fail_pending_request(request_id, "HTTP/3 request timeout while pending", qb::http::status::REQUEST_TIMEOUT);
                    self->process_pending_requests();
                } else {
                    // The event-loop timer source can wake this callback slightly
                    // before the steady_clock deadline (the two clocks are not the
                    // same). Re-arm for the remaining time instead of dropping the
                    // timeout — otherwise the one-shot fire is lost and the request
                    // stays queued forever (never completes, never fails).
                    self->schedule_request_timeout(request_id, self->_request_timeout - elapsed);
                }
                return;
            }
            auto it = std::find_if(self->_active_requests.begin(), self->_active_requests.end(),
                                   [request_id](auto const &entry) { return entry.second && entry.second->request_id == request_id; });
            if (it == self->_active_requests.end()) {
                return;
            }
            const auto elapsed = std::chrono::duration_cast<qb::duration>(now - it->second->created_at);
            if (elapsed < self->_request_timeout) {
                // Woke early (see note above) — re-arm for the remaining time.
                self->schedule_request_timeout(request_id, self->_request_timeout - elapsed);
                return;
            }
            const auto stream_id = it->first;
            self->fail_request(stream_id, "HTTP/3 request timeout", qb::http::status::REQUEST_TIMEOUT);
            // Timeout aborts the in-flight request stream (RFC 9114 §4.1).
            self->reset_stream(0, stream_id, NGHTTP3_H3_REQUEST_CANCELLED);
            self->process_pending_requests();
        },
        delay);
}

qb::http::Response
Client::create_error_response(qb::http::status status, std::string const &message) {
    qb::http::Response response;
    response.status() = status;
    response.body()   = message;
    response.set_header("content-type", "text/plain");
    response.set_header("content-length", std::to_string(message.size()));
    return response;
}

std::uint64_t
Client::open_http3_unidirectional_stream(std::uint64_t connection_id) {
    return open_unidirectional_stream(connection_id).id();
}

void
Client::send_http3_stream_data(std::uint64_t connection_id, std::uint64_t stream_id, std::string_view data, bool fin) {
    send_stream_data(connection_id, stream_id, data, fin);
}

void
Client::extend_http3_stream_credit(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t bytes) {
    extend_stream_credit(connection_id, stream_id, bytes);
}

void
Client::reset_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t app_error_code) {
    reset_stream(connection_id, stream_id, app_error_code);
}

void
Client::stop_http3_stream(std::uint64_t connection_id, std::uint64_t stream_id, std::uint64_t app_error_code) {
    stop_stream(connection_id, stream_id, app_error_code);
}

void
Client::close_http3_connection(std::uint64_t, std::uint64_t app_error_code, std::string_view reason) {
    close(app_error_code, reason);
}

void
Client::on_http3_stream_acked(std::uint64_t, std::uint64_t) {}

void
Client::on_http3_stream_closed(std::uint64_t stream_id, std::uint64_t) {
    if (_active_requests.find(stream_id) != _active_requests.end()) {
        fail_request(stream_id, "HTTP/3 stream closed before response completion");
    }
}

void
Client::on_http3_shutdown(std::uint64_t, std::uint64_t) {
    _remote_shutdown = true;
    while (!_pending_requests.empty()) {
        auto ctx = std::move(_pending_requests.front());
        _pending_requests.pop_front();
        ++_failed_requests;
        ctx->callback(create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "HTTP/3 server is shutting down"));
    }
}

void
Client::on_http3_response(std::uint64_t stream_id, qb::http::Response response) {
    auto it = _active_requests.find(stream_id);
    if (it == _active_requests.end()) {
        return;
    }
    auto ctx = std::move(it->second);
    _active_requests.erase(it);
    ++_successful_requests;
    ctx->callback(std::move(response));
    process_pending_requests();
}

void
Client::dispatch(qb::io::async::quic::event::connected const &ev) {
    EventLifetime lifetime{*this};
    if (ev.negotiated_alpn != "h3") {
        close_failed_transport("HTTP/3 ALPN negotiation failed");
        handle_connection_failure("HTTP/3 ALPN negotiation failed: " + ev.negotiated_alpn);
        return;
    }
    handle_connection_success(ev.negotiated_alpn);
}

void
Client::dispatch(qb::io::async::quic::event::connection_closed const &ev) {
    EventLifetime lifetime{*this};
    if (_closing_failed_attempt || (_deferred_close && _deferred_close->empty())) {
        return; // the explicit close already owns notification and teardown
    }
    std::string reason = ev.reason_phrase.empty() ? "HTTP/3 connection closed" : ev.reason_phrase;
    if (ev.error_code != 0) {
        reason += " (" + std::to_string(ev.error_code) + ")";
    }
    // If a read is on the stack, this close was delivered reentrantly from a send inside
    // nghttp3_conn_read_stream2. Tearing _h3 down now would call nghttp3_conn_del mid-read
    // (UAF) and reconnect on a live-but-doomed stack. Defer: dispatch(stream_data) runs the
    // teardown + reconnect once the outermost read unwinds. First reason wins.
    if (_read_depth > 0 || _submit_depth > 0) {
        if (!_deferred_close) {
            _deferred_close = std::move(reason);
        }
        return;
    }
    // endpoint has marked its state closed, but its socket and watchers are
    // still attached. Retire them before failure callbacks may start a retry.
    close_failed_transport("HTTP/3 connection closed");
    handle_connection_failure(reason);
    if (_auto_reconnect && has_pending_or_active_work()) {
        connect(nullptr);
    }
}

void
Client::dispatch(qb::io::async::quic::event::stream_data const &ev) {
    if (!_h3) {
        return;
    }
    if (_deferred_close && _deferred_close->empty() && _read_depth == 0 && _submit_depth == 0) {
        // An explicit close is notifying -- nothing else leaves its mark with no read or submission on the stack --, and a
        // loop pumped from one of its callbacks delivers what its connection still carried: it goes with that connection.
        // Read, it would complete the close from inside the close (Huly QB-1246).
        return;
    }
    EventLifetime lifetime{*this};
    // Guard the read: a response callback reached from nghttp3_conn_read_stream2 can
    // reentrantly fail the connection (see _read_depth in client.h). While the read is on
    // the stack the teardown is deferred; run it here, after the outermost read unwinds and
    // the stack (including nghttp3's own frames) is clear. The RAII guard restores _read_depth
    // on EVERY exit — including an exception escaping read_stream — so a throw can never wedge
    // the counter ≥1 and permanently freeze the deferral / reconnect.
    struct DepthGuard {
        int &d;
        explicit DepthGuard(int &d_) noexcept
            : d(d_) {
            ++d;
        }
        ~DepthGuard() {
            --d;
        }
    };
    const auto finish_deferred_close = [this] {
        if (_read_depth != 0 || _submit_depth != 0 || !_deferred_close) {
            return;
        }
        const std::string reason = std::move(*_deferred_close);
        _deferred_close.reset();
        if (reason.empty()) {
            complete_disconnect(); // explicit intent: fail once and close after nghttp3 unwinds
            return;
        }
        close_failed_transport("HTTP/3 connection closed");
        try {
            handle_connection_failure(reason);
        } catch (...) {
            start_deferred_connect();
            throw;
        }
        if (_auto_reconnect && has_pending_or_active_work()) {
            connect(nullptr);
        }
        start_deferred_connect(); // a connect() asked while this close was deferred: the teardown has completed
    };
    try {
        DepthGuard guard(_read_depth);
        _h3->read_stream(ev.id, ev.payload, ev.fin);
    } catch (...) {
        // A read cut short by an exception -- an allocation, as the engine's callbacks contain their own -- still completes
        // the close it deferred: left pending, its mark would keep every later disconnect() out (Huly QB-1246).
        try {
            finish_deferred_close();
        } catch (...) {
            // what a callback of that close throws: the read's own exception is the one that goes on
        }
        throw;
    }
    finish_deferred_close();
}

void
Client::dispatch(qb::io::async::quic::event::stream_data_acked const &ev) {
    if (_h3) {
        EventLifetime lifetime{*this};
        _h3->add_ack_offset(ev.id, ev.bytes);
    }
}

void
Client::dispatch(qb::io::async::quic::event::stream_closed const &ev) {
    EventLifetime lifetime{*this};
    on_http3_stream_closed(ev.id, ev.error_code);
    // nghttp3 frees a stream only when told, and the request, the response and the body copy kept
    // beside it go with it: until 3.2 nobody told it, and a long-lived connection kept every
    // exchange it had ever made. The engine reports the close back through
    // on_http3_stream_closed(), which by then finds the request already settled.
    if (_h3) {
        _h3->close_stream(ev.id, ev.error_code);
    }
}

qb::http::async::awaiter<ConnectResult>
Client::connect() {
    auto weak_self = weak_from_this();
    return qb::http::async::make_awaiter<ConnectResult>([weak_self](std::function<void(ConnectResult &&)> complete) mutable {
        auto self = weak_self.lock();
        if (!self) {
            complete(ConnectResult{false, "HTTP/3 client no longer available"});
            return;
        }
        if (self->_failure_callbacks > 0 || (self->_deferred_close && (self->_read_depth > 0 || self->_deferred_close->empty()))) {
            // Awaited from a callback of a close or of a failure, it answers at once. connect(callback) queues the attempt for
            // the end of a close, which cannot come before the callback returns; and a failure runs its callbacks inside the
            // endpoint's dispatch, which delivers an attempt's `connected` only once it has returned. A coroutine blocked on
            // either there -- run_sync() pumps the loop until it completes -- waited for ever (Huly QB-1246).
            complete(ConnectResult{false, "HTTP/3 connection is closing"});
            return;
        }
        // connect() answers through its callback -- at once when connected, at the attempt's end otherwise -- and returns false,
        // given one, only when nothing starts (a client being destroyed, an attempt it cannot start), where it never calls it:
        // the awaiter then completes here.
        // `complete` is COPIED into the callback so this end still holds one (one allocation on a connection attempt: a cold path).
        if (!self->connect([complete](bool ok, std::string const &error) mutable { complete(ConnectResult{ok, error}); })) {
            complete(ConnectResult{false, "Unable to start QUIC connection"});
        }
    });
}

qb::http::async::awaiter<qb::http::Response>
Client::push_request(qb::http::Request request) {
    auto weak_self = weak_from_this();
    return qb::http::async::make_awaiter<qb::http::Response>(
        [weak_self, req = std::move(request)](std::function<void(qb::http::Response &&)> complete) mutable {
            auto self = weak_self.lock();
            if (!self) {
                qb::http::Response response;
                response.status() = qb::http::status::SERVICE_UNAVAILABLE;
                response.body()   = "HTTP/3 client no longer available";
                complete(std::move(response));
                return;
            }
            // The callback answers every outcome, a refusal by the pending bound included (push_request returns false then,
            // its 503 delivered or owed its turn) -- but one: pushed from inside an answer the destructor's close delivers, the
            // push is refused by its return value alone and never calls its callback. The awaiter completes here then.
            auto answered = std::make_shared<bool>(false);
            if (!self->push_request(std::move(req),
                                    [complete, answered](qb::http::Response response) mutable {
                                        *answered = true;
                                        complete(std::move(response));
                                    })
                && !*answered && self->_destroying) {
                complete(self->create_error_response(qb::http::status::SERVICE_UNAVAILABLE, "HTTP/3 client disconnect"));
            }
        });
}

qb::http::async::awaiter<std::vector<qb::http::Response>>
Client::push_requests(std::vector<qb::http::Request> requests) {
    auto weak_self = weak_from_this();
    return qb::http::async::make_awaiter<std::vector<qb::http::Response>>(
        [weak_self, reqs = std::move(requests)](std::function<void(std::vector<qb::http::Response> &&)> complete) mutable {
            auto self = weak_self.lock();
            if (!self) {
                complete({});
                return;
            }
            const bool unheard = self->_destroying && self->_refusal_depth != 0; // refused by the return value alone: see push_request()
            self->push_requests(std::move(reqs),
                                [complete](std::vector<qb::http::Response> responses) mutable { complete(std::move(responses)); });
            if (unheard) {
                complete({});
            }
        });
}

std::shared_ptr<Client>
make_client(std::string const &base_uri) {
    return std::make_shared<Client>(base_uri);
}

std::shared_ptr<Client>
make_client(qb::io::uri const &uri) {
    return std::make_shared<Client>(uri);
}

} // namespace qb::http3
