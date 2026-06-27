/**
 * @file qbm/http/3/protocol/connection.h
 * @brief HTTP/3 connection adapter backed by nghttp3.
 *
 * This header-only template layer adapts the libnghttp3 HTTP/3 engine onto the
 * qbm/http message model (`qb::http::Request` / `qb::http::Response`). It is the
 * protocol core shared by the HTTP/3 server (`3/http3.h`) and client
 * (`3/client.h`):
 *   - `qb::protocol::http3::connection<Owner>` is a CRTP adapter. It owns one
 *     `nghttp3_conn`, tracks per-stream state, bridges every nghttp3 C callback
 *     back into the `Owner` (the QUIC transport), and materializes inbound
 *     header/trailer blocks into typed messages. All callbacks run under an
 *     exception guard so a throwing handler never unwinds through C frames.
 *   - The `detail` namespace holds the HTTP/3 framing helpers consumed from the
 *     `connection` template body: header validation/sanitization (RFC 9114),
 *     content-length reconciliation, pseudo-header ordering, and request /
 *     response / trailer field-block construction.
 *
 * Because every definition here is either a template, a member of the
 * `connection<Owner>` template, or a helper invoked from those template bodies,
 * the unit is header-only by design and has no companion translation unit.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#ifndef QBM_HTTP_HAS_HTTP3
#error "qbm/http3 requires QBM_HTTP_HAS_HTTP3"
#endif

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nghttp3/nghttp3.h>
#include <openssl/rand.h>
#include <qb/system/container/unordered_map.h>

#include "../../1.1/protocol/base.h"
#include "../../headers.h"
#include "../../logger.h"
#include "../../request.h"
#include "../../response.h"
#include "../../utility.h"

namespace qb::protocol::http3 {

/**
 * @brief HTTP/3 framing helpers shared by the `connection` template.
 *
 * These functions implement the RFC 9114 / RFC 7230 field-validation and
 * field-block construction rules. They are consumed exclusively from the
 * `connection<Owner>` template body (and from one another), which is why they
 * live in the header rather than a separate translation unit.
 */
namespace detail {

/**
 * @brief ASCII-lowercase a header name.
 * @param value Header name to fold.
 * @return Lowercased copy of @p value (ASCII only; non-ASCII bytes untouched).
 */
inline std::string
lower_header_name(std::string_view value) {
    std::string out(value);
    std::transform(out.begin(), out.end(), out.begin(), [](char c) { return qb::http::utility::ascii_to_lower(c); });
    return out;
}

/**
 * @brief Test whether a header is a connection-specific field banned in HTTP/3.
 * @param name Header name (case-insensitive).
 * @return @c true if @p name is one of the hop-by-hop / connection-management
 *         fields prohibited by RFC 9114 section 4.2 (e.g. @c connection,
 *         @c transfer-encoding, @c upgrade).
 */
inline bool
is_forbidden_h3_header(std::string_view name) {
    const auto lower = lower_header_name(name);
    return lower == "connection" || lower == "keep-alive" || lower == "proxy-connection" || lower == "proxy-authenticate"
           || lower == "proxy-authorization" || lower == "transfer-encoding" || lower == "upgrade";
}

/**
 * @brief Test whether a name is disallowed as an HTTP/3 trailer field.
 * @param name Trailer field name (case-insensitive).
 * @return @c true if @p name is empty, a pseudo-header, @c content-length,
 *         @c trailer, or any field forbidden by ::is_forbidden_h3_header.
 */
inline bool
is_forbidden_h3_trailer(std::string_view name) {
    const auto lower = lower_header_name(name);
    return lower.empty() || lower.front() == ':' || lower == "content-length" || lower == "trailer" || is_forbidden_h3_header(lower);
}

/**
 * @brief Parse a @c content-length field value as an unsigned 64-bit integer.
 * @param value Raw field value.
 * @return The parsed length, or @c std::nullopt if @p value is not a single
 *         well-formed decimal integer that consumes the entire string.
 */
inline std::optional<std::uint64_t>
parse_content_length(std::string_view value) {
    std::uint64_t parsed = 0;
    auto const   *begin  = value.data();
    auto const   *end    = value.data() + value.size();
    auto [ptr, ec]       = std::from_chars(begin, end, parsed);
    if (ec != std::errc{} || ptr != end) {
        return std::nullopt;
    }
    return parsed;
}

/**
 * @brief Outcome of reconciling all @c content-length fields on a message.
 * @tparam Message Message type (@c qb::http::Request or @c qb::http::Response).
 */
template <typename Message>
struct declared_content_length_result {
    bool                         ok = true; ///< False if any value is malformed or values disagree.
    std::optional<std::uint64_t> value;     ///< The single agreed length, if declared.
};

/**
 * @brief Collapse a message's @c content-length field(s) into one value.
 * @tparam Message Message type exposing @c headers().
 * @param msg Message to inspect.
 * @return A result whose @c ok is false when a value fails to parse or two
 *         declared values disagree; otherwise @c value holds the declared
 *         length (absent when no @c content-length is present).
 */
template <typename Message>
declared_content_length_result<Message>
declared_content_length(Message const &msg) {
    declared_content_length_result<Message> result;
    auto                                    it = msg.headers().find("content-length");
    if (it == msg.headers().end()) {
        return result;
    }
    for (auto const &raw_value : it->second) {
        auto parsed = parse_content_length(raw_value);
        if (!parsed || (result.value && *result.value != *parsed)) {
            result.ok = false;
            return result;
        }
        result.value = *parsed;
    }
    return result;
}

/**
 * @brief A stable-storage HTTP/3 header field block ready for nghttp3.
 *
 * @c storage owns the name/value byte buffers; @c nva holds the
 * @c nghttp3_nv view array that points into that storage. A @c std::deque is
 * used so existing entries keep stable addresses as more fields are appended,
 * which is required because @c nva aliases the stored bytes.
 */
struct header_block {
    std::deque<std::pair<std::string, std::string>> storage; ///< Owning name/value byte buffers.
    std::vector<nghttp3_nv>                         nva;     ///< nghttp3 field views into @c storage.

    /**
     * @brief Append a field, copying ownership into @c storage and adding its view.
     * @param name  Field name (moved into the block).
     * @param value Field value (moved into the block).
     */
    void
    add(std::string name, std::string value) {
        storage.emplace_back(std::move(name), std::move(value));
        auto &[stored_name, stored_value] = storage.back();
        nva.push_back(nghttp3_nv{
            reinterpret_cast<uint8_t *>(stored_name.data()), reinterpret_cast<uint8_t *>(stored_value.data()), stored_name.size(),
            stored_value.size(), NGHTTP3_NV_FLAG_NONE
        });
    }
};

/**
 * @brief Verify pseudo-headers precede all regular headers in a block.
 * @param block Field block to check (inspected in insertion order).
 * @return @c true if no pseudo-header (name starting with ':') appears after a
 *         regular header, as mandated by RFC 9114 section 4.3.
 */
inline bool
pseudo_headers_before_regular_headers(header_block const &block) noexcept {
    bool regular_headers_started = false;
    for (auto const &[name, value] : block.storage) {
        (void) value;
        if (!name.empty() && name.front() == ':') {
            if (regular_headers_started) {
                return false;
            }
        } else {
            regular_headers_started = true;
        }
    }
    return true;
}

/**
 * @brief Check that all mandatory request pseudo-headers are present and non-empty.
 * @param method    Value of @c :method, if seen.
 * @param scheme    Value of @c :scheme, if seen.
 * @param authority Value of @c :authority, if seen.
 * @param path      Value of @c :path, if seen.
 * @return @c true only when every one of the four is present and non-empty.
 */
inline bool
has_required_request_pseudo_headers(std::optional<std::string> const &method, std::optional<std::string> const &scheme,
                                    std::optional<std::string> const &authority, std::optional<std::string> const &path) noexcept {
    return method && !method->empty() && scheme && !scheme->empty() && authority && !authority->empty() && path && !path->empty();
}

/**
 * @brief Test whether a byte is a valid HTTP token character for a header name.
 * @param c Byte to test.
 * @return @c true if @p c is a lowercase token character per RFC 7230 (uppercase
 *         letters are intentionally excluded; HTTP/3 names must be lowercase).
 */
inline bool
is_header_name_char(unsigned char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*'
           || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

/**
 * @brief Validate an outgoing (regular) header field's name and value.
 * @param name  Field name; must be a non-empty lowercase token within length limits.
 * @param value Field value; must be within limits and free of NUL/CR/LF and
 *              other control characters (TAB allowed).
 * @return @c true if the field is safe to emit on the wire.
 */
inline bool
is_valid_header_field(std::string_view name, std::string_view value) noexcept {
    if (name.empty() || name.size() > qb::http::protocol_limits::MAX_HEADER_NAME_LENGTH
        || value.size() > qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH) {
        return false;
    }

    for (unsigned char c : name) {
        if (!is_header_name_char(c)) {
            return false;
        }
    }

    for (unsigned char c : value) {
        if (c == 0x00 || c == 0x0d || c == 0x0a) {
            return false;
        }
        if ((c < 0x20 && c != 0x09) || c == 0x7f) {
            return false;
        }
    }

    return true;
}

/**
 * @brief Validate an incoming header field's name and value.
 * @param name  Field name; may be a pseudo-header (leading ':') but the part
 *              after any leading colon must be a non-empty lowercase token.
 * @param value Field value; same control-character rules as outgoing fields.
 * @return @c true if the received field is well-formed and within limits.
 */
inline bool
is_valid_incoming_header_field(std::string_view name, std::string_view value) noexcept {
    if (name.empty() || name.size() > qb::http::protocol_limits::MAX_HEADER_NAME_LENGTH
        || value.size() > qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH) {
        return false;
    }

    const bool pseudo = name.front() == ':';
    for (std::size_t i = pseudo ? 1u : 0u; i < name.size(); ++i) {
        if (!is_header_name_char(static_cast<unsigned char>(name[i]))) {
            return false;
        }
    }
    if (pseudo && name.size() == 1u) {
        return false;
    }

    for (unsigned char c : value) {
        if (c == 0x00 || c == 0x0d || c == 0x0a) {
            return false;
        }
        if ((c < 0x20 && c != 0x09) || c == 0x7f) {
            return false;
        }
    }

    return true;
}

/**
 * @brief Collect the lowercased field names announced in a @c trailer header.
 * @tparam Message Message type exposing @c has_header() and @c headers().
 * @param msg Message to inspect.
 * @return The set of trailer field names declared by the @c trailer header
 *         (empty when none is present).
 */
template <typename Message>
std::vector<std::string>
announced_trailers(Message const &msg) {
    std::vector<std::string> trailers;
    if (!msg.has_header("trailer")) {
        return trailers;
    }
    auto it = msg.headers().find("trailer");
    if (it == msg.headers().end()) {
        return trailers;
    }
    for (auto const &value : it->second) {
        auto names = qb::http::utility::split_and_trim_header_list(value, ',');
        for (auto &name : names) {
            trailers.push_back(lower_header_name(name));
        }
    }
    return trailers;
}

/**
 * @brief Test whether a field name appears in the announced trailer set.
 * @param name     Field name (case-insensitive).
 * @param trailers Lowercased trailer names from ::announced_trailers.
 * @return @c true if @p name was announced as a trailer.
 */
inline bool
is_announced_trailer(std::string_view name, std::vector<std::string> const &trailers) noexcept {
    return std::find(trailers.begin(), trailers.end(), lower_header_name(name)) != trailers.end();
}

/**
 * @brief Copy an nghttp3 reference-counted buffer into a @c std::string.
 * @param buf nghttp3 buffer handle.
 * @return A copy of the buffer's bytes.
 */
inline std::string
rcbuf_to_string(nghttp3_rcbuf *buf) {
    const auto view = nghttp3_rcbuf_get_buf(buf);
    return {reinterpret_cast<const char *>(view.base), view.len};
}

/**
 * @brief Build the @c :path origin-form target (path plus optional query).
 * @param uri Request URI.
 * @return The path (defaulting to "/" when empty), with @c ?query appended when
 *         the URI carries encoded queries.
 */
inline std::string
request_target(qb::io::uri const &uri) {
    std::string path = uri.path().empty() ? "/" : std::string(uri.path());
    if (!uri.encoded_queries().empty()) {
        path.push_back('?');
        path += uri.encoded_queries();
    }
    return path;
}

/**
 * @brief Build the @c :authority value (host plus optional ":port").
 * @param uri Request URI.
 * @return The host, with @c :port appended when the URI specifies one.
 */
inline std::string
authority(qb::io::uri const &uri) {
    std::string value(uri.host());
    if (!uri.port().empty()) {
        value.push_back(':');
        value += uri.port();
    }
    return value;
}

/**
 * @brief Append a message's regular (non-pseudo, non-trailer) headers to a block.
 * @tparam Message Message type exposing @c headers().
 * @param block  Destination field block.
 * @param msg    Source message.
 * @param fields Running field count, enforced against
 *               @c protocol_limits::MAX_HEADERS_COUNT and updated in place.
 * @return @c false (leaving @p block partially populated) if a forbidden field,
 *         an invalid field, or the field-count limit is encountered; @c true on
 *         success. @c host is dropped (folded into @c :authority) and announced
 *         trailers are skipped.
 */
template <typename Message>
bool
add_regular_headers(header_block &block, Message const &msg, std::size_t &fields) {
    const auto trailers = announced_trailers(msg);
    for (auto const &[name, values] : msg.headers()) {
        const auto lower = lower_header_name(name);
        if (lower.empty() || lower.front() == ':' || is_forbidden_h3_header(lower)) {
            return false;
        }
        if (lower == "host") {
            continue;
        }
        if (lower != "trailer" && is_announced_trailer(lower, trailers)) {
            continue;
        }
        for (auto const &value : values) {
            if (++fields > qb::http::protocol_limits::MAX_HEADERS_COUNT || !is_valid_header_field(lower, value)) {
                return false;
            }
            block.add(lower, value);
        }
    }
    return true;
}

/**
 * @brief Build the trailer field block for a message, if any are announced.
 * @tparam Message Message type exposing @c headers().
 * @param msg Source message.
 * @return The trailer field block, or @c std::nullopt when no trailers are
 *         announced or none resolve to non-empty fields. Returns @c std::nullopt
 *         on the first forbidden trailer, invalid field, or count-limit breach.
 */
template <typename Message>
std::optional<header_block>
make_trailers(Message const &msg) {
    const auto trailers = announced_trailers(msg);
    if (trailers.empty()) {
        return std::nullopt;
    }
    header_block block;
    std::size_t  fields = 0;
    for (auto const &[name, values] : msg.headers()) {
        const auto lower = lower_header_name(name);
        if (!is_announced_trailer(lower, trailers)) {
            continue;
        }
        if (is_forbidden_h3_trailer(lower)) {
            return std::nullopt;
        }
        for (auto const &value : values) {
            if (++fields > qb::http::protocol_limits::MAX_HEADERS_COUNT || !is_valid_header_field(lower, value)) {
                return std::nullopt;
            }
            block.add(lower, value);
        }
    }
    return block.nva.empty() ? std::nullopt : std::optional<header_block>{std::move(block)};
}

/**
 * @brief Build the request header field block (pseudo-headers + regular headers).
 * @param request Request to serialize.
 * @return The field block, or @c std::nullopt if the target exceeds
 *         @c MAX_URL_LENGTH, the declared @c content-length disagrees with the
 *         body size, or regular-header assembly fails. A @c content-length is
 *         synthesized when the body is non-empty and none was supplied.
 */
inline std::optional<header_block>
make_request_headers(qb::http::Request const &request) {
    header_block block;
    std::size_t  fields = 4;
    auto         target = request_target(request.uri());
    if (target.size() > qb::http::protocol_limits::MAX_URL_LENGTH) {
        return std::nullopt;
    }
    const auto declared_length = declared_content_length(request);
    if (!declared_length.ok || (declared_length.value && *declared_length.value != request.body().size())) {
        return std::nullopt;
    }
    block.add(":method", std::string(request.method()));
    block.add(":scheme", request.uri().scheme().empty() ? "https" : std::string(request.uri().scheme()));
    block.add(":authority", authority(request.uri()));
    block.add(":path", std::move(target));
    if (!add_regular_headers(block, request, fields)) {
        return std::nullopt;
    }
    if (!request.body().empty() && !request.has_header("content-length")) {
        if (++fields > qb::http::protocol_limits::MAX_HEADERS_COUNT) {
            return std::nullopt;
        }
        block.add("content-length", std::to_string(request.body().size()));
    }
    return block;
}

/**
 * @brief Decide whether a response body must satisfy its declared content-length.
 * @param response       Response being sent.
 * @param request_method Method of the request being answered.
 * @return @c false for responses with no payload semantics (HEAD requests, 1xx,
 *         204, 304), where a declared content-length need not equal the body
 *         size; @c true otherwise.
 */
inline bool
response_body_length_must_match(qb::http::Response const &response, qb::http::Method request_method) noexcept {
    if (request_method == qb::http::method::HEAD) {
        return false;
    }
    const auto status_code = response.status().code();
    return !((status_code >= 100 && status_code < 200) || status_code == 204 || status_code == 304);
}

/**
 * @brief Build the response header field block (@c :status + regular headers).
 * @param response Response to serialize.
 * @return The field block, or @c std::nullopt if regular-header assembly fails
 *         or the field-count limit is hit. A @c content-length is synthesized
 *         when the body is non-empty and none was supplied.
 */
inline std::optional<header_block>
make_response_headers(qb::http::Response const &response) {
    header_block block;
    std::size_t  fields = 1;
    block.add(":status", std::to_string(response.status().code()));
    if (!add_regular_headers(block, response, fields)) {
        return std::nullopt;
    }
    if (!response.body().empty() && !response.has_header("content-length")) {
        if (++fields > qb::http::protocol_limits::MAX_HEADERS_COUNT) {
            return std::nullopt;
        }
        block.add("content-length", std::to_string(response.body().size()));
    }
    return block;
}

} // namespace detail

/**
 * @brief CRTP HTTP/3 connection adapter over a single @c nghttp3_conn.
 *
 * One instance maps a QUIC connection onto the HTTP/3 application layer for one
 * direction of use (client or server). It owns the nghttp3 connection object,
 * keeps per-stream state, feeds inbound QUIC stream bytes into nghttp3, drains
 * outbound frames back to the transport, and materializes received header /
 * trailer / data into typed @c qb::http::Request / @c qb::http::Response objects.
 *
 * The @p Owner is the QUIC transport; the adapter calls back into it for stream
 * I/O (e.g. @c open_http3_unidirectional_stream, @c send_http3_stream_data,
 * @c extend_http3_stream_credit), flow-control and lifecycle events, and request
 * / response delivery. Optional @c Owner hooks are detected with @c requires and
 * skipped when absent, so an owner only implements the callbacks it needs.
 *
 * @tparam Owner Transport type providing the HTTP/3 owner interface.
 *
 * @note Every nghttp3 C callback body runs under ::guard_callback so a thrown
 *       exception becomes @c NGHTTP3_ERR_CALLBACK_FAILURE instead of unwinding
 *       through C frames (undefined behaviour).
 */
template <typename Owner>
class connection {
public:
    /// @brief Direction of the connection: outbound client or inbound server.
    enum class role { client, server };

private:
    struct stream_state {
        qb::http::Request            request;
        qb::http::Response           response;
        detail::header_block         incoming_headers;
        nghttp3_data_reader          reader{read_data_cb};
        std::string                  tx_body;
        std::size_t                  tx_offset              = 0;
        std::size_t                  incoming_header_fields = 0;
        std::optional<std::uint64_t> expected_content_length;
        bool                         main_headers_seen     = false;
        bool                         response_headers_seen = false;
        bool                         output_drained        = false;
    };

    Owner                                                          &_owner;
    role                                                            _role;
    std::uint64_t                                                   _connection_id = 0;
    nghttp3_conn                                                   *_conn          = nullptr;
    qb::unordered_map<std::uint64_t, std::unique_ptr<stream_state>> _streams;
    bool                                                            _local_streams_bound = false;
    bool                                                            _shutdown_started    = false;
    // Liveness flag for reentrancy-safe teardown. drain() forwards bytes to the owner,
    // which can SYNCHRONOUSLY destroy this connection (the owner erases it from its
    // _connections map when the transport reports a close mid-send). drain() captures a
    // copy of this shared_ptr so it can detect that destruction and bail out instead of
    // dereferencing freed members (_conn, _owner, _streams).
    std::shared_ptr<bool> _alive = std::make_shared<bool>(true);

    static nghttp3_tstamp
    now_ts() noexcept {
        return static_cast<nghttp3_tstamp>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    [[nodiscard]] stream_state &
    state_for(std::uint64_t stream_id) {
        auto &ptr = _streams[stream_id];
        if (!ptr) {
            ptr = std::make_unique<stream_state>();
        }
        return *ptr;
    }

    [[nodiscard]] static connection *
    self(void *conn_user_data) noexcept {
        return static_cast<connection *>(conn_user_data);
    }

    // nghttp3 invokes the callbacks below across a C ABI. A C++ exception that
    // escaped into libnghttp3 would be undefined behaviour — there is no
    // unwinding through C frames. Run each callback body under this guard so any
    // exception (allocation failure, a throwing user request/response handler, a
    // bad URI during header materialization, ...) becomes
    // NGHTTP3_ERR_CALLBACK_FAILURE, which nghttp3 turns into a clean
    // stream/connection failure instead of std::terminate.
    template <typename Fn>
    static auto
    guard_callback(Fn &&fn) noexcept -> decltype(fn()) {
        try {
            return fn();
        } catch (...) {
            return static_cast<decltype(fn())>(NGHTTP3_ERR_CALLBACK_FAILURE);
        }
    }

    static void
    rand_cb(uint8_t *dest, size_t destlen) {
        if (RAND_bytes(dest, static_cast<int>(destlen)) != 1) {
            // Entropy failure must never hand predictable bytes to the QUIC/HTTP3
            // crypto layer (connection IDs, nonces, ...). Fail closed instead of
            // silently zeroing, which would make those values attacker-predictable.
            LOG_HTTP_ERROR("HTTP/3 RAND_bytes failed; aborting to avoid predictable crypto material");
            std::abort();
        }
    }

    static nghttp3_ssize
    read_data_cb(nghttp3_conn *, int64_t stream_id, nghttp3_vec *vec, size_t veccnt, uint32_t *pflags, void *conn_user_data,
                 void *stream_user_data) {
        return guard_callback([&]() -> nghttp3_ssize {
            auto *me = self(conn_user_data);
            auto *state =
                stream_user_data ? static_cast<stream_state *>(stream_user_data) : &me->state_for(static_cast<std::uint64_t>(stream_id));
            if (state->tx_offset >= state->tx_body.size()) {
                *pflags = NGHTTP3_DATA_FLAG_EOF;
                return 0;
            }
            if (veccnt == 0) {
                return NGHTTP3_ERR_WOULDBLOCK;
            }
            vec[0].base      = reinterpret_cast<uint8_t *>(state->tx_body.data() + state->tx_offset);
            vec[0].len       = state->tx_body.size() - state->tx_offset;
            state->tx_offset = state->tx_body.size();
            *pflags          = NGHTTP3_DATA_FLAG_EOF;
            return 1;
        });
    }

    static int
    acked_stream_data_cb(nghttp3_conn *, int64_t stream_id, uint64_t datalen, void *conn_user_data, void *) {
        return guard_callback([&]() -> int {
            self(conn_user_data)->_owner.on_http3_stream_acked(static_cast<std::uint64_t>(stream_id), datalen);
            return 0;
        });
    }

    static int
    stream_close_cb(nghttp3_conn *, int64_t stream_id, uint64_t app_error_code, void *conn_user_data, void *) {
        return guard_callback([&]() -> int {
            auto *me = self(conn_user_data);
            if constexpr (requires(Owner &owner, std::uint64_t connection_id, std::uint64_t sid, std::uint64_t code) {
                              owner.on_http3_stream_closed(connection_id, sid, code);
                          }) {
                me->_owner.on_http3_stream_closed(me->_connection_id, static_cast<std::uint64_t>(stream_id), app_error_code);
            } else {
                me->_owner.on_http3_stream_closed(static_cast<std::uint64_t>(stream_id), app_error_code);
            }
            me->_streams.erase(static_cast<std::uint64_t>(stream_id));
            return 0;
        });
    }

    static int
    recv_data_cb(nghttp3_conn *, int64_t stream_id, const uint8_t *data, size_t datalen, void *conn_user_data, void *) {
        return guard_callback([&]() -> int {
            auto      *me           = self(conn_user_data);
            auto      &st           = me->state_for(static_cast<std::uint64_t>(stream_id));
            const auto current_size = me->_role == role::server ? st.request.body().size() : st.response.body().size();
            if constexpr (requires(Owner &owner) { owner.max_http3_body_size(); }) {
                const auto limit = me->_owner.max_http3_body_size();
                if (limit != 0 && current_size + datalen > limit) {
                    me->_owner.reset_http3_stream(me->_connection_id, static_cast<std::uint64_t>(stream_id), NGHTTP3_H3_REQUEST_CANCELLED);
                    return NGHTTP3_ERR_CALLBACK_FAILURE;
                }
            }
            if (me->_role == role::server) {
                st.request.body().raw().put(reinterpret_cast<const char *>(data), datalen);
            } else if (st.request.method() != qb::http::method::HEAD) {
                st.response.body().raw().put(reinterpret_cast<const char *>(data), datalen);
            }
            return 0;
        });
    }

    static int
    deferred_consume_cb(nghttp3_conn *, int64_t stream_id, size_t consumed, void *conn_user_data, void *) {
        return guard_callback([&]() -> int {
            auto *me = self(conn_user_data);
            me->_owner.extend_http3_stream_credit(me->_connection_id, static_cast<std::uint64_t>(stream_id), consumed);
            return 0;
        });
    }

    static int
    begin_headers_cb(nghttp3_conn *, int64_t stream_id, void *conn_user_data, void *) {
        return guard_callback([&]() -> int {
            auto &st                  = self(conn_user_data)->state_for(static_cast<std::uint64_t>(stream_id));
            st.incoming_headers       = {};
            st.incoming_header_fields = 0;
            return 0;
        });
    }

    static int
    recv_header_cb(nghttp3_conn *, int64_t stream_id, int32_t, nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t, void *conn_user_data,
                   void *) {
        return guard_callback([&]() -> int {
            auto &st           = self(conn_user_data)->state_for(static_cast<std::uint64_t>(stream_id));
            auto  header_name  = detail::rcbuf_to_string(name);
            auto  header_value = detail::rcbuf_to_string(value);
            if (++st.incoming_header_fields > qb::http::protocol_limits::MAX_HEADERS_COUNT
                || !detail::is_valid_incoming_header_field(header_name, header_value)) {
                return NGHTTP3_ERR_CALLBACK_FAILURE;
            }
            st.incoming_headers.add(std::move(header_name), std::move(header_value));
            return 0;
        });
    }

    static int
    end_headers_cb(nghttp3_conn *, int64_t stream_id, int, void *conn_user_data, void *) {
        return guard_callback([&]() -> int {
            auto *me = self(conn_user_data);
            auto &st = me->state_for(static_cast<std::uint64_t>(stream_id));
            if (!me->materialize_headers(static_cast<std::uint64_t>(stream_id), st)) {
                me->_owner.close_http3_connection(me->_connection_id, NGHTTP3_H3_MESSAGE_ERROR, "Malformed HTTP/3 headers");
                return NGHTTP3_ERR_CALLBACK_FAILURE;
            }
            st.main_headers_seen = true;
            return 0;
        });
    }

    static int
    begin_trailers_cb(nghttp3_conn *, int64_t stream_id, void *conn_user_data, void *) {
        return guard_callback([&]() -> int {
            auto &st                  = self(conn_user_data)->state_for(static_cast<std::uint64_t>(stream_id));
            st.incoming_headers       = {};
            st.incoming_header_fields = 0;
            return 0;
        });
    }

    static int
    end_trailers_cb(nghttp3_conn *, int64_t stream_id, int, void *conn_user_data, void *) {
        return guard_callback([&]() -> int {
            auto *me = self(conn_user_data);
            auto &st = me->state_for(static_cast<std::uint64_t>(stream_id));
            if (!me->materialize_trailers(st)) {
                me->_owner.close_http3_connection(me->_connection_id, NGHTTP3_H3_MESSAGE_ERROR, "Malformed HTTP/3 trailers");
                return NGHTTP3_ERR_CALLBACK_FAILURE;
            }
            return 0;
        });
    }

    static int
    end_stream_cb(nghttp3_conn *, int64_t stream_id, void *conn_user_data, void *) {
        return guard_callback([&]() -> int {
            auto      *me = self(conn_user_data);
            auto      &st = me->state_for(static_cast<std::uint64_t>(stream_id));
            const auto id = static_cast<std::uint64_t>(stream_id);
            if (!me->content_length_matches(st)) {
                me->_owner.close_http3_connection(me->_connection_id, NGHTTP3_H3_MESSAGE_ERROR, "HTTP/3 content-length mismatch");
                return NGHTTP3_ERR_CALLBACK_FAILURE;
            }
            if (me->_role == role::server) {
                st.request.stream_id = id;
                if constexpr (requires(Owner &owner, std::uint64_t cid, std::uint64_t sid, qb::http::Request req) {
                                  owner.on_http3_request(cid, sid, std::move(req));
                              }) {
                    me->_owner.on_http3_request(me->_connection_id, id, std::move(st.request));
                }
            } else {
                st.response.stream_id = id;
                if constexpr (requires(Owner &owner, std::uint64_t sid, qb::http::Response res) {
                                  owner.on_http3_response(sid, std::move(res));
                              }) {
                    me->_owner.on_http3_response(id, std::move(st.response));
                }
            }
            return 0;
        });
    }

    static int
    stop_sending_cb(nghttp3_conn *, int64_t stream_id, uint64_t app_error_code, void *conn_user_data, void *) {
        return guard_callback([&]() -> int {
            auto *me = self(conn_user_data);
            me->_owner.stop_http3_stream(me->_connection_id, static_cast<std::uint64_t>(stream_id), app_error_code);
            return 0;
        });
    }

    static int
    reset_stream_cb(nghttp3_conn *, int64_t stream_id, uint64_t app_error_code, void *conn_user_data, void *) {
        return guard_callback([&]() -> int {
            auto *me = self(conn_user_data);
            me->_owner.reset_http3_stream(me->_connection_id, static_cast<std::uint64_t>(stream_id), app_error_code);
            return 0;
        });
    }

    static int
    shutdown_cb(nghttp3_conn *, int64_t id, void *conn_user_data) {
        return guard_callback([&]() -> int {
            auto *me = self(conn_user_data);
            if constexpr (requires(Owner &owner, std::uint64_t connection_id, std::uint64_t last_id) {
                              owner.on_http3_shutdown(connection_id, last_id);
                          }) {
                me->_owner.on_http3_shutdown(me->_connection_id, static_cast<std::uint64_t>(id));
            }
            return 0;
        });
    }

    bool
    materialize_headers(std::uint64_t stream_id, stream_state &st) {
        if (!detail::pseudo_headers_before_regular_headers(st.incoming_headers)) {
            return false;
        }

        std::optional<std::string>   method;
        std::optional<std::string>   scheme;
        std::optional<std::string>   authority;
        std::optional<std::string>   path;
        std::optional<int>           status;
        std::optional<std::uint64_t> content_length;

        for (auto const &[name, value] : st.incoming_headers.storage) {
            if (name == ":method") {
                if (method || _role != role::server) {
                    return false;
                }
                method = value;
            } else if (name == ":scheme") {
                if (scheme || _role != role::server) {
                    return false;
                }
                scheme = value;
            } else if (name == ":authority") {
                if (authority || _role != role::server) {
                    return false;
                }
                authority = value;
            } else if (name == ":path") {
                if (path || _role != role::server) {
                    return false;
                }
                path = value;
            } else if (name == ":status") {
                if (status || _role != role::client) {
                    return false;
                }
                int         parsed_status = 0;
                auto const *begin         = value.data();
                auto const *end           = value.data() + value.size();
                auto [ptr, ec]            = std::from_chars(begin, end, parsed_status);
                if (ec != std::errc{} || ptr != end || parsed_status < 100 || parsed_status > 999) {
                    return false;
                }
                status = parsed_status;
            } else if (!name.empty() && name.front() == ':') {
                return false;
            } else if (name == "content-length") {
                auto parsed = detail::parse_content_length(value);
                if (!parsed || (content_length && *content_length != *parsed)) {
                    return false;
                }
                content_length = *parsed;
                if (_role == role::server) {
                    st.request.add_header(name, value);
                } else {
                    st.response.add_header(name, value);
                }
            } else {
                if (detail::is_forbidden_h3_header(name)) {
                    return false;
                }
                if (_role == role::server) {
                    st.request.add_header(name, value);
                } else {
                    st.response.add_header(name, value);
                }
            }
        }
        st.expected_content_length = content_length;

        if (_role == role::server) {
            if (!detail::has_required_request_pseudo_headers(method, scheme, authority, path)) {
                return false;
            }
            auto parsed_method = qb::http::Method(method.value_or("GET"));
            if (parsed_method == qb::http::method::UNINITIALIZED) {
                return false;
            }
            st.request.method()      = parsed_method;
            st.request.uri()         = qb::io::uri(*scheme + "://" + *authority + *path);
            st.request.major_version = 3;
            st.request.minor_version = 0;
            st.request.stream_id     = stream_id;
        } else {
            if (!status) {
                return false;
            }
            st.response.status()      = *status;
            st.response.major_version = 3;
            st.response.minor_version = 0;
            st.response.stream_id     = stream_id;
            st.response_headers_seen  = true;
        }
        return true;
    }

    bool
    materialize_trailers(stream_state &st) {
        if (!st.main_headers_seen) {
            return false;
        }
        for (auto const &[name, value] : st.incoming_headers.storage) {
            if (detail::is_forbidden_h3_trailer(name)) {
                return false;
            }
            if (_role == role::server) {
                st.request.add_header(name, value);
            } else {
                st.response.add_header(name, value);
            }
        }
        return true;
    }

    [[nodiscard]] bool
    content_length_matches(stream_state const &st) const noexcept {
        if (!st.expected_content_length) {
            return true;
        }
        if (_role == role::client && st.request.method() == qb::http::method::HEAD) {
            return true;
        }
        if (_role == role::client) {
            const auto status_code = st.response.status().code();
            if ((status_code >= 100 && status_code < 200) || status_code == 204 || status_code == 304) {
                return true;
            }
        }
        const auto actual = _role == role::server ? st.request.body().size() : st.response.body().size();
        return actual == *st.expected_content_length;
    }

    [[nodiscard]] static nghttp3_callbacks
    callbacks() noexcept {
        nghttp3_callbacks cb{};
        cb.acked_stream_data = acked_stream_data_cb;
        cb.stream_close      = stream_close_cb;
        cb.recv_data         = recv_data_cb;
        cb.deferred_consume  = deferred_consume_cb;
        cb.begin_headers     = begin_headers_cb;
        cb.recv_header       = recv_header_cb;
        cb.end_headers       = end_headers_cb;
        cb.begin_trailers    = begin_trailers_cb;
        cb.recv_trailer      = recv_header_cb;
        cb.end_trailers      = end_trailers_cb;
        cb.stop_sending      = stop_sending_cb;
        cb.end_stream        = end_stream_cb;
        cb.reset_stream      = reset_stream_cb;
        cb.shutdown          = shutdown_cb;
        cb.rand              = rand_cb;
        return cb;
    }

public:
    /**
     * @brief Create the HTTP/3 connection and its underlying @c nghttp3_conn.
     * @param owner         Transport that owns this connection (stored by reference).
     * @param connection_id Identifier passed back on every owner callback.
     * @param r             Client or server role.
     * @throws std::runtime_error if the nghttp3 connection cannot be created.
     */
    connection(Owner &owner, std::uint64_t connection_id, role r)
        : _owner(owner)
        , _role(r)
        , _connection_id(connection_id) {
        nghttp3_settings settings;
        nghttp3_settings_default(&settings);
        settings.qpack_blocked_streams  = 32;
        settings.max_field_section_size = 64 * 1024;

        const auto cb = callbacks();
        const auto rv = _role == role::server ? nghttp3_conn_server_new(&_conn, &cb, &settings, nghttp3_mem_default(), this)
                                              : nghttp3_conn_client_new(&_conn, &cb, &settings, nghttp3_mem_default(), this);
        if (rv != 0) {
            throw std::runtime_error("nghttp3_conn_new failed");
        }
    }

    /// @brief Destroy the connection, releasing the underlying @c nghttp3_conn.
    ~connection() {
        if (_alive)
            *_alive = false; // wake any drain() still on the stack so it bails out
        nghttp3_conn_del(_conn);
    }

    connection(connection const &)            = delete;
    connection &operator=(connection const &) = delete;

    /**
     * @brief Move-construct, transferring ownership of the nghttp3 connection.
     * @param rhs Source connection; its @c _conn is reset to null.
     */
    connection(connection &&rhs) noexcept
        : _owner(rhs._owner)
        , _role(rhs._role)
        , _connection_id(rhs._connection_id)
        , _conn(std::exchange(rhs._conn, nullptr))
        , _streams(std::move(rhs._streams))
        , _alive(std::move(rhs._alive)) {}

    /**
     * @brief Whether the underlying nghttp3 connection is live.
     * @return @c true unless the connection has been moved-from.
     */
    [[nodiscard]] bool
    ok() const noexcept {
        return _conn != nullptr;
    }

    /**
     * @brief Open and bind the HTTP/3 control and QPACK encoder/decoder streams.
     *
     * Idempotent: a no-op once the local streams are bound. On first success the
     * pending control/QPACK output is drained to the transport.
     *
     * @return @c true on success (or if already bound); @c false if any stream
     *         fails to bind.
     */
    bool
    bind_local_streams() {
        if (_local_streams_bound) {
            return true;
        }
        const auto control       = _owner.open_http3_unidirectional_stream(_connection_id);
        const auto qpack_encoder = _owner.open_http3_unidirectional_stream(_connection_id);
        const auto qpack_decoder = _owner.open_http3_unidirectional_stream(_connection_id);
        if (nghttp3_conn_bind_control_stream(_conn, static_cast<int64_t>(control)) != 0)
            return false;
        if (nghttp3_conn_bind_qpack_streams(_conn, static_cast<int64_t>(qpack_encoder), static_cast<int64_t>(qpack_decoder)) != 0)
            return false;
        _local_streams_bound = true;
        drain();
        return true;
    }

    /**
     * @brief Feed inbound QUIC stream bytes into the HTTP/3 engine.
     * @param stream_id QUIC stream the bytes arrived on.
     * @param data      Received bytes.
     * @param fin       Whether this completes the stream (QUIC FIN).
     * @return @c true on success; @c false after a protocol read error (which
     *         also closes the connection via the owner). On success the consumed
     *         byte count is returned to the owner as flow-control credit and any
     *         resulting output is drained.
     */
    bool
    read_stream(std::uint64_t stream_id, std::string_view data, bool fin) {
        (void) state_for(stream_id);
        auto rv = nghttp3_conn_read_stream2(_conn, static_cast<int64_t>(stream_id), reinterpret_cast<const uint8_t *>(data.data()), data.size(),
                                            fin ? 1 : 0, now_ts());
        if (rv < 0) {
            _owner.close_http3_connection(_connection_id, static_cast<std::uint64_t>(-rv), "HTTP/3 protocol read error");
            return false;
        }
        _owner.extend_http3_stream_credit(_connection_id, stream_id, static_cast<std::uint64_t>(rv));
        drain();
        return true;
    }

    /**
     * @brief Acknowledge that the peer received @p bytes of stream output.
     * @param stream_id Stream whose output was acknowledged.
     * @param bytes     Number of newly acknowledged bytes (a zero count is a no-op).
     */
    void
    add_ack_offset(std::uint64_t stream_id, std::uint64_t bytes) {
        if (bytes != 0) {
            (void) nghttp3_conn_add_ack_offset(_conn, static_cast<int64_t>(stream_id), bytes);
        }
    }

    /**
     * @brief Send a GOAWAY shutdown notice without closing the connection.
     * @return @c true on success (output is drained); @c false if nghttp3 rejects
     *         the notice.
     */
    bool
    submit_shutdown_notice() {
        if (nghttp3_conn_submit_shutdown_notice(_conn) != 0) {
            return false;
        }
        drain();
        return true;
    }

    /**
     * @brief Begin graceful shutdown of the connection (GOAWAY).
     *
     * Marks the connection as shutting down so ::is_drained can later report
     * completion, then drains any resulting output.
     *
     * @return @c true on success; @c false if nghttp3 rejects the shutdown.
     */
    bool
    shutdown() {
        _shutdown_started = true;
        if (nghttp3_conn_shutdown(_conn) != 0) {
            return false;
        }
        drain();
        return true;
    }

    /**
     * @brief Whether a started shutdown has fully drained.
     * @return @c true only after ::shutdown was called and nghttp3 reports the
     *         connection drained (safe to close the transport).
     */
    [[nodiscard]] bool
    is_drained() const noexcept {
        return _shutdown_started && nghttp3_conn_is_drained(_conn) != 0;
    }

    /**
     * @brief Submit a response (server role) on a request stream.
     * @param stream_id Stream the request arrived on.
     * @param response  Response to send.
     * @return @c true on success; @c false if the declared @c content-length is
     *         malformed or (where it must match) disagrees with the body, header
     *         assembly fails, nghttp3 rejects the submission, or a @c trailer
     *         header is present but no valid trailer block can be built. On
     *         success the body is captured, trailers are submitted when present,
     *         per-stream user data is registered, and output is drained.
     */
    bool
    submit_response(std::uint64_t stream_id, qb::http::Response const &response) {
        auto      &st              = state_for(stream_id);
        const auto declared_length = detail::declared_content_length(response);
        if (!declared_length.ok
            || (declared_length.value && detail::response_body_length_must_match(response, st.request.method())
                && *declared_length.value != response.body().size())) {
            return false;
        }
        st.tx_body   = response.body().template as<std::string>();
        st.tx_offset = 0;
        auto headers = detail::make_response_headers(response);
        if (!headers) {
            return false;
        }
        const auto rv = nghttp3_conn_submit_response(_conn, static_cast<int64_t>(stream_id), headers->nva.data(), headers->nva.size(),
                                                     st.tx_body.empty() ? nullptr : &st.reader);
        if (rv != 0) {
            return false;
        }
        if (auto trailers = detail::make_trailers(response)) {
            if (nghttp3_conn_submit_trailers(_conn, static_cast<int64_t>(stream_id), trailers->nva.data(), trailers->nva.size()) != 0) {
                return false;
            }
        } else if (response.has_header("trailer")) {
            return false;
        }
        (void) nghttp3_conn_set_stream_user_data(_conn, static_cast<int64_t>(stream_id), &st);
        drain();
        return true;
    }

    /**
     * @brief Submit a request (client role) on a freshly opened stream.
     * @param stream_id Stream to send the request on.
     * @param request   Request to send (copied into per-stream state).
     * @return @c true on success; @c false if header assembly fails, nghttp3
     *         rejects the submission, or a @c trailer header is present but no
     *         valid trailer block can be built. On success the body is captured,
     *         trailers are submitted when present, and output is drained.
     */
    bool
    submit_request(std::uint64_t stream_id, qb::http::Request const &request) {
        auto &st     = state_for(stream_id);
        st.request   = request;
        st.tx_body   = request.body().template as<std::string>();
        st.tx_offset = 0;
        auto headers = detail::make_request_headers(request);
        if (!headers) {
            return false;
        }
        const auto rv = nghttp3_conn_submit_request(_conn, static_cast<int64_t>(stream_id), headers->nva.data(), headers->nva.size(),
                                                    st.tx_body.empty() ? nullptr : &st.reader, &st);
        if (rv != 0) {
            return false;
        }
        if (auto trailers = detail::make_trailers(request)) {
            if (nghttp3_conn_submit_trailers(_conn, static_cast<int64_t>(stream_id), trailers->nva.data(), trailers->nva.size()) != 0) {
                return false;
            }
        } else if (request.has_header("trailer")) {
            return false;
        }
        drain();
        return true;
    }

    /**
     * @brief Pump pending HTTP/3 output to the transport.
     *
     * Repeatedly asks nghttp3 for stream frames (bounded by a per-call budget),
     * forwards each chunk to the owner via @c send_http3_stream_data, advances
     * the write offset, and, when a stream's output reaches FIN, notifies the
     * owner once via the optional @c on_http3_stream_output_drained hook. A write
     * error closes the connection through the owner.
     */
    void
    drain() {
        nghttp3_vec                vec[16];
        std::vector<std::uint64_t> drained_streams;
        auto                       notify_drained = [&]() {
            for (auto stream_id : drained_streams) {
                if constexpr (requires(Owner &owner, std::uint64_t connection_id, std::uint64_t sid) {
                                  owner.on_http3_stream_output_drained(connection_id, sid);
                              }) {
                    _owner.on_http3_stream_output_drained(_connection_id, stream_id);
                }
            }
        };
        // Reentrancy guard: each send_http3_stream_data() below may synchronously destroy
        // this connection (owner erases it on a transport close). Hold a copy of the alive
        // flag on the stack so we can detect that and stop touching freed members.
        const auto alive = _alive;
        for (std::size_t budget = 0; budget < 256; ++budget) {
            int64_t    stream_id = -1;
            int        fin       = 0;
            const auto nvec      = nghttp3_conn_writev_stream(_conn, &stream_id, &fin, vec, 16);
            if (nvec < 0) {
                _owner.close_http3_connection(_connection_id, static_cast<std::uint64_t>(-nvec), "HTTP/3 protocol write error");
                return;
            }
            if (stream_id == -1) {
                notify_drained();
                return;
            }
            std::size_t accepted = 0;
            for (nghttp3_ssize i = 0; i < nvec; ++i) {
                if (vec[i].len == 0) {
                    continue;
                }
                _owner.send_http3_stream_data(_connection_id, static_cast<std::uint64_t>(stream_id),
                                              std::string_view(reinterpret_cast<const char *>(vec[i].base), vec[i].len), false);
                if (!*alive)
                    return; // this connection was destroyed mid-send
                accepted += vec[i].len;
            }
            if (fin) {
                _owner.send_http3_stream_data(_connection_id, static_cast<std::uint64_t>(stream_id), std::string_view{}, true);
                if (!*alive)
                    return;
            }
            (void) nghttp3_conn_add_write_offset(_conn, stream_id, accepted);
            if (fin) {
                auto &st = state_for(static_cast<std::uint64_t>(stream_id));
                if (!st.output_drained) {
                    st.output_drained = true;
                    drained_streams.push_back(static_cast<std::uint64_t>(stream_id));
                }
            }
            if (nvec == 0 && !fin) {
                notify_drained();
                return;
            }
        }
        notify_drained();
    }
};

} // namespace qb::protocol::http3
