/**
 * @file qbm/http/message_base.h
 * @brief Defines the base class for HTTP request and response messages.
 *
 * This file contains the `MessageBase` class, which provides common
 * functionalities and properties for HTTP messages, such as version handling,
 * header management (via inheritance from `Headers`), and body access (via
 * inheritance from `Body`).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <cstdint>
#include <string_view>
#include <utility>
#include <qb/io/uri.h>
#include <qb/utility/branch_hints.h> // QB_NOINLINE, QB_COLD (TrailerSection)
#include "body.h"
#include "headers.h"

namespace qb::http {
/**
 * @brief Internal implementation details for the HTTP module.
 */
namespace internal {
/**
 * @brief Owns a message's trailer section, allocated when it is first written to: a message
 *        without one carries a null pointer and nothing else (Huly QB-1073).
 *
 * Copying deep-copies the section, so a copied message owns its own trailers, as it owns its own
 * header fields; moving moves the pointer. Everything a section that exists needs -- allocation,
 * copy, destruction -- is out of line and cold: a message without trailers pays one pointer test
 * where it is copied, reset or destroyed, and nothing else (measured, Huly QB-1073).
 */
class TrailerSection {
public:
    TrailerSection() noexcept = default;

    TrailerSection(const TrailerSection &other)
        : _fields(other._fields ? clone(*other._fields) : nullptr) {}

    TrailerSection(TrailerSection &&other) noexcept
        : _fields(std::exchange(other._fields, nullptr)) {}

    TrailerSection &
    operator=(const TrailerSection &other) {
        if ((_fields || other._fields) && this != &other) [[unlikely]] {
            assign(other);
        }
        return *this;
    }

    TrailerSection &
    operator=(TrailerSection &&other) noexcept {
        if (this != &other) {
            Headers *const previous = std::exchange(_fields, std::exchange(other._fields, nullptr));
            if (previous) [[unlikely]] {
                destroy(previous);
            }
        }
        return *this;
    }

    ~TrailerSection() {
        if (_fields) [[unlikely]] {
            destroy(_fields);
        }
    }

    /// The section, or nullptr while nothing was written to it.
    [[nodiscard]] Headers *
    get() const noexcept {
        return _fields;
    }

    /// The section, created empty on the first call.
    [[nodiscard]] Headers &
    get_or_create() {
        if (!_fields) [[unlikely]] {
            _fields = create();
        }
        return *_fields;
    }

    /// Drops the section: the message carries no trailer field any more.
    void
    reset() noexcept {
        if (_fields) [[unlikely]] {
            destroy(std::exchange(_fields, nullptr));
        }
    }

private:
    [[nodiscard]] QB_NOINLINE QB_COLD static Headers *create();
    [[nodiscard]] QB_NOINLINE QB_COLD static Headers *clone(const Headers &fields);
    QB_NOINLINE QB_COLD static void                   destroy(Headers *fields) noexcept;
    QB_NOINLINE QB_COLD void                          assign(const TrailerSection &other);

    Headers *_fields = nullptr; ///< Owned; null while the message carries no trailer section.
};

/**
 * @brief Base class for HTTP messages (Requests and Responses).
 *
 * Encapsulates common message properties: HTTP version, header
 * management (through `Headers`), and body (through `Body`).
 *
 * @note Previously templated on `String` (`std::string` vs
 * `std::string_view`); the view mode has been retired
 * (see `headers.h` for rationale).
 */
struct MessageBase
    : public Headers // header management capabilities
    , public Body    // body management capabilities
{
    /** @brief Type alias kept for backwards source-compat. */
    using string_type = std::string;

    /** @brief Major HTTP version number (e.g., 1 for HTTP/1.1). */
    uint16_t major_version;
    /** @brief Minor HTTP version number (e.g., 1 for HTTP/1.1). */
    uint16_t minor_version;

    /**
     * @brief Flag indicating if the HTTP connection is to be upgraded
     *        (e.g., to WebSocket). Relevant for both requests and responses.
     */
    bool upgrade{};

    /**
     * @brief HTTP stream identifier.
     *
     * For HTTP/2 requests/responses, this contains the stream ID (odd for client-initiated,
     * even for server-initiated). For HTTP/3, this contains the QUIC stream ID.
     * For HTTP/1.1, this is 0.
     * This avoids the need for string conversions and provides type safety.
     */
    std::uint64_t stream_id{0};

    /**
     * @brief HTTP/1.x persistence decision computed by the parser.
     *
     * For HTTP/1.1 this is true by default unless @c Connection: close
     * is present. For HTTP/1.0 it is true only with
     * @c Connection: keep-alive. HTTP/2 and HTTP/3 ignore this flag.
     */
    bool keep_alive{false};

private:
    /// The trailer section (trailers()): null for a message that carries none.
    TrailerSection _trailers;

public:
    /**
     * @brief Default constructor.
     *
     * Initializes a message with HTTP version 1.1 (`major_version = 1`, `minor_version = 1`), no
     * header field, no trailer section, an empty body: the state `reset()` restores.
     * The `upgrade` flag is default-initialized to `false`.
     */
    MessageBase() noexcept
        : major_version(1)
        , minor_version(1)
        , upgrade(false)
        , stream_id(0)
        , keep_alive(false) {}

    /**
     * @brief Copy constructor.
     * @param other Message to copy from.
     * Creates a deep copy of another message including its HTTP version,
     * upgrade status, all headers (via `Headers` copy constructor),
     * and body content (via `Body` copy constructor).
     */
    MessageBase(const MessageBase &) = default;

    /**
     * @brief Constructs a MessageBase with specified initial headers and body.
     * HTTP version is defaulted to 1.1. Upgrade status is defaulted to false.
     * @param initial_headers A map of headers to initialize with. Values will be moved.
     * @param initial_body The initial body content for the message. Will be moved.
     */
    MessageBase(qb::icase_unordered_map<std::vector<std::string>> initial_headers, Body initial_body)
        : Headers(std::move(initial_headers))
        , Body(std::move(initial_body))
        , major_version(1)
        , minor_version(1)
        , upgrade(false)
        , stream_id(0)
        , keep_alive(false) {}

    /**
     * @brief Move constructor.
     * @param other Message to move from.
     * Efficiently transfers ownership of resources (headers and body)
     * from the source message to this message without unnecessary copying.
     */
    MessageBase(MessageBase &&) noexcept = default;

    /**
     * @brief Copy assignment operator.
     * @param other Message to copy from.
     * @return Reference to this message.
     * Creates a deep copy of the source message.
     */
    MessageBase &operator=(const MessageBase &) = default;

    /**
     * @brief Move assignment operator.
     * @param other Message to move from.
     * @return Reference to this message.
     * Efficiently transfers ownership of resources.
     */
    MessageBase &operator=(MessageBase &&) noexcept = default;

    /**
     * @brief Resets the message headers to an empty state.
     *
     * Clears all headers managed by the `Headers` base part of this message.
     * Resets transport/protocol metadata to the default HTTP/1.1 message state.
     * Derived classes may override or extend this to reset their specific fields.
     */
    void reset() noexcept;

public:
    /**
     * @brief Provides mutable access to the message body.
     * @return A reference to the `Body` object associated with this message.
     */
    [[nodiscard]] inline Body &
    body() noexcept {
        return static_cast<Body &>(*this);
    }

    /**
     * @brief Provides constant access to the message body.
     * @return A constant reference to the `Body` object associated with this message.
     */
    [[nodiscard]] inline const Body &
    body() const noexcept {
        return static_cast<Body const &>(*this);
    }

    /**
     * @brief The message's trailer section: the fields that follow its content (RFC 9110 §6.5),
     *        kept apart from its header section -- HTTP/1.1 (a chunked message), HTTP/2 and HTTP/3
     *        alike (Huly QB-1073).
     *
     * **Received**: every field of the peer's trailer section, in arrival order. For 3.x source
     * compatibility each one is ALSO added to the header fields (`headers()`, `header()`), after
     * the header-section values of the same name, as before 3.3: code that reads a trailer through
     * `headers()` keeps working. Read `trailers()` to tell a trailer field from a header field --
     * RFC 9110 §6.5.1 forbids trusting a trailer field as a header one. A field a trailer section
     * must not carry (framing, connection, routing, proxy authentication:
     * `detail::is_forbidden_trailer_field`) refuses the message or its stream before it reaches
     * here.
     *
     * **Sent**: the fields set here travel in the trailer section, after the body, announced by a
     * `Trailer` header the protocol adds when the message carries none. HTTP/1.1 has a trailer
     * section only in a chunked message (`Transfer-Encoding: chunked`): a message framed otherwise
     * sends no trailers. A forbidden field set here refuses the message.
     *
     * The section is allocated by the first call of this non-const accessor: a message nobody
     * gives trailers carries no allocation. To read without allocating, use the const accessor or
     * has_trailers().
     *
     * @return The trailer section, created empty on the first call.
     */
    [[nodiscard]] Headers &
    trailers() {
        return _trailers.get_or_create();
    }

    /**
     * @brief The message's trailer section, or an empty one (one process-wide object) when it
     *        carries none. Allocates nothing.
     */
    [[nodiscard]] const Headers &trailers() const noexcept;

    /// Whether the message carries at least one trailer field (trailers()). Allocates nothing.
    [[nodiscard]] bool
    has_trailers() const noexcept {
        const Headers *const fields = _trailers.get();
        return fields != nullptr && fields->header_count() != 0;
    }
};
} // namespace internal

namespace detail {
/**
 * @brief Stores a field of a received trailer section in @p message: in its `trailers()` and, for
 *        3.x source compatibility, in its header fields after the header-section values (Huly
 *        QB-1073). The one place the three protocols store a received trailer field.
 * @param message The message being received.
 * @param name The field name, in any case.
 * @param value The field value.
 */
void store_received_trailer(internal::MessageBase &message, std::string_view name, std::string_view value);
} // namespace detail

/**
 * @brief A message serialized without its content: the start line and the header section only.
 *
 * `out << MessageHead{msg}` writes what `out << msg` writes up to and including the empty line
 * that ends the header section — the framing headers included — and nothing after it: no body,
 * and no chunked last-chunk. Validation is the full serialization's; the body, if any, is ignored.
 * Two uses:
 *
 * - **The response to a HEAD request** (RFC 9110 §9.3.2), whose framing headers describe the
 *   content a GET would have carried. A `Response` does not know the method it answers, so the
 *   HTTP/1.1 server session states the suppression this way for every HEAD request.
 * - **A body you stream yourself**: write the head of a message that declares
 *   `Transfer-Encoding: chunked`, then its `Chunk`s and the terminating `Chunk{}`. Serializing the
 *   message itself writes a COMPLETE message instead: an empty chunked body is its last-chunk alone.
 *
 * @tparam Message `Request` or `Response`.
 */
template <typename Message>
struct MessageHead {
    const Message &message; ///< The message whose head is serialized; it must outlive this view.
};

/** @brief `MessageHead{msg}` deduces the message type. */
template <typename Message>
MessageHead(const Message &) -> MessageHead<Message>;
} // namespace qb::http
