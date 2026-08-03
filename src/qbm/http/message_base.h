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
#include <qb/io/uri.h>
#include "body.h"
#include "headers.h"

namespace qb::http {
/**
 * @brief Internal implementation details for the HTTP module.
 */
namespace internal {
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

    /**
     * @brief Default constructor.
     *
     * Initializes a message with HTTP version 1.1 (`major_version = 1`, `minor_version = 1`)
     * and calls `reset()` to ensure a clean initial state for headers.
     * The `upgrade` flag is default-initialized to `false`.
     */
    MessageBase() noexcept
        : major_version(1)
        , minor_version(1)
        , upgrade(false)
        , stream_id(0)
        , keep_alive(false) {
        this->Headers::_headers.clear();
    }

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
};
} // namespace internal
} // namespace qb::http
