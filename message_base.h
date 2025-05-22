/**
 * @file qbm/http/message_base.h
 * @brief Defines the base class for HTTP request and response messages.
 *
 * This file contains the `MessageBase` template class, which provides common
 * functionalities and properties for HTTP messages, such as version handling,
 * header management (via inheritance from `THeaders`), and body access (via
 * inheritance from `Body`).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

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
         * This template class encapsulates common properties of HTTP messages, including
         * HTTP version, header management (through `THeaders`), and message body handling
         * (through `Body`). It serves as a CRTP (Curiously Recurring Template Pattern) base
         * for concrete message types like `TRequest` and `TResponse`.
         *
         * @tparam String The string type used for storing header names and values
         *                (typically `std::string` or `std::string_view`).
         */
        template<typename String>
        struct MessageBase
                : public THeaders<String> // Inherits header management capabilities
                  , public Body // Inherits body management capabilities
        {
            /** @brief Type alias for the string type used in headers. */
            using string_type = String;

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
             * @brief Default constructor.
             *
             * Initializes a message with HTTP version 1.1 (`major_version = 1`, `minor_version = 1`)
             * and calls `reset()` to ensure a clean initial state for headers.
             * The `upgrade` flag is default-initialized to `false`.
             */
            MessageBase() noexcept
                : major_version(1)
                  , minor_version(1)
                  , upgrade(false) // Explicitly initialize upgrade flag
            {
                // reset() is called to clear headers from THeaders, Body is default constructed.
                // The THeaders part of MessageBase is default constructed before this body,
                // then its _content_type is initialized using its default ContentType constructor.
                // Then MessageBase::reset() is called.
                this->THeaders<String>::_headers.clear(); // Ensures headers are cleared.
                // Body is default constructed. ContentType in THeaders is default constructed.
            }

            /**
             * @brief Copy constructor.
             * @param other Message to copy from.
             * Creates a deep copy of another message including its HTTP version,
             * upgrade status, all headers (via `THeaders` copy constructor),
             * and body content (via `Body` copy constructor).
             */
            MessageBase(const MessageBase &) = default;

            /**
             * @brief Constructs a MessageBase with specified initial headers and body.
             * HTTP version is defaulted to 1.1. Upgrade status is defaulted to false.
             * @param initial_headers A map of headers to initialize with. Values will be moved.
             * @param initial_body The initial body content for the message. Will be moved.
             */
            MessageBase(qb::icase_unordered_map<std::vector<String> > initial_headers, Body initial_body)
                : THeaders<String>(std::move(initial_headers)) // Initialize THeaders part
                  , Body(std::move(initial_body)) // Initialize Body part
                  , major_version(1)
                  , minor_version(1)
                  , upgrade(false) {
            }

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
             * Clears all headers managed by the `THeaders` base part of this message.
             * The HTTP version, upgrade flag, and body content are not affected by this method.
             * Derived classes may override or extend this to reset their specific fields.
             */
            void
            reset() noexcept {
                this->THeaders<String>::_headers.clear();
                // Reset ContentType to its default state as well, as it's part of THeaders state
                this->THeaders<String>::_content_type = typename THeaders<String>::ContentType{};
                // Note: Body is not cleared here by design, typically managed separately or by derived reset().
                // HTTP version and upgrade flag are also not reset here, typically set at construction or explicitly.
            }

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
