/**
 * @file ws.h
 * @brief WebSocket protocol implementation for the qb Actor Framework
 *
 * This module provides WebSocket capabilities conforming to RFC 6455 including:
 * - WebSocket client and server implementations
 * - Support for text and binary messages
 * - Handling of control frames (ping, pong, close)
 * - Built-in security mechanisms for frame validation
 * - Support for secure WebSockets over TLS/SSL
 *
 * The implementation relies on the HTTP module for the initial handshake
 * and requires OpenSSL for security features.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

// WebSocket protocol requires OpenSSL crypto library
#ifndef QB_HAS_SSL
#error "websocket protocol requires OpenSSL crypto library"
#endif

#include <qb/io/async/tcp/connector.h>
#include <qb/io/crypto.h>
#include <chrono>
#include <functional>
#include <algorithm>
#include <string>
#include <string_view>
#include <vector>
#include "../http.h"

// Forward declarations (must be outside qb::http::ws to avoid creating phantom namespaces)
namespace qb {
namespace allocator {
template <typename T>
class pipe;
} // namespace allocator
namespace io {
namespace transport {
class tcp;
} // namespace transport
} // namespace io
} // namespace qb

/**
 * @namespace qb::http::ws
 * @brief WebSocket protocol implementation within the HTTP namespace
 *
 * This namespace contains classes and functions for WebSocket communication,
 * including message types, connection handling, and protocol operations.
 */
namespace qb::http::ws {

/**
 * @brief Checks if a string view contains valid UTF-8 data.
 * @param sv The string_view to validate.
 * @return True if the data is valid UTF-8, false otherwise.
 */
bool is_utf8(std::string_view sv) noexcept;

/**
 * @enum opcode
 * @brief WebSocket frame opcodes as defined in RFC 6455
 *
 * These values represent the different types of WebSocket frames
 * with their corresponding opcode values (including FIN bit set).
 */
enum opcode : unsigned char {
    Continuation = 0, /**< Continuation frame (opcode 0x0) */
    _Text        = 1, /**< Text frame (opcode 0x1) */
    _Binary      = 2, /**< Binary frame (opcode 0x2) */
    _Close       = 8, /**< Close frame (opcode 0x8) */
    _Ping        = 9, /**< Ping frame (opcode 0x9) */
    _Pong        = 10,/**< Pong frame (opcode 0xA) */

    Text   = 129, /**< Text frame (0x81): FIN bit + opcode 0x1 */
    Binary = 130, /**< Binary frame (0x82): FIN bit + opcode 0x2 */
    Close  = 136, /**< Connection close frame (0x88): FIN bit + opcode 0x8 */
    Ping   = 137, /**< Ping frame (0x89): FIN bit + opcode 0x9 */
    Pong   = 138  /**< Pong frame (0x8A): FIN bit + opcode 0xA */
};

/**
 * @struct Message
 * @brief Base class for all WebSocket message types
 *
 * Provides core functionality for WebSocket messages, including
 * data storage, frame composition, and state management.
 */
struct Message {
    unsigned char fin_rsv_opcode =
        0; /**< Combined field for FIN bit, RSV bits, and opcode */
    bool masked =
        false; /**< Whether the message should be masked (required for client->server) */
    ::qb::allocator::pipe<char>
        _data; /**< Internal buffer storing the message payload */

    ::qb::allocator::pipe<char>&
    data() noexcept {
        return _data;
    } /**< Pointer to the message data buffer */

    /**
     * @brief Get the size of the message payload
     * @return Size of the message data in bytes
     */
    [[nodiscard]] std::size_t
    size() const noexcept {
        return _data.size();
    }

    /**
     * @brief Append data to the message payload
     * @tparam T Type of data to append
     * @param data The data to append to the message
     * @return Reference to this message for chaining
     */
    template <typename T>
    Message &
    operator<<(T const &data) {
        _data << data;
        return *this;
    }

    /**
     * @brief Reset the message to its initial state
     *
     * Clears the message data and resets the frame control bits.
     */
    void
    reset() {
        fin_rsv_opcode = 0;
        _data.reset();
    }
};

/**
 * @struct MessageText
 * @brief WebSocket text message
 *
 * Specialization of Message for UTF-8 encoded text data.
 */
struct MessageText : public Message {
    /**
     * @brief Construct a new text message with the appropriate opcode
     */
    MessageText() {
        fin_rsv_opcode = opcode::Text;
    }
};

/**
 * @struct MessageBinary
 * @brief WebSocket binary message
 *
 * Specialization of Message for binary data.
 */
struct MessageBinary : public Message {
    /**
     * @brief Construct a new binary message with the appropriate opcode
     */
    MessageBinary() {
        fin_rsv_opcode = opcode::Binary;
    }
};

/**
 * @struct MessagePing
 * @brief WebSocket ping control message
 *
 * Used to verify that the remote endpoint is still responsive.
 * The recipient must respond with a pong containing the same payload.
 */
struct MessagePing : public Message {
    /**
     * @brief Construct a new ping message with the appropriate opcode
     */
    MessagePing() {
        fin_rsv_opcode = opcode::Ping;
        masked         = false;
    }
};

/**
 * @struct MessagePong
 * @brief WebSocket pong control message
 *
 * Response to a ping message, containing the same payload as the ping.
 */
struct MessagePong : public Message {
    /**
     * @brief Construct a new pong message with the appropriate opcode
     */
    MessagePong() {
        fin_rsv_opcode = opcode::Pong;
    }
};

/**
 * @enum CloseStatus
 * @brief WebSocket close status codes as defined in RFC 6455 §7.4 and the
 *        IANA WebSocket Close Code Number Registry.
 *
 * Codes annotated as `Reserved*` MUST NOT be sent on the wire — the
 * `MessageClose` constructor will refuse to build a frame carrying them.
 */
enum class CloseStatus : std::uint16_t {
    /// 1000 - Normal closure; the connection successfully completed its purpose.
    Normal                 = 1000,
    /// 1001 - The endpoint is going away (e.g., server shutdown).
    GoingAway              = 1001,
    /// 1002 - Protocol error (malformed frame, reserved opcode, etc.).
    ProtocolError          = 1002,
    /// 1003 - Received data cannot be accepted (e.g., invalid data format).
    DataNotAccepted        = 1003,
    /// 1004 - Reserved. MUST NOT be set as a status code in a Close frame.
    Reserved1004           = 1004,
    /// 1005 - Reserved: "no status received". MUST NOT appear on the wire.
    NoStatusReceived       = 1005,
    /// 1006 - Reserved: "abnormal closure". MUST NOT appear on the wire.
    AbnormalClosure        = 1006,
    /// 1007 - Data is inconsistent with message type (e.g., non-UTF-8 in Text).
    DataNotConsistent      = 1007,
    /// 1008 - Message violates policy.
    PolicyViolation        = 1008,
    /// 1009 - Message is too large to process.
    MessageTooBig          = 1009,
    /// 1010 - Client expected server to negotiate an extension.
    MissingExtension       = 1010,
    /// 1011 - Server encountered an unexpected condition.
    UnexpectedReason       = 1011,
    /// 1012 - Service restart.
    ServiceRestart         = 1012,
    /// 1013 - Try again later.
    TryAgainLater          = 1013,
    /// 1014 - Bad gateway.
    BadGateway             = 1014,
    /// 1015 - Reserved: "TLS handshake failure". MUST NOT appear on the wire.
    TLSHandshakeFailed     = 1015
};

/**
 * @brief Report whether a numeric close code is allowed on the wire per
 *        RFC 6455 §7.4.1 / §7.4.2 + IANA registry.
 *
 * The forbidden set is: 1004, 1005, 1006, 1015, and any value below 1000
 * or above 4999.  Codes 3000-3999 are reserved for registered libraries
 * and 4000-4999 for private use — both are allowed here.
 */
[[nodiscard]] constexpr bool
is_sendable_close_code(std::uint16_t code) noexcept {
    if (code < 1000u || code > 4999u)
        return false;
    switch (code) {
        case 1004u: case 1005u: case 1006u: case 1015u:
            return false;
        default:
            return true;
    }
}

/**
 * @struct MessageClose
 * @brief WebSocket close control message.
 *
 * The RFC allows a 2-byte status code followed by an optional UTF-8 reason
 * string. Total payload is capped at 125 bytes (control frame limit), of
 * which 2 are used for the status, leaving 123 bytes for the reason.
 *
 * The constructor rejects reserved status codes (1004/1005/1006/1015) and
 * anything outside `[1000..4999]` by throwing `std::invalid_argument` —
 * building such a message is always a programming error.
 *
 * Reason strings longer than 123 bytes are truncated on a UTF-8 boundary
 * when possible; callers should keep them short by construction.
 */
struct MessageClose : Message {
    MessageClose() = delete;

    /**
     * @brief Construct a Close frame from a typed status code.
     */
    explicit MessageClose(CloseStatus      status = CloseStatus::Normal,
                          std::string_view reason = "closed normally")
        : MessageClose(static_cast<std::uint16_t>(status), reason) {}

    /**
     * @brief Construct a Close frame from a raw numeric status.
     *
     * @throws std::invalid_argument if @p status is reserved or out of range.
     */
    explicit MessageClose(std::uint16_t    status,
                          std::string_view reason) {
        if (!is_sendable_close_code(status)) {
            throw std::invalid_argument(
                "qb::http::ws::MessageClose: close code " +
                std::to_string(static_cast<unsigned>(status)) +
                " is reserved or out of range and must not be sent");
        }

        fin_rsv_opcode = static_cast<unsigned char>(opcode::Close);

        // Clip reason if the resulting payload would exceed the control-frame
        // limit (125 bytes = 2 status + 123 reason). Keep the truncated
        // prefix UTF-8 clean: cutting through a multi-byte sequence would
        // otherwise generate an invalid close reason on the wire.
        if (reason.length() > 123) {
            reason = reason.substr(0, 123);
            while (!reason.empty() && !is_utf8(reason)) {
                reason.remove_suffix(1);
            }
        }
        if (!reason.empty() && !is_utf8(reason)) {
            throw std::invalid_argument(
                "qb::http::ws::MessageClose: close reason must be valid UTF-8");
        }

        _data.reserve(2 + reason.size());
        _data << static_cast<unsigned char>((status >> 8) & 0xFF)
              << static_cast<unsigned char>(status & 0xFF)
              << reason;
    }
};

/**
 * @brief Generate a random WebSocket key for handshake
 * @return Base64-encoded random 16-byte value
 *
 * This function creates a secure random key for use in the WebSocket opening handshake.
 */
std::string generateKey();

} // namespace qb::http::ws

/**
 * @namespace qb::http
 * @brief HTTP protocol related functionality
 */
namespace qb::http {

/**
 * @struct WebSocketRequest
 * @brief HTTP request specifically formatted for a WebSocket upgrade
 *
 * Extends the standard HTTP Request to include headers required for a WebSocket
 * handshake.
 */
struct WebSocketRequest : public Request {
    WebSocketRequest() = delete;

    /**
     * @brief Construct a WebSocket upgrade request with the specified key
     * @param key The WebSocket key for the handshake
     */
    explicit WebSocketRequest(std::string const &key) {
        method() = qb::http::Method::GET;
        _headers["Upgrade"].emplace_back("websocket");
        _headers["Connection"].emplace_back("Upgrade");
        _headers["Sec-WebSocket-Key"].emplace_back(key);
        _headers["Sec-WebSocket-Version"].emplace_back("13");
    }
};
} // namespace qb::http

/**
 * @namespace qb::protocol
 * @brief Protocol implementations for network communication
 */
namespace qb::protocol {

/**
 * @namespace qb::protocol::ws_internal
 * @brief Internal implementation details for WebSocket protocol
 */
namespace ws_internal {

/**
 * @namespace qb::protocol::ws_internal::rfc
 * @brief Constants related to the WebSocket RFC 6455 specification.
 */
namespace rfc {
constexpr uint8_t     FIN_BIT_MASK                 = 0x80;
constexpr uint8_t     RSV_BITS_MASK                = 0x70;
constexpr uint8_t     OPCODE_MASK                  = 0x0F;
constexpr uint8_t     MASK_BIT_MASK                = 0x80;
constexpr size_t      MAX_CONTROL_FRAME_PAYLOAD_SIZE = 125;
constexpr uint8_t     PAYLOAD_LEN_16_BIT           = 126;
constexpr uint8_t     PAYLOAD_LEN_64_BIT           = 127;
} // namespace rfc

/**
 * @brief Wire-level WebSocket events (not nested inside base<IO_>).
 *
 * Previously `base<IO_>::message` etc. were nested classes, so
 * `base<BoundedSession>::message` and `base<coro_session<...>>::message`
 * were unrelated types and `coro_session::on(WS_Protocol::message&&)`
 * could not bind. These aggregates are shared for every I/O handler type.
 */
struct event_close {
    const std::size_t       size;
    const char             *data;
    ::qb::http::ws::Message &ws;
};

struct event_ping {
    const std::size_t       size;
    const char             *data;
    ::qb::http::ws::Message &ws;
};

struct event_pong {
    const std::size_t       size;
    const char             *data;
    ::qb::http::ws::Message &ws;
};

struct event_message {
    const std::size_t       size;
    const char             *data;
    ::qb::http::ws::Message &ws;
};

[[nodiscard]] constexpr bool
is_valid_frame_opcode(unsigned char frame_opcode) noexcept {
    switch (frame_opcode) {
        case ::qb::http::ws::opcode::Continuation:
        case ::qb::http::ws::opcode::_Text:
        case ::qb::http::ws::opcode::_Binary:
        case ::qb::http::ws::opcode::_Close:
        case ::qb::http::ws::opcode::_Ping:
        case ::qb::http::ws::opcode::_Pong:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] inline bool
is_valid_received_close_code(std::uint16_t code) noexcept {
    return ::qb::http::ws::is_sendable_close_code(code);
}

/**
 * @class base
 * @brief Base implementation of the WebSocket protocol
 *
 * Provides core functionality for both client and server WebSocket endpoints,
 * including frame parsing, message handling, and event dispatching.
 *
 * @tparam IO_ The I/O handler type
 */
template <typename IO_>
class base : public qb::io::async::AProtocol<IO_> {
    std::size_t   _parsed = 0; /**< Number of bytes parsed from the current frame */
    std::size_t   _expected_size = 0; /**< Expected payload size based on frame header */
    unsigned char _fin_rsv_opcode = 0; /**< Current frame's FIN, RSV, and opcode bits */
    unsigned char _data_opcode    = 0; /**< Opcode for the current fragmented data message */
    ::qb::http::ws::Message _message;   /**< Current message being assembled */
    size_t _max_payload_size = 0;       /**< Max allowed payload size, 0 for unlimited */

    /**
     * @brief Fails the WebSocket connection by queuing a Close frame.
     *
     * Contract:
     *   - The Close frame is **appended** to any already-queued outbound data
     *     so that in-flight frames are still delivered before the peer sees
     *     the failure (addresses previous W20: `_io.out().reset()` used to
     *     drop them).
     *   - The reassembly buffer (`_message`) is reset so that no half-frame
     *     leaks into a subsequent session if the I/O layer decides to stay
     *     alive for an orderly TCP close.
     *   - `not_ok()` makes the protocol refuse any further inbound parsing.
     *
     * @param status The CloseStatus code.
     * @param reason The reason for closing.
     * @return The size of the input buffer, instructing the I/O layer to
     *         drop any unparsed bytes (the connection is now broken).
     */
    std::size_t
    fail_connection(::qb::http::ws::CloseStatus status, std::string_view reason) {
        if (this->ok()) {
            ::qb::http::ws::MessageClose close_msg(status, reason);
            if constexpr (!IO_::has_server) {
                close_msg.masked = true;
            }
            this->_io << close_msg;
            notify_protocol_error();
            this->not_ok();
            _message.reset();
            _data_opcode = 0;
        }
        return this->_io.in().size();
    }

    void
    notify_protocol_error() {
        if constexpr (requires { typename IO_::error; }) {
            if constexpr (qb::has_on<IO_, typename IO_::error>) {
                this->_io.on(typename IO_::error{});
            }
        }
    }

    void
    processControlFrame(unsigned char frame_opcode, ::qb::http::ws::Message &current_frame_message) {
        // Handle control frames immediately and separately.
        current_frame_message.fin_rsv_opcode = _fin_rsv_opcode;
        if constexpr (IO_::has_server)
            current_frame_message.masked = false;
        else
            current_frame_message.masked = true; // For client sending pong reply etc.

        if (frame_opcode == ::qb::http::ws::opcode::_Close) {
            if (current_frame_message.size() == 1u) {
                fail_connection(::qb::http::ws::CloseStatus::ProtocolError,
                                "Close frame payload of 1 byte is invalid");
                return;
            }
            if (current_frame_message.size() >= 2u) {
                const auto *payload =
                    reinterpret_cast<const unsigned char *>(
                        current_frame_message._data.cbegin());
                const auto close_code =
                    static_cast<std::uint16_t>((payload[0] << 8u) | payload[1]);
                if (!is_valid_received_close_code(close_code)) {
                    fail_connection(::qb::http::ws::CloseStatus::ProtocolError,
                                    "Invalid close status code");
                    return;
                }
                if (current_frame_message.size() > 2u &&
                    !::qb::http::ws::is_utf8(
                        {current_frame_message._data.cbegin() + 2,
                         current_frame_message.size() - 2})) {
                    fail_connection(
                        ::qb::http::ws::CloseStatus::DataNotConsistent,
                        "Invalid UTF-8 in close reason");
                    return;
                }
            }

            // Let any previously queued frames flush before the close is
            // observed by the peer. We used to `_io.out().reset()` here which
            // silently dropped them (W20). The close frame is simply appended
            // after the in-flight data.
            if constexpr (qb::has_on<IO_, close>) {
                this->_io.on(
                    close{current_frame_message.size(),
                          current_frame_message._data.cbegin(),
                          current_frame_message});
            } else {
                // Default behavior: echo the close frame back (RFC 6455 §5.5.1
                // requires the peer to respond with a Close — we oblige).
                this->_io << current_frame_message;
            }
            this->not_ok();
        } else if (frame_opcode == ::qb::http::ws::opcode::_Ping) {
            if constexpr (qb::has_on<IO_, ping>) {
                this->_io.on(
                    ping{current_frame_message.size(),
                         current_frame_message._data.cbegin(),
                         current_frame_message});
            }
            // Send pong automatically
            current_frame_message.fin_rsv_opcode = ::qb::http::ws::opcode::Pong;
            this->_io << current_frame_message;
        } else if (frame_opcode == ::qb::http::ws::opcode::_Pong) {
            if constexpr (qb::has_on<IO_, pong>) {
                this->_io.on(
                    pong{current_frame_message.size(),
                         current_frame_message._data.cbegin(),
                         current_frame_message});
            }
        }
    }

    void
    processDataFrame(unsigned char frame_opcode, bool is_final_frame, ::qb::http::ws::Message &current_frame_message) {
        // Handle data frames (Continuation, Text, Binary).
        if (frame_opcode != ::qb::http::ws::opcode::Continuation) {
            if (_data_opcode != 0) {
                // New data message started before previous one finished.
                fail_connection(
                    ::qb::http::ws::CloseStatus::ProtocolError,
                    "Received new data message before previous was complete");
            } else {
                _data_opcode = frame_opcode;
                _message.reset();
            }
        } else { // Continuation frame
            if (_data_opcode == 0) {
                // Continuation frame received without a prior data frame.
                fail_connection(::qb::http::ws::CloseStatus::ProtocolError,
                                "Received continuation frame without initial data frame");
            }
        }

        if (this->ok()) {
            if (_max_payload_size > 0u) {
                if (_message.size() > _max_payload_size ||
                    current_frame_message.size() >
                        (_max_payload_size - _message.size())) {
                    fail_connection(::qb::http::ws::CloseStatus::MessageTooBig,
                                    "Payload size exceeds configured limit");
                    return;
                }
            }
            // Append the payload of the current frame to the main reassembly buffer
            _message._data << current_frame_message._data;

            if (is_final_frame) {
                if (_data_opcode == 0) {
                    // This can happen if a single-frame message is sent with opcode 0
                    fail_connection(
                        ::qb::http::ws::CloseStatus::ProtocolError,
                        "Received final continuation frame with no initial data frame");
                } else {
                    // Complete message has been reassembled.
                    _message.fin_rsv_opcode = _data_opcode | rfc::FIN_BIT_MASK;

                    if (_data_opcode == ::qb::http::ws::opcode::_Text &&
                        !::qb::http::ws::is_utf8(
                            {_message._data.cbegin(), _message.size()})) {
                        fail_connection(
                            ::qb::http::ws::CloseStatus::DataNotConsistent,
                            "Invalid UTF-8 in text message");
                    } else {
                        if constexpr (IO_::has_server)
                            _message.masked = false;
                        else
                            _message.masked = true;

                        this->_io.on(
                            message{_message.size(), _message._data.cbegin(), _message});
                    }

                    // Reset for the next message.
                    _message.reset();
                    _data_opcode = 0;
                }
            }
        }
    }

public:
    using close   = event_close;
    using ping    = event_ping;
    using pong    = event_pong;
    using message = event_message;

    base() = delete;

    /**
     * @brief Construct a WebSocket protocol handler
     * @param io Reference to the I/O handler
     */
    explicit base(IO_ &io)
        : qb::io::async::AProtocol<IO_>(io) {}

    /**
     * @brief Sets the maximum allowed payload size for a single message.
     * @param size The maximum size in bytes. 0 means no limit.
     */
    void
    set_max_payload_size(size_t size) {
        _max_payload_size = size;
    }

    /**
     * @brief Calculate the expected size of the incoming WebSocket message
     * @return Expected total size of the current frame in bytes, or 0 if incomplete
     *
     * This method parses WebSocket frame headers to determine the total expected
     * size of the frame, including header and payload.
     */
    std::size_t
    getMessageSize() noexcept final {
        if (!this->ok())
            return 0;

        auto      &buffer      = this->_io.in();
        const auto buffer_size = buffer.size();
        auto first_bytes = reinterpret_cast<const unsigned char *>(buffer.cbegin());
        if (!_parsed) {
            if (buffer_size < 2u)
                return 0;

            _fin_rsv_opcode  = first_bytes[0];
            const auto frame_opcode = _fin_rsv_opcode & rfc::OPCODE_MASK;

            if (!is_valid_frame_opcode(frame_opcode)) {
                return fail_connection(::qb::http::ws::CloseStatus::ProtocolError,
                                       "Reserved or unknown opcode");
            }

            // RFC 5.2: RSV bits MUST be 0 unless an extension is negotiated.
            if ((_fin_rsv_opcode & rfc::RSV_BITS_MASK) != 0) {
                return fail_connection(::qb::http::ws::CloseStatus::ProtocolError, "RSV bits must be 0");
            }

            const bool is_control_frame = frame_opcode >= ::qb::http::ws::opcode::_Close;
            if (is_control_frame) {
                // RFC 5.5: Control frames MUST NOT be fragmented.
                if ((_fin_rsv_opcode & rfc::FIN_BIT_MASK) == 0) {
                    return fail_connection(::qb::http::ws::CloseStatus::ProtocolError, "Control frame cannot be fragmented");
                }
            }

            _message.masked = (first_bytes[1] & rfc::MASK_BIT_MASK) != 0;
            // only server side
            if constexpr (IO_::has_server) {
                if (!_message.masked) {
                    // RFC 5.1: A server MUST close the connection if it receives an unmasked frame.
                    return fail_connection(::qb::http::ws::CloseStatus::ProtocolError, "Message from client not masked");
                }
            } else {
                if (_message.masked) {
                    // RFC 5.1: A client MUST close the connection if it receives a masked frame from server.
                    return fail_connection(::qb::http::ws::CloseStatus::ProtocolError, "Message from server must not be masked");
                }
            }
            _parsed += 2u;
        }
        if (!_expected_size) {
            const auto payload_indicator = first_bytes[1] & 127u;
            std::size_t length = payload_indicator;
            const bool is_control_frame = (_fin_rsv_opcode & rfc::OPCODE_MASK) >= ::qb::http::ws::opcode::_Close;

            if (is_control_frame && length > rfc::MAX_CONTROL_FRAME_PAYLOAD_SIZE) {
                 return fail_connection(::qb::http::ws::CloseStatus::ProtocolError, "Control frame payload cannot exceed 125 bytes");
            }

            // 2 or 8 next bytes is the size of content
            std::size_t num_bytes = 0;
            if (payload_indicator == rfc::PAYLOAD_LEN_16_BIT) {
                num_bytes = 2;
            } else if (payload_indicator == rfc::PAYLOAD_LEN_64_BIT) {
                num_bytes = 8;
            }

            if (num_bytes) {
                if (is_control_frame) {
                    return fail_connection(::qb::http::ws::CloseStatus::ProtocolError, "Control frame cannot have extended payload length");
                }
                if (buffer_size < (num_bytes + 2u))
                    return 0u;
                // position after 2 firt bytes
                auto length_bytes =
                    reinterpret_cast<const unsigned char *>(buffer.cbegin() + 2u);
                length = 0u;
                for (std::size_t c = 0u; c < num_bytes; c++)
                    length += static_cast<std::size_t>(length_bytes[c])
                              << (8u * (num_bytes - 1u - c));

                if (payload_indicator == rfc::PAYLOAD_LEN_64_BIT &&
                    (length_bytes[0] & 0x80u) != 0u) {
                    return fail_connection(::qb::http::ws::CloseStatus::ProtocolError,
                                           "Most significant bit of 64-bit payload length must be 0");
                }
            }

            if (payload_indicator == rfc::PAYLOAD_LEN_16_BIT && length < 126u) {
                return fail_connection(::qb::http::ws::CloseStatus::ProtocolError,
                                       "Non-minimal payload length encoding");
            }
            if (payload_indicator == rfc::PAYLOAD_LEN_64_BIT && length <= 0xFFFFu) {
                return fail_connection(::qb::http::ws::CloseStatus::ProtocolError,
                                       "Non-minimal payload length encoding");
            }
            _expected_size = length;

            // Enforce max payload size for data frames
            if (!is_control_frame && _max_payload_size > 0 && _expected_size > _max_payload_size) {
                return fail_connection(::qb::http::ws::CloseStatus::MessageTooBig, "Payload size exceeds configured limit");
            }
            _parsed += num_bytes;
        }

        const auto full_size =
            _expected_size + _parsed + (_message.masked ? 4u : 0u);
        if (buffer_size < full_size)
            return 0;

        return full_size;
    }

    void
    onMessage(std::size_t) noexcept final {
        if (!this->ok())
            return;

        auto      &buffer      = this->_io.in();
        const auto frame_opcode      = _fin_rsv_opcode & rfc::OPCODE_MASK;
        const bool is_final_frame = (_fin_rsv_opcode & rfc::FIN_BIT_MASK) != 0;

        // Create a temporary message to hold the current frame's payload
        // This avoids corrupting the main reassembly buffer (_message) with control frames.
        ::qb::http::ws::Message current_frame_message;
        current_frame_message.masked = _message.masked;

        if (current_frame_message.masked) {
            auto mask = reinterpret_cast<const unsigned char *>(buffer.cbegin() + _parsed);
            auto begin_buffer_data = buffer.begin() + _parsed + 4;
            auto begin_data = current_frame_message._data.allocate_back(_expected_size);
            for (auto i = 0u; i < _expected_size; ++i)
                begin_data[i] = begin_buffer_data[i] ^ mask[i % 4];
        } else {
            std::memcpy(current_frame_message._data.allocate_back(_expected_size),
                        buffer.begin() + _parsed, _expected_size);
        }

        const bool is_control_frame = frame_opcode >= ::qb::http::ws::opcode::_Close;
        if (is_control_frame) {
            processControlFrame(frame_opcode, current_frame_message);
        } else {
            processDataFrame(frame_opcode, is_final_frame, current_frame_message);
        }

        // Reset per-frame state
        _expected_size = _parsed = _fin_rsv_opcode = 0;
    }

    void
    reset() noexcept final {
        _message.reset();
        _expected_size = _parsed = _fin_rsv_opcode = 0;
        _data_opcode = 0;
    }
};

} // namespace ws_internal

namespace detail {

[[nodiscard]] inline unsigned char
ascii_to_lower(unsigned char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<unsigned char>(c + ('a' - 'A')) : c;
}

// RFC 6455 §1.3 — GUID appended to the client key before SHA-1. Kept as a
// string_view so we can concatenate without allocating a separate literal.
inline constexpr std::string_view ws_magic_guid =
    "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute the `Sec-WebSocket-Accept` header value for a given client key.
[[nodiscard]] inline std::string
compute_accept_key(std::string_view client_key) {
    std::string buf;
    buf.reserve(client_key.size() + ws_magic_guid.size());
    buf.append(client_key);
    buf.append(ws_magic_guid);
    return crypto::base64::encode(crypto::sha1(buf));
}

/// Case-insensitive equality test for small ASCII header tokens.
[[nodiscard]] inline bool
iequal_ascii(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        const auto ca = static_cast<unsigned char>(a[i]);
        const auto cb = static_cast<unsigned char>(b[i]);
        if (ascii_to_lower(ca) != ascii_to_lower(cb)) return false;
    }
    return true;
}

[[nodiscard]] inline bool
is_token_char(unsigned char c) noexcept {
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
           c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
           c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

[[nodiscard]] inline bool
is_valid_token(std::string_view value) noexcept {
    return !value.empty() &&
           std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return is_token_char(c);
           });
}

/// Case-insensitive token containment for comma-separated header fields
/// (RFC 7230 token lists such as `Connection`).
[[nodiscard]] inline bool
has_token_ci(std::string_view header_value, std::string_view expected_token) noexcept {
    std::size_t pos = 0;
    while (pos <= header_value.size()) {
        const auto comma = header_value.find(',', pos);
        const auto end = (comma == std::string_view::npos) ? header_value.size() : comma;

        auto token = header_value.substr(pos, end - pos);
        const auto first = token.find_first_not_of(" \t");
        if (first != std::string_view::npos) {
            token.remove_prefix(first);
            const auto last = token.find_last_not_of(" \t");
            token = token.substr(0, last + 1);
            if (iequal_ascii(token, expected_token)) {
                return true;
            }
        }

        if (comma == std::string_view::npos) {
            break;
        }
        pos = comma + 1;
    }
    return false;
}

/// Trim ASCII optional whitespace (OWS) around a header value.
[[nodiscard]] inline std::string_view
trim_ows(std::string_view sv) noexcept {
    const auto first = sv.find_first_not_of(" \t");
    if (first == std::string_view::npos) {
        return {};
    }
    const auto last = sv.find_last_not_of(" \t");
    return sv.substr(first, last - first + 1);
}

/// Constant-time equality for two byte strings of identical length.
[[nodiscard]] inline bool
constant_time_equal(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    unsigned diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i]) ^
                static_cast<unsigned char>(b[i]);
    }
    return diff == 0;
}

} // namespace detail

template <typename IO_>
class ws_server : public ws_internal::base<IO_> {
    std::string endpoint;

    /**
     * @brief Populate @p response with a valid `101 Switching Protocols`
     *        reply for a well-formed RFC 6455 upgrade request.
     * @return true when the handshake is valid.
     *
     * Enforces:
     *   - HTTP method is `GET` (RFC §4.2.1/1);
     *   - presence of `Sec-WebSocket-Key` (RFC §4.2.1/5);
     *   - presence of `Sec-WebSocket-Version` with value `13` (MUST).
     */
    template <typename HttpRequest, typename HttpResponse>
    static bool
    populate_handshake_response(HttpRequest const &request,
                                HttpResponse      &response) {
        if (request.method() != HTTP_GET)
            return false;
        if (!request.upgrade)
            return false;
        if (!detail::iequal_ascii(request.header("Upgrade"), "websocket"))
            return false;
        if (!detail::has_token_ci(request.header("Connection"), "Upgrade"))
            return false;

        const std::string_view ws_key_raw  =
            detail::trim_ows(request.header("Sec-WebSocket-Key"));
        const std::string_view version =
            detail::trim_ows(request.header("Sec-WebSocket-Version"));
        if (ws_key_raw.empty())
            return false;
        // RFC 6455 §4.2.1: client key is a base64 value of 16 random bytes.
        if (ws_key_raw.size() != 24u)
            return false;
        std::string decoded_key;
        try {
            decoded_key = crypto::base64::decode(std::string(ws_key_raw));
        } catch (...) {
            return false;
        }
        if (decoded_key.size() != 16u)
            return false;
        if (crypto::base64::encode(decoded_key) != ws_key_raw)
            return false;

        const std::string_view ws_key = ws_key_raw;
        if (!detail::iequal_ascii(version, "13"))
            return false;

        response.status() = qb::http::status::SWITCHING_PROTOCOLS;
        response.headers()["Upgrade"].emplace_back("websocket");
        response.headers()["Connection"].emplace_back("Upgrade");
        response.headers()["Sec-WebSocket-Accept"].emplace_back(
            detail::compute_accept_key(ws_key));
        return true;
    }

public:
    // server side event
    struct sending_http_response {
        qb::http::Response &response;
    };
    // !server side event

    using close   = ws_internal::event_close;
    using ping    = ws_internal::event_ping;
    using pong    = ws_internal::event_pong;
    using message = ws_internal::event_message;

    ws_server() = delete;
    template <typename HttpRequest>
    ws_server(IO_ &io, HttpRequest const &http)
        : ws_internal::base<IO_>(io) {
        qb::http::Response res;
        if (populate_handshake_response(http, res)) {
            if constexpr (qb::has_on<IO_, sending_http_response>) {
                this->_io.on(sending_http_response{res});
            }
            this->_io << res;
            endpoint = http.uri().path();
            return;
        }
        res.status() = qb::http::status::BAD_REQUEST;
        this->_io << res;
        this->not_ok();
    }

    template <typename HttpRequest, typename HttpResponse>
    ws_server(IO_ &io, HttpRequest const &request, HttpResponse &response)
        : ws_internal::base<IO_>(io) {
        if (populate_handshake_response(request, response)) {
            endpoint = request.uri().path();
            return;
        }
        response.status() = qb::http::status::BAD_REQUEST;
        this->not_ok();
    }
};

template <typename IO_>
class ws_client : public ws_internal::base<IO_> {

    /**
     * @brief Validate the server's 101 response against the client key.
     *
     * Per RFC 6455 §4.1, the client MUST verify:
     *   - HTTP status is `101 Switching Protocols`;
     *   - `Upgrade` header value case-insensitively matches `websocket`;
     *   - `Connection` header value contains `Upgrade` (case-insensitive,
     *     since the header may carry other tokens such as `keep-alive`);
     *   - `Sec-WebSocket-Accept` equals `base64(sha1(key + GUID))`.
     *
     * The final comparison is done in constant time to stay consistent with
     * the security guidelines used across the rest of the framework — even
     * though the accept key is not itself a secret, treating it like one
     * costs nothing and prevents surprises if the handshake is ever used
     * as an oracle.
     */
    template <typename HttpResponse>
    [[nodiscard]] static bool
    validate_handshake_response(HttpResponse const &http,
                                std::string const  &key) noexcept {
        if (!http.upgrade)
            return false;
        if (http.status() != qb::http::status::SWITCHING_PROTOCOLS)
            return false;
        if (!detail::iequal_ascii(http.header("Upgrade"), "websocket"))
            return false;
        if (!detail::has_token_ci(http.header("Connection"), "Upgrade"))
            return false;

        const std::string_view res_key =
            detail::trim_ows(http.header("Sec-WebSocket-Accept"));
        if (res_key.empty())
            return false;

        std::string expected = detail::compute_accept_key(key);
        return detail::constant_time_equal(res_key, expected);
    }

public:
    using close   = ws_internal::event_close;
    using ping    = ws_internal::event_ping;
    using pong    = ws_internal::event_pong;
    using message = ws_internal::event_message;

    ws_client() = delete;
    template <typename HttpResponse>
    ws_client(IO_ &io, HttpResponse const &http, std::string const &key)
        : ws_internal::base<IO_>(io) {
        if (!validate_handshake_response(http, key)) {
            this->not_ok();
        }
    }
};

} // namespace qb::protocol

namespace qb::http::ws {

namespace internal {

template <typename IO_, bool has_server = IO_::has_server>
struct side {
    using protocol = ::qb::protocol::ws_server<IO_>;
};

template <typename IO_>
struct side<IO_, false> {
    using protocol = ::qb::protocol::ws_client<IO_>;
};

} // namespace internal

template <typename IO_>
using protocol = typename internal::side<IO_>::protocol;


/**
 * @class WebSocket
 * @brief WebSocket client implementation
 *
 * This class provides a complete implementation of a WebSocket client
 * according to RFC 6455. It handles:
 * - Connection establishment and handshake
 * - Message sending and receiving (text and binary)
 * - Control frames (ping/pong for keepalive)
 * - Connection management and cleanup
 * - Event-based callbacks for WebSocket events
 *
 * @tparam T Parent class type that will receive event notifications
 * @tparam Transport Transport layer implementation (TCP by default or secure TCP)
 */
template <typename T, typename Transport = ::qb::io::transport::tcp>
class WebSocket
    : public ::qb::io::async::tcp::client<WebSocket<T, Transport>, Transport>
    , public ::qb::io::use<WebSocket<T, Transport>>::timeout {
    const std::string _ws_key;        /**< WebSocket handshake key */
    int               _ping_interval; /**< Interval for sending ping frames (in ms) */
    ::qb::io::uri     _remote;        /**< Remote server URI */

    /// Ordered list of subprotocols the client wishes to negotiate
    /// (advertised as `Sec-WebSocket-Protocol` in the upgrade request).
    std::vector<std::string> _offered_subprotocols;
    /// Value selected by the server (taken verbatim from
    /// `Sec-WebSocket-Protocol` in the `101` response, or empty when the
    /// server did not advertise any). Populated in `on(http_response)`.
    std::string _negotiated_subprotocol;
    bool _close_sent{false};

private:
    T& derived() noexcept { return *static_cast<T*>(this); }
    const T& derived() const noexcept { return *static_cast<const T*>(this); }

    /// Trim ASCII whitespace from both ends of @p sv (RFC 7230 OWS).
    [[nodiscard]] static std::string_view
    trim_ows(std::string_view sv) noexcept {
        constexpr std::string_view kOws = " \t";
        const auto first = sv.find_first_not_of(kOws);
        if (first == std::string_view::npos)
            return {};
        const auto last = sv.find_last_not_of(kOws);
        return sv.substr(first, last - first + 1);
    }

    /// Build a RFC-compatible Host header value from a URI.
    /// - Keep default ports implicit (80 for ws/http, 443 for wss/https).
    /// - Bracket IPv6 literals when needed.
    [[nodiscard]] static std::string
    make_host_header_value(::qb::io::uri const &uri) {
        std::string host = std::string(uri.host());
        const bool already_bracketed_ipv6 =
            host.size() >= 2 && host.front() == '[' && host.back() == ']';
        if (!already_bracketed_ipv6 && host.find(':') != std::string::npos) {
            host = "[" + host + "]";
        }

        const std::string_view port = uri.port();
        if (port.empty()) {
            return host;
        }

        const std::string_view scheme = uri.scheme();
        const bool is_default_ws_port =
            ((scheme == "ws" || scheme == "http") && port == "80");
        const bool is_default_wss_port =
            ((scheme == "wss" || scheme == "https") && port == "443");
        if (!is_default_ws_port && !is_default_wss_port) {
            host += ":";
            host += port;
        }
        return host;
    }

public:
    using http_protocol = http::protocol<WebSocket<T, Transport>>;
    using ws_protocol   = http::ws::protocol<WebSocket<T, Transport>>;

    // public events
    /**
     * @struct sending_http_request
     * @brief Event triggered when a WebSocket handshake request is being sent
     */
    struct sending_http_request {
        http::WebSocketRequest
            &request; /**< Reference to the WebSocket handshake request */
    };

    /**
     * @struct connected
     * @brief Event triggered when WebSocket connection is established
     */
    struct connected {};

    /**
     * @struct error
     * @brief Event triggered when a WebSocket error occurs
     */
    struct error {};

    using closed  = typename ws_protocol::close;   /**< Connection closed event */
    using ping    = typename ws_protocol::ping;    /**< Ping message received event */
    using pong    = typename ws_protocol::pong;    /**< Pong message received event */
    using message = typename ws_protocol::message; /**< Data message received event */
    using disconnected = ::qb::io::async::event::disconnected; /**< TCP disconnection event */
    using timeout      = ::qb::io::async::event::timeout;      /**< Timeout event for pings */

public:
    /**
     * @brief Constructs a WebSocket client
     *
     * Initializes the WebSocket client with a randomly generated key
     * for the WebSocket handshake.
     */
    explicit WebSocket()
        : _ws_key(http::ws::generateKey())
        , _ping_interval(0)
        {}

    /**
     * @brief Sets the ping interval for keepalive.
     * @param ping_interval Interval in milliseconds (0 to disable pings).
     *
     * Configures automatic ping/pong keepalive mechanism.
     * A value of 0 disables automatic pings.
     */
    void
    set_ping_interval(int ping_interval = 0) {
        _ping_interval = ping_interval;
        this->setTimeout(ping_interval);
    }

    /**
     * @brief Chrono-friendly overload of `set_ping_interval`.
     *
     * Accepts any duration; values under one millisecond disable keepalive.
     */
    template <typename Rep, typename Period>
    void
    set_ping_interval(std::chrono::duration<Rep, Period> ping_interval) {
        const auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(ping_interval)
                .count();
        set_ping_interval(ms <= 0 ? 0 : static_cast<int>(ms));
    }

    /**
     * @brief Send a Close frame with an explicit status + reason.
     *
     * Convenience over building a `MessageClose` by hand. The frame is queued
     * on the outbound pipe and will be flushed on the next I/O tick; call
     * `disconnect()` afterwards if you want to tear the TCP stream down
     * immediately (otherwise RFC 6455 §5.5.1 prescribes waiting for the
     * peer's Close echo).
     *
     * @throws std::invalid_argument when @p status is a reserved code.
     */
    void
    close(CloseStatus status = CloseStatus::Normal,
          std::string_view reason = "closed normally") {
        MessageClose msg(status, reason);
        _close_sent = true;
        *this << msg;
    }

    // -------------------------------------------------------------------
    // Subprotocol negotiation (RFC 6455 §1.9 / §4.1 / §4.2.2)
    // -------------------------------------------------------------------

    /**
     * @brief Set the list of subprotocols offered to the server.
     *
     * The values are serialised verbatim as a comma-separated
     * `Sec-WebSocket-Protocol` header on the upgrade request. The server
     * MUST either pick exactly one of them (case-sensitive match) or drop
     * the header entirely — the final choice is available via
     * `negotiated_subprotocol()` after `on(connected)` fires.
     *
     * Must be called before `connect()`.
     */
    void
    set_subprotocols(std::vector<std::string> protocols) {
        for (const auto &protocol : protocols) {
            if (!::qb::protocol::detail::is_valid_token(protocol)) {
                throw std::invalid_argument(
                    "qb::http::ws::WebSocket::set_subprotocols: invalid subprotocol token");
            }
        }
        _offered_subprotocols = std::move(protocols);
    }

    /**
     * @brief Append a single subprotocol to the list offered on the next
     *        handshake. See `set_subprotocols()`.
     */
    void
    add_subprotocol(std::string protocol) {
        if (!::qb::protocol::detail::is_valid_token(protocol)) {
            throw std::invalid_argument(
                "qb::http::ws::WebSocket::add_subprotocol: invalid subprotocol token");
        }
        _offered_subprotocols.emplace_back(std::move(protocol));
    }

    /**
     * @brief The subprotocol the server picked (empty when none was
     *        negotiated). Valid after the `connected` event has fired.
     */
    [[nodiscard]] std::string_view
    negotiated_subprotocol() const noexcept {
        return _negotiated_subprotocol;
    }

    /**
     * @brief Connects to a WebSocket server
     * @param remote URI of the remote WebSocket endpoint
     * @param timeout Connection timeout in milliseconds (0 for no timeout)
     *
     * Initiates a connection to the specified WebSocket server.
     * The connection process includes establishing a TCP connection and
     * performing the WebSocket handshake.
     */
    void
    connect(::qb::io::uri const &remote, int timeout = 0, bool verify_peer = true) {
        this->clear_protocols();
        this->setTimeout(0);
        _remote                 = remote;
        _negotiated_subprotocol.clear();
        _close_sent             = false;
        ::qb::io::async::tcp::connect<typename Transport::transport_io_type>(
            remote,
            [this](auto &&transport) {
                if (!transport.is_open()) {
                    if constexpr (qb::has_on<T, error>) {
                        derived().on(error{});
                    }
                } else {
                    this->transport() = std::move(transport);
                    this->template switch_protocol<http_protocol>(*this);
                    this->start();

                    http::WebSocketRequest request(_ws_key);
                    request.headers()["host"].emplace_back(make_host_header_value(_remote));
                    request.uri() = _remote;

                    if (!_offered_subprotocols.empty()) {
                        std::string joined;
                        for (std::size_t i = 0; i < _offered_subprotocols.size();
                             ++i) {
                            if (i) joined.append(", ");
                            joined.append(_offered_subprotocols[i]);
                        }
                        request.headers()["Sec-WebSocket-Protocol"].emplace_back(
                            std::move(joined));
                    }

                    if constexpr (qb::has_on<T, sending_http_request>) {
                        derived().on(sending_http_request{request});
                    }

                    *this << request;
                }
            },
            timeout,
            verify_peer);
    }

    /**
     * @brief Chrono-friendly overload of `connect()`.
     *
     * Accepts any `std::chrono::duration`; values under one millisecond
     * disable the connection timeout (same convention as
     * `set_ping_interval`).
     */
    template <typename Rep, typename Period>
    void
    connect(::qb::io::uri const                  &remote,
            std::chrono::duration<Rep, Period>   timeout,
            bool                                 verify_peer = true) {
        const auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count();
        connect(remote, ms <= 0 ? 0 : static_cast<int>(ms), verify_peer);
    }

    /**
     * @brief Handles HTTP response events during handshake
     * @param event HTTP response event from the server
     *
     * Processes the HTTP response during the WebSocket handshake.
     * Validates the response and switches to the WebSocket protocol
     * if the handshake was successful.
     */
    void
    on(typename http_protocol::response &&event) {
        if (!this->template switch_protocol<ws_protocol>(*this, event, _ws_key)) {
            if constexpr (qb::has_on<T, error>) {
                derived().on(error{});
            }
            this->disconnect();
            return;
        }

        // Capture the negotiated subprotocol (RFC 6455 §4.2.2 — the
        // server MUST echo exactly one of the client's offers, or omit
        // the header). We trim OWS and take the first token to be
        // defensive against servers that misuse list syntax.
        const std::string_view selected =
            trim_ows(event.header("Sec-WebSocket-Protocol"));
        if (!selected.empty()) {
            const auto comma = selected.find(',');
            const std::string_view selected_token =
                trim_ows(selected.substr(0, comma));
            const bool has_multiple_tokens = (comma != std::string_view::npos);

            // RFC 6455 §4.2.2: server must return exactly one subprotocol and it
            // must be one the client actually offered.
            if (has_multiple_tokens || _offered_subprotocols.empty()) {
                if constexpr (qb::has_on<T, error>) {
                    derived().on(error{});
                }
                this->disconnect();
                return;
            }

            const bool was_offered =
                std::any_of(_offered_subprotocols.begin(),
                            _offered_subprotocols.end(),
                            [&](const std::string &offered) {
                                return offered == selected_token;
                            });
            if (!was_offered) {
                if constexpr (qb::has_on<T, error>) {
                    derived().on(error{});
                }
                this->disconnect();
                return;
            }

            _negotiated_subprotocol.assign(selected_token);
        }

        if constexpr (qb::has_on<T, connected>) {
            derived().on(connected{});
        }
        this->setTimeout(_ping_interval);
    }

    /**
     * @brief Handles ping events
     * @param event Ping event containing the ping payload
     *
     * Forwards ping events to the parent class if it has a handler.
     */
    void
    on(ping &&event) {
        if constexpr (qb::has_on<T, ping>) {
            derived().on(std::forward<ping>(event));
        }
    }

    /**
     * @brief Handles pong events
     * @param event Pong event containing the pong payload
     *
     * Forwards pong events to the parent class if it has a handler.
     */
    void
    on(pong &&event) {
        if constexpr (qb::has_on<T, pong>) {
            derived().on(std::forward<pong>(event));
        }
    }

    /**
     * @brief Handles message events
     * @param event Message event containing the data payload
     *
     * Forwards WebSocket message events to the parent class.
     */
    void
    on(message &&event) {
        derived().on(std::forward<message>(event));
    }

    /**
     * @brief Handles close events
     * @param event Close event containing the status code and reason
     *
     * Forwards WebSocket close events to the parent class if it has a handler.
     */
    void
    on(closed &&event) {
        if (!_close_sent) {
            Message echo = event.ws;
            _close_sent = true;
            *this << echo;
        }
        if constexpr (qb::has_on<T, closed>) {
            derived().on(std::forward<closed>(event));
        }
    }

    /**
     * @brief Handles disconnection events
     * @param event Disconnection event
     *
     * Forwards TCP disconnection events to the parent class.
     */
    void
    on(disconnected &&event) {
        _close_sent = false;
        derived().on(std::forward<disconnected>(event));
    }

    /**
     * @brief Handles timeout events
     * @param event Timeout event
     *
     * Sends a ping message when a timeout occurs and resets the timer.
     * This is used for the ping/pong keepalive mechanism.
     */
    void
    on(timeout const &) {
        MessagePing msg;
        *this << msg;
        this->setTimeout(_ping_interval);
    }

    /**
     * @brief Sends a message to the WebSocket server
     * @tparam ToSend Type of the message to send
     * @param msg Message to send
     * @return Reference to this object for method chaining
     */
    template <typename ToSend>
    WebSocket &operator<<(ToSend &&msg) {
        if constexpr (std::is_base_of_v<Message, std::decay_t<ToSend>>) {
            if constexpr (std::is_same_v<std::decay_t<ToSend>, MessageClose>) {
                _close_sent = true;
            }
            // RFC 6455 §5.1: all client->server frames (including control) MUST be masked.
            std::decay_t<ToSend> outbound(std::forward<ToSend>(msg));
            outbound.masked = true;
            ::qb::io::async::tcp::client<WebSocket<T, Transport>, Transport>::operator<<(std::move(outbound));
            return *this;
        }
        ::qb::io::async::tcp::client<WebSocket<T, Transport>, Transport>::operator<<(std::forward<ToSend>(msg));
        return *this;
    }
};

/**
 * @typedef WebSocketSecure
 * @brief Secure WebSocket client using TLS/SSL
 *
 * A specialized version of the WebSocket client that uses secure
 * transport (TLS/SSL) for encrypted connections.
 */
template <typename T>
using WebSocketSecure = WebSocket<T, ::qb::io::transport::stcp>;

/**
 * @class Client
 * @brief WebSocket client implementation using callbacks
 *
 * This class provides a WebSocket client that uses callback functions
 * instead of inheritance for handling WebSocket events. It inherits from
 * WebSocket internally but exposes a callback-based interface.
 *
 * @tparam Transport Transport layer implementation (TCP by default or secure TCP)
 */
template <typename Transport = ::qb::io::transport::tcp>
class Client : public WebSocket<Client<Transport>, Transport> {
public:
    using base_type = WebSocket<Client<Transport>, Transport>;

    // Callback types for each event
    using sending_http_request_callback_t = std::function<void(typename base_type::sending_http_request&)>;
    using connected_callback_t = std::function<void(typename base_type::connected&)>;
    using error_callback_t = std::function<void(typename base_type::error&)>;
    using closed_callback_t = std::function<void(typename base_type::closed&)>;
    using ping_callback_t = std::function<void(typename base_type::ping&)>;
    using pong_callback_t = std::function<void(typename base_type::pong&)>;
    using message_callback_t = std::function<void(typename base_type::message&)>;
    using disconnected_callback_t = std::function<void(typename base_type::disconnected&)>;

private:
    sending_http_request_callback_t _on_sending_http_request;
    connected_callback_t _on_connected;
    error_callback_t _on_error;
    closed_callback_t _on_closed;
    ping_callback_t _on_ping;
    pong_callback_t _on_pong;
    message_callback_t _on_message;
    disconnected_callback_t _on_disconnected;

public:
    /**
     * @brief Constructs a WebSocket client with callback-based event handling
     */
    Client() : base_type() {}

    /**
     * @brief Set callback for HTTP request sending event
     * @param callback Function to call when sending HTTP request
     * @return Reference to this object for method chaining
     */
    Client& on_sending_http_request(sending_http_request_callback_t callback) {
        _on_sending_http_request = std::move(callback);
        return *this;
    }

    /**
     * @brief Set callback for connection established event
     * @param callback Function to call when connection is established
     * @return Reference to this object for method chaining
     */
    Client& on_connected(connected_callback_t callback) {
        _on_connected = std::move(callback);
        return *this;
    }

    /**
     * @brief Set callback for error event
     * @param callback Function to call when an error occurs
     * @return Reference to this object for method chaining
     */
    Client& on_error(error_callback_t callback) {
        _on_error = std::move(callback);
        return *this;
    }

    /**
     * @brief Set callback for connection closed event
     * @param callback Function to call when connection is closed
     * @return Reference to this object for method chaining
     */
    Client& on_closed(closed_callback_t callback) {
        _on_closed = std::move(callback);
        return *this;
    }

    /**
     * @brief Set callback for ping message event
     * @param callback Function to call when ping is received
     * @return Reference to this object for method chaining
     */
    Client& on_ping(ping_callback_t callback) {
        _on_ping = std::move(callback);
        return *this;
    }

    /**
     * @brief Set callback for pong message event
     * @param callback Function to call when pong is received
     * @return Reference to this object for method chaining
     */
    Client& on_pong(pong_callback_t callback) {
        _on_pong = std::move(callback);
        return *this;
    }

    /**
     * @brief Set callback for data message event
     * @param callback Function to call when a message is received
     * @return Reference to this object for method chaining
     */
    Client& on_message(message_callback_t callback) {
        _on_message = std::move(callback);
        return *this;
    }

    /**
     * @brief Set callback for disconnection event
     * @param callback Function to call when disconnected
     * @return Reference to this object for method chaining
     */
    Client& on_disconnected(disconnected_callback_t callback) {
        _on_disconnected = std::move(callback);
        return *this;
    }

    // Event handlers that delegate to callbacks
    void on(typename base_type::sending_http_request&& event) {
        if (_on_sending_http_request) {
            _on_sending_http_request(event);
        }
    }

    void on(typename base_type::connected&& event) {
        if (_on_connected) {
            _on_connected(event);
        }
    }

    void on(typename base_type::error&& event) {
        if (_on_error) {
            _on_error(event);
        }
    }

    void on(typename base_type::closed&& event) {
        if (_on_closed) {
            _on_closed(event);
        }
    }

    void on(typename base_type::ping&& event) {
        if (_on_ping) {
            _on_ping(event);
        }
    }

    void on(typename base_type::pong&& event) {
        if (_on_pong) {
            _on_pong(event);
        }
    }

    void on(typename base_type::message&& event) {
        if (_on_message) {
            _on_message(event);
        }
    }

    void on(typename base_type::disconnected&& event) {
        if (_on_disconnected) {
            _on_disconnected(event);
        }
    }
};

/**
 * @typedef ClientSecure
 * @brief Secure WebSocket client using callbacks and TLS/SSL
 *
 * A specialized version of the Client that uses secure
 * transport (TLS/SSL) for encrypted connections.
 */
using ClientSecure = Client<::qb::io::transport::stcp>;

using client = Client<::qb::io::transport::tcp>;
using client_secure = Client<::qb::io::transport::stcp>;

} // namespace qb::http::ws

namespace qb::allocator {

template <>
pipe<char> &pipe<char>::put<http::ws::Message>(const http::ws::Message &msg);

template <>
pipe<char> &pipe<char>::put<http::ws::MessagePing>(const http::ws::MessagePing &msg);

template <>
pipe<char> &pipe<char>::put<http::ws::MessagePong>(const http::ws::MessagePong &msg);

template <>
pipe<char> &pipe<char>::put<http::ws::MessageText>(const http::ws::MessageText &msg);

template <>
pipe<char> &pipe<char>::put<http::ws::MessageBinary>(const http::ws::MessageBinary &msg);

template <>
pipe<char> &pipe<char>::put<http::ws::MessageClose>(const http::ws::MessageClose &msg);

template <>
pipe<char> &pipe<char>::put<http::WebSocketRequest>(const http::WebSocketRequest &msg);

} // namespace qb::allocator
