/**
 * @file qbm/http/2/protocol/frames.h
 * @brief HTTP/2 frame definitions and structures
 *
 * This file provides comprehensive definitions for HTTP/2 frames as specified in RFC 9113,
 * including frame types, flags, error codes, and concrete frame structures. It serves as
 * the foundation for HTTP/2 protocol implementation in the qb-io framework.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup HTTP2
 */

#pragma once

#include <cstdint>
#include <vector>
#include <string_view>
#include <array>
#include <optional>

namespace qb::protocol::http2 {

/**
 * @brief HTTP/2 frame types as defined in RFC 9113 Section 6
 */
enum class FrameType : uint8_t {
    DATA          = 0x0,  ///< DATA frame (Section 6.1)
    HEADERS       = 0x1,  ///< HEADERS frame (Section 6.2)
    PRIORITY      = 0x2,  ///< PRIORITY frame (Section 6.3)
    RST_STREAM    = 0x3,  ///< RST_STREAM frame (Section 6.4)
    SETTINGS      = 0x4,  ///< SETTINGS frame (Section 6.5)
    PUSH_PROMISE  = 0x5,  ///< PUSH_PROMISE frame (Section 6.6)
    PING          = 0x6,  ///< PING frame (Section 6.7)
    GOAWAY        = 0x7,  ///< GOAWAY frame (Section 6.8)
    WINDOW_UPDATE = 0x8,  ///< WINDOW_UPDATE frame (Section 6.9)
    CONTINUATION  = 0x9,  ///< CONTINUATION frame (Section 6.10)
    UNKNOWN       = 0xFF  ///< Unknown frame type (internal use)
};

/**
 * @brief HTTP/2 frame flags
 * @{
 */
constexpr uint8_t FLAG_END_STREAM  = 0x1;  ///< END_STREAM flag (DATA, HEADERS)
constexpr uint8_t FLAG_ACK         = 0x1;  ///< ACK flag (SETTINGS, PING)
constexpr uint8_t FLAG_END_HEADERS = 0x4;  ///< END_HEADERS flag (HEADERS, CONTINUATION)
constexpr uint8_t FLAG_PADDED      = 0x8;  ///< PADDED flag (DATA, HEADERS)
constexpr uint8_t FLAG_PRIORITY    = 0x20; ///< PRIORITY flag (HEADERS)
/** @} */

/**
 * @brief HTTP/2 error codes as defined in RFC 9113 Section 7
 */
enum class ErrorCode : uint32_t {
    NO_ERROR            = 0x0,  ///< Graceful shutdown
    PROTOCOL_ERROR      = 0x1,  ///< Protocol error detected
    INTERNAL_ERROR      = 0x2,  ///< Implementation fault
    FLOW_CONTROL_ERROR  = 0x3,  ///< Flow control limits exceeded
    SETTINGS_TIMEOUT    = 0x4,  ///< Settings not acknowledged
    STREAM_CLOSED       = 0x5,  ///< Frame received for closed stream
    FRAME_SIZE_ERROR    = 0x6,  ///< Frame size incorrect
    REFUSED_STREAM      = 0x7,  ///< Stream not processed
    CANCEL              = 0x8,  ///< Stream cancelled
    COMPRESSION_ERROR   = 0x9,  ///< Compression state not updated
    CONNECT_ERROR       = 0xA,  ///< TCP connection error for CONNECT method
    ENHANCE_YOUR_CALM   = 0xB,  ///< Processing capacity exceeded
    INADEQUATE_SECURITY = 0xC,  ///< Negotiated TLS parameters not acceptable
    HTTP_1_1_REQUIRED   = 0xD   ///< Use HTTP/1.1 for the request
};

/**
 * @brief HTTP/2 setting identifiers as defined in RFC 9113 Section 6.5.2
 */
enum class Http2SettingIdentifier : uint16_t {
    SETTINGS_HEADER_TABLE_SIZE      = 0x1,  ///< Header compression table size
    SETTINGS_ENABLE_PUSH            = 0x2,  ///< Server push enabled flag
    SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,  ///< Maximum concurrent streams
    SETTINGS_INITIAL_WINDOW_SIZE    = 0x4,  ///< Initial flow control window size
    SETTINGS_MAX_FRAME_SIZE         = 0x5,  ///< Maximum frame payload size
    SETTINGS_MAX_HEADER_LIST_SIZE   = 0x6,  ///< Maximum header list size
    SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x8  ///< Extended CONNECT protocol (RFC 8441)
};

/**
 * @brief Default settings values as defined in RFC 9113
 * @{
 */
constexpr uint32_t DEFAULT_SETTINGS_HEADER_TABLE_SIZE = 4096;
constexpr uint32_t DEFAULT_SETTINGS_ENABLE_PUSH_SERVER = 1;
constexpr uint32_t DEFAULT_SETTINGS_ENABLE_PUSH_CLIENT = 0;
constexpr uint32_t DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS = 0xFFFFFFFF;
constexpr uint32_t DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE = 65535;
constexpr uint32_t DEFAULT_SETTINGS_MAX_FRAME_SIZE = 16384;
constexpr uint32_t DEFAULT_MAX_FRAME_SIZE = 16384;
constexpr uint32_t MIN_MAX_FRAME_SIZE = 16384;
constexpr uint32_t MAX_FRAME_SIZE_LIMIT = 16777215;  // 2^24 - 1
constexpr uint32_t MAX_WINDOW_SIZE_LIMIT = 2147483647U;  // 2^31 - 1
constexpr uint32_t DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE = 0xFFFFFFFF;
/** @} */

/**
 * @brief HTTP/2 frame header structure (9 octets)
 * 
 * The frame header is transmitted as a fixed 9-octet sequence:
 * - Length (24 bits): The length of the frame payload
 * - Type (8 bits): The frame type
 * - Flags (8 bits): Type-specific boolean flags
 * - R (1 bit): Reserved bit (must be 0)
 * - Stream ID (31 bits): Stream identifier
 */
#pragma pack(push, 1)
struct FrameHeader {
    std::array<uint8_t, 3> length_bytes;     ///< 24-bit payload length in network byte order
    uint8_t type;                            ///< Frame type
    uint8_t flags;                           ///< Frame flags
    std::array<uint8_t, 4> stream_id_bytes;  ///< 31-bit stream ID + 1 reserved bit

    /**
     * @brief Get the payload length from the header
     * @return The payload length (0 to 2^24-1)
     */
    [[nodiscard]] uint32_t get_payload_length() const noexcept {
        return (static_cast<uint32_t>(length_bytes[0]) << 16) |
               (static_cast<uint32_t>(length_bytes[1]) << 8)  |
               (static_cast<uint32_t>(length_bytes[2]));
    }

    /**
     * @brief Set the payload length in the header
     * @param len The payload length (must be <= MAX_FRAME_SIZE_LIMIT)
     */
    void set_payload_length(uint32_t len) noexcept {
        length_bytes[0] = static_cast<uint8_t>((len >> 16) & 0xFF);
        length_bytes[1] = static_cast<uint8_t>((len >> 8) & 0xFF);
        length_bytes[2] = static_cast<uint8_t>(len & 0xFF);
    }

    /**
     * @brief Get the frame type
     * @return The frame type as an enum
     */
    [[nodiscard]] FrameType get_type() const noexcept {
        return static_cast<FrameType>(type);
    }

    /**
     * @brief Get the stream identifier
     * @return The 31-bit stream ID (reserved bit is masked out)
     */
    [[nodiscard]] uint32_t get_stream_id() const noexcept {
        return (static_cast<uint32_t>(stream_id_bytes[0] & 0x7F) << 24) |
               (static_cast<uint32_t>(stream_id_bytes[1]) << 16) |
               (static_cast<uint32_t>(stream_id_bytes[2]) << 8)  |
               (static_cast<uint32_t>(stream_id_bytes[3]));
    }

    /**
     * @brief Set the stream identifier
     * @param id The 31-bit stream ID (reserved bit will be cleared)
     */
    void set_stream_id(uint32_t id) noexcept {
        stream_id_bytes[0] = static_cast<uint8_t>(((id >> 24) & 0xFF) & 0x7F);
        stream_id_bytes[1] = static_cast<uint8_t>((id >> 16) & 0xFF);
        stream_id_bytes[2] = static_cast<uint8_t>((id >> 8) & 0xFF);
        stream_id_bytes[3] = static_cast<uint8_t>(id & 0xFF);
    }
};
#pragma pack(pop)

constexpr std::size_t FRAME_HEADER_SIZE = sizeof(FrameHeader);  ///< Frame header size (9 octets)

/**
 * @brief Priority information for stream dependency
 */
struct Http2PriorityData {
    uint32_t stream_dependency;   ///< Stream dependency ID
    uint8_t weight;              ///< Priority weight (1-256)
    bool exclusive_dependency;   ///< Exclusive flag for dependency
};

/**
 * @brief DATA frame payload structure
 * 
 * DATA frames convey arbitrary, variable-length sequences of octets
 * associated with a stream.
 */
struct DataFrame {
    std::vector<uint8_t> data_payload;  ///< Application data
};

/**
 * @brief HEADERS frame payload structure
 * 
 * HEADERS frames open a stream and carry header block fragments.
 */
struct HeadersFrame {
    std::vector<uint8_t> header_block_fragment;    ///< HPACK-encoded header data
    std::optional<Http2PriorityData> priority_info; ///< Priority information (if FLAG_PRIORITY set)
};

/**
 * @brief PRIORITY frame payload structure
 * 
 * PRIORITY frames specify the sender-advised priority of a stream.
 */
struct PriorityFrame {
    Http2PriorityData priority_data;  ///< Priority information
};

/**
 * @brief RST_STREAM frame payload structure
 * 
 * RST_STREAM frames allow for immediate termination of a stream.
 */
struct RstStreamFrame {
    ErrorCode error_code;  ///< Error code indicating why the stream is being terminated
};

/**
 * @brief Single SETTINGS parameter
 */
struct SettingsFrameEntry {
    Http2SettingIdentifier identifier;  ///< Setting identifier
    uint32_t value;                    ///< Setting value
};

/**
 * @brief SETTINGS frame payload structure
 * 
 * SETTINGS frames convey configuration parameters that affect how
 * endpoints communicate.
 */
struct SettingsFrame {
    std::vector<SettingsFrameEntry> entries;  ///< List of settings
};

/**
 * @brief PUSH_PROMISE frame payload structure
 * 
 * PUSH_PROMISE frames are used to notify the peer endpoint in advance
 * of streams the sender intends to initiate.
 */
struct PushPromiseFrame {
    uint32_t promised_stream_id;                   ///< Promised stream identifier
    std::vector<uint8_t> header_block_fragment;    ///< HPACK-encoded header data
};

/**
 * @brief PING frame payload structure
 * 
 * PING frames are used to measure round-trip time and check connection liveness.
 */
struct PingFrame {
    std::array<uint8_t, 8> opaque_data;  ///< Opaque data (echoed in response)
};

/**
 * @brief GOAWAY frame payload structure
 * 
 * GOAWAY frames inform the remote peer to stop creating streams on this connection.
 */
struct GoAwayFrame {
    uint32_t last_stream_id;                    ///< Last peer-initiated stream ID
    ErrorCode error_code;                       ///< Error code
    std::vector<uint8_t> additional_debug_data; ///< Additional debug information
};

/**
 * @brief WINDOW_UPDATE frame payload structure
 * 
 * WINDOW_UPDATE frames are used to implement flow control.
 */
struct WindowUpdateFrame {
    uint32_t window_size_increment;  ///< Window size increment (1 to 2^31-1)
};

/**
 * @brief CONTINUATION frame payload structure
 * 
 * CONTINUATION frames are used to continue a sequence of header block fragments.
 */
struct ContinuationFrame {
    std::vector<uint8_t> header_block_fragment;  ///< Continuation of header block
};

/**
 * @brief Generic frame data structure for typed dispatch and serialization
 * @tparam PayloadType The specific frame payload type
 */
template<typename PayloadType>
struct Http2FrameData {
    FrameHeader header;   ///< Frame header
    PayloadType payload;  ///< Frame payload
};

/**
 * @brief Event dispatched when the HTTP/2 connection preface is successfully received
 */
struct PrefaceCompleteEvent {};

/**
 * @brief Reasons why a PUSH_PROMISE might not be sent by the server.
 */
enum class PushPromiseFailureReason {
    NONE,                             ///< Placeholder, should not be returned if actually failed. Success indicated differently.
    PEER_PUSH_DISABLED,               ///< Client has SETTINGS_ENABLE_PUSH set to 0.
    PEER_CONCURRENCY_LIMIT_REACHED,   ///< Sending would exceed client's MAX_CONCURRENT_STREAMS.
    INVALID_ASSOCIATED_STREAM,        ///< The client-initiated stream for association is invalid or in wrong state.
    INTERNAL_HPACK_ERROR,             ///< HPACK encoding failed for push promise headers.
    CONNECTION_INACTIVE,              ///< Connection is not active or protocol is not ok.
    INTERNAL_ERROR                    ///< An internal server error prevented sending the push promise.
    // Add other specific reasons as needed
};

} // namespace qb::protocol::http2 