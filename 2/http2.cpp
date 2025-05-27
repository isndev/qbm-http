/**
 * @file qbm/http/2/http2.cpp
 * @brief HTTP/2 frame serialization implementation
 *
 * This file implements the serialization of HTTP/2 frames into byte streams
 * for transmission over the network. Each frame type has a specialized
 * template implementation that handles the specific payload structure and
 * encoding requirements according to RFC 7540.
 *
 * The implementations are template specializations of the qb::allocator::pipe
 * put method for each HTTP/2 frame type, enabling efficient serialization
 * directly into the output buffer.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http2
 */

#include "./http2.h"

namespace qb::http2 {
    template class Server<DefaultSession>;
} // namespace qb::protocol::http2

namespace qb::allocator {

    /**
     * @brief Serialize DATA frame to output pipe
     * 
     * DATA frames contain arbitrary variable-length sequences of octets
     * associated with a stream. One or more DATA frames are used to carry
     * HTTP request or response payloads.
     * 
     * @param frame_to_send DATA frame to serialize
     * @return Reference to this pipe for chaining
     */
    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::DataFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::DataFrame>& frame_to_send) {
        qb::protocol::http2::FrameHeader header = frame_to_send.header;
        const auto& payload_struct = frame_to_send.payload;
        
        header.set_payload_length(static_cast<uint32_t>(payload_struct.data_payload.size()));
        this->put(reinterpret_cast<const char*>(&header), qb::protocol::http2::FRAME_HEADER_SIZE);
        
        if (!payload_struct.data_payload.empty()) {
            this->put(reinterpret_cast<const char*>(payload_struct.data_payload.data()), 
                     payload_struct.data_payload.size());
        }
        return *this;
    }

    /**
     * @brief Serialize HEADERS frame to output pipe
     * 
     * HEADERS frames open a stream and carry header block fragments.
     * HEADERS frames can be sent on a stream in the "idle", "reserved (local)",
     * "open", or "half-closed (remote)" state.
     * 
     * @param frame_to_send HEADERS frame to serialize
     * @return Reference to this pipe for chaining
     */
    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::HeadersFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::HeadersFrame>& frame_to_send) {
        qb::protocol::http2::FrameHeader header = frame_to_send.header;
        const auto& payload_struct = frame_to_send.payload;
        
        header.set_payload_length(static_cast<uint32_t>(payload_struct.header_block_fragment.size()));
        this->put(reinterpret_cast<const char*>(&header), qb::protocol::http2::FRAME_HEADER_SIZE);
        
        if (!payload_struct.header_block_fragment.empty()) {
            this->put(reinterpret_cast<const char*>(payload_struct.header_block_fragment.data()), 
                     payload_struct.header_block_fragment.size());
        }
        return *this;
    }

    /**
     * @brief Serialize PRIORITY frame to output pipe
     * 
     * PRIORITY frames specify the sender-advised priority of a stream.
     * Contains stream dependency and weight information.
     * 
     * Frame format:
     * +-----------------------------------------------+
     * |E|                  Stream Dependency (31)     |
     * +-+-------------+-------------------------------+
     * |   Weight (8)  |
     * +-+-------------+
     * 
     * @param frame_to_send PRIORITY frame to serialize
     * @return Reference to this pipe for chaining
     */
    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::PriorityFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::PriorityFrame>& frame_to_send) {
        qb::protocol::http2::FrameHeader header = frame_to_send.header;
        const auto& payload_struct = frame_to_send.payload;
        std::array<uint8_t, 5> payload_bytes_arr;

        // Pack stream dependency with exclusive bit
        uint32_t stream_dep_val = payload_struct.priority_data.stream_dependency & 0x7FFFFFFF;
        if (payload_struct.priority_data.exclusive_dependency) {
            stream_dep_val |= (1U << 31);
        }
        
        // Serialize as big-endian
        payload_bytes_arr[0] = static_cast<uint8_t>((stream_dep_val >> 24) & 0xFF);
        payload_bytes_arr[1] = static_cast<uint8_t>((stream_dep_val >> 16) & 0xFF);
        payload_bytes_arr[2] = static_cast<uint8_t>((stream_dep_val >> 8) & 0xFF);
        payload_bytes_arr[3] = static_cast<uint8_t>(stream_dep_val & 0xFF);
        payload_bytes_arr[4] = payload_struct.priority_data.weight;
        
        header.set_payload_length(5);
        this->put(reinterpret_cast<const char*>(&header), qb::protocol::http2::FRAME_HEADER_SIZE);
        this->put(reinterpret_cast<const char*>(payload_bytes_arr.data()), payload_bytes_arr.size());
        return *this;
    }

    /**
     * @brief Serialize RST_STREAM frame to output pipe
     * 
     * RST_STREAM frames allow for immediate termination of a stream.
     * Contains a single 32-bit error code.
     * 
     * @param frame_to_send RST_STREAM frame to serialize
     * @return Reference to this pipe for chaining
     */
    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::RstStreamFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::RstStreamFrame>& frame_to_send) {
        qb::protocol::http2::FrameHeader header = frame_to_send.header;
        const auto& payload = frame_to_send.payload;
        std::array<uint8_t, 4> payload_bytes_arr;

        // Serialize error code as big-endian 32-bit
        uint32_t error_code_val = static_cast<uint32_t>(payload.error_code);
        payload_bytes_arr[0] = static_cast<uint8_t>((error_code_val >> 24) & 0xFF);
        payload_bytes_arr[1] = static_cast<uint8_t>((error_code_val >> 16) & 0xFF);
        payload_bytes_arr[2] = static_cast<uint8_t>((error_code_val >> 8) & 0xFF);
        payload_bytes_arr[3] = static_cast<uint8_t>(error_code_val & 0xFF);

        header.set_payload_length(4);
        this->put(reinterpret_cast<const char*>(&header), qb::protocol::http2::FRAME_HEADER_SIZE);
        this->put(reinterpret_cast<const char*>(payload_bytes_arr.data()), payload_bytes_arr.size());
        return *this;
    }

    /**
     * @brief Serialize SETTINGS frame to output pipe
     * 
     * SETTINGS frames convey configuration parameters that affect how
     * endpoints communicate. Each parameter is a 16-bit identifier followed
     * by a 32-bit value.
     * 
     * @param frame_to_send SETTINGS frame to serialize
     * @return Reference to this pipe for chaining
     */
    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::SettingsFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::SettingsFrame>& frame_to_send) {
        qb::protocol::http2::FrameHeader header = frame_to_send.header;
        const auto& payload_struct = frame_to_send.payload;
        std::vector<uint8_t> payload_bytes;

        // SETTINGS ACK has no payload
        if (!(header.flags & qb::protocol::http2::FLAG_ACK)) {
            payload_bytes.reserve(payload_struct.entries.size() * 6);
            
            for (const auto& entry : payload_struct.entries) {
                // 16-bit identifier (big-endian)
                uint16_t identifier_val = static_cast<uint16_t>(entry.identifier);
                payload_bytes.push_back(static_cast<uint8_t>((identifier_val >> 8) & 0xFF));
                payload_bytes.push_back(static_cast<uint8_t>(identifier_val & 0xFF));
                
                // 32-bit value (big-endian)
                payload_bytes.push_back(static_cast<uint8_t>((entry.value >> 24) & 0xFF));
                payload_bytes.push_back(static_cast<uint8_t>((entry.value >> 16) & 0xFF));
                payload_bytes.push_back(static_cast<uint8_t>((entry.value >> 8) & 0xFF));
                payload_bytes.push_back(static_cast<uint8_t>(entry.value & 0xFF));
            }
        } 
        
        header.set_payload_length(static_cast<uint32_t>(payload_bytes.size()));
        this->put(reinterpret_cast<const char*>(&header), qb::protocol::http2::FRAME_HEADER_SIZE);
        
        if (!payload_bytes.empty()) {
            this->put(reinterpret_cast<const char*>(payload_bytes.data()), payload_bytes.size());
        }
        return *this;
    }

    /**
     * @brief Serialize PUSH_PROMISE frame to output pipe
     * 
     * PUSH_PROMISE frames are used to notify the peer endpoint in advance
     * of streams the sender intends to initiate.
     * 
     * Frame format:
     * +-----------------------------------------------+
     * |R|                Promised Stream ID (31)      |
     * +-+---------------------------------------------+
     * |            Header Block Fragment (*)        ...
     * +-----------------------------------------------+
     * 
     * @param frame_to_send PUSH_PROMISE frame to serialize
     * @return Reference to this pipe for chaining
     */
    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::PushPromiseFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::PushPromiseFrame>& frame_to_send) {
        qb::protocol::http2::FrameHeader header = frame_to_send.header;
        const auto& payload_struct = frame_to_send.payload;
        std::vector<uint8_t> payload_bytes;
        
        // Reserved bit (R) must be unset
        uint32_t promised_id = payload_struct.promised_stream_id & 0x7FFFFFFF; 
        payload_bytes.push_back(static_cast<uint8_t>((promised_id >> 24) & 0xFF));
        payload_bytes.push_back(static_cast<uint8_t>((promised_id >> 16) & 0xFF));
        payload_bytes.push_back(static_cast<uint8_t>((promised_id >> 8) & 0xFF));
        payload_bytes.push_back(static_cast<uint8_t>(promised_id & 0xFF));
        
        // Append header block fragment
        payload_bytes.insert(payload_bytes.end(), 
                           payload_struct.header_block_fragment.begin(), 
                           payload_struct.header_block_fragment.end());
        
        // Note: PADDED flag handling would need to be implemented if supported
        
        header.set_payload_length(static_cast<uint32_t>(payload_bytes.size()));
        this->put(reinterpret_cast<const char*>(&header), qb::protocol::http2::FRAME_HEADER_SIZE);
        
        if (!payload_bytes.empty()) {
            this->put(reinterpret_cast<const char*>(payload_bytes.data()), payload_bytes.size());
        }
        return *this;
    }

    /**
     * @brief Serialize PING frame to output pipe
     * 
     * PING frames are used to measure round-trip time and check connection
     * liveness. Must contain exactly 8 octets of opaque data.
     * 
     * @param frame_to_send PING frame to serialize
     * @return Reference to this pipe for chaining
     */
    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::PingFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::PingFrame>& frame_to_send) {
        qb::protocol::http2::FrameHeader header = frame_to_send.header;
        const auto& payload = frame_to_send.payload;
        
        header.set_payload_length(static_cast<uint32_t>(payload.opaque_data.size())); // Must be 8
        this->put(reinterpret_cast<const char*>(&header), qb::protocol::http2::FRAME_HEADER_SIZE);
        this->put(reinterpret_cast<const char*>(payload.opaque_data.data()), payload.opaque_data.size());
        return *this;
    }

    /**
     * @brief Serialize GOAWAY frame to output pipe
     * 
     * GOAWAY frames inform the remote peer to stop creating streams on this
     * connection. Contains the last stream ID that will be processed and
     * an error code.
     * 
     * Frame format:
     * +-----------------------------------------------+
     * |R|                  Last-Stream-ID (31)        |
     * +-+---------------------------------------------+
     * |                   Error Code (32)             |
     * +-----------------------------------------------+
     * |              Additional Debug Data (*)        |
     * +-----------------------------------------------+
     * 
     * @param frame_to_send GOAWAY frame to serialize
     * @return Reference to this pipe for chaining
     */
    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::GoAwayFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::GoAwayFrame>& frame_to_send) {
        qb::protocol::http2::FrameHeader header = frame_to_send.header;
        const auto& payload = frame_to_send.payload;
        std::vector<uint8_t> payload_bytes;
        payload_bytes.reserve(8 + payload.additional_debug_data.size());

        // Last stream ID with reserved bit cleared
        uint32_t last_sid = payload.last_stream_id & 0x7FFFFFFF;
        payload_bytes.push_back(static_cast<uint8_t>((last_sid >> 24) & 0xFF));
        payload_bytes.push_back(static_cast<uint8_t>((last_sid >> 16) & 0xFF));
        payload_bytes.push_back(static_cast<uint8_t>((last_sid >> 8) & 0xFF));
        payload_bytes.push_back(static_cast<uint8_t>(last_sid & 0xFF));
        
        // Error code
        uint32_t error_code_val = static_cast<uint32_t>(payload.error_code);
        payload_bytes.push_back(static_cast<uint8_t>((error_code_val >> 24) & 0xFF));
        payload_bytes.push_back(static_cast<uint8_t>((error_code_val >> 16) & 0xFF));
        payload_bytes.push_back(static_cast<uint8_t>((error_code_val >> 8) & 0xFF));
        payload_bytes.push_back(static_cast<uint8_t>(error_code_val & 0xFF));
        
        // Optional debug data
        if (!payload.additional_debug_data.empty()) {
            payload_bytes.insert(payload_bytes.end(), 
                               payload.additional_debug_data.begin(), 
                               payload.additional_debug_data.end());
        }

        header.set_payload_length(static_cast<uint32_t>(payload_bytes.size()));
        this->put(reinterpret_cast<const char*>(&header), qb::protocol::http2::FRAME_HEADER_SIZE);
        
        if (!payload_bytes.empty()) { 
            this->put(reinterpret_cast<const char*>(payload_bytes.data()), payload_bytes.size());
        }
        return *this;
    }

    /**
     * @brief Serialize WINDOW_UPDATE frame to output pipe
     * 
     * WINDOW_UPDATE frames are used to implement flow control. The payload
     * contains a 32-bit unsigned integer indicating the number of octets
     * the sender can transmit in addition to the existing flow control window.
     * 
     * @param frame_to_send WINDOW_UPDATE frame to serialize
     * @return Reference to this pipe for chaining
     */
    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::WindowUpdateFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::WindowUpdateFrame>& frame_to_send) {
        qb::protocol::http2::FrameHeader header = frame_to_send.header;
        const auto& payload = frame_to_send.payload;
        std::array<uint8_t, 4> payload_bytes_arr;

        // Window increment with reserved bit cleared
        uint32_t increment = payload.window_size_increment & 0x7FFFFFFF;
        payload_bytes_arr[0] = static_cast<uint8_t>((increment >> 24) & 0xFF);
        payload_bytes_arr[1] = static_cast<uint8_t>((increment >> 16) & 0xFF);
        payload_bytes_arr[2] = static_cast<uint8_t>((increment >> 8) & 0xFF);
        payload_bytes_arr[3] = static_cast<uint8_t>(increment & 0xFF);

        header.set_payload_length(4);
        this->put(reinterpret_cast<const char*>(&header), qb::protocol::http2::FRAME_HEADER_SIZE);
        this->put(reinterpret_cast<const char*>(payload_bytes_arr.data()), payload_bytes_arr.size());
        return *this;
    }

    /**
     * @brief Serialize CONTINUATION frame to output pipe
     * 
     * CONTINUATION frames are used to continue a sequence of header block
     * fragments. Any number of CONTINUATION frames can be sent, as long as
     * the preceding frame is on the same stream and is HEADERS, PUSH_PROMISE,
     * or CONTINUATION without the END_HEADERS flag set.
     * 
     * @param frame_to_send CONTINUATION frame to serialize
     * @return Reference to this pipe for chaining
     */
    template<>
    pipe<char>& pipe<char>::put<qb::protocol::http2::Http2FrameData<qb::protocol::http2::ContinuationFrame>>(
        const qb::protocol::http2::Http2FrameData<qb::protocol::http2::ContinuationFrame>& frame_to_send) {
        qb::protocol::http2::FrameHeader header = frame_to_send.header;
        const auto& payload_struct = frame_to_send.payload;
        
        header.set_payload_length(static_cast<uint32_t>(payload_struct.header_block_fragment.size()));
        this->put(reinterpret_cast<const char*>(&header), qb::protocol::http2::FRAME_HEADER_SIZE);
        
        if (!payload_struct.header_block_fragment.empty()) {
            this->put(reinterpret_cast<const char*>(payload_struct.header_block_fragment.data()), 
                     payload_struct.header_block_fragment.size());
        }
        return *this;
    }

} // namespace qb::allocator