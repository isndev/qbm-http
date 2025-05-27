/**
 * @file qbm/http/2/protocol/hpack.h
 * @brief HPACK header compression implementation for HTTP/2
 *
 * This file provides a complete implementation of HPACK header compression and
 * decompression as specified in RFC 7541. It includes static and dynamic table
 * management, integer and string literal encoding/decoding, and header field
 * representation handling for HTTP/2 protocol.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup HTTP2
 */

#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <string_view>
#include <memory> // For std::unique_ptr
#include <deque>  // For dynamic table
#include <array>  // For static table
#include <utility> // For std::pair
#include <stdexcept> // For std::runtime_error in integer decoding potentially
#include <optional>

#include "./hpack_huffman.h" // Include the new Huffman stubs

// Forward declaration
namespace qb::http {
    template<typename StringType> class THeaders;
    // Ensure this alias matches the one used in http2_client_protocol.h and http2_server_protocol.h
    using Headers = THeaders<std::string>; 
}

namespace qb::protocol::hpack {

/**
 * @brief HPACK instruction type constants for header field representation
 */
enum class InstructionType : uint8_t {
    INDEXED_HEADER_FIELD = 0x80,              ///< Indexed Header Field (1xxxxxxx)
    LITERAL_WITH_INCREMENTAL_INDEXING = 0x40, ///< Literal with Incremental Indexing (01xxxxxx)
    DYNAMIC_TABLE_SIZE_UPDATE = 0x20,         ///< Dynamic Table Size Update (001xxxxx)
    LITERAL_NEVER_INDEXED = 0x10,             ///< Literal Never Indexed (0001xxxx)
    LITERAL_WITHOUT_INDEXING = 0x00           ///< Literal without Indexing (0000xxxx)
};

/**
 * @brief HPACK error codes for decoding/encoding operations
 */
enum class HpackError {
    SUCCESS = 0,                 ///< Operation completed successfully
    INVALID_INDEX,              ///< Invalid table index referenced
    INTEGER_OVERFLOW,           ///< Integer decoding overflow
    INSUFFICIENT_DATA,          ///< Not enough data to decode
    INVALID_INSTRUCTION,        ///< Invalid HPACK instruction
    TABLE_SIZE_EXCEEDED,        ///< Dynamic table size limit exceeded
    HEADER_LIST_SIZE_EXCEEDED,  ///< Header list size limit exceeded
    HUFFMAN_DECODE_ERROR,       ///< Huffman decoding failed
    UNKNOWN_ERROR              ///< Unknown error occurred
};

/**
 * @brief HPACK statistics for monitoring and debugging
 */
struct HpackStats {
    std::size_t headers_encoded = 0;             ///< Total headers encoded
    std::size_t headers_decoded = 0;             ///< Total headers decoded
    std::size_t bytes_encoded = 0;               ///< Total bytes encoded
    std::size_t bytes_decoded = 0;               ///< Total bytes decoded
    std::size_t dynamic_table_insertions = 0;    ///< Dynamic table insertions
    std::size_t dynamic_table_evictions = 0;     ///< Dynamic table evictions
    std::size_t huffman_encoded_strings = 0;     ///< Strings Huffman encoded
    std::size_t huffman_decoded_strings = 0;     ///< Strings Huffman decoded
    std::size_t static_table_hits = 0;           ///< Static table lookup hits
    std::size_t dynamic_table_hits = 0;          ///< Dynamic table lookup hits
    
    /**
     * @brief Reset all statistics to zero
     */
    void reset() {
        *this = HpackStats{};
    }
};

/**
 * @brief Create the HPACK static table as defined in RFC 7541 Appendix A
 * @return Array of 61 predefined header field pairs
 */
constexpr std::array<std::pair<std::string_view, std::string_view>, 61> create_static_table() {
    return {{
        {":authority", ""}, // 1
        {":method", "GET"}, // 2
        {":method", "POST"}, // 3
        {":path", "/"}, // 4
        {":path", "/index.html"}, // 5
        {":scheme", "http"}, // 6
        {":scheme", "https"}, // 7
        {":status", "200"}, // 8
        {":status", "204"}, // 9
        {":status", "206"}, // 10
        {":status", "304"}, // 11
        {":status", "400"}, // 12
        {":status", "404"}, // 13
        {":status", "500"}, // 14
        {"accept-charset", ""}, // 15
        {"accept-encoding", "gzip, deflate"}, // 16
        {"accept-language", ""}, // 17
        {"accept-ranges", ""}, // 18
        {"accept", ""}, // 19
        {"access-control-allow-origin", ""}, // 20
        {"age", ""}, // 21
        {"allow", ""}, // 22
        {"authorization", ""}, // 23
        {"cache-control", ""}, // 24
        {"content-disposition", ""}, // 25
        {"content-encoding", ""}, // 26
        {"content-language", ""}, // 27
        {"content-length", ""}, // 28
        {"content-location", ""}, // 29
        {"content-range", ""}, // 30
        {"content-type", ""}, // 31
        {"cookie", ""}, // 32
        {"date", ""}, // 33
        {"etag", ""}, // 34
        {"expect", ""}, // 35
        {"expires", ""}, // 36
        {"from", ""}, // 37
        {"host", ""}, // 38
        {"if-match", ""}, // 39
        {"if-modified-since", ""}, // 40
        {"if-none-match", ""}, // 41
        {"if-range", ""}, // 42
        {"if-unmodified-since", ""}, // 43
        {"last-modified", ""}, // 44
        {"link", ""}, // 45
        {"location", ""}, // 46
        {"max-forwards", ""}, // 47
        {"proxy-authenticate", ""}, // 48
        {"proxy-authorization", ""}, // 49
        {"range", ""}, // 50
        {"referer", ""}, // 51
        {"refresh", ""}, // 52
        {"retry-after", ""}, // 53
        {"server", ""}, // 54
        {"set-cookie", ""}, // 55
        {"strict-transport-security", ""}, // 56
        {"transfer-encoding", ""}, // 57
        {"user-agent", ""}, // 58
        {"vary", ""}, // 59
        {"via", ""}, // 60
        {"www-authenticate", ""} // 61
    }};
}

/**
 * @brief HPACK static table constant
 */
constexpr std::array<std::pair<std::string_view, std::string_view>, 61> STATIC_TABLE = create_static_table();

/**
 * @brief Default maximum dynamic table size (4096 octets)
 */
static constexpr uint32_t HPACK_DEFAULT_MAX_TABLE_SIZE = 4096U;

/**
 * @brief Default maximum header list size (unlimited)
 */
static constexpr uint32_t HPACK_DEFAULT_MAX_HEADER_LIST_SIZE = 0xFFFFFFFF;

/**
 * @brief Overhead per dynamic table entry (32 octets) as per RFC 7541
 */
static constexpr std::size_t HPACK_ENTRY_OVERHEAD = 32;

/**
 * @brief Represents a single header field with name, value and sensitivity flag
 */
struct HeaderField {
    std::string name;      ///< Header field name
    std::string value;     ///< Header field value
    bool sensitive = false; ///< Indicates if field should not be indexed
    
    /**
     * @brief Default constructor
     */
    HeaderField() = default;
    
    /**
     * @brief Construct header field with name and value
     * @param n Header name
     * @param v Header value
     * @param sens Sensitivity flag (default: false)
     */
    HeaderField(std::string n, std::string v, bool sens = false) 
        : name(std::move(n)), value(std::move(v)), sensitive(sens) {}
    
    /**
     * @brief Calculate HPACK size of this header field
     * @return Size in octets including overhead
     */
    [[nodiscard]] std::size_t hpack_size() const {
        return name.length() + value.length() + HPACK_ENTRY_OVERHEAD;
    }
    
    /**
     * @brief Check if this is a pseudo-header field
     * @return true if name starts with ':'
     */
    [[nodiscard]] bool is_pseudo_header() const {
        return !name.empty() && name[0] == ':';
    }
    
    /**
     * @brief Check if this header is sensitive by default
     * @return true for authorization, cookie, and similar headers
     */
    [[nodiscard]] bool is_sensitive_by_default() const {
        return name == "authorization" || 
               name == "cookie" || 
               name == "proxy-authorization" ||
               name.find("set-cookie") == 0;
    }
};

/**
 * @brief Utility functions for static table lookups
 */
namespace static_table {
    /**
     * @brief Find exact match (name and value) in static table
     * @param name Header field name to search
     * @param value Header field value to search
     * @return 1-based index if found, nullopt otherwise
     */
    inline std::optional<std::size_t> find_exact_match(const std::string& name, const std::string& value) {
        for (std::size_t i = 0; i < STATIC_TABLE.size(); ++i) {
            if (STATIC_TABLE[i].first == name && STATIC_TABLE[i].second == value) {
                return i + 1; // HPACK indices are 1-based
            }
        }
        return std::nullopt;
    }
    
    /**
     * @brief Find name match in static table
     * @param name Header field name to search
     * @return 1-based index of first match if found, nullopt otherwise
     */
    inline std::optional<std::size_t> find_name_match(const std::string& name) {
        for (std::size_t i = 0; i < STATIC_TABLE.size(); ++i) {
            if (STATIC_TABLE[i].first == name) {
                return i + 1; // HPACK indices are 1-based
            }
        }
        return std::nullopt;
    }
    
    /**
     * @brief Get entry by index from static table
     * @param index 1-based index into static table
     * @return Header field pair if valid index, nullopt otherwise
     */
    inline std::optional<std::pair<std::string_view, std::string_view>> get_entry(std::size_t index) {
        if (index == 0 || index > STATIC_TABLE.size()) {
            return std::nullopt;
        }
        return STATIC_TABLE[index - 1];
    }
    
    /**
     * @brief Validate if index is within static table bounds
     * @param index 1-based index to validate
     * @return true if index is valid
     */
    [[nodiscard]] inline bool is_valid_index(std::size_t index) {
        return index > 0 && index <= STATIC_TABLE.size();
    }
}

/**
 * @brief Utility functions for header field validation
 */
namespace header_validation {
    /**
     * @brief Check if header name is valid according to RFC 7230
     * @param name Header field name to validate
     * @return true if name is valid
     */
    [[nodiscard]] inline bool is_valid_header_name(const std::string& name) {
        if (name.empty()) return false;
        
        for (char c : name) {
            if (c < 0x21 || c > 0x7E || c == ':' || c == ' ' || c == '\t') {
                // Allow ':' only for pseudo-headers at the beginning
                if (c == ':' && name[0] == ':') continue;
                return false;
            }
        }
        return true;
    }
    
    /**
     * @brief Check if header value is valid according to RFC 7230
     * @param value Header field value to validate
     * @return true if value is valid
     */
    [[nodiscard]] inline bool is_valid_header_value(const std::string& value) {
        for (char c : value) {
            if (c < 0x20 && c != '\t') return false;
            if (c == 0x7F) return false;
        }
        return true;
    }
    
    /**
     * @brief Check if header field is valid
     * @param field Header field to validate
     * @return true if both name and value are valid
     */
    [[nodiscard]] inline bool is_valid_header_field(const HeaderField& field) {
        return is_valid_header_name(field.name) && is_valid_header_value(field.value);
    }
}

/**
 * @brief Interface for HPACK decoder implementations
 *
 * Manages the dynamic table and decodes HPACK-encoded header blocks into
 * header fields. The decoder is stateful and maintains a dynamic table
 * that can be updated via SETTINGS frames.
 */
class Decoder {
public:
    virtual ~Decoder() = default;

    /**
     * @brief Decode an HPACK-encoded header block
     *
     * @param encoded_block The HPACK-encoded data
     * @param out_headers Output vector for decoded header fields
     * @param out_is_possibly_incomplete Set to true if decoding might be incomplete
     * @return true if decoding succeeded, false on critical error
     */
    virtual bool decode(
        const std::vector<uint8_t>& encoded_block,
        std::vector<HeaderField>& out_headers,
        bool& out_is_possibly_incomplete) = 0;

    /**
     * @brief Update the maximum size of the dynamic table
     * 
     * Called when SETTINGS_HEADER_TABLE_SIZE is received from peer.
     * 
     * @param max_size New maximum size in octets
     */
    virtual void set_max_dynamic_table_size(uint32_t max_size) = 0;

    /**
     * @brief Update the maximum header list size
     * 
     * Called when SETTINGS_MAX_HEADER_LIST_SIZE is received from peer.
     * 
     * @param max_list_size New maximum size in octets
     */
    virtual void set_max_header_list_size(uint32_t max_list_size) = 0;

    /**
     * @brief Reset decoder state including dynamic table
     */
    virtual void reset() = 0;
    
    /**
     * @brief Get decoder statistics
     * @return Reference to statistics structure
     */
    [[nodiscard]] virtual const HpackStats& get_stats() const = 0;
    
    /**
     * @brief Get current dynamic table size in octets
     * @return Current size
     */
    [[nodiscard]] virtual std::size_t get_dynamic_table_size() const = 0;
    
    /**
     * @brief Get current dynamic table entry count
     * @return Number of entries
     */
    [[nodiscard]] virtual std::size_t get_dynamic_table_entry_count() const = 0;

    /**
     * @brief Create a new decoder instance
     * @return Unique pointer to decoder implementation
     */
    static std::unique_ptr<Decoder> create();
};

/**
 * @brief Interface for HPACK encoder implementations
 *
 * Manages the dynamic table and encodes header fields into HPACK format.
 * The encoder is stateful and maintains a dynamic table synchronized with
 * the decoder's table on the peer.
 */
class Encoder {
public:
    virtual ~Encoder() = default;

    /**
     * @brief Encode header fields into HPACK format
     *
     * @param headers_to_encode Vector of header fields to encode
     * @param out_buffer Output buffer (data is appended)
     * @return true if encoding succeeded, false on error
     */
    virtual bool encode(
        const std::vector<HeaderField>& headers_to_encode,
        std::vector<uint8_t>& out_buffer) = 0;

    /**
     * @brief Update peer's maximum dynamic table size
     * 
     * Called when SETTINGS_HEADER_TABLE_SIZE is received from peer.
     * 
     * @param max_size New maximum size in octets
     */
    virtual void set_peer_max_dynamic_table_size(uint32_t max_size) = 0;
    
    /**
     * @brief Set maximum capacity for this encoder's dynamic table
     * 
     * Sets the maximum size of our dynamic table.
     * 
     * @param max_capacity New maximum capacity in octets
     */
    virtual void set_max_capacity(uint32_t max_capacity) = 0;

    /**
     * @brief Reset encoder state including dynamic table
     */
    virtual void reset() = 0;
    
    /**
     * @brief Get encoder statistics
     * @return Reference to statistics structure
     */
    [[nodiscard]] virtual const HpackStats& get_stats() const = 0;
    
    /**
     * @brief Get current dynamic table size in octets
     * @return Current size
     */
    [[nodiscard]] virtual std::size_t get_dynamic_table_size() const = 0;
    
    /**
     * @brief Get current dynamic table entry count
     * @return Number of entries
     */
    [[nodiscard]] virtual std::size_t get_dynamic_table_entry_count() const = 0;

    /**
     * @brief Create a new encoder instance
     * @return Unique pointer to encoder implementation
     */
    static std::unique_ptr<Encoder> create();
};

// Forward declarations
class HpackDecoderImpl;
class HpackEncoderImpl;

/**
 * @brief HPACK decoder implementation
 * 
 * Implements the HPACK decoding algorithm as specified in RFC 7541.
 * Manages a dynamic table synchronized with the encoder's table and
 * decodes header blocks using indexed, literal, and Huffman representations.
 */
class HpackDecoderImpl : public Decoder {
private:
    /**
     * @brief Dynamic table entry structure
     */
    struct DynamicTableEntry {
        std::string name;   ///< Header field name
        std::string value;  ///< Header field value
        std::size_t size;   ///< Size in octets (name_len + value_len + 32)

        DynamicTableEntry(std::string n, std::string v) : name(std::move(n)), value(std::move(v)) {
            size = name.length() + value.length() + HPACK_ENTRY_OVERHEAD;
        }
    };

    std::deque<DynamicTableEntry> _dynamic_table;                                    ///< Dynamic header table
    std::size_t _current_dynamic_table_octets = 0;                                  ///< Current table size
    std::size_t _max_dynamic_table_octets = HPACK_DEFAULT_MAX_TABLE_SIZE;          ///< Max table size
    std::size_t _max_dynamic_table_octets_limit_from_settings = HPACK_DEFAULT_MAX_TABLE_SIZE; ///< Settings limit
    std::size_t _max_header_list_size_from_settings = HPACK_DEFAULT_MAX_HEADER_LIST_SIZE;   ///< Max header list
    mutable HpackStats _stats;                                                      ///< Decoding statistics

    /**
     * @brief Decode an integer from HPACK format (RFC 7541, Section 5.1)
     * @param current_pos Current position in buffer (updated)
     * @param end_pos End of buffer
     * @param N Prefix size in bits
     * @return Decoded value and bytes consumed, or {0, -1} on error
     */
    [[nodiscard]] static std::pair<uint64_t, int> decode_integer(const uint8_t*& current_pos, const uint8_t* end_pos, uint8_t N) {
        if (current_pos >= end_pos) return {0, -1};

        const uint8_t prefix_mask = (1 << N) - 1;
        uint64_t value = (*current_pos) & prefix_mask;
        int bytes_consumed = 1;

        if (value < prefix_mask) {
            current_pos++;
            return {value, bytes_consumed};
        }

        // Multi-byte integer
        current_pos++;
        uint64_t M = 0;
        uint8_t byte_val;

        do {
            if (current_pos >= end_pos) return {0, -1};
            byte_val = *current_pos;
            bytes_consumed++;

            if (M >= 64) {
                return {0, -1}; // Overflow protection
            }
            
            uint64_t term = static_cast<uint64_t>(byte_val & 0x7F);
            
            if (M > 0 && term > (UINT64_MAX >> M)) {
                return {0, -1};
            }
            
            uint64_t shifted_term = term << M;
            
            if (value > UINT64_MAX - shifted_term) {
                return {0, -1};
            }

            value += shifted_term;
            current_pos++;
            M += 7;
        } while (byte_val & 0x80);

        return {value, bytes_consumed};
    }

    /**
     * @brief Decode a string literal from HPACK format (RFC 7541, Section 5.2)
     * @param current_pos Current position in buffer (updated)
     * @param end_pos End of buffer
     * @param out_is_possibly_incomplete Set to true if decoding incomplete
     * @param stats Statistics to update
     * @return Decoded string and bytes consumed, or nullopt on error
     */
    [[nodiscard]] static std::pair<std::optional<std::string>, int> decode_string_literal(
        const uint8_t*& current_pos, const uint8_t* end_pos, bool& out_is_possibly_incomplete, HpackStats& stats) {
        
        if (current_pos >= end_pos) {
            return {std::nullopt, -1};
        }

        uint8_t first_byte_of_string_field = *current_pos;
        bool huffman_encoded = (first_byte_of_string_field & 0x80);
        
        auto [length, len_consumed] = decode_integer(current_pos, end_pos, 7);

        if (len_consumed == -1) {
            return {std::nullopt, -1};
        }

        if (length > static_cast<uint64_t>(end_pos - current_pos)) {
            out_is_possibly_incomplete = true;
            return {std::nullopt, -1};
        }

        std::string value_str;
        if (huffman_encoded) {
            if (!huffman::huffman_decode(current_pos, length, value_str)) {
                out_is_possibly_incomplete = true;
                current_pos += length;
                return {std::nullopt, -1};
            }
            stats.huffman_decoded_strings++;
        } else {
            value_str.assign(reinterpret_cast<const char*>(current_pos), length);
        }
        
        current_pos += length;
        stats.bytes_decoded += length;
        return {std::move(value_str), static_cast<int>(length)};
    }

    /**
     * @brief Add entry to dynamic table
     * @param name Header field name
     * @param value Header field value
     */
    void add_to_dynamic_table(std::string name, std::string value) {
        DynamicTableEntry new_entry(std::move(name), std::move(value));
        std::size_t entry_size = new_entry.size;

        if (entry_size > _max_dynamic_table_octets) {
            _dynamic_table.clear();
            _current_dynamic_table_octets = 0;
            return;
        }

        while (_current_dynamic_table_octets + entry_size > _max_dynamic_table_octets && !_dynamic_table.empty()) {
            evict_oldest_entry();
        }
        
        if (_current_dynamic_table_octets + entry_size <= _max_dynamic_table_octets) {
            _dynamic_table.push_front(std::move(new_entry));
            _current_dynamic_table_octets += entry_size;
            _stats.dynamic_table_insertions++;
        }
    }
    
    /**
     * @brief Evict oldest entry from dynamic table
     */
    void evict_oldest_entry() {
        if (_dynamic_table.empty()) return;
        const auto& entry_to_evict = _dynamic_table.back();
        _current_dynamic_table_octets -= entry_to_evict.size;
        _dynamic_table.pop_back();
        _stats.dynamic_table_evictions++;
    }

    /**
     * @brief Get entry from static or dynamic table by index
     * @param index 1-based index
     * @param name Output name
     * @param value Output value
     * @return true if found
     */
    [[nodiscard]] bool get_dynamic_table_entry(uint64_t index, std::string& name, std::string& value) const {
        if (index <= STATIC_TABLE.size()) {
            const auto& entry = STATIC_TABLE[index - 1];
            name = std::string(entry.first);
            value = std::string(entry.second);
            _stats.static_table_hits++;
            return true;
        } else {
            std::size_t dynamic_index = index - STATIC_TABLE.size();
            if (dynamic_index > _dynamic_table.size() || dynamic_index == 0) {
                return false;
            }
            const auto& entry = _dynamic_table[dynamic_index - 1];
            name = entry.name;
            value = entry.value;
            _stats.dynamic_table_hits++;
            return true;
        }
    }

    /**
     * @brief Get name from static or dynamic table by index
     * @param index 1-based index
     * @param name Output name
     * @return true if found
     */
    [[nodiscard]] bool get_name_from_index(uint64_t index, std::string& name) const {
        if (index <= STATIC_TABLE.size()) {
            name = std::string(STATIC_TABLE[index - 1].first);
            _stats.static_table_hits++;
            return true;
        } else {
            std::size_t dynamic_index = index - STATIC_TABLE.size();
            if (dynamic_index > _dynamic_table.size() || dynamic_index == 0) {
                return false;
            }
            name = _dynamic_table[dynamic_index - 1].name;
            _stats.dynamic_table_hits++;
            return true;
        }
    }

    /**
     * @brief Evict entries until table fits within size limit
     */
    void evict_until_fit() {
        while (_current_dynamic_table_octets > _max_dynamic_table_octets) {
            if (_dynamic_table.empty()) {
                _current_dynamic_table_octets = 0;
                break;
            }
            evict_oldest_entry();
        }
    }

public:
    HpackDecoderImpl() = default;

    bool decode(const std::vector<uint8_t>& encoded_block, std::vector<HeaderField>& out_headers, bool& out_is_possibly_incomplete) override {
        const uint8_t* current_pos = encoded_block.data();
        const uint8_t* end_pos = encoded_block.data() + encoded_block.size();
        out_is_possibly_incomplete = false;
        std::size_t current_header_list_size_check = 0;
        out_headers.clear();

        _stats.bytes_decoded += encoded_block.size();

        while (current_pos < end_pos) {
            uint8_t first_byte = *current_pos;

            if (first_byte >> 7 == 1) { // Indexed Header Field (1xxxxxxx)
                auto [index, index_len] = decode_integer(current_pos, end_pos, 7);
                if (index_len < 0) { out_is_possibly_incomplete = true; return false; }

                if (index == 0) { return false; }

                std::string name, value;
                if (!get_dynamic_table_entry(index, name, value)) {
                    return false;
                }
                out_headers.emplace_back(std::move(name), std::move(value));
                current_header_list_size_check += out_headers.back().hpack_size();

            } else if (first_byte >> 6 == 0b01) { // Literal Header Field with Incremental Indexing (01xxxxxx)
                auto [index, index_len] = decode_integer(current_pos, end_pos, 6);
                if (index_len < 0) { out_is_possibly_incomplete = true; return false; }

                std::string name, value;

                if (index == 0) {
                    auto [decoded_name, name_consumed_len] = decode_string_literal(current_pos, end_pos, out_is_possibly_incomplete, _stats);
                    if (!decoded_name) { return false; }
                    name = std::move(decoded_name.value());
                } else {
                    if (!get_name_from_index(index, name)) {
                        return false;
                    }
                }

                auto [decoded_value, value_consumed_len] = decode_string_literal(current_pos, end_pos, out_is_possibly_incomplete, _stats);
                if (!decoded_value) { out_is_possibly_incomplete = true; return false; }
                value = std::move(decoded_value.value());

                current_header_list_size_check += name.length() + value.length() + HPACK_ENTRY_OVERHEAD;
                out_headers.emplace_back(name, value);
                add_to_dynamic_table(std::move(name), std::move(value));

            } else if (first_byte >> 4 == 0b0000) { // Literal Header Field without Indexing (0000xxxx)
                auto [index, index_len] = decode_integer(current_pos, end_pos, 4);
                if (index_len < 0) { out_is_possibly_incomplete = true; return false; }

                std::string name, value;
                if (index == 0) {
                    auto [decoded_name, name_consumed_len] = decode_string_literal(current_pos, end_pos, out_is_possibly_incomplete, _stats);
                    if (!decoded_name) { return false; }
                    name = std::move(decoded_name.value());
                } else {
                    if (!get_name_from_index(index, name)) {
                        return false;
                    }
                }
                auto [decoded_value, value_consumed_len] = decode_string_literal(current_pos, end_pos, out_is_possibly_incomplete, _stats);
                if (!decoded_value) { out_is_possibly_incomplete = true; return false; }
                value = std::move(decoded_value.value());

                current_header_list_size_check += name.length() + value.length() + HPACK_ENTRY_OVERHEAD;
                out_headers.emplace_back(std::move(name), std::move(value));

            } else if (first_byte >> 4 == 0b0001) { // Literal Header Field never Indexed (0001xxxx)
                auto [index, index_len] = decode_integer(current_pos, end_pos, 4);
                if (index_len < 0) { out_is_possibly_incomplete = true; return false; }
                
                std::string name, value;
                if (index == 0) {
                    auto [decoded_name, name_consumed_len] = decode_string_literal(current_pos, end_pos, out_is_possibly_incomplete, _stats);
                    if (!decoded_name) { return false; }
                    name = std::move(decoded_name.value());
                } else {
                    if (!get_name_from_index(index, name)) {
                        return false;
                    }
                }
                auto [decoded_value, value_consumed_len] = decode_string_literal(current_pos, end_pos, out_is_possibly_incomplete, _stats);
                if (!decoded_value) { out_is_possibly_incomplete = true; return false; }
                value = std::move(decoded_value.value());

                current_header_list_size_check += name.length() + value.length() + HPACK_ENTRY_OVERHEAD;
                HeaderField field(std::move(name), std::move(value));
                field.sensitive = true; // Mark as sensitive
                out_headers.push_back(std::move(field));

            } else if (first_byte >> 5 == 0b001) { // Dynamic Table Size Update (001xxxxx)
                auto [new_max_size, size_len] = decode_integer(current_pos, end_pos, 5);
                if (size_len < 0) { out_is_possibly_incomplete = true; return false; }

                if (new_max_size > _max_dynamic_table_octets_limit_from_settings) {
                    return false; 
                }
                _max_dynamic_table_octets = static_cast<std::size_t>(new_max_size);
                evict_until_fit();
            } else {
                return false; // Unknown instruction
            }

            if (_max_header_list_size_from_settings > 0 && current_header_list_size_check > _max_header_list_size_from_settings) {
                return false;
            }
        }
        
        _stats.headers_decoded += out_headers.size();
        return true;
    }

    void set_max_dynamic_table_size(uint32_t max_size) override {
        _max_dynamic_table_octets_limit_from_settings = max_size;
        _max_dynamic_table_octets = max_size; 
        evict_until_fit();
    }

    void set_max_header_list_size(uint32_t max_list_size) override {
        _max_header_list_size_from_settings = max_list_size;
    }

    void reset() override {
        _dynamic_table.clear();
        _current_dynamic_table_octets = 0;
        _stats.reset();
    }
    
    [[nodiscard]] const HpackStats& get_stats() const override {
        return _stats;
    }
    
    [[nodiscard]] std::size_t get_dynamic_table_size() const override {
        return _current_dynamic_table_octets;
    }
    
    [[nodiscard]] std::size_t get_dynamic_table_entry_count() const override {
        return _dynamic_table.size();
    }
};

/**
 * @brief HPACK encoder implementation
 * 
 * Implements the HPACK encoding algorithm as specified in RFC 7541.
 * Manages a dynamic table synchronized with the decoder's table and
 * encodes header fields using optimal representations.
 */
class HpackEncoderImpl : public Encoder {
private:
    /**
     * @brief Dynamic table entry structure
     */
    struct DynamicTableEntry {
        std::string name;   ///< Header field name
        std::string value;  ///< Header field value
        std::size_t size;   ///< Size in octets

        DynamicTableEntry(std::string n, std::string v) : name(std::move(n)), value(std::move(v)) {
            size = name.length() + value.length() + HPACK_ENTRY_OVERHEAD;
        }
    };
    
    std::deque<DynamicTableEntry> _dynamic_table;                              ///< Dynamic header table
    std::size_t _current_dynamic_table_octets = 0;                            ///< Current table size
    std::size_t _local_max_dynamic_table_octets = HPACK_DEFAULT_MAX_TABLE_SIZE; ///< Our max table size
    std::size_t _peer_max_dynamic_table_octets = HPACK_DEFAULT_MAX_TABLE_SIZE;  ///< Peer's max table size
    mutable HpackStats _stats;                                                  ///< Encoding statistics

    /**
     * @brief Encode an integer in HPACK format (RFC 7541, Section 5.1)
     * @param buffer Output buffer
     * @param prefix_bits Prefix bits for the first byte
     * @param N Prefix size in bits
     * @param value Value to encode
     */
    static void encode_integer(std::vector<uint8_t>& buffer, uint8_t prefix_bits, uint8_t N, uint64_t value) {
        uint8_t prefix_mask = (1 << N) - 1;
        if (value < prefix_mask) {
            buffer.push_back(prefix_bits | static_cast<uint8_t>(value));
        } else {
            buffer.push_back(prefix_bits | prefix_mask);
            value -= prefix_mask;
            while (value >= 128) {
                buffer.push_back(static_cast<uint8_t>((value % 128) | 0x80));
                value /= 128;
            }
            buffer.push_back(static_cast<uint8_t>(value));
        }
    }

    /**
     * @brief Encode a string literal in HPACK format (RFC 7541, Section 5.2)
     * @param buffer Output buffer
     * @param str String to encode
     * @param huffman_allowed Whether Huffman encoding is allowed
     */
    void encode_string_literal(std::vector<uint8_t>& buffer, const std::string& str, bool huffman_allowed = true) const {
        bool use_huffman = huffman_allowed && huffman::should_use_huffman(str);
        
        uint8_t prefix_byte_for_length = use_huffman ? 0x80 : 0x00;
        
        if (use_huffman) {
           std::vector<uint8_t> huffman_encoded_str_bytes;
           if (huffman::huffman_encode(str, huffman_encoded_str_bytes)) {
               encode_integer(buffer, prefix_byte_for_length, 7, huffman_encoded_str_bytes.size());
               buffer.insert(buffer.end(), huffman_encoded_str_bytes.begin(), huffman_encoded_str_bytes.end());
               _stats.huffman_encoded_strings++;
               _stats.bytes_encoded += huffman_encoded_str_bytes.size();
           } else {
               // Fallback to non-Huffman
               encode_integer(buffer, 0x00, 7, str.length());
               buffer.insert(buffer.end(), str.begin(), str.end());
               _stats.bytes_encoded += str.length();
           }
        } else {
            encode_integer(buffer, 0x00, 7, str.length());
            buffer.insert(buffer.end(), str.begin(), str.end());
            _stats.bytes_encoded += str.length();
        }
    }
    
    /**
     * @brief Add entry to encoder's dynamic table
     * @param name Header field name
     * @param value Header field value
     */
    void add_to_dynamic_table(std::string name, std::string value) {
        DynamicTableEntry new_entry(std::move(name), std::move(value));
        std::size_t entry_size = new_entry.size;

        if (entry_size > _local_max_dynamic_table_octets) {
            return; 
        }

        while (_current_dynamic_table_octets + entry_size > _local_max_dynamic_table_octets && !_dynamic_table.empty()) {
            evict_oldest_entry();
        }
        
        if (_current_dynamic_table_octets + entry_size <= _local_max_dynamic_table_octets) {
            _dynamic_table.push_front(std::move(new_entry));
            _current_dynamic_table_octets += entry_size;
            _stats.dynamic_table_insertions++;
        }
    }

    /**
     * @brief Evict oldest entry from dynamic table
     */
    void evict_oldest_entry() {
        if (_dynamic_table.empty()) return;
        const auto& entry_to_evict = _dynamic_table.back();
        _current_dynamic_table_octets -= entry_to_evict.size;
        _dynamic_table.pop_back();
        _stats.dynamic_table_evictions++;
    }

public:
    HpackEncoderImpl() = default;

    bool encode(const std::vector<HeaderField>& headers_to_encode, std::vector<uint8_t>& out_buffer) override {
        std::size_t initial_size = out_buffer.size();
        
        for (const auto& header_field : headers_to_encode) {
            const std::string& name = header_field.name;
            const std::string& value = header_field.value;

            // Validate header field
            if (!header_validation::is_valid_header_field(header_field)) {
                return false;
            }
            
            std::size_t pre_header_buffer_size = out_buffer.size(); // LOG: Size before this header

            // Try to find exact match in static table
            if (auto static_index = static_table::find_exact_match(name, value)) {
                encode_integer(out_buffer, static_cast<uint8_t>(InstructionType::INDEXED_HEADER_FIELD), 7, *static_index);
                _stats.static_table_hits++;
                continue;
            }

            // Try to find exact match in dynamic table
            bool found_in_dynamic_full = false;
            for (size_t i = 0; i < _dynamic_table.size(); ++i) {
                if (_dynamic_table[i].name == name && _dynamic_table[i].value == value) {
                    encode_integer(out_buffer, static_cast<uint8_t>(InstructionType::INDEXED_HEADER_FIELD), 7, STATIC_TABLE.size() + i + 1);
                    found_in_dynamic_full = true;
                    _stats.dynamic_table_hits++;
                    break;
                }
            }
            if (found_in_dynamic_full) continue;
            
            // Find name matches
            auto static_name_idx = static_table::find_name_match(name);
            std::optional<std::size_t> dynamic_name_idx;
            for (size_t i = 0; i < _dynamic_table.size(); ++i) {
                if (_dynamic_table[i].name == name) {
                    dynamic_name_idx = STATIC_TABLE.size() + i + 1;
                    break;
                }
            }

            // Determine encoding strategy
            bool is_sensitive = header_field.sensitive || header_field.is_sensitive_by_default();
            bool is_pseudo = header_field.is_pseudo_header();
            bool use_never_indexed = is_sensitive || is_pseudo;
            bool can_be_added_to_table = header_field.hpack_size() <= _local_max_dynamic_table_octets && !is_sensitive && !is_pseudo;

            if (use_never_indexed) {
                // Literal Header Field Never Indexed
                if (dynamic_name_idx) {
                    encode_integer(out_buffer, static_cast<uint8_t>(InstructionType::LITERAL_NEVER_INDEXED), 4, *dynamic_name_idx);
                } else if (static_name_idx) {
                    encode_integer(out_buffer, static_cast<uint8_t>(InstructionType::LITERAL_NEVER_INDEXED), 4, *static_name_idx);
                } else {
                    encode_integer(out_buffer, static_cast<uint8_t>(InstructionType::LITERAL_NEVER_INDEXED), 4, 0);
                    encode_string_literal(out_buffer, name, !is_pseudo);
                }
                encode_string_literal(out_buffer, value, true);
            } else if (can_be_added_to_table) {
                // Literal Header Field with Incremental Indexing
                if (dynamic_name_idx) {
                    encode_integer(out_buffer, static_cast<uint8_t>(InstructionType::LITERAL_WITH_INCREMENTAL_INDEXING), 6, *dynamic_name_idx);
                } else if (static_name_idx) {
                    encode_integer(out_buffer, static_cast<uint8_t>(InstructionType::LITERAL_WITH_INCREMENTAL_INDEXING), 6, *static_name_idx);
                } else {
                    encode_integer(out_buffer, static_cast<uint8_t>(InstructionType::LITERAL_WITH_INCREMENTAL_INDEXING), 6, 0);
                    encode_string_literal(out_buffer, name, !is_pseudo);
                }
                encode_string_literal(out_buffer, value, true);
                add_to_dynamic_table(name, value);
            } else {
                // Literal Header Field without Indexing
                if (dynamic_name_idx) {
                    encode_integer(out_buffer, static_cast<uint8_t>(InstructionType::LITERAL_WITHOUT_INDEXING), 4, *dynamic_name_idx);
                } else if (static_name_idx) {
                    encode_integer(out_buffer, static_cast<uint8_t>(InstructionType::LITERAL_WITHOUT_INDEXING), 4, *static_name_idx);
                } else {
                    encode_integer(out_buffer, static_cast<uint8_t>(InstructionType::LITERAL_WITHOUT_INDEXING), 4, 0);
                    encode_string_literal(out_buffer, name, !is_pseudo);
                }
                encode_string_literal(out_buffer, value, true);
            }
        }
        
        _stats.headers_encoded += headers_to_encode.size();
        _stats.bytes_encoded += (out_buffer.size() - initial_size);
        return true;
    }

    void set_peer_max_dynamic_table_size(uint32_t max_size) override {
        _peer_max_dynamic_table_octets = max_size;

        if (_local_max_dynamic_table_octets > _peer_max_dynamic_table_octets) {
            _local_max_dynamic_table_octets = _peer_max_dynamic_table_octets;
            while (_current_dynamic_table_octets > _local_max_dynamic_table_octets && !_dynamic_table.empty()) {
                evict_oldest_entry();
            }
        }
    }
    
    void set_max_capacity(uint32_t max_capacity) override {
        _local_max_dynamic_table_octets = max_capacity;
        while (_current_dynamic_table_octets > _local_max_dynamic_table_octets) {
            if (_dynamic_table.empty()) {
                _current_dynamic_table_octets = 0;
                break;
            }
            evict_oldest_entry();
        }
    }

    void reset() override {
        _dynamic_table.clear();
        _current_dynamic_table_octets = 0;
        _stats.reset();
    }
    
    [[nodiscard]] const HpackStats& get_stats() const override {
        return _stats;
    }
    
    [[nodiscard]] std::size_t get_dynamic_table_size() const override {
        return _current_dynamic_table_octets;
    }
    
    [[nodiscard]] std::size_t get_dynamic_table_entry_count() const override {
        return _dynamic_table.size();
    }
};

// Factory method implementations
inline std::unique_ptr<Decoder> Decoder::create() {
    return std::make_unique<HpackDecoderImpl>();
}

inline std::unique_ptr<Encoder> Encoder::create() {
    return std::make_unique<HpackEncoderImpl>();
}

// Utility functions for converting between HeaderField and qb::http::Headers
namespace conversion {
    // Convert from qb::http::Headers to std::vector<HeaderField>
    template<typename HeadersType>
    std::vector<HeaderField> from_qb_headers(const HeadersType& qb_headers) {
        std::vector<HeaderField> fields;
        // This would need to be implemented based on the actual qb::http::Headers interface
        // For now, this is a placeholder
        return fields;
    }
    
    // Convert from std::vector<HeaderField> to qb::http::Headers
    template<typename HeadersType>
    HeadersType to_qb_headers(const std::vector<HeaderField>& fields) {
        HeadersType headers;
        // This would need to be implemented based on the actual qb::http::Headers interface
        // For now, this is a placeholder
        return headers;
    }
}

// Convenience functions for common operations
namespace convenience {
    /**
     * @brief Encode headers directly to bytes
     * @param headers Header fields to encode
     * @return Encoded HPACK bytes
     */
    inline std::vector<uint8_t> encode_headers(const std::vector<HeaderField>& headers) {
        auto encoder = Encoder::create();
        std::vector<uint8_t> result;
        encoder->encode(headers, result);
        return result;
    }
    
    /**
     * @brief Decode bytes directly to headers
     * @param data HPACK-encoded data
     * @return Decoded header fields, or nullopt on error
     */
    inline std::optional<std::vector<HeaderField>> decode_headers(const std::vector<uint8_t>& data) {
        auto decoder = Decoder::create();
        std::vector<HeaderField> headers;
        bool incomplete = false;
        
        if (decoder->decode(data, headers, incomplete) && !incomplete) {
            return headers;
        }
        return std::nullopt;
    }
    
    /**
     * @brief Create a header field with automatic sensitivity detection
     * @param name Header field name
     * @param value Header field value
     * @return Header field with appropriate sensitivity flag
     */
    inline HeaderField make_header(const std::string& name, const std::string& value) {
        HeaderField field(name, value);
        field.sensitive = field.is_sensitive_by_default();
        return field;
    }
}

} // namespace qb::protocol::hpack 