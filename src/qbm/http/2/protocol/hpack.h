/**
 * @file qbm/http/2/protocol/hpack.h
 * @brief HPACK header compression implementation for qb-io framework
 *
 * This file provides a complete HPACK (HTTP/2 Header Compression) implementation
 * according to RFC 7541. It includes:
 *
 * - Complete HPACK encoder and decoder implementations
 * - Dynamic table management with eviction policies
 * - Static table lookup for common headers
 * - Huffman string encoding and decoding
 * - Integer encoding/decoding with variable length
 * - Header field indexing strategies
 * - Statistics collection and performance monitoring
 * - Memory-efficient dynamic table operations
 *
 * The implementation provides both high-level interfaces for easy integration
 * and low-level control for performance optimization.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <array> // For static table
#include <cstdint>
#include <memory> // For std::unique_ptr
#include <optional>
#include <stdexcept> // For std::runtime_error in integer decoding potentially
#include <string>
#include <string_view>
#include <utility> // For std::pair
#include <vector>

#include "./hpack_huffman.h" // Include the new Huffman stubs

// Forward declaration
namespace qb::http {
class Headers;
}

namespace qb::protocol::hpack {

/**
 * @brief HPACK instruction type constants for header field representation
 */
enum class InstructionType : uint8_t {
    INDEXED_HEADER_FIELD              = 0x80, ///< Indexed Header Field (1xxxxxxx)
    LITERAL_WITH_INCREMENTAL_INDEXING = 0x40, ///< Literal with Incremental Indexing (01xxxxxx)
    DYNAMIC_TABLE_SIZE_UPDATE         = 0x20, ///< Dynamic Table Size Update (001xxxxx)
    LITERAL_NEVER_INDEXED             = 0x10, ///< Literal Never Indexed (0001xxxx)
    LITERAL_WITHOUT_INDEXING          = 0x00  ///< Literal without Indexing (0000xxxx)
};

/**
 * @brief HPACK error codes for decoding/encoding operations
 */
enum class HpackError {
    SUCCESS = 0,               ///< Operation completed successfully
    INVALID_INDEX,             ///< Invalid table index referenced
    INTEGER_OVERFLOW,          ///< Integer decoding overflow
    INSUFFICIENT_DATA,         ///< Not enough data to decode
    INVALID_INSTRUCTION,       ///< Invalid HPACK instruction
    TABLE_SIZE_EXCEEDED,       ///< Dynamic table size limit exceeded
    HEADER_LIST_SIZE_EXCEEDED, ///< Header list size limit exceeded
    HUFFMAN_DECODE_ERROR,      ///< Huffman decoding failed
    UNKNOWN_ERROR              ///< Unknown error occurred
};

/**
 * @brief HPACK statistics for monitoring and debugging
 */
struct HpackStats {
    std::size_t headers_encoded          = 0; ///< Total headers encoded
    std::size_t headers_decoded          = 0; ///< Total headers decoded
    std::size_t bytes_encoded            = 0; ///< Total bytes encoded
    std::size_t bytes_decoded            = 0; ///< Total bytes decoded
    std::size_t dynamic_table_insertions = 0; ///< Dynamic table insertions
    std::size_t dynamic_table_evictions  = 0; ///< Dynamic table evictions
    std::size_t huffman_encoded_strings  = 0; ///< Strings Huffman encoded
    std::size_t huffman_decoded_strings  = 0; ///< Strings Huffman decoded
    std::size_t static_table_hits        = 0; ///< Static table lookup hits
    std::size_t dynamic_table_hits       = 0; ///< Dynamic table lookup hits

    /**
     * @brief Reset all statistics to zero
     */
    void
    reset() {
        *this = HpackStats{};
    }
};

/**
 * @brief Create the HPACK static table as defined in RFC 7541 Appendix A
 * @return Array of 61 predefined header field pairs
 */
constexpr std::array<std::pair<std::string_view, std::string_view>, 61>
create_static_table() {
    return {{
        {":authority", ""},                   // 1
        {":method", "GET"},                   // 2
        {":method", "POST"},                  // 3
        {":path", "/"},                       // 4
        {":path", "/index.html"},             // 5
        {":scheme", "http"},                  // 6
        {":scheme", "https"},                 // 7
        {":status", "200"},                   // 8
        {":status", "204"},                   // 9
        {":status", "206"},                   // 10
        {":status", "304"},                   // 11
        {":status", "400"},                   // 12
        {":status", "404"},                   // 13
        {":status", "500"},                   // 14
        {"accept-charset", ""},               // 15
        {"accept-encoding", "gzip, deflate"}, // 16
        {"accept-language", ""},              // 17
        {"accept-ranges", ""},                // 18
        {"accept", ""},                       // 19
        {"access-control-allow-origin", ""},  // 20
        {"age", ""},                          // 21
        {"allow", ""},                        // 22
        {"authorization", ""},                // 23
        {"cache-control", ""},                // 24
        {"content-disposition", ""},          // 25
        {"content-encoding", ""},             // 26
        {"content-language", ""},             // 27
        {"content-length", ""},               // 28
        {"content-location", ""},             // 29
        {"content-range", ""},                // 30
        {"content-type", ""},                 // 31
        {"cookie", ""},                       // 32
        {"date", ""},                         // 33
        {"etag", ""},                         // 34
        {"expect", ""},                       // 35
        {"expires", ""},                      // 36
        {"from", ""},                         // 37
        {"host", ""},                         // 38
        {"if-match", ""},                     // 39
        {"if-modified-since", ""},            // 40
        {"if-none-match", ""},                // 41
        {"if-range", ""},                     // 42
        {"if-unmodified-since", ""},          // 43
        {"last-modified", ""},                // 44
        {"link", ""},                         // 45
        {"location", ""},                     // 46
        {"max-forwards", ""},                 // 47
        {"proxy-authenticate", ""},           // 48
        {"proxy-authorization", ""},          // 49
        {"range", ""},                        // 50
        {"referer", ""},                      // 51
        {"refresh", ""},                      // 52
        {"retry-after", ""},                  // 53
        {"server", ""},                       // 54
        {"set-cookie", ""},                   // 55
        {"strict-transport-security", ""},    // 56
        {"transfer-encoding", ""},            // 57
        {"user-agent", ""},                   // 58
        {"vary", ""},                         // 59
        {"via", ""},                          // 60
        {"www-authenticate", ""}              // 61
    }};
}

/**
 * @brief HPACK static table constant
 */
constexpr std::array<std::pair<std::string_view, std::string_view>, 61> STATIC_TABLE = create_static_table();

namespace static_table_detail {
/**
 * @brief Tiny FNV-1a hash used to build the compile-time name index.
 *
 * HPACK names are case-sensitive (all lowercase per RFC 7541) so we hash
 * the bytes verbatim. The hash is not a cryptographic one; its only job
 * is to spread 61 short names across the index table.
 */
constexpr std::uint32_t
name_hash(std::string_view s) noexcept {
    std::uint32_t h = 0x811c9dc5u; // FNV offset basis.
    for (unsigned char c : s) {
        h ^= c;
        h *= 0x01000193u; // FNV prime.
    }
    return h;
}

/// Power-of-two table size; 128 slots keeps the load factor below 0.5
/// for the 61 static-table entries (~40 unique names), so probe chains
/// stay extremely short.
constexpr std::size_t kNameIndexCapacity = 128;
constexpr std::size_t kNameIndexMask     = kNameIndexCapacity - 1;

/**
 * @brief Single slot of the compile-time name index.
 *
 * `table_index` is the 1-based HPACK index of the FIRST occurrence of the
 * name in the static table (matching the legacy O(N) lookup's semantics
 * for `:method`, `:path`, `:scheme`, `:status`, which have multiple
 * entries sharing the same name). A `table_index` of 0 marks an empty
 * slot in the open-addressing table.
 */
struct NameIndexSlot {
    std::uint32_t key_hash    = 0;
    std::uint8_t  table_index = 0;
};

/**
 * @brief Build the compile-time static-table name index.
 *
 * Iterates the static table forward and inserts one entry per unique
 * name; if the slot is already populated by the same name (verified via
 * hash + back-check against `STATIC_TABLE[idx - 1].first`), we keep the
 * smallest index, matching the RFC-compliant behaviour of the prior
 * `find_name_match` helper.
 */
constexpr std::array<NameIndexSlot, kNameIndexCapacity>
build_name_index() {
    std::array<NameIndexSlot, kNameIndexCapacity> table{};
    for (std::size_t i = 0; i < STATIC_TABLE.size(); ++i) {
        const std::string_view name = STATIC_TABLE[i].first;
        const std::uint32_t    h    = name_hash(name);
        std::size_t            slot = h & kNameIndexMask;
        for (std::size_t probe = 0; probe < kNameIndexCapacity; ++probe) {
            NameIndexSlot &e = table[slot];
            if (e.table_index == 0) {
                e = NameIndexSlot{h, static_cast<std::uint8_t>(i + 1)};
                break;
            }
            if (e.key_hash == h && STATIC_TABLE[e.table_index - 1].first == name) {
                // Same name already stored (smaller index wins; we got
                // here because forward iteration hits the first copy
                // earlier). Nothing to do.
                break;
            }
            slot = (slot + 1) & kNameIndexMask;
        }
    }
    return table;
}

/// The compile-time index. Lookup is O(1) average, bounded by the very
/// short probe chains guaranteed by the <0.5 load factor.
constexpr std::array<NameIndexSlot, kNameIndexCapacity> kStaticNameIndex = build_name_index();
} // namespace static_table_detail

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
 * @brief Single entry of the HPACK dynamic table.
 *
 * Shared by both the encoder and decoder. `size` is cached to avoid
 * recomputing `name.length() + value.length() + overhead` on every eviction.
 */
struct DynamicTableEntry {
    std::string name;
    std::string value;
    std::size_t size = 0;

    DynamicTableEntry() = default;

    DynamicTableEntry(std::string n, std::string v)
        : name(std::move(n))
        , value(std::move(v))
        , size(name.length() + value.length() + HPACK_ENTRY_OVERHEAD) {}
};

/**
 * @brief Fixed-capacity ring-buffer implementation of the HPACK dynamic
 *        table (F34).
 *
 * Replaces the previous per-impl `std::deque<DynamicTableEntry>` that paid
 * for chunk allocations on every push/pop. The ring buffer keeps all entries
 * in a single contiguous `std::vector`, reuses slots on eviction, and grows
 * only when the logical entry count actually exceeds the current capacity
 * (which happens at most `log2(max_entries)` times over the table's life).
 *
 * Logical indexing follows HPACK's newest-first convention: `operator[](0)`
 * returns the most recently inserted entry, `operator[](size() - 1)` returns
 * the oldest.
 *
 * This class is the single source of truth for the dynamic table's byte
 * budget, enforcing RFC 7541 §4.4: if a new entry alone exceeds the maximum
 * size, the table is cleared and the entry is NOT stored; otherwise the
 * oldest entries are evicted until it fits.
 */
class DynamicTable {
public:
    /**
     * @brief Result of an `add` operation &mdash; used by callers to feed
     *        their statistics without needing a second pass.
     */
    struct AddResult {
        bool        added   = false;
        std::size_t evicted = 0;
    };

    DynamicTable()                                    = default;
    DynamicTable(const DynamicTable &)                = delete;
    DynamicTable &operator=(const DynamicTable &)     = delete;
    DynamicTable(DynamicTable &&) noexcept            = default;
    DynamicTable &operator=(DynamicTable &&) noexcept = default;

    [[nodiscard]] std::size_t
    size() const noexcept {
        return _count;
    }
    [[nodiscard]] bool
    empty() const noexcept {
        return _count == 0;
    }
    [[nodiscard]] std::size_t
    byte_size() const noexcept {
        return _bytes;
    }
    [[nodiscard]] std::size_t
    max_byte_size() const noexcept {
        return _max_bytes;
    }

    /// Ring-buffer storage capacity (not an HPACK-visible concept; exposed
    /// for tests).
    [[nodiscard]] std::size_t
    capacity() const noexcept {
        return _storage.size();
    }

    /// Logical access; `i = 0` is the newest entry.
    [[nodiscard]] const DynamicTableEntry &
    operator[](std::size_t i) const noexcept {
        return _storage[slot_of(i)];
    }

    /// The oldest entry; undefined behaviour when the table is empty.
    [[nodiscard]] const DynamicTableEntry &
    back() const noexcept {
        return _storage[slot_of(_count - 1)];
    }

    /**
     * @brief Add a new entry at the front (newest position), evicting older
     *        entries as necessary to honour the byte budget.
     *
     * @return The number of entries evicted (before insertion) and whether
     *         the entry itself was inserted. An entry larger than the whole
     *         table causes a clear-and-drop (RFC 7541 §4.4); in that case
     *         `added == false` and `evicted == size()` before the clear.
     */
    AddResult add(std::string name, std::string value);

    /**
     * @brief Adjust the byte budget and evict oldest entries to honour it.
     *
     * @return Number of entries evicted.
     */
    std::size_t set_max_byte_size(std::size_t new_max);

    /**
     * @brief Clear all entries but retain the ring-buffer allocation.
     */
    void
    clear() noexcept {
        clear_storage();
    }

private:
    /// Initial entry capacity &mdash; sized to hold ~128 entries (4096 octet
    /// budget, 32 octet minimum overhead) without ever reallocating for the
    /// default HPACK configuration. Must be a power of two.
    static constexpr std::size_t kInitialCapacity = 128;

    std::vector<DynamicTableEntry> _storage;
    std::size_t                    _head      = 0; ///< Slot holding the newest entry.
    std::size_t                    _count     = 0; ///< Live entry count.
    std::size_t                    _bytes     = 0; ///< Sum of live entries' `size` fields.
    std::size_t                    _max_bytes = HPACK_DEFAULT_MAX_TABLE_SIZE;
    std::size_t                    _mask      = 0; ///< `capacity() - 1` when storage is a power of two.

    [[nodiscard]] std::size_t
    slot_of(std::size_t logical) const noexcept {
        return (_head + logical) & _mask;
    }

    void
    evict_oldest_impl() noexcept {
        const std::size_t slot = slot_of(_count - 1);
        _bytes -= _storage[slot].size;
        _storage[slot] = DynamicTableEntry{}; // Frees the strings.
        --_count;
    }

    void
    clear_storage() noexcept {
        for (std::size_t i = 0; i < _count; ++i) {
            _storage[slot_of(i)] = DynamicTableEntry{};
        }
        _count = 0;
        _bytes = 0;
        _head  = 0;
    }

    /**
     * @brief Ensure the ring buffer has room for one more entry, growing
     *        (and linearising) it when the logical count would exceed
     *        capacity.
     *
     * On growth, capacity is doubled and live entries are moved so the new
     * head starts at slot 0. This happens at most a handful of times over
     * the life of a long-running HTTP/2 connection.
     */
    void ensure_capacity_for_one_more();
};

/**
 * @brief Represents a single header field with name, value and sensitivity flag
 */
struct HeaderField {
    std::string name;              ///< Header field name
    std::string value;             ///< Header field value
    bool        sensitive = false; ///< Indicates if field should not be indexed

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
        : name(std::move(n))
        , value(std::move(v))
        , sensitive(sens) {}

    /**
     * @brief Calculate HPACK size of this header field
     * @return Size in octets including overhead
     */
    [[nodiscard]] std::size_t
    hpack_size() const {
        return name.length() + value.length() + HPACK_ENTRY_OVERHEAD;
    }

    /**
     * @brief Check if this is a pseudo-header field
     * @return true if name starts with ':'
     */
    [[nodiscard]] bool
    is_pseudo_header() const {
        return !name.empty() && name[0] == ':';
    }

    /**
     * @brief Check if this header is sensitive by default
     *
     * F36 &mdash; uses `std::string_view::starts_with` instead of the legacy
     * `find(..., 0) == 0` idiom. HTTP/2 field names are always lowercase
     * (RFC 7540 §8.1.2), so no case-insensitive compare is needed here.
     *
     * @return true for authorization, cookie, and similar headers
     */
    [[nodiscard]] bool
    is_sensitive_by_default() const noexcept {
        const std::string_view n{name};
        return n == "authorization" || n == "cookie" || n == "proxy-authorization" || n.starts_with("set-cookie");
    }
};

/**
 * @brief Utility functions for static table lookups.
 *
 * F33 &mdash; the legacy O(N) linear scans have been replaced by a
 * compile-time open-addressing index keyed on the header name. Lookup is now
 * O(1) average with an extremely short probe chain (load factor ≈ 0.48).
 *
 * For exact-match lookups (name + value), we first resolve the first index
 * sharing the requested name via the index, then walk forward through the
 * static table while names still match, comparing values. The longest such
 * run is `:status` with 7 entries, so the tail scan is bounded.
 */
namespace static_table {
/**
 * @brief Find the 1-based HPACK index of the first occurrence of `name`
 *        in the static table.
 *
 * Accepts `std::string_view` to avoid an upstream `std::string`
 * construction when the caller already holds a view.
 */
[[nodiscard]] inline std::optional<std::size_t>
find_name_match(std::string_view name) noexcept {
    using namespace static_table_detail;
    const std::uint32_t h    = name_hash(name);
    std::size_t         slot = h & kNameIndexMask;
    for (std::size_t probe = 0; probe < kNameIndexCapacity; ++probe) {
        const NameIndexSlot &e = kStaticNameIndex[slot];
        if (e.table_index == 0) {
            return std::nullopt; // Empty slot terminates the probe chain.
        }
        if (e.key_hash == h && STATIC_TABLE[e.table_index - 1].first == name) {
            return static_cast<std::size_t>(e.table_index);
        }
        slot = (slot + 1) & kNameIndexMask;
    }
    return std::nullopt;
}

/**
 * @brief Legacy `std::string`-accepting overload, forwards to the view
 *        variant. Kept for binary-compat.
 */
[[nodiscard]] inline std::optional<std::size_t>
find_name_match(const std::string &name) noexcept {
    return find_name_match(std::string_view{name});
}

/**
 * @brief Find the 1-based index of an entry matching both `name` and
 *        `value` in the static table.
 *
 * The implementation leans on the fact that duplicate-name entries
 * appear in contiguous runs (e.g. `:status` at indices 8..14). A single
 * name-index lookup tells us where the run starts, then we walk forward
 * comparing values until the name changes.
 */
[[nodiscard]] inline std::optional<std::size_t>
find_exact_match(std::string_view name, std::string_view value) noexcept {
    const auto first = find_name_match(name);
    if (!first)
        return std::nullopt;
    for (std::size_t i = *first - 1; i < STATIC_TABLE.size(); ++i) {
        const auto &entry = STATIC_TABLE[i];
        if (entry.first != name)
            break; // Left the contiguous same-name run.
        if (entry.second == value) {
            return i + 1;
        }
    }
    return std::nullopt;
}

/**
 * @brief Legacy `std::string`-accepting overload.
 */
[[nodiscard]] inline std::optional<std::size_t>
find_exact_match(const std::string &name, const std::string &value) noexcept {
    return find_exact_match(std::string_view{name}, std::string_view{value});
}

/**
 * @brief Retrieve an entry by its 1-based index.
 */
[[nodiscard]] inline std::optional<std::pair<std::string_view, std::string_view>>
get_entry(std::size_t index) noexcept {
    if (index == 0 || index > STATIC_TABLE.size()) {
        return std::nullopt;
    }
    return STATIC_TABLE[index - 1];
}

/**
 * @brief Validate if index is within static table bounds.
 */
[[nodiscard]] inline bool
is_valid_index(std::size_t index) noexcept {
    return index > 0 && index <= STATIC_TABLE.size();
}
} // namespace static_table

/**
 * @brief Utility functions for header field validation
 */
namespace header_validation {
/**
 * @brief Check if header name is valid according to RFC 7230
 * @param name Header field name to validate
 * @return true if name is valid
 */
[[nodiscard]] inline bool
is_valid_header_name(const std::string &name) {
    if (name.empty())
        return false;

    for (char c : name) {
        if (c < 0x21 || c > 0x7E || c == ':' || c == ' ' || c == '\t') {
            // Allow ':' only for pseudo-headers at the beginning
            if (c == ':' && name[0] == ':')
                continue;
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
[[nodiscard]] inline bool
is_valid_header_value(const std::string &value) {
    for (char c : value) {
        if (c < 0x20 && c != '\t')
            return false;
        if (c == 0x7F)
            return false;
    }
    return true;
}

/**
 * @brief Check if header field is valid
 * @param field Header field to validate
 * @return true if both name and value are valid
 */
[[nodiscard]] inline bool
is_valid_header_field(const HeaderField &field) {
    return is_valid_header_name(field.name) && is_valid_header_value(field.value);
}
} // namespace header_validation

/**
 * @brief HPACK decoder (RFC 7541).
 *
 * F35 &mdash; this class used to inherit from an abstract `Decoder`
 * interface with a `create()` factory returning `std::unique_ptr<Decoder>`.
 * Since there is exactly one implementation and decoding is called in the
 * HTTP/2 hot path (once per header block, sometimes every frame), the base
 * class added a per-call virtual dispatch and a heap allocation for a
 * configuration we never varied. Both have been removed: the HTTP/2 client
 * and server now own a `Decoder` by value, calls are statically bound, and
 * the ring-buffer dynamic table (F34) is allocated inline.
 *
 * Manages a dynamic table synchronized with the encoder's table and
 * decodes header blocks using indexed, literal, and Huffman representations.
 */
class Decoder {
private:
    DynamicTable       _dynamic_table;                                                               ///< Dynamic header table (F34 ring buffer)
    std::size_t        _max_dynamic_table_octets_limit_from_settings = HPACK_DEFAULT_MAX_TABLE_SIZE; ///< Settings limit
    std::size_t        _max_header_list_size_from_settings           = HPACK_DEFAULT_MAX_HEADER_LIST_SIZE; ///< Max header list
    mutable HpackStats _stats;                                                                             ///< Decoding statistics

    /**
     * @brief Decode an integer from HPACK format (RFC 7541, Section 5.1)
     * @param current_pos Current position in buffer (updated)
     * @param end_pos End of buffer
     * @param N Prefix size in bits
     * @return Decoded value and bytes consumed, or {0, -1} on error
     */
    [[nodiscard]] static std::pair<uint64_t, int> decode_integer(const uint8_t *&current_pos, const uint8_t *end_pos, uint8_t N);

    /**
     * @brief Decode a string literal from HPACK format (RFC 7541, Section 5.2)
     * @param current_pos Current position in buffer (updated)
     * @param end_pos End of buffer
     * @param out_is_possibly_incomplete Set to true if decoding incomplete
     * @param stats Statistics to update
     * @return Decoded string and bytes consumed, or nullopt on error
     */
    [[nodiscard]] static std::pair<std::optional<std::string>, int> decode_string_literal(const uint8_t *&current_pos, const uint8_t *end_pos,
                                                                                          bool &out_is_possibly_incomplete, HpackStats &stats);

    /**
     * @brief Add entry to dynamic table through the shared ring buffer.
     *
     * Statistics are updated from the `AddResult` so the hot path stays
     * branch-light.
     */
    void
    add_to_dynamic_table(std::string name, std::string value) {
        const auto result = _dynamic_table.add(std::move(name), std::move(value));
        _stats.dynamic_table_evictions += result.evicted;
        if (result.added) {
            _stats.dynamic_table_insertions++;
        }
    }

    /**
     * @brief Get entry from static or dynamic table by index
     * @param index 1-based index
     * @param name Output name
     * @param value Output value
     * @return true if found
     */
    [[nodiscard]] bool get_dynamic_table_entry(uint64_t index, std::string &name, std::string &value) const;

    /**
     * @brief Get name from static or dynamic table by index
     * @param index 1-based index
     * @param name Output name
     * @return true if found
     */
    [[nodiscard]] bool get_name_from_index(uint64_t index, std::string &name) const;

public:
    Decoder() = default;

    /**
     * @brief Decode an HPACK-encoded header block into a list of header fields.
     *
     * Processes indexed, literal (with/without/never indexed), and dynamic
     * table size update representations per RFC 7541, synchronising the
     * decoder's dynamic table as it goes and enforcing the configured
     * dynamic-table and header-list size limits.
     *
     * @param encoded_block               The HPACK-encoded header block.
     * @param out_headers                 Cleared then filled with the decoded
     *                                    header fields on success.
     * @param out_is_possibly_incomplete  Set to true when decoding failed
     *                                    because the block appears truncated
     *                                    (as opposed to malformed).
     * @return true on a fully decoded block, false on any decode error.
     */
    bool decode(const std::vector<uint8_t> &encoded_block, std::vector<HeaderField> &out_headers, bool &out_is_possibly_incomplete);

    void
    set_max_dynamic_table_size(uint32_t max_size) {
        _max_dynamic_table_octets_limit_from_settings = max_size;
        _stats.dynamic_table_evictions += _dynamic_table.set_max_byte_size(max_size);
    }

    void
    set_max_header_list_size(uint32_t max_list_size) {
        _max_header_list_size_from_settings = max_list_size;
    }

    void
    reset() {
        _dynamic_table.clear();
        _stats.reset();
    }

    [[nodiscard]] const HpackStats &
    get_stats() const {
        return _stats;
    }

    [[nodiscard]] std::size_t
    get_dynamic_table_size() const {
        return _dynamic_table.byte_size();
    }

    [[nodiscard]] std::size_t
    get_dynamic_table_entry_count() const {
        return _dynamic_table.size();
    }
};

/**
 * @brief HPACK encoder (RFC 7541).
 *
 * F35 &mdash; de-virtualised companion to `Decoder`. See that class's
 * comment for the rationale.
 *
 * Manages a dynamic table synchronized with the decoder's table and
 * encodes header fields using optimal representations.
 */
class Encoder {
private:
    DynamicTable       _dynamic_table;                                                ///< Dynamic header table (F34 ring buffer)
    std::size_t        _peer_max_dynamic_table_octets = HPACK_DEFAULT_MAX_TABLE_SIZE; ///< Peer's max table size
    mutable HpackStats _stats;                                                        ///< Encoding statistics

    /**
     * @brief Encode an integer in HPACK format (RFC 7541, Section 5.1)
     * @param buffer Output buffer
     * @param prefix_bits Prefix bits for the first byte
     * @param N Prefix size in bits
     * @param value Value to encode
     */
    static void encode_integer(std::vector<uint8_t> &buffer, uint8_t prefix_bits, uint8_t N, uint64_t value);

    /**
     * @brief Encode a string literal in HPACK format (RFC 7541, Section 5.2).
     *
     * Takes the payload by `std::string_view` so callers holding views, spans,
     * or `HeaderField::name/value` fields don't pay a `std::string` copy just
     * to invoke the encoder.
     *
     * @param buffer Output buffer (data is appended)
     * @param str String to encode
     * @param huffman_allowed Whether Huffman encoding is allowed
     */
    void encode_string_literal(std::vector<uint8_t> &buffer, std::string_view str, bool huffman_allowed = true) const;

    /**
     * @brief Add entry to encoder's dynamic table through the shared ring
     *        buffer. Statistics are updated from the `AddResult` so the hot
     *        path stays branch-light.
     */
    void
    add_to_dynamic_table(std::string name, std::string value) {
        const auto result = _dynamic_table.add(std::move(name), std::move(value));
        _stats.dynamic_table_evictions += result.evicted;
        if (result.added) {
            _stats.dynamic_table_insertions++;
        }
    }

public:
    Encoder() = default;

    /**
     * @brief Encode a list of header fields into an HPACK header block.
     *
     * Chooses the most compact representation for each field: indexed when an
     * exact static/dynamic match exists, otherwise a literal (never indexed
     * for sensitive or pseudo-headers, incremental indexing when the field is
     * eligible for the dynamic table, plain literal otherwise). The dynamic
     * table is updated for incrementally-indexed fields. Encoded bytes are
     * appended to @p out_buffer.
     *
     * @param headers_to_encode List of header fields to encode.
     * @param out_buffer        Buffer the encoded block is appended to.
     * @return true on success, false if any field fails validation.
     */
    bool encode(const std::vector<HeaderField> &headers_to_encode, std::vector<uint8_t> &out_buffer);

    void
    set_peer_max_dynamic_table_size(uint32_t max_size) {
        _peer_max_dynamic_table_octets = max_size;
        // Clamp our local budget so we never advertise more than the peer
        // allows. Evictions happen inside `DynamicTable::set_max_byte_size`.
        if (_dynamic_table.max_byte_size() > _peer_max_dynamic_table_octets) {
            _stats.dynamic_table_evictions += _dynamic_table.set_max_byte_size(_peer_max_dynamic_table_octets);
        }
    }

    void
    set_max_capacity(uint32_t max_capacity) {
        _stats.dynamic_table_evictions += _dynamic_table.set_max_byte_size(max_capacity);
    }

    void
    reset() {
        _dynamic_table.clear();
        _stats.reset();
    }

    [[nodiscard]] const HpackStats &
    get_stats() const {
        return _stats;
    }

    [[nodiscard]] std::size_t
    get_dynamic_table_size() const {
        return _dynamic_table.byte_size();
    }

    [[nodiscard]] std::size_t
    get_dynamic_table_entry_count() const {
        return _dynamic_table.size();
    }
};

// F35 &mdash; the former abstract interfaces and `create()` factories have
// been removed. Consumers now own `Decoder` / `Encoder` by value.

// Utility functions for converting between HeaderField and qb::http::Headers
namespace conversion {
// Convert from qb::http::Headers to std::vector<HeaderField>
template <typename HeadersType>
std::vector<HeaderField>
from_qb_headers(const HeadersType & /*qb_headers*/) {
    std::vector<HeaderField> fields;
    // This would need to be implemented based on the actual qb::http::Headers interface
    // For now, this is a placeholder
    return fields;
}

// Convert from std::vector<HeaderField> to qb::http::Headers
template <typename HeadersType>
HeadersType
to_qb_headers(const std::vector<HeaderField> & /*fields*/) {
    HeadersType headers;
    // This would need to be implemented based on the actual qb::http::Headers interface
    // For now, this is a placeholder
    return headers;
}
} // namespace conversion

// Convenience functions for common operations
namespace convenience {
/**
 * @brief Encode headers directly to bytes
 * @param headers Header fields to encode
 * @return Encoded HPACK bytes
 */
inline std::vector<uint8_t>
encode_headers(const std::vector<HeaderField> &headers) {
    Encoder              encoder;
    std::vector<uint8_t> result;
    encoder.encode(headers, result);
    return result;
}

/**
 * @brief Decode bytes directly to headers
 * @param data HPACK-encoded data
 * @return Decoded header fields, or nullopt on error
 */
inline std::optional<std::vector<HeaderField>>
decode_headers(const std::vector<uint8_t> &data) {
    Decoder                  decoder;
    std::vector<HeaderField> headers;
    bool                     incomplete = false;

    if (decoder.decode(data, headers, incomplete) && !incomplete) {
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
inline HeaderField
make_header(const std::string &name, const std::string &value) {
    HeaderField field(name, value);
    field.sensitive = field.is_sensitive_by_default();
    return field;
}
} // namespace convenience

} // namespace qb::protocol::hpack
