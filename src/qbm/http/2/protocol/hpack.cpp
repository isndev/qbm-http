/**
 * @file qbm/http/2/protocol/hpack.cpp
 * @brief HPACK header compression out-of-line definitions for qb-io framework
 *
 * This file holds the non-template, out-of-line definitions for the HPACK
 * (HTTP/2 Header Compression, RFC 7541) implementation declared in hpack.h:
 *
 * - Dynamic table ring-buffer operations (add / resize / growth)
 * - HPACK integer and string-literal encoding/decoding
 * - Static and dynamic table index resolution
 * - The encoder and decoder header-block entry points
 *
 * The compile-time static table, statistics, validation helpers, trivial
 * accessors, and the conversion templates remain inline in hpack.h.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./hpack.h"

#include <algorithm>

namespace qb::protocol::hpack {

DynamicTable::AddResult
DynamicTable::add(std::string name, std::string value) {
    DynamicTableEntry entry(std::move(name), std::move(value));
    const std::size_t entry_size = entry.size;

    AddResult result{};

    // RFC 7541 §4.4: oversize entry => wipe table, do not insert.
    if (entry_size > _max_bytes) {
        result.evicted = _count;
        clear_storage();
        return result;
    }

    while (_bytes + entry_size > _max_bytes && _count > 0) {
        evict_oldest_impl();
        ++result.evicted;
    }

    ensure_capacity_for_one_more();

    // Push to front: the "head" is the slot holding the newest entry.
    _head           = (_head - 1) & _mask;
    _storage[_head] = std::move(entry);
    ++_count;
    _bytes += entry_size;
    result.added = true;
    return result;
}

std::size_t
DynamicTable::set_max_byte_size(std::size_t new_max) {
    _max_bytes          = new_max;
    std::size_t evicted = 0;
    while (_bytes > _max_bytes && _count > 0) {
        evict_oldest_impl();
        ++evicted;
    }
    if (_count == 0) {
        _bytes = 0; // Paranoid reset against accumulated rounding.
    }
    return evicted;
}

void
DynamicTable::ensure_capacity_for_one_more() {
    if (_storage.empty()) {
        _storage.resize(kInitialCapacity);
        _mask = kInitialCapacity - 1;
        return;
    }
    if (_count + 1 <= _storage.size()) {
        return;
    }
    // Double the ring-buffer capacity and linearise entries so that the
    // new head starts at slot 0. This happens at most a handful of times
    // over the life of a long-running HTTP/2 connection.
    const std::size_t              new_cap = _storage.size() * 2;
    std::vector<DynamicTableEntry> new_storage(new_cap);
    for (std::size_t i = 0; i < _count; ++i) {
        new_storage[i] = std::move(_storage[slot_of(i)]);
    }
    _storage = std::move(new_storage);
    _head    = 0;
    _mask    = new_cap - 1;
}

std::pair<uint64_t, int>
Decoder::decode_integer(const uint8_t *&current_pos, const uint8_t *end_pos, uint8_t N) {
    if (current_pos >= end_pos)
        return {0, -1};

    const uint8_t prefix_mask    = (1 << N) - 1;
    uint64_t      value          = (*current_pos) & prefix_mask;
    int           bytes_consumed = 1;

    if (value < prefix_mask) {
        current_pos++;
        return {value, bytes_consumed};
    }

    // Multi-byte integer
    current_pos++;
    uint64_t M = 0;
    uint8_t  byte_val;

    do {
        if (current_pos >= end_pos)
            return {0, -1};
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

std::pair<std::optional<std::string>, int>
Decoder::decode_string_literal(const uint8_t *&current_pos, const uint8_t *end_pos, bool &out_is_possibly_incomplete, HpackStats &stats) {
    if (current_pos >= end_pos) {
        return {std::nullopt, -1};
    }

    uint8_t first_byte_of_string_field = *current_pos;
    bool    huffman_encoded            = (first_byte_of_string_field & 0x80);

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
        value_str.assign(reinterpret_cast<const char *>(current_pos), length);
    }

    current_pos += length;
    stats.bytes_decoded += length;
    return {std::move(value_str), static_cast<int>(length)};
}

bool
Decoder::get_dynamic_table_entry(uint64_t index, std::string_view &name, std::string_view &value) const {
    // index != 0 guards the STATIC_TABLE[index - 1] access below: index 0 is invalid in
    // HPACK (callers reject it), but without this an index of 0 would compute
    // STATIC_TABLE[(size_t)-1] — a wild OOB read. Defense-in-depth against a future caller.
    if (index != 0 && index <= STATIC_TABLE.size()) {
        const auto &entry = STATIC_TABLE[index - 1];
        name              = entry.first;
        value             = entry.second;
        _stats.static_table_hits++;
        return true;
    } else {
        std::size_t dynamic_index = index - STATIC_TABLE.size();
        if (dynamic_index > _dynamic_table.size() || dynamic_index == 0) {
            return false;
        }
        const auto &entry = _dynamic_table[dynamic_index - 1];
        name              = entry.name;
        value             = entry.value;
        _stats.dynamic_table_hits++;
        return true;
    }
}

bool
Decoder::get_name_from_index(uint64_t index, std::string_view &name) const {
    // index != 0 guards STATIC_TABLE[index - 1] against a (size_t)-1 OOB read (see
    // get_dynamic_table_entry). Defense-in-depth; current callers already reject index 0.
    if (index != 0 && index <= STATIC_TABLE.size()) {
        name = STATIC_TABLE[index - 1].first;
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

bool
Decoder::decode(const std::vector<uint8_t> &encoded_block, std::vector<HeaderField> &out_headers, bool &out_is_possibly_incomplete) {
    return decode_block(encoded_block, out_headers, out_is_possibly_incomplete, nullptr);
}

bool
Decoder::decode(const std::vector<uint8_t> &encoded_block, std::vector<HeaderField> &out_headers, bool &out_is_possibly_incomplete,
                bool &out_over_list_size) {
    out_over_list_size = false;
    return decode_block(encoded_block, out_headers, out_is_possibly_incomplete, &out_over_list_size);
}

bool
Decoder::decode_block(const std::vector<uint8_t> &encoded_block, std::vector<HeaderField> &out_headers, bool &out_is_possibly_incomplete,
                      bool *out_over_list_size) {
    const uint8_t *current_pos                 = encoded_block.data();
    const uint8_t *end_pos                     = encoded_block.data() + encoded_block.size();
    out_is_possibly_incomplete                 = false;
    std::size_t current_header_list_size_check = 0;
    out_headers.clear();

    _stats.bytes_decoded += encoded_block.size();
    bool dynamic_table_size_updates_allowed = true;

    // The header-list bound (RFC 9113 §6.5.2: names, values and 32 octets a field). Past it, a caller that asked to
    // discard has the rest of the block decoded -- the dynamic table kept in step with the peer's encoder, which
    // indexed those fields whatever the receiver does with them (RFC 9113 §10.5.1) -- and dropped, up to
    // HPACK_DISCARDED_LIST_FACTOR times the bound; another caller has the block refused, as every caller had (Huly
    // QB-1196: the HTTP/2 server closed the connection for a list its peer was never told it would refuse).
    const std::size_t bound   = _max_header_list_size_from_settings;
    const std::size_t ceiling = bound > SIZE_MAX / HPACK_DISCARDED_LIST_FACTOR ? SIZE_MAX : bound * HPACK_DISCARDED_LIST_FACTOR;
    bool              refused = false;
    // Counts a field of `size` octets: whether it is kept. A field past the bound is dropped; `refused` says the block
    // fails instead.
    const auto admit = [&](std::size_t size) noexcept -> bool {
        current_header_list_size_check += size;
        if (bound == 0 || current_header_list_size_check <= bound) [[likely]] {
            return true;
        }
        if (!out_over_list_size || current_header_list_size_check > ceiling) {
            refused = true;
        } else {
            *out_over_list_size = true;
        }
        return false;
    };

    while (current_pos < end_pos) {
        uint8_t first_byte = *current_pos;

        if (first_byte >> 7 == 1) { // Indexed Header Field (1xxxxxxx)
            dynamic_table_size_updates_allowed = false;
            auto [index, index_len]            = decode_integer(current_pos, end_pos, 7);
            if (index_len < 0) {
                out_is_possibly_incomplete = true;
                return false;
            }

            if (index == 0) {
                return false;
            }

            // Read in place: a field dropped past the bound costs no copy, so a reference to a large entry repeated
            // across the block amplifies nothing. A field kept is written into the vector from the two views, name
            // then value -- no temporary, no move. Two temporaries moved in (`std::string(name), std::string(value)`)
            // cost g++ 14 +6.7 % on a browser's request with FEWER instructions: built to their exact length, their
            // buffers fell into a glibc bin the request's own malloc_consolidate() empties, fifteen allocations a
            // request past the tcache, where assign() on an empty string sizes as the pushed train's copies did (QB-1196).
            std::string_view name, value;
            if (!get_dynamic_table_entry(index, name, value)) {
                return false;
            }
            if (admit(name.size() + value.size() + HPACK_ENTRY_OVERHEAD)) {
                auto &field = out_headers.emplace_back();
                field.name.assign(name.data(), name.size());
                field.value.assign(value.data(), value.size());
            } else if (refused) {
                return false;
            }

        } else if (first_byte >> 6 == 0b01) { // Literal Header Field with Incremental Indexing (01xxxxxx)
            dynamic_table_size_updates_allowed = false;
            auto [index, index_len]            = decode_integer(current_pos, end_pos, 6);
            if (index_len < 0) {
                out_is_possibly_incomplete = true;
                return false;
            }

            std::string name, value;

            if (index == 0) {
                auto [decoded_name, name_consumed_len] = decode_string_literal(current_pos, end_pos, out_is_possibly_incomplete, _stats);
                if (!decoded_name) {
                    return false;
                }
                name = std::move(decoded_name.value());
            } else {
                std::string_view indexed_name;
                if (!get_name_from_index(index, indexed_name)) {
                    return false;
                }
                name.assign(indexed_name); // the table entry it names may be evicted by this one
            }

            auto [decoded_value, value_consumed_len] = decode_string_literal(current_pos, end_pos, out_is_possibly_incomplete, _stats);
            if (!decoded_value) {
                out_is_possibly_incomplete = true;
                return false;
            }
            value = std::move(decoded_value.value());

            if (admit(name.length() + value.length() + HPACK_ENTRY_OVERHEAD)) {
                out_headers.emplace_back(name, value);
            } else if (refused) {
                return false;
            }
            add_to_dynamic_table(std::move(name), std::move(value)); // kept or dropped, the peer's encoder indexed it

        } else if (first_byte >> 4 == 0b0000 || first_byte >> 4 == 0b0001) {
            // Literal Header Field without Indexing (0000xxxx) or never Indexed (0001xxxx): one layout, the second
            // marking the field sensitive.
            const bool never_indexed           = first_byte >> 4 == 0b0001;
            dynamic_table_size_updates_allowed = false;
            auto [index, index_len]            = decode_integer(current_pos, end_pos, 4);
            if (index_len < 0) {
                out_is_possibly_incomplete = true;
                return false;
            }

            std::string      literal_name;
            std::string_view indexed_name;
            if (index == 0) {
                auto [decoded_name, name_consumed_len] = decode_string_literal(current_pos, end_pos, out_is_possibly_incomplete, _stats);
                if (!decoded_name) {
                    return false;
                }
                literal_name = std::move(decoded_name.value());
            } else {
                if (!get_name_from_index(index, indexed_name)) {
                    return false;
                }
            }
            auto [decoded_value, value_consumed_len] = decode_string_literal(current_pos, end_pos, out_is_possibly_incomplete, _stats);
            if (!decoded_value) {
                out_is_possibly_incomplete = true;
                return false;
            }

            const std::size_t name_length = index == 0 ? literal_name.length() : indexed_name.length();
            if (admit(name_length + decoded_value->length() + HPACK_ENTRY_OVERHEAD)) {
                // The literal name moves straight in and the indexed one is copied straight in: a conditional
                // expression over the two materialised a temporary, moved in, for both.
                if (index == 0) {
                    out_headers.emplace_back(std::move(literal_name), std::move(decoded_value.value()), never_indexed);
                } else {
                    out_headers.emplace_back(std::string(indexed_name), std::move(decoded_value.value()), never_indexed);
                }
            } else if (refused) {
                return false;
            }

        } else if (first_byte >> 5 == 0b001) { // Dynamic Table Size Update (001xxxxx)
            if (!dynamic_table_size_updates_allowed) {
                return false;
            }
            auto [new_max_size, size_len] = decode_integer(current_pos, end_pos, 5);
            if (size_len < 0) {
                out_is_possibly_incomplete = true;
                return false;
            }

            if (new_max_size > _max_dynamic_table_octets_limit_from_settings) {
                return false;
            }
            _stats.dynamic_table_evictions += _dynamic_table.set_max_byte_size(static_cast<std::size_t>(new_max_size));
        } else {
            return false; // Unknown instruction
        }
    }

    _stats.headers_decoded += out_headers.size();
    return true;
}

void
Encoder::encode_integer(std::vector<uint8_t> &buffer, uint8_t prefix_bits, uint8_t N, uint64_t value) {
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

void
Encoder::encode_string_literal(std::vector<uint8_t> &buffer, std::string_view str, bool huffman_allowed) const {
    const bool    use_huffman            = huffman_allowed && huffman::should_use_huffman(str);
    const uint8_t prefix_byte_for_length = use_huffman ? 0x80 : 0x00;

    if (use_huffman) {
        std::vector<uint8_t> huffman_encoded_str_bytes;
        if (huffman::huffman_encode(str, huffman_encoded_str_bytes)) {
            encode_integer(buffer, prefix_byte_for_length, 7, huffman_encoded_str_bytes.size());
            buffer.insert(buffer.end(), huffman_encoded_str_bytes.begin(), huffman_encoded_str_bytes.end());
            _stats.huffman_encoded_strings++;
            _stats.bytes_encoded += huffman_encoded_str_bytes.size();
            return;
        }
        // Fallback to non-Huffman
    }
    encode_integer(buffer, 0x00, 7, str.length());
    buffer.insert(buffer.end(), str.begin(), str.end());
    _stats.bytes_encoded += str.length();
}

void
Encoder::apply_table_size() {
    const std::size_t size = std::min(_own_max_dynamic_table_octets, _peer_max_dynamic_table_octets);
    if (size == _dynamic_table.max_byte_size()) {
        return; // nothing changed, nothing to announce
    }
    _stats.dynamic_table_evictions += _dynamic_table.set_max_byte_size(size);
    _pending_min_table_size    = _table_size_update_pending ? std::min(_pending_min_table_size, size) : size;
    _table_size_update_pending = true;
}

bool
Encoder::encode(const std::vector<HeaderField> &headers_to_encode, std::vector<uint8_t> &out_buffer) {
    // Validate the whole list before writing a byte or touching the table: a refused list must
    // leave the encoder exactly as the peer's decoder, which never receives it, believes it is
    // (Huly QB-563). The fields below are then known valid.
    for (const auto &header_field : headers_to_encode) {
        if (!header_validation::is_valid_header_field(header_field)) [[unlikely]] {
            return false;
        }
    }

    std::size_t initial_size = out_buffer.size();

    // RFC 7541 §4.2: a table size change since the previous block is announced at the start of
    // this one -- the smallest size reached first when the size moved more than once.
    if (_table_size_update_pending) [[unlikely]] {
        const std::size_t final_size = _dynamic_table.max_byte_size();
        if (_pending_min_table_size < final_size) {
            encode_integer(out_buffer, static_cast<uint8_t>(InstructionType::DYNAMIC_TABLE_SIZE_UPDATE), 5, _pending_min_table_size);
        }
        encode_integer(out_buffer, static_cast<uint8_t>(InstructionType::DYNAMIC_TABLE_SIZE_UPDATE), 5, final_size);
        _table_size_update_pending = false;
    }

    for (const auto &header_field : headers_to_encode) {
        const std::string &name  = header_field.name;
        const std::string &value = header_field.value;

        // A field the caller marked never-indexed stays a literal never indexed whatever the
        // tables hold: an indexed representation would drop the marker every intermediary must
        // keep (RFC 7541 §6.2.3, Huly QB-526). So an exact match is used only for an unmarked
        // field -- tested on the match, off the common path. (A default-sensitive name needs no
        // such test: it is never inserted in the dynamic table, and its static entries only match
        // an empty value, which hides nothing.)
        const bool marked_never_indexed = header_field.sensitive;

        // Try to find exact match in static table
        if (auto static_index = static_table::find_exact_match(name, value); static_index && !marked_never_indexed) {
            encode_integer(out_buffer, static_cast<uint8_t>(InstructionType::INDEXED_HEADER_FIELD), 7, *static_index);
            _stats.static_table_hits++;
            continue;
        }

        // PERFORMANCE FIX: Combined search for exact match and name match in single pass
        // Previously: Two separate O(N) loops (2N comparisons worst case)
        // Now: Single O(N) loop with early exit on exact match (N comparisons)
        // For dynamic tables with 64 entries and 100 headers: saves ~6,400 comparisons
        auto                       static_name_idx = static_table::find_name_match(name);
        std::optional<std::size_t> dynamic_name_idx;
        bool                       found_in_dynamic_full = false;

        for (size_t i = 0; i < _dynamic_table.size(); ++i) {
            if (_dynamic_table[i].name == name) {
                dynamic_name_idx = STATIC_TABLE.size() + i + 1;
                if (_dynamic_table[i].value == value && !marked_never_indexed) {
                    // Exact match found - can stop here
                    encode_integer(out_buffer, static_cast<uint8_t>(InstructionType::INDEXED_HEADER_FIELD), 7, STATIC_TABLE.size() + i + 1);
                    found_in_dynamic_full = true;
                    _stats.dynamic_table_hits++;
                    break;
                }
            }
        }
        if (found_in_dynamic_full)
            continue;

        // Determine encoding strategy
        bool is_sensitive          = marked_never_indexed || header_field.is_sensitive_by_default();
        bool is_pseudo             = header_field.is_pseudo_header();
        bool use_never_indexed     = is_sensitive || is_pseudo;
        bool can_be_added_to_table = header_field.hpack_size() <= _dynamic_table.max_byte_size() && !is_sensitive && !is_pseudo;

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

} // namespace qb::protocol::hpack
