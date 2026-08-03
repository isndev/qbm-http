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
Decoder::get_dynamic_table_entry(uint64_t index, std::string &name, std::string &value) const {
    // index != 0 guards the STATIC_TABLE[index - 1] access below: index 0 is invalid in
    // HPACK (callers reject it), but without this an index of 0 would compute
    // STATIC_TABLE[(size_t)-1] — a wild OOB read. Defense-in-depth against a future caller.
    if (index != 0 && index <= STATIC_TABLE.size()) {
        const auto &entry = STATIC_TABLE[index - 1];
        name              = std::string(entry.first);
        value             = std::string(entry.second);
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
Decoder::get_name_from_index(uint64_t index, std::string &name) const {
    // index != 0 guards STATIC_TABLE[index - 1] against a (size_t)-1 OOB read (see
    // get_dynamic_table_entry). Defense-in-depth; current callers already reject index 0.
    if (index != 0 && index <= STATIC_TABLE.size()) {
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

bool
Decoder::decode(const std::vector<uint8_t> &encoded_block, std::vector<HeaderField> &out_headers, bool &out_is_possibly_incomplete) {
    const uint8_t *current_pos                 = encoded_block.data();
    const uint8_t *end_pos                     = encoded_block.data() + encoded_block.size();
    out_is_possibly_incomplete                 = false;
    std::size_t current_header_list_size_check = 0;
    out_headers.clear();

    _stats.bytes_decoded += encoded_block.size();
    bool dynamic_table_size_updates_allowed = true;

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

            std::string name, value;
            if (!get_dynamic_table_entry(index, name, value)) {
                return false;
            }
            out_headers.emplace_back(std::move(name), std::move(value));
            current_header_list_size_check += out_headers.back().hpack_size();

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
                if (!get_name_from_index(index, name)) {
                    return false;
                }
            }

            auto [decoded_value, value_consumed_len] = decode_string_literal(current_pos, end_pos, out_is_possibly_incomplete, _stats);
            if (!decoded_value) {
                out_is_possibly_incomplete = true;
                return false;
            }
            value = std::move(decoded_value.value());

            current_header_list_size_check += name.length() + value.length() + HPACK_ENTRY_OVERHEAD;
            out_headers.emplace_back(name, value);
            add_to_dynamic_table(std::move(name), std::move(value));

        } else if (first_byte >> 4 == 0b0000) { // Literal Header Field without Indexing (0000xxxx)
            dynamic_table_size_updates_allowed = false;
            auto [index, index_len]            = decode_integer(current_pos, end_pos, 4);
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
                if (!get_name_from_index(index, name)) {
                    return false;
                }
            }
            auto [decoded_value, value_consumed_len] = decode_string_literal(current_pos, end_pos, out_is_possibly_incomplete, _stats);
            if (!decoded_value) {
                out_is_possibly_incomplete = true;
                return false;
            }
            value = std::move(decoded_value.value());

            current_header_list_size_check += name.length() + value.length() + HPACK_ENTRY_OVERHEAD;
            out_headers.emplace_back(std::move(name), std::move(value));

        } else if (first_byte >> 4 == 0b0001) { // Literal Header Field never Indexed (0001xxxx)
            dynamic_table_size_updates_allowed = false;
            auto [index, index_len]            = decode_integer(current_pos, end_pos, 4);
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
                if (!get_name_from_index(index, name)) {
                    return false;
                }
            }
            auto [decoded_value, value_consumed_len] = decode_string_literal(current_pos, end_pos, out_is_possibly_incomplete, _stats);
            if (!decoded_value) {
                out_is_possibly_incomplete = true;
                return false;
            }
            value = std::move(decoded_value.value());

            current_header_list_size_check += name.length() + value.length() + HPACK_ENTRY_OVERHEAD;
            HeaderField field(std::move(name), std::move(value));
            field.sensitive = true; // Mark as sensitive
            out_headers.push_back(std::move(field));

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

        if (_max_header_list_size_from_settings > 0 && current_header_list_size_check > _max_header_list_size_from_settings) {
            return false;
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

bool
Encoder::encode(const std::vector<HeaderField> &headers_to_encode, std::vector<uint8_t> &out_buffer) {
    std::size_t initial_size = out_buffer.size();

    for (const auto &header_field : headers_to_encode) {
        const std::string &name  = header_field.name;
        const std::string &value = header_field.value;

        // Validate header field
        if (!header_validation::is_valid_header_field(header_field)) {
            return false;
        }

        // Try to find exact match in static table
        if (auto static_index = static_table::find_exact_match(name, value)) {
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
                if (_dynamic_table[i].value == value) {
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
        bool is_sensitive          = header_field.sensitive || header_field.is_sensitive_by_default();
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
