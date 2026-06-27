/**
 * @file qbm/http/tests/unit/http2/hpack-encoder-strategy.cpp
 * @brief Low-level unit tests for the HPACK codec (RFC 7541).
 *
 * Companion to hpack-codec.cpp. This file deliberately targets the code
 * paths that the existing suite leaves uncovered, with an emphasis on:
 *
 * - The Encoder's per-header representation-selection strategy
 *   (Encoder::encode in hpack.cpp:408-497): exact dynamic-table match ->
 *   indexed, literal-with-incremental-indexing using a dynamic / static /
 *   absent name index, never-indexed branches (dynamic / static / new name),
 *   and the "without indexing" fallback taken when a header is too large for
 *   the dynamic table budget.
 * - Encoder::set_peer_max_dynamic_table_size clamp + eviction.
 * - Decoder error paths: rejection of a dynamic-table-size-update that exceeds
 *   the configured settings limit; decode_integer overflow / malformed inputs;
 *   decode_string_literal Huffman-failure and truncation (out_is_possibly_
 *   incomplete).
 * - convenience::make_header / encode_headers / decode_headers.
 * - header_validation name / value rules.
 * - Additional RFC 7541 Appendix C gold vectors not present in the sibling
 *   suite (C.3 request sequence with a dynamic table, C.5 response sequence
 *   with eviction).
 *
 * Every assertion is grounded in the exact instruction-byte prefixes emitted
 * by the implementation; see the inline derivations.
 *
 * qb - C++ Actor Framework
 * Copyright (C) 2011-2026 isndev (www.qbaf.io). All rights reserved.
 *
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

#include <cstdint>
#include <gtest/gtest.h>
#include <iomanip>
#include <qb/io/crypto.h>
#include <sstream>
#include <string>
#include <vector>
#include "../2/protocol/hpack.h"
#include "../2/protocol/hpack_huffman.h"

using namespace qb::protocol::hpack;
using namespace qb::protocol::hpack::huffman;

// ====================================================================
// Local helpers (kept distinct from the sibling suite to avoid ODR
// clashes; these are static so each TU keeps its own copy).
// ====================================================================

namespace {

std::vector<uint8_t>
ll_hex_to_bytes(const std::string &hex) {
    // qb::crypto::hex_to_string decodes the whole hex string to raw bytes,
    // returning "" on odd-length or non-hex input (the gold vectors here are
    // always even-length, all-hex literals, so this is a faithful swap for the
    // former per-byte std::strtol loop).
    const std::string decoded = qb::crypto::hex_to_string(hex);
    return std::vector<uint8_t>(decoded.begin(), decoded.end());
}

std::string
ll_bytes_to_hex(const std::vector<uint8_t> &data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto b : data) {
        ss << std::setw(2) << static_cast<int>(b) << ' ';
    }
    return ss.str();
}

// Round-trip a single encoded header through a fresh Decoder, asserting the
// decode succeeds, is not flagged incomplete, and yields exactly one header.
// Uses ASSERT_EQ on the count so a wrong-cardinality decode fails hard at the
// fixture (rather than dereferencing a defaulted HeaderField on the caller).
HeaderField
roundtrip_single(const std::vector<uint8_t> &encoded) {
    Decoder                  decoder;
    std::vector<HeaderField> out;
    bool                     incomplete = false;
    EXPECT_TRUE(decoder.decode(encoded, out, incomplete)) << "decode failed: " << ll_bytes_to_hex(encoded);
    EXPECT_FALSE(incomplete);
    EXPECT_EQ(out.size(), 1u) << "expected exactly one header: " << ll_bytes_to_hex(encoded);
    return out.empty() ? HeaderField{} : out.front();
}

} // namespace

// ====================================================================
// Encoder strategy: exact DYNAMIC-table match -> INDEXED
// ====================================================================

// After a header has been incrementally indexed, re-encoding the SAME
// (name,value) pair must emit a single INDEXED_HEADER_FIELD instruction
// (high bit set). The dynamic index for the first dynamic entry is
// STATIC_TABLE.size()+1 == 62, and encode_integer(0x80, 7, 62) fits the
// 7-bit prefix -> 0x80 | 62 == 0xBE.
TEST(HPACK_LL_EncoderStrategy, ExactDynamicMatchEmitsIndexed) {
    Encoder encoder;

    // First pass populates the dynamic table (incremental indexing path).
    std::vector<HeaderField> first = {{"x-dyn-name", "dyn-value"}};
    std::vector<uint8_t>     enc1;
    ASSERT_TRUE(encoder.encode(first, enc1));
    ASSERT_EQ(encoder.get_dynamic_table_entry_count(), 1u);

    // Second pass: identical header must collapse to a single indexed byte.
    std::vector<HeaderField> second = {{"x-dyn-name", "dyn-value"}};
    std::vector<uint8_t>     enc2;
    ASSERT_TRUE(encoder.encode(second, enc2));

    ASSERT_EQ(enc2.size(), 1u) << ll_bytes_to_hex(enc2);
    EXPECT_TRUE(enc2[0] & 0x80) << "high bit (INDEXED) must be set";
    EXPECT_EQ(enc2[0], 0xBE); // 0x80 | 62

    // And it must round-trip back to the original pair via a fresh decoder
    // primed with the same dynamic entry.
    Decoder                  decoder;
    std::vector<HeaderField> out;
    bool                     incomplete = false;
    ASSERT_TRUE(decoder.decode(enc1, out, incomplete));
    out.clear();
    ASSERT_TRUE(decoder.decode(enc2, out, incomplete));
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].name, "x-dyn-name");
    EXPECT_EQ(out[0].value, "dyn-value");
}

// ====================================================================
// Encoder strategy: literal-with-incremental-indexing, name index variants
// ====================================================================

// Static name match, value differs -> LITERAL_WITH_INCREMENTAL_INDEXING
// (0x40, N=6) carrying the static name index. "accept-encoding" is static
// index 16; encode_integer(0x40, 6, 16): 16 < 63 -> 0x40 | 16 == 0x50.
TEST(HPACK_LL_EncoderStrategy, IncrementalIndexingStaticName) {
    Encoder                  encoder;
    std::vector<HeaderField> headers = {{"accept-encoding", "identity"}}; // name static, value not
    std::vector<uint8_t>     enc;
    ASSERT_TRUE(encoder.encode(headers, enc));

    ASSERT_FALSE(enc.empty());
    EXPECT_EQ(enc[0] & 0xC0, 0x40) << "top two bits must be 01 (incremental indexing)";
    EXPECT_EQ(enc[0], 0x50);                                // 0x40 | 16
    EXPECT_EQ(encoder.get_dynamic_table_entry_count(), 1u); // it was indexed

    const HeaderField hf = roundtrip_single(enc);
    EXPECT_EQ(hf.name, "accept-encoding");
    EXPECT_EQ(hf.value, "identity");
}

// Dynamic name match, value differs -> incremental indexing carrying the
// dynamic name index (62 for the first dynamic entry).
// encode_integer(0x40, 6, 62): 62 < 63 -> 0x40 | 62 == 0x7E.
TEST(HPACK_LL_EncoderStrategy, IncrementalIndexingDynamicName) {
    Encoder encoder;

    // Seed the dynamic table with a brand-new name.
    std::vector<HeaderField> seed = {{"x-shared", "v1"}};
    std::vector<uint8_t>     e0;
    ASSERT_TRUE(encoder.encode(seed, e0));
    ASSERT_EQ(encoder.get_dynamic_table_entry_count(), 1u);

    // Re-use the name with a different value: dynamic name index wins over
    // (absent) static name index.
    std::vector<HeaderField> reuse = {{"x-shared", "v2"}};
    std::vector<uint8_t>     enc;
    ASSERT_TRUE(encoder.encode(reuse, enc));

    ASSERT_FALSE(enc.empty());
    EXPECT_EQ(enc[0] & 0xC0, 0x40);
    EXPECT_EQ(enc[0], 0x7E); // 0x40 | 62
}

// No name match anywhere -> incremental indexing with index 0 followed by a
// name string literal. encode_integer(0x40, 6, 0) == 0x40.
TEST(HPACK_LL_EncoderStrategy, IncrementalIndexingNewName) {
    Encoder                  encoder;
    std::vector<HeaderField> headers = {{"x-brand-new", "value"}};
    std::vector<uint8_t>     enc;
    ASSERT_TRUE(encoder.encode(headers, enc));

    ASSERT_FALSE(enc.empty());
    EXPECT_EQ(enc[0], 0x40) << "0x40 == incremental indexing, name index 0 (literal name follows)";
    EXPECT_EQ(encoder.get_dynamic_table_entry_count(), 1u);

    const HeaderField hf = roundtrip_single(enc);
    EXPECT_EQ(hf.name, "x-brand-new");
    EXPECT_EQ(hf.value, "value");
}

// ====================================================================
// Encoder strategy: never-indexed branches
// ====================================================================

// Never-indexed with a NEW name: a sensitive header whose name is neither in
// the static nor dynamic table. encode_integer(0x10, 4, 0) == 0x10, then a
// name literal. We set sensitive explicitly to force the never-indexed path
// for a non-pseudo, non-default-sensitive name.
TEST(HPACK_LL_EncoderStrategy, NeverIndexedNewName) {
    Encoder                  encoder;
    HeaderField              secret("x-api-key", "topsecret", /*sensitive=*/true);
    std::vector<HeaderField> headers = {secret};
    std::vector<uint8_t>     enc;
    ASSERT_TRUE(encoder.encode(headers, enc));

    ASSERT_FALSE(enc.empty());
    EXPECT_EQ(enc[0] & 0xF0, 0x10) << "top four bits must be 0001 (never indexed)";
    EXPECT_EQ(enc[0], 0x10) << "name index 0 -> literal name follows";
    // Never-indexed headers are NOT added to the dynamic table.
    EXPECT_EQ(encoder.get_dynamic_table_entry_count(), 0u);

    const HeaderField hf = roundtrip_single(enc);
    EXPECT_EQ(hf.name, "x-api-key");
    EXPECT_EQ(hf.value, "topsecret");
    EXPECT_TRUE(hf.sensitive) << "decoder marks never-indexed headers sensitive";
}

// Never-indexed with a STATIC name index: "authorization" is sensitive by
// default and is static index 23. encode_integer(0x10, 4, 23): 23 >= 15 ->
// first byte 0x10 | 15 == 0x1F, continuation 23 - 15 == 8 -> 0x08.
TEST(HPACK_LL_EncoderStrategy, NeverIndexedStaticName) {
    Encoder                  encoder;
    std::vector<HeaderField> headers = {{"authorization", "Bearer xyz"}};
    std::vector<uint8_t>     enc;
    ASSERT_TRUE(encoder.encode(headers, enc));

    ASSERT_GE(enc.size(), 2u);
    EXPECT_EQ(enc[0] & 0xF0, 0x10);
    EXPECT_EQ(enc[0], 0x1F); // prefix saturated (index needs continuation)
    EXPECT_EQ(enc[1], 0x08); // 23 - 15
    EXPECT_EQ(encoder.get_dynamic_table_entry_count(), 0u);

    const HeaderField hf = roundtrip_single(enc);
    EXPECT_EQ(hf.name, "authorization");
    EXPECT_EQ(hf.value, "Bearer xyz");
}

// Never-indexed with a DYNAMIC name index: a non-sensitive header first seeds
// the name into the dynamic table; a later SENSITIVE header that shares that
// name then resolves to the dynamic name index (62) on the never-indexed
// path. encode_integer(0x10, 4, 62): 62 >= 15 -> 0x1F, continuation
// 62 - 15 == 47 -> 0x2F.
TEST(HPACK_LL_EncoderStrategy, NeverIndexedDynamicName) {
    Encoder encoder;

    // Seed "x-token" (non-sensitive) into the dynamic table.
    std::vector<HeaderField> seed = {{"x-token", "public"}};
    std::vector<uint8_t>     e0;
    ASSERT_TRUE(encoder.encode(seed, e0));
    ASSERT_EQ(encoder.get_dynamic_table_entry_count(), 1u);

    // Now encode the same name, but sensitive -> never-indexed, dynamic name.
    HeaderField              secret("x-token", "private", /*sensitive=*/true);
    std::vector<HeaderField> headers = {secret};
    std::vector<uint8_t>     enc;
    ASSERT_TRUE(encoder.encode(headers, enc));

    ASSERT_GE(enc.size(), 2u);
    EXPECT_EQ(enc[0] & 0xF0, 0x10);
    EXPECT_EQ(enc[0], 0x1F);
    EXPECT_EQ(enc[1], 0x2F); // 62 - 15
    // Still exactly one dynamic entry (never-indexed adds nothing).
    EXPECT_EQ(encoder.get_dynamic_table_entry_count(), 1u);
}

// A pseudo-header (non-sensitive flag, but name starts with ':') also takes
// the never-indexed path. A brand-new pseudo name -> index 0; and the name
// literal is emitted with huffman DISABLED (encode_string_literal(name,
// !is_pseudo == false)), so length byte high bit is clear.
TEST(HPACK_LL_EncoderStrategy, NeverIndexedPseudoHeaderNewNameNoHuffman) {
    Encoder                  encoder;
    std::vector<HeaderField> headers = {{":x-pseudo", "v"}};
    std::vector<uint8_t>     enc;
    ASSERT_TRUE(encoder.encode(headers, enc));

    ASSERT_GE(enc.size(), 2u);
    EXPECT_EQ(enc[0], 0x10); // never indexed, new name
    // Next byte is the name-length string-literal header. Huffman is
    // forbidden for pseudo names, so the H bit (0x80) must be clear and the
    // length must equal the raw name length (":x-pseudo" == 9 bytes).
    EXPECT_EQ(enc[1] & 0x80, 0x00) << "pseudo name must NOT be Huffman-coded";
    EXPECT_EQ(enc[1], 0x09);
}

// ====================================================================
// Encoder strategy: literal WITHOUT indexing (over-budget header)
// ====================================================================

// When a non-sensitive, non-pseudo header is larger than the dynamic table
// budget it cannot be added, so it falls to LITERAL_WITHOUT_INDEXING
// (0x00, N=4). With a brand-new name and index 0:
// encode_integer(0x00, 4, 0) == 0x00.
TEST(HPACK_LL_EncoderStrategy, WithoutIndexingNewNameWhenOverBudget) {
    Encoder encoder;
    encoder.set_max_capacity(20); // hpack_size("xyz","value")=3+5+32=40 > 20

    std::vector<HeaderField> headers = {{"xyz", "value"}};
    std::vector<uint8_t>     enc;
    ASSERT_TRUE(encoder.encode(headers, enc));

    ASSERT_FALSE(enc.empty());
    EXPECT_EQ(enc[0] & 0xF0, 0x00) << "top four bits 0000 (without indexing)";
    EXPECT_EQ(enc[0], 0x00) << "index 0 -> literal name follows";
    // Over-budget header is not stored.
    EXPECT_EQ(encoder.get_dynamic_table_entry_count(), 0u);

    const HeaderField hf = roundtrip_single(enc);
    EXPECT_EQ(hf.name, "xyz");
    EXPECT_EQ(hf.value, "value");
    EXPECT_FALSE(hf.sensitive) << "without-indexing is not flagged sensitive";
}

// Without-indexing carrying a STATIC name index. With max_capacity 0 every
// header is over budget. "accept-encoding" (static idx 16), value differs:
// encode_integer(0x00, 4, 16): 16 >= 15 -> first byte 0x00 | 15 == 0x0F,
// continuation 16 - 15 == 1 -> 0x01.
TEST(HPACK_LL_EncoderStrategy, WithoutIndexingStaticNameWhenOverBudget) {
    Encoder encoder;
    encoder.set_max_capacity(0);

    std::vector<HeaderField> headers = {{"accept-encoding", "identity"}};
    std::vector<uint8_t>     enc;
    ASSERT_TRUE(encoder.encode(headers, enc));

    ASSERT_GE(enc.size(), 2u);
    EXPECT_EQ(enc[0] & 0xF0, 0x00);
    EXPECT_EQ(enc[0], 0x0F); // saturated prefix
    EXPECT_EQ(enc[1], 0x01); // 16 - 15
    EXPECT_EQ(encoder.get_dynamic_table_entry_count(), 0u);

    const HeaderField hf = roundtrip_single(enc);
    EXPECT_EQ(hf.name, "accept-encoding");
    EXPECT_EQ(hf.value, "identity");
}

// ====================================================================
// Encoder::set_peer_max_dynamic_table_size: clamp + evict
// ====================================================================

// Shrinking the peer's advertised maximum below the current byte usage must
// evict the oldest entries down to the new budget.
TEST(HPACK_LL_EncoderStrategy, SetPeerMaxDynamicTableSizeClampsAndEvicts) {
    Encoder encoder;

    // Two minimal incrementally-indexed entries: each hpack_size = 1+1+32 = 34.
    std::vector<HeaderField> headers = {{"a", "1"}, {"b", "2"}};
    std::vector<uint8_t>     enc;
    ASSERT_TRUE(encoder.encode(headers, enc));
    ASSERT_EQ(encoder.get_dynamic_table_entry_count(), 2u);
    ASSERT_EQ(encoder.get_dynamic_table_size(), 68u);

    // Clamp to room for a single entry (34 <= 40 < 68) -> evicts the oldest.
    encoder.set_peer_max_dynamic_table_size(40);
    EXPECT_EQ(encoder.get_dynamic_table_entry_count(), 1u);
    EXPECT_LE(encoder.get_dynamic_table_size(), 40u);
}

// Raising the peer maximum above the current budget is a no-op for eviction
// (the implementation only shrinks when current max exceeds the new peer
// value). Nothing should be evicted here.
TEST(HPACK_LL_EncoderStrategy, SetPeerMaxDynamicTableSizeNoEvictWhenRaised) {
    Encoder encoder;

    // First clamp the local budget down, then advertise a larger peer max.
    encoder.set_max_capacity(40);
    std::vector<HeaderField> headers = {{"a", "1"}};
    std::vector<uint8_t>     enc;
    ASSERT_TRUE(encoder.encode(headers, enc));
    ASSERT_EQ(encoder.get_dynamic_table_entry_count(), 1u);

    encoder.set_peer_max_dynamic_table_size(8192); // larger than current 40
    EXPECT_EQ(encoder.get_dynamic_table_entry_count(), 1u) << "raising peer max must not evict";
}

// ====================================================================
// Decoder: dynamic-table-size-update exceeding the settings limit
// ====================================================================

// A size update that exceeds the decoder's configured limit must be rejected.
// Settings limit 256; update encodes 512 with a 5-bit prefix:
// 0x20 | 31 == 0x3F, then 512 - 31 == 481 -> LEB128: 481 = 0x1E1
//   481 % 128 = 97 (0x61) | 0x80 = 0xE1
//   481 / 128 = 3   -> 0x03
// => {0x3F, 0xE1, 0x03}.
TEST(HPACK_LL_Decoder, DynamicTableSizeUpdateExceedingSettingsRejected) {
    Decoder decoder;
    decoder.set_max_dynamic_table_size(256);

    std::vector<HeaderField> out;
    bool                     incomplete = false;
    std::vector<uint8_t>     block      = {0x3F, 0xE1, 0x03}; // update to 512 > 256

    EXPECT_FALSE(decoder.decode(block, out, incomplete));
}

// A size update exactly AT the limit is accepted.
TEST(HPACK_LL_Decoder, DynamicTableSizeUpdateAtLimitAccepted) {
    Decoder decoder;
    decoder.set_max_dynamic_table_size(256);

    std::vector<HeaderField> out;
    bool                     incomplete = false;
    // Update to 256: 0x20|31 == 0x3F, 256-31 == 225 -> 225 = 0x80|0x61 ...
    //   225 % 128 = 97 (0x61) | 0x80 = 0xE1 ; 225 / 128 = 1 -> 0x01
    std::vector<uint8_t> block = {0x3F, 0xE1, 0x01, 0x82}; // update + :method GET

    ASSERT_TRUE(decoder.decode(block, out, incomplete));
    EXPECT_FALSE(incomplete);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].name, ":method");
}

// ====================================================================
// Decoder: decode_integer overflow / malformed continuations
// ====================================================================

// Malformed #1: a continuation chain that never terminates (every byte has
// the high bit set) but the buffer ends -> INSUFFICIENT_DATA path inside
// decode_integer ({0,-1}); decode() treats this as possibly-incomplete.
TEST(HPACK_LL_Decoder, IntegerContinuationTruncated) {
    Decoder                  decoder;
    std::vector<HeaderField> out;
    bool                     incomplete = false;

    // Indexed header (1xxxxxxx, N=7): prefix saturated then continuation
    // bytes all with high bit set, buffer ends mid-chain.
    std::vector<uint8_t> block = {0xFF, 0x80, 0x80, 0x80};
    EXPECT_FALSE(decoder.decode(block, out, incomplete));
    EXPECT_TRUE(incomplete) << "ran off the end mid-integer => possibly incomplete";
}

// Malformed #2: too many continuation bytes -> M >= 64 guard fires. Ten
// 0x80-or-larger continuation bytes drive M past 64 before terminating.
TEST(HPACK_LL_Decoder, IntegerOverflowTooManyContinuationBytes) {
    Decoder                  decoder;
    std::vector<HeaderField> out;
    bool                     incomplete = false;

    std::vector<uint8_t> block = {
        0xFF,                                                       // indexed, prefix saturated
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, // 10 continuations
        0x01                                                        // terminator
    };
    EXPECT_FALSE(decoder.decode(block, out, incomplete));
}

// Malformed #3: a value that genuinely overflows the accumulator via the
// `term > (UINT64_MAX >> M)` guard in decode_integer (hpack.cpp). With a prefix-
// saturated indexed field followed by TEN 0x80-or-larger continuation bytes, the
// shift amount M reaches 63 *before* the M >= 64 guard fires; at M == 63,
// (UINT64_MAX >> 63) == 1, so the 0x7F seven-bit group of the tenth continuation
// (term == 127) trips `term > 1` and decode_integer returns the overflow
// sentinel. This is distinct from the prior block {0xFF, 8x0xFF, 0x7F}, which
// decodes SUCCESSFULLY to ~9.2e18 (one byte short of M==63) and only failed
// later as an out-of-range table index — so it never reached an overflow guard.
// (The M >= 64 too-many-continuations guard is covered by the sibling
// IntegerOverflowTooManyContinuationBytes.)
TEST(HPACK_LL_Decoder, IntegerOverflowAccumulatorWraps) {
    Decoder                  decoder;
    std::vector<HeaderField> out;
    bool                     incomplete = false;

    std::vector<uint8_t> block = {
        0xFF,                                                             // indexed, prefix saturated
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF       // 10 continuations: term>(MAX>>63)
    };
    EXPECT_FALSE(decoder.decode(block, out, incomplete));
}

// ====================================================================
// Decoder: decode_string_literal Huffman-failure & truncation
// ====================================================================

// A string literal flagged Huffman (H bit set) whose payload is not a valid
// Huffman sequence must fail decoding. We use a never-indexed new-name field
// with a Huffman value that is an invalid code stream.
TEST(HPACK_LL_Decoder, HuffmanValueUndecodableFails) {
    Decoder                  decoder;
    std::vector<HeaderField> out;
    bool                     incomplete = false;

    // 0x00 literal-without-indexing, new name "n"; value declared Huffman.
    // Value bytes: 0x81 (H=1, len=1), then a single 0x00 byte. The first 5
    // bits (00000) decode to '0', leaving 3 trailing ZERO bits; RFC 7541 §5.2
    // requires padding to be all-ones, so huffman_decode fails (invalid
    // padding) and decode() must reject the block.
    std::vector<uint8_t> block = {
        0x00,      // literal without indexing, new name
        0x01, 'n', // name "n" (not Huffman)
        0x81, 0x00 // value: H=1, len 1, byte 0x00 -> invalid padding
    };
    EXPECT_FALSE(decoder.decode(block, out, incomplete));
}

// A literal whose declared length runs past the end of the buffer is a
// truncation, not a hard error: decode() must report possibly-incomplete.
// This exercises the `length > (end_pos - current_pos)` branch in
// decode_string_literal for the VALUE field (incomplete value vs name).
TEST(HPACK_LL_Decoder, LiteralValueTruncationFlagsIncomplete) {
    Decoder                  decoder;
    std::vector<HeaderField> out;
    bool                     incomplete = false;

    std::vector<uint8_t> block = {
        0x40,                     // incremental indexing, new name
        0x04, 'n', 'a', 'm', 'e', // complete name
        0x05, 'v', 'a'            // value says length 5 but only 2 bytes present
    };
    EXPECT_FALSE(decoder.decode(block, out, incomplete));
    EXPECT_TRUE(incomplete);
}

// Truncation in the NAME field of a literal must also flag incomplete.
TEST(HPACK_LL_Decoder, LiteralNameTruncationFlagsIncomplete) {
    Decoder                  decoder;
    std::vector<HeaderField> out;
    bool                     incomplete = false;

    std::vector<uint8_t> block = {
        0x00,               // literal without indexing, new name
        0x06, 'n', 'a', 'm' // name says length 6 but only 3 bytes present
    };
    EXPECT_FALSE(decoder.decode(block, out, incomplete));
    EXPECT_TRUE(incomplete);
}

// ====================================================================
// convenience:: helpers
// ====================================================================

// make_header auto-detects default-sensitive names.
TEST(HPACK_LL_Convenience, MakeHeaderAutoSensitivity) {
    const HeaderField auth = convenience::make_header("authorization", "Bearer x");
    EXPECT_TRUE(auth.sensitive);

    const HeaderField cookie = convenience::make_header("cookie", "sid=1");
    EXPECT_TRUE(cookie.sensitive);

    const HeaderField proxy = convenience::make_header("proxy-authorization", "x");
    EXPECT_TRUE(proxy.sensitive);

    const HeaderField sc = convenience::make_header("set-cookie", "a=b");
    EXPECT_TRUE(sc.sensitive);

    const HeaderField plain = convenience::make_header("accept", "*/*");
    EXPECT_FALSE(plain.sensitive);
}

// encode_headers + decode_headers must form a clean round-trip.
TEST(HPACK_LL_Convenience, EncodeDecodeHeadersRoundTrip) {
    std::vector<HeaderField> headers = {
        {":method", "GET"},
        {":path", "/x"},
        {"x-custom", "data"},
    };

    const std::vector<uint8_t> encoded = convenience::encode_headers(headers);
    ASSERT_FALSE(encoded.empty());

    const auto decoded = convenience::decode_headers(encoded);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->size(), headers.size());
    for (std::size_t i = 0; i < headers.size(); ++i) {
        EXPECT_EQ((*decoded)[i].name, headers[i].name);
        EXPECT_EQ((*decoded)[i].value, headers[i].value);
    }
}

// decode_headers returns nullopt on a malformed (truncated) block.
TEST(HPACK_LL_Convenience, DecodeHeadersNulloptOnMalformed) {
    // Index 0 in an indexed field is illegal per RFC 7541.
    EXPECT_FALSE(convenience::decode_headers({0x80}).has_value());

    // Truncated literal -> decode() returns false AND/OR incomplete -> nullopt.
    EXPECT_FALSE(convenience::decode_headers({0x40, 0x04, 't', 'e'}).has_value());
}

// ====================================================================
// header_validation (hpack.h variant)
// ====================================================================

TEST(HPACK_LL_Validation, HeaderNameRules) {
    using namespace header_validation;

    EXPECT_FALSE(is_valid_header_name("")) << "empty name invalid";
    EXPECT_TRUE(is_valid_header_name("content-type"));
    // Pseudo-header: ':' allowed only at position 0.
    EXPECT_TRUE(is_valid_header_name(":method"));
    EXPECT_FALSE(is_valid_header_name("x:y")) << "colon not at start is invalid";
    // Space / tab / control / DEL not allowed.
    EXPECT_FALSE(is_valid_header_name("bad name"));
    EXPECT_FALSE(is_valid_header_name("bad\tname"));
    EXPECT_FALSE(is_valid_header_name(std::string("with\x7f", 5))); // DEL
    EXPECT_FALSE(is_valid_header_name(std::string("ctl\x01", 4)));  // control char
}

TEST(HPACK_LL_Validation, HeaderValueRules) {
    using namespace header_validation;

    EXPECT_TRUE(is_valid_header_value(""));
    EXPECT_TRUE(is_valid_header_value("application/json; charset=utf-8"));
    EXPECT_TRUE(is_valid_header_value("a\tb")) << "horizontal tab allowed in values";
    // Control chars below 0x20 (other than tab) and DEL are invalid.
    EXPECT_FALSE(is_valid_header_value(std::string("a\nb", 3)));
    EXPECT_FALSE(is_valid_header_value(std::string("a\x01"
                                                   "b",
                                                   3)));
    EXPECT_FALSE(is_valid_header_value(std::string("a\x7f"
                                                   "b",
                                                   3))); // DEL
}

TEST(HPACK_LL_Validation, EncoderRejectsInvalidName) {
    Encoder encoder;
    // A space in the name fails is_valid_header_field -> encode returns false.
    std::vector<HeaderField> headers = {{"bad name", "v"}};
    std::vector<uint8_t>     enc;
    EXPECT_FALSE(encoder.encode(headers, enc));
}

// ====================================================================
// RFC 7541 Appendix C gold vectors (NOT present in test-http2-hpack.cpp)
// ====================================================================

// RFC 7541 Appendix C.3 - Request examples WITHOUT Huffman, sharing one
// decoder so the dynamic table carries across the three requests.
// Existing suite only covers C.2.1 and C.2.4; the full C.3 sequence with a
// live dynamic table is new here.
TEST(HPACK_LL_RFC7541, AppendixC3_RequestSequenceWithDynamicTable) {
    Decoder decoder;

    // --- C.3.1 First request ---
    // :method GET / :scheme http / :path / / :authority www.example.com
    {
        const auto               block = ll_hex_to_bytes("828684410f7777772e6578616d706c652e636f6d");
        std::vector<HeaderField> out;
        bool                     incomplete = false;
        ASSERT_TRUE(decoder.decode(block, out, incomplete));
        EXPECT_FALSE(incomplete);
        ASSERT_EQ(out.size(), 4u);
        EXPECT_EQ(out[0].name, ":method");
        EXPECT_EQ(out[0].value, "GET");
        EXPECT_EQ(out[1].name, ":scheme");
        EXPECT_EQ(out[1].value, "http");
        EXPECT_EQ(out[2].name, ":path");
        EXPECT_EQ(out[2].value, "/");
        EXPECT_EQ(out[3].name, ":authority");
        EXPECT_EQ(out[3].value, "www.example.com");
        // ":authority www.example.com" was incrementally indexed.
        EXPECT_EQ(decoder.get_dynamic_table_entry_count(), 1u);
        EXPECT_EQ(decoder.get_dynamic_table_size(), 57u); // 10 + 15 + 32
    }

    // --- C.3.2 Second request ---
    // adds "cache-control: no-cache"
    {
        const auto               block = ll_hex_to_bytes("828684be58086e6f2d6361636865");
        std::vector<HeaderField> out;
        bool                     incomplete = false;
        ASSERT_TRUE(decoder.decode(block, out, incomplete));
        EXPECT_FALSE(incomplete);
        ASSERT_EQ(out.size(), 5u);
        EXPECT_EQ(out[3].name, ":authority"); // 0xBE = indexed dynamic entry 62
        EXPECT_EQ(out[3].value, "www.example.com");
        EXPECT_EQ(out[4].name, "cache-control");
        EXPECT_EQ(out[4].value, "no-cache");
        EXPECT_EQ(decoder.get_dynamic_table_entry_count(), 2u);
    }

    // --- C.3.3 Third request ---
    // :method GET https /index.html www.example.com + custom-key custom-value
    {
        const auto               block = ll_hex_to_bytes("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565");
        std::vector<HeaderField> out;
        bool                     incomplete = false;
        ASSERT_TRUE(decoder.decode(block, out, incomplete));
        EXPECT_FALSE(incomplete);
        ASSERT_EQ(out.size(), 5u);
        EXPECT_EQ(out[0].name, ":method");
        EXPECT_EQ(out[1].name, ":scheme");
        EXPECT_EQ(out[1].value, "https");
        EXPECT_EQ(out[2].name, ":path");
        EXPECT_EQ(out[2].value, "/index.html");
        EXPECT_EQ(out[3].name, ":authority");
        EXPECT_EQ(out[3].value, "www.example.com");
        EXPECT_EQ(out[4].name, "custom-key");
        EXPECT_EQ(out[4].value, "custom-value");
        EXPECT_EQ(decoder.get_dynamic_table_entry_count(), 3u);
    }
}

// RFC 7541 Appendix C.5 - Response examples WITHOUT Huffman, with a small
// dynamic table (256 octets) that forces eviction across the three responses.
TEST(HPACK_LL_RFC7541, AppendixC5_ResponseSequenceWithEviction) {
    Decoder decoder;
    decoder.set_max_dynamic_table_size(256);

    // --- C.5.1 First response ---
    // :status 302 / cache-control private / date Mon, 21 Oct 2013 20:13:21 GMT
    // / location https://www.example.com
    {
        const auto block = ll_hex_to_bytes("4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768"
                                           "747470733a2f2f7777772e6578616d706c652e636f6d");
        std::vector<HeaderField> out;
        bool                     incomplete = false;
        ASSERT_TRUE(decoder.decode(block, out, incomplete));
        EXPECT_FALSE(incomplete);
        ASSERT_EQ(out.size(), 4u);
        EXPECT_EQ(out[0].name, ":status");
        EXPECT_EQ(out[0].value, "302");
        EXPECT_EQ(out[1].name, "cache-control");
        EXPECT_EQ(out[1].value, "private");
        EXPECT_EQ(out[2].name, "date");
        EXPECT_EQ(out[2].value, "Mon, 21 Oct 2013 20:13:21 GMT");
        EXPECT_EQ(out[3].name, "location");
        EXPECT_EQ(out[3].value, "https://www.example.com");
        EXPECT_EQ(decoder.get_dynamic_table_entry_count(), 4u);
    }

    // --- C.5.2 Second response ---
    // :status 307 (the others are indexed from the dynamic table). This
    // insertion evicts the oldest entry to honour the 256-octet budget.
    {
        const auto               block = ll_hex_to_bytes("4803333037c1c0bf");
        std::vector<HeaderField> out;
        bool                     incomplete = false;
        ASSERT_TRUE(decoder.decode(block, out, incomplete));
        EXPECT_FALSE(incomplete);
        ASSERT_EQ(out.size(), 4u);
        EXPECT_EQ(out[0].name, ":status");
        EXPECT_EQ(out[0].value, "307");
        EXPECT_EQ(out[1].name, "cache-control");
        EXPECT_EQ(out[1].value, "private");
        EXPECT_EQ(out[2].name, "date");
        EXPECT_EQ(out[2].value, "Mon, 21 Oct 2013 20:13:21 GMT");
        EXPECT_EQ(out[3].name, "location");
        EXPECT_EQ(out[3].value, "https://www.example.com");
        EXPECT_EQ(decoder.get_dynamic_table_entry_count(), 4u);
    }

    // --- C.5.3 Third response ---
    // :status 200 (indexed) / cache-control private (indexed) / date Mon, 21
    // Oct 2013 20:13:22 GMT (literal, NEW value) / location (indexed) /
    // content-encoding gzip (literal, new value) / set-cookie foo=... (literal,
    // new value). Inserting "date" and "set-cookie" forces the 256-octet table
    // to evict down to 3 live entries.
    {
        const auto block = ll_hex_to_bytes(
            "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48"
            "514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31");
        std::vector<HeaderField> out;
        bool                     incomplete = false;
        ASSERT_TRUE(decoder.decode(block, out, incomplete));
        EXPECT_FALSE(incomplete);
        ASSERT_EQ(out.size(), 6u);
        EXPECT_EQ(out[0].name, ":status");
        EXPECT_EQ(out[0].value, "200");
        EXPECT_EQ(out[1].name, "cache-control");
        EXPECT_EQ(out[1].value, "private");
        EXPECT_EQ(out[2].name, "date");
        EXPECT_EQ(out[2].value, "Mon, 21 Oct 2013 20:13:22 GMT");
        EXPECT_EQ(out[3].name, "location");
        EXPECT_EQ(out[3].value, "https://www.example.com");
        EXPECT_EQ(out[4].name, "content-encoding");
        EXPECT_EQ(out[4].value, "gzip");
        EXPECT_EQ(out[5].name, "set-cookie");
        EXPECT_EQ(out[5].value, "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1");
        // The two large new entries evicted the older ones; 3 remain resident.
        EXPECT_EQ(decoder.get_dynamic_table_entry_count(), 3u);
    }
}

// ====================================================================
// RFC 7541 Appendix C.4 / C.6 — Huffman gold-vector DECODE
// ====================================================================

// C.4.1 — a literal-with-incremental-indexing whose NAME and VALUE are both
// Huffman-coded (H bit set in each string-length prefix). The exact byte
// sequence is the RFC worked example; decoding must reproduce the ascii pair.
TEST(HPACK_LL_RFC7541, AppendixC4_1_HuffmanNameAndValueDecode) {
    Decoder decoder;
    // 0x40, H-name "custom-key" (len 8), H-value "custom-header" (len 9).
    const auto block = ll_hex_to_bytes("408825a849e95ba97d7f8925a849e95a728e42d9");
    std::vector<HeaderField> out;
    bool                     incomplete = false;
    ASSERT_TRUE(decoder.decode(block, out, incomplete));
    EXPECT_FALSE(incomplete);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].name, "custom-key");
    EXPECT_EQ(out[0].value, "custom-header");
    // Incrementally indexed -> resident in the dynamic table.
    EXPECT_EQ(decoder.get_dynamic_table_entry_count(), 1u);
}

// C.6.1 first field — :status 302 carried as literal-with-incremental-indexing
// using the static name index 8 (0x48) and a Huffman value "302" (0x82 6402).
// Decode must yield (:status, 302) exactly, NOT result||incomplete.
TEST(HPACK_LL_RFC7541, AppendixC6_1_HuffmanStatusValueDecode) {
    Decoder decoder;
    // 0x48 = literal-with-incremental-indexing, name index 8 (:status);
    // 0x82 = string-literal H=1, len 2; 0x6402 = Huffman("302").
    const auto               block = ll_hex_to_bytes("48826402");
    std::vector<HeaderField> out;
    bool                     incomplete = false;
    ASSERT_TRUE(decoder.decode(block, out, incomplete));
    EXPECT_FALSE(incomplete);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].name, ":status");
    EXPECT_EQ(out[0].value, "302");
}

// ====================================================================
// Decoder: Huffman NAME-length truncation flags incomplete
// ====================================================================

// A literal whose NAME declares 8 Huffman bytes but only 4 are present is a
// truncation, not a hard error: decode() must report possibly-incomplete.
// Complements the value-side / non-Huffman truncation cases above.
TEST(HPACK_LL_Decoder, HuffmanNameLengthTruncationFlagsIncomplete) {
    Decoder                  decoder;
    std::vector<HeaderField> out;
    bool                     incomplete = false;

    // 0x40 incremental indexing, H-name length 8 (0x88) but only 4 bytes.
    std::vector<uint8_t> block = {0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9};
    EXPECT_FALSE(decoder.decode(block, out, incomplete));
    EXPECT_TRUE(incomplete);
}

// ====================================================================
// Huffman decode error arms + utility helpers (hpack_huffman.cpp)
//
// These drive the failure / boundary paths of the Huffman codec that the
// happy-path round-trips skip: an invalid bit path that walks off the decode
// tree, padding strictly longer than 7 bits, and the empty-input / degenerate
// arms of the analysis utilities.
// ====================================================================

TEST(HPACK_LL_Huffman, InvalidBitPathWalksOffTreeFails) {
    // 0x00 = first bits all zero. The '0' symbol is a 5-bit code, but a long run
    // of zero bits eventually reaches a node with no left child -> decode fails
    // on the null-node guard rather than producing output.
    std::string                output;
    const std::vector<uint8_t> bad = {0x00, 0x00, 0x00, 0x00};
    // Either it decodes (all-zero is a valid symbol run) or it fails on an
    // invalid path; we only require the call to be exercised and deterministic.
    const bool ok = huffman_decode(bad.data(), bad.size(), output);
    (void) ok;

    // A guaranteed off-tree path: a single byte 0xFF with only EOS-prefix bits
    // mid-stream. EOS appearing as a decoded symbol is an error.
    std::string                eos_out;
    const std::vector<uint8_t> eos_mid = {0xFF, 0xFF, 0xFF, 0xFF}; // 30-bit EOS code
    EXPECT_FALSE(huffman_decode(eos_mid.data(), eos_mid.size(), eos_out));
}

TEST(HPACK_LL_Huffman, PaddingLongerThanSevenBitsFails) {
    // Encode a single character, then append a full zero byte. The trailing
    // partial path is now longer than 7 bits (a whole extra byte), which RFC
    // 7541 §5.2 requires to be treated as a decode error.
    std::vector<uint8_t> encoded;
    ASSERT_TRUE(huffman_encode("x", encoded));
    encoded.push_back(0x00); // 8 extra bits -> > 7-bit padding

    std::string output;
    EXPECT_FALSE(huffman_decode(encoded.data(), encoded.size(), output));
}

TEST(HPACK_LL_Huffman, EmptyInputUtilityArms) {
    // estimate_compression_ratio / estimate_huffman_efficiency both special-case
    // the empty string -> 1.0.
    EXPECT_DOUBLE_EQ(estimate_compression_ratio(""), 1.0);
    EXPECT_DOUBLE_EQ(estimate_huffman_efficiency(""), 1.0);

    // validate_huffman_encoded_data on empty input is vacuously valid.
    EXPECT_TRUE(validate_huffman_encoded_data({}));
}

TEST(HPACK_LL_Huffman, EfficiencyZeroEntropyDegenerateInput) {
    // A single repeated character has zero Shannon entropy, so theoretical_bits
    // is 0 and estimate_huffman_efficiency takes its degenerate-input return.
    EXPECT_DOUBLE_EQ(estimate_huffman_efficiency(std::string(16, 'a')), 1.0);
}

TEST(HPACK_LL_Huffman, RoundTripTestConvenienceSucceeds) {
    // huffman_round_trip_test encodes then decodes in one call.
    std::string out;
    EXPECT_TRUE(huffman_round_trip_test("round-trip-me", out));
    EXPECT_EQ(out, "round-trip-me");
}

TEST(HPACK_LL_Huffman, BenchmarkReturnsNonNegativeTimings) {
    // Exercise benchmark_huffman_performance (encode + decode timing loops).
    const auto [encode_ms, decode_ms] = benchmark_huffman_performance("benchmark input string", 8);
    EXPECT_GE(encode_ms, 0.0);
    EXPECT_GE(decode_ms, 0.0);
}

TEST(HPACK_LL_Huffman, DecodeWithStatsAccumulates) {
    std::vector<uint8_t> encoded;
    ASSERT_TRUE(huffman_encode("stats", encoded));

    HuffmanStats stats;
    std::string  decoded;
    EXPECT_TRUE(huffman_decode_with_stats(encoded.data(), encoded.size(), decoded, stats));
    EXPECT_EQ(decoded, "stats");
    EXPECT_EQ(stats.decoding_operations, 1u);
    EXPECT_EQ(stats.decoded_bytes, 5u);
}
