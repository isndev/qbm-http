/**
 * @file qbm/http/tests/unit/http2/hpack-codec.cpp
 * @brief HPACK (HTTP/2 Header Compression, RFC 7541) codec test suite.
 *
 * Pure-logic unit coverage of the HPACK encoder/decoder and the Huffman codec.
 * No socket, no TLS — the whole `2/protocol/hpack*.{h,cpp}` surface includes
 * only the STL, so this TU is built unconditionally (it used to ride the
 * SSL gate by accident).
 *
 * Covers:
 * - Static table layout + the compile-time name/exact index (F33).
 * - DynamicTable ring buffer: insertion order, eviction, oversized-entry
 *   clear-and-drop, shrink-from-back, capacity growth (F34).
 * - Huffman codec: gold-vector encode/decode (RFC 7541 Appendix B/C.4/C.6),
 *   padding rules, round-trips, the `should_use_huffman` heuristic with
 *   *concrete* expectations, and the analysis helpers.
 * - Decoder: every representation, error paths, RFC 7541 Appendix C.2/C.3/C.5
 *   gold sequences with a live dynamic table.
 * - Encoder: static-table matching, sensitive/pseudo never-indexed, dynamic
 *   table reuse shrinking the second encoding.
 *
 * Performance/benchmark cases (`HPACK_Performance.*`, `PerformanceBenchmark`)
 * were excised — they now live in `benchmark/http2/hpack.bench.cpp`.
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

#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <vector>

#include "../2/protocol/hpack.h"
#include "../2/protocol/hpack_huffman.h"

using namespace qb::protocol::hpack;
using namespace qb::protocol::hpack::huffman;

// ====================================================================
// Utility Functions
// ====================================================================

namespace {

std::vector<uint8_t>
hex_to_bytes(const std::string &hex) {
    std::vector<uint8_t> bytes;
    for (std::size_t i = 0; i + 1 < hex.length(); i += 2) {
        const std::string byte_string = hex.substr(i, 2);
        bytes.push_back(static_cast<uint8_t>(std::strtol(byte_string.c_str(), nullptr, 16)));
    }
    return bytes;
}

// Decode a whole block through a fresh decoder, asserting it succeeds and is
// not flagged incomplete.
std::vector<HeaderField>
decode_ok(Decoder &decoder, const std::vector<uint8_t> &block) {
    std::vector<HeaderField> out;
    bool                     incomplete = false;
    EXPECT_TRUE(decoder.decode(block, out, incomplete));
    EXPECT_FALSE(incomplete);
    return out;
}

} // namespace

// ====================================================================
// Static Table Tests
// ====================================================================

TEST(HPACK_StaticTable, TableSize) {
    EXPECT_EQ(STATIC_TABLE.size(), 61u);
}

TEST(HPACK_StaticTable, WellKnownEntries) {
    EXPECT_EQ(STATIC_TABLE[0].first, ":authority");
    EXPECT_EQ(STATIC_TABLE[0].second, "");

    EXPECT_EQ(STATIC_TABLE[1].first, ":method");
    EXPECT_EQ(STATIC_TABLE[1].second, "GET");

    EXPECT_EQ(STATIC_TABLE[2].first, ":method");
    EXPECT_EQ(STATIC_TABLE[2].second, "POST");

    EXPECT_EQ(STATIC_TABLE[3].first, ":path");
    EXPECT_EQ(STATIC_TABLE[3].second, "/");

    EXPECT_EQ(STATIC_TABLE[6].first, ":scheme");
    EXPECT_EQ(STATIC_TABLE[6].second, "https");

    EXPECT_EQ(STATIC_TABLE[37].first, "host");
    EXPECT_EQ(STATIC_TABLE[37].second, "");

    EXPECT_EQ(STATIC_TABLE[57].first, "user-agent");
    EXPECT_EQ(STATIC_TABLE[57].second, "");
}

TEST(HPACK_StaticTable, AllEntriesHaveNonEmptyNames) {
    for (std::size_t i = 0; i < STATIC_TABLE.size(); ++i) {
        EXPECT_FALSE(STATIC_TABLE[i].first.empty()) << "Entry " << i << " has empty name";
    }
}

TEST(HPACK_Decoder, DynamicTableSizeUpdateAllowedAtHeaderBlockStart) {
    Decoder                  decoder;
    std::vector<HeaderField> decoded;
    bool                     incomplete = false;

    const std::vector<uint8_t> block = {
        0x20, // Dynamic table size update to 0
        0x82  // Indexed static header: :method GET
    };

    ASSERT_TRUE(decoder.decode(block, decoded, incomplete));
    EXPECT_FALSE(incomplete);
    ASSERT_EQ(decoded.size(), 1u);
    EXPECT_EQ(decoded[0].name, ":method");
    EXPECT_EQ(decoded[0].value, "GET");
}

TEST(HPACK_Decoder, DynamicTableSizeUpdateRejectedAfterHeaderField) {
    Decoder                  decoder;
    std::vector<HeaderField> decoded;
    bool                     incomplete = false;

    const std::vector<uint8_t> block = {
        0x82, // Indexed static header: :method GET
        0x20  // Dynamic table size update after a header field is forbidden
    };

    EXPECT_FALSE(decoder.decode(block, decoded, incomplete));
}

// ====================================================================
// Huffman: table + gold-vector encode / decode (RFC 7541 Appendix B)
// ====================================================================

TEST(HPACK_Huffman, HuffmanTableSize) {
    EXPECT_EQ(HUFFMAN_TABLE.size(), 257u); // 256 characters + EOS
}

TEST(HPACK_Huffman, BasicCharacterCodes) {
    // Spot-check against RFC 7541 Appendix B.
    EXPECT_EQ(HUFFMAN_TABLE[48].code, 0x0u); // '0' = 00000
    EXPECT_EQ(HUFFMAN_TABLE[48].bits, 5u);

    EXPECT_EQ(HUFFMAN_TABLE[97].code, 0x3u); // 'a' = 00011
    EXPECT_EQ(HUFFMAN_TABLE[97].bits, 5u);

    EXPECT_EQ(HUFFMAN_TABLE[111].code, 0x7u); // 'o' = 00111
    EXPECT_EQ(HUFFMAN_TABLE[111].bits, 5u);

    EXPECT_EQ(HUFFMAN_TABLE[32].code, 0x14u); // ' ' = 010100
    EXPECT_EQ(HUFFMAN_TABLE[32].bits, 6u);

    EXPECT_EQ(HUFFMAN_TABLE[256].code, 0x3fffffffu); // EOS = 30 1-bits
    EXPECT_EQ(HUFFMAN_TABLE[256].bits, 30u);
}

TEST(HPACK_Huffman, GoldVectorEncodeWww) {
    // 'w' (119) = {0x78, 7}. "www" = 1111000 1111000 1111000, padded with 1s:
    //   0xF1 0xE3 0xC7. (RFC 7541-style worked example.)
    std::vector<uint8_t> encoded;
    ASSERT_TRUE(huffman_encode("www", encoded));
    ASSERT_EQ(encoded.size(), 3u);
    EXPECT_EQ(encoded[0], 0xF1);
    EXPECT_EQ(encoded[1], 0xE3);
    EXPECT_EQ(encoded[2], 0xC7);
}

TEST(HPACK_Huffman, GoldVectorEncodeCustomKey) {
    // RFC 7541 C.4.1 — "custom-key" Huffman-encodes to the 8-byte sequence
    // 25 a8 49 e9 5b a9 7d 7f.
    std::vector<uint8_t> encoded;
    ASSERT_TRUE(huffman_encode("custom-key", encoded));
    const std::vector<uint8_t> expected = {0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f};
    EXPECT_EQ(encoded, expected);
}

TEST(HPACK_Huffman, GoldVectorEncodeResponseValues) {
    // RFC 7541 C.6.1 worked-example value encodings.
    struct {
        std::string          in;
        std::vector<uint8_t> out;
    } cases[] = {
        {"302", {0x64, 0x02}},
        {"private", {0xae, 0xc3, 0x77, 0x1a, 0x4b}},
        {"https://www.example.com",
         {0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8, 0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3}},
        {"307", {0x64, 0x0e, 0xff}},
    };
    for (const auto &c : cases) {
        std::vector<uint8_t> encoded;
        ASSERT_TRUE(huffman_encode(c.in, encoded)) << c.in;
        EXPECT_EQ(encoded, c.out) << c.in;
    }
}

TEST(HPACK_Huffman, GoldVectorDecodeCustomKey) {
    // Reverse of C.4.1: the 8-byte sequence must decode back to "custom-key".
    const std::vector<uint8_t> data = {0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f};
    std::string                result;
    ASSERT_TRUE(huffman_decode(data.data(), data.size(), result));
    EXPECT_EQ(result, "custom-key");
}

TEST(HPACK_Huffman, SimpleDecoding) {
    // 'H' (72) = {0x63, 7} = 1100011; padded with a single 1 => 0xC7.
    std::string          result;
    std::vector<uint8_t> data_h_padded = {0xC7};
    ASSERT_TRUE(huffman_decode(data_h_padded.data(), data_h_padded.size(), result));
    EXPECT_EQ(result, "H");
}

TEST(HPACK_Huffman, OverlongPaddingRejected) {
    // 'H' + one padding bit fills 0xC7; an extra all-ones byte is 9 trailing
    // 1-bits — padding longer than 7 bits, a decode error per RFC 7541 §5.2.
    std::string          result;
    std::vector<uint8_t> data = {0xC7, 0xFF};
    EXPECT_FALSE(huffman_decode(data.data(), data.size(), result));
}

TEST(HPACK_Huffman, MultiCharacterDecoding) {
    // {0xAA, 0xAA, 0xBF} decodes to "nnn" under RFC 7541.
    std::string          result;
    std::vector<uint8_t> data = {0xAA, 0xAA, 0xBF};
    ASSERT_TRUE(huffman_decode(data.data(), data.size(), result));
    EXPECT_EQ(result, "nnn");
}

TEST(HPACK_Huffman, InvalidEosInStream) {
    // EOS (30 1-bits) appearing mid-stream followed by a non-padding zero byte
    // must be rejected.
    std::string result;
    uint8_t     invalid_eos[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00};
    EXPECT_FALSE(huffman_decode(invalid_eos, 5, result));
}

TEST(HPACK_Huffman, EmptyInput) {
    std::string result = "stale";
    EXPECT_TRUE(huffman_decode(nullptr, 0, result));
    EXPECT_TRUE(result.empty());
}

// ShouldUseHuffman: the heuristic is `ceil(huffman_bits/8) < input.size()`,
// i.e. it returns true iff Huffman actually shrinks the payload. Concrete,
// computable expectations (no x==true||x==false tautology).
TEST(HPACK_Huffman, ShouldUseHuffmanConcrete) {
    // No benefit: empty, single char, short uncompressible runs.
    EXPECT_FALSE(should_use_huffman(""));    // 0 < 0 is false
    EXPECT_FALSE(should_use_huffman("a"));   // 'a' = 5 bits -> 1 byte; 1 < 1 false
    EXPECT_FALSE(should_use_huffman("0"));   // '0' = 5 bits -> 1 byte; 1 < 1 false
    EXPECT_FALSE(should_use_huffman("www")); // 21 bits -> 3 bytes; 3 < 3 false

    // Clear wins: "test" (4 -> 3), repeated 'a' (10 -> 7), a long sentence.
    EXPECT_TRUE(should_use_huffman("test"));
    EXPECT_TRUE(should_use_huffman("00000"));      // 25 bits -> 4 bytes; 4 < 5
    EXPECT_TRUE(should_use_huffman("aaaaaaaaaa")); // 50 bits -> 7 bytes; 7 < 10
    EXPECT_TRUE(should_use_huffman("This is a long text with many repeated characters eeeeeeee"));

    // And the heuristic must agree with reality: when it says "use", the
    // encoded form is strictly smaller; when it says "don't", it is not.
    for (const std::string &s : {std::string("test"), std::string("www"), std::string("aaaaaaaaaa")}) {
        std::vector<uint8_t> encoded;
        ASSERT_TRUE(huffman_encode(s, encoded));
        EXPECT_EQ(should_use_huffman(s), encoded.size() < s.size()) << s;
    }
}

TEST(HPACK_Huffman, EncodeProducesValidRoundTrip) {
    std::vector<uint8_t> output;
    const std::string    input = "test string";
    ASSERT_TRUE(huffman_encode(input, output));
    EXPECT_LT(output.size(), input.size()) << "compressible ASCII must shrink";

    std::string decoded;
    ASSERT_TRUE(huffman_decode(output.data(), output.size(), decoded));
    EXPECT_EQ(decoded, input);
}

TEST(HPACK_Huffman, HuffmanRoundTrip) {
    std::string          original = "Hello World!";
    std::vector<uint8_t> encoded;
    std::string          decoded;
    ASSERT_TRUE(huffman_encode(original, encoded));
    ASSERT_TRUE(huffman_decode(encoded.data(), encoded.size(), decoded));
    EXPECT_EQ(original, decoded);
}

TEST(HPACK_Huffman, HuffmanRoundTripConvenience) {
    std::string input = "test string for round trip";
    std::string output;
    ASSERT_TRUE(huffman_round_trip_test(input, output));
    EXPECT_EQ(input, output);
}

TEST(HPACK_Huffman, CalculateEncodedSizeMatchesEncoding) {
    const std::string    input           = "test";
    const std::size_t    calculated_size = calculate_huffman_encoded_size(input);
    std::vector<uint8_t> encoded;
    ASSERT_TRUE(huffman_encode(input, encoded));
    EXPECT_EQ(calculated_size, encoded.size());
    EXPECT_EQ(calculated_size, 3u); // "test" -> 49 50 9f
}

TEST(HPACK_Huffman, CompressionRatioBounds) {
    const std::string input = "aaaaaaaaaa"; // 10 -> 7 bytes
    const double      ratio = estimate_compression_ratio(input);
    EXPECT_GT(ratio, 0.0);
    EXPECT_LT(ratio, 1.0) << "repeated 'a' must compress below 1.0";
    EXPECT_DOUBLE_EQ(ratio, 7.0 / 10.0);
}

TEST(HPACK_Huffman, HuffmanTableValidation) {
    EXPECT_TRUE(validate_huffman_table());
}

TEST(HPACK_Huffman, HuffmanStats) {
    HuffmanStats         stats;
    const std::string    input = "test string";
    std::vector<uint8_t> encoded;

    ASSERT_TRUE(huffman_encode_with_stats(input, encoded, stats));
    EXPECT_EQ(stats.encoding_operations, 1u);
    EXPECT_EQ(stats.original_bytes, input.length());
    EXPECT_EQ(stats.encoded_bytes, encoded.size());
    EXPECT_GT(stats.total_bits_encoded, 0u);

    std::string decoded;
    ASSERT_TRUE(huffman_decode_with_stats(encoded.data(), encoded.size(), decoded, stats));
    EXPECT_EQ(stats.decoding_operations, 1u);
    EXPECT_EQ(stats.decoded_bytes, decoded.length());
    EXPECT_EQ(decoded, input);

    const double ratio = stats.compression_ratio();
    EXPECT_GT(ratio, 0.0);
    EXPECT_LE(ratio, 1.0);
    EXPECT_DOUBLE_EQ(stats.space_savings(), 1.0 - ratio);
}

TEST(HPACK_Huffman, BatchEncoding) {
    std::vector<std::string> inputs = {"first string", "second string", "third string with more content"};

    std::vector<std::vector<uint8_t>> outputs;
    ASSERT_TRUE(huffman_encode_batch(inputs, outputs));
    ASSERT_EQ(outputs.size(), inputs.size());

    for (std::size_t i = 0; i < inputs.size(); ++i) {
        std::string decoded;
        ASSERT_TRUE(huffman_decode(outputs[i].data(), outputs[i].size(), decoded));
        EXPECT_EQ(decoded, inputs[i]);
    }
}

TEST(HPACK_Huffman, CharacterFrequencyAnalysis) {
    auto frequencies = analyze_character_frequency("aaabbbccc");
    EXPECT_EQ(frequencies['a'], 3u);
    EXPECT_EQ(frequencies['b'], 3u);
    EXPECT_EQ(frequencies['c'], 3u);
    EXPECT_EQ(frequencies['d'], 0u);
}

TEST(HPACK_Huffman, HuffmanEfficiencyBounds) {
    const double efficiency = estimate_huffman_efficiency("test string with various characters");
    EXPECT_GT(efficiency, 0.0);
    EXPECT_LE(efficiency, 1.0);
}

TEST(HPACK_Huffman, ValidateEncodedData) {
    std::vector<uint8_t> encoded_valid;
    ASSERT_TRUE(huffman_encode("validation test", encoded_valid));
    EXPECT_TRUE(validate_huffman_encoded_data(encoded_valid));

    // Valid encoding of "a" followed by a full all-ones byte = >7 padding bits.
    std::vector<uint8_t> encoded_short;
    ASSERT_TRUE(huffman_encode("a", encoded_short));
    ASSERT_FALSE(encoded_short.empty());
    std::vector<uint8_t> corrupted_padding = encoded_short;
    corrupted_padding.push_back(0xFF);
    EXPECT_FALSE(validate_huffman_encoded_data(corrupted_padding));

    // All-zero bytes: after the first symbol the trailing padding contains
    // zero bits, which violates the all-ones padding rule.
    std::vector<uint8_t> invalid_data = {0x00, 0x00, 0x00};
    EXPECT_FALSE(validate_huffman_encoded_data(invalid_data));
}

TEST(HPACK_Huffman, GlobalStatsResetIsZeroed) {
    auto &global_stats = get_global_huffman_stats();
    global_stats.encoding_operations = 5;
    global_stats.decoding_operations = 7;
    global_stats.reset();
    EXPECT_EQ(global_stats.encoding_operations, 0u);
    EXPECT_EQ(global_stats.decoding_operations, 0u);
    EXPECT_EQ(global_stats.original_bytes, 0u);
    EXPECT_EQ(global_stats.encoded_bytes, 0u);
}

TEST(HPACK_Huffman, DebugFunctionsProduceOutput) {
    std::stringstream ss;
    print_huffman_code('a', ss);
    std::string output = ss.str();
    EXPECT_FALSE(output.empty());
    EXPECT_NE(output.find("'a'"), std::string::npos);

    ss.str("");
    ss.clear();
    print_string_HUFFMAN_TABLE("test", ss);
    output = ss.str();
    EXPECT_FALSE(output.empty());
    EXPECT_NE(output.find("test"), std::string::npos);
}

TEST(HPACK_Huffman, EdgeCases) {
    std::vector<uint8_t> encoded;
    std::string          decoded;

    ASSERT_TRUE(huffman_encode("", encoded));
    EXPECT_TRUE(encoded.empty());

    decoded = "stale";
    ASSERT_TRUE(huffman_decode(nullptr, 0, decoded));
    EXPECT_TRUE(decoded.empty());

    ASSERT_TRUE(huffman_encode("a", encoded));
    ASSERT_TRUE(huffman_decode(encoded.data(), encoded.size(), decoded));
    EXPECT_EQ(decoded, "a");

    std::string all_ascii;
    for (int i = 32; i < 127; ++i) {
        all_ascii += static_cast<char>(i);
    }
    encoded.clear();
    decoded.clear();
    ASSERT_TRUE(huffman_encode(all_ascii, encoded));
    ASSERT_TRUE(huffman_decode(encoded.data(), encoded.size(), decoded));
    EXPECT_EQ(decoded, all_ascii);
}

TEST(HPACK_Huffman, SpecialCharacters) {
    std::string          special = std::string("\x00\x01\x02\xFF", 4); // binary data
    std::vector<uint8_t> encoded;
    std::string          decoded;
    ASSERT_TRUE(huffman_encode(special, encoded));
    ASSERT_TRUE(huffman_decode(encoded.data(), encoded.size(), decoded));
    EXPECT_EQ(decoded, special);
}

TEST(HPACK_Huffman, LargeRepeatedDataCompresses) {
    const std::string    large_data(1000, 'x');
    std::vector<uint8_t> encoded;
    std::string          decoded;
    ASSERT_TRUE(huffman_encode(large_data, encoded));
    ASSERT_TRUE(huffman_decode(encoded.data(), encoded.size(), decoded));
    EXPECT_EQ(decoded, large_data);
    // 'x' = {0xf9, 8}? no — 'x' is a 7-bit code, so 1000*7/8 == 875 bytes.
    EXPECT_LT(encoded.size(), large_data.size());
}

TEST(HPACK_Huffman, RoundTripAcrossStringFamilies) {
    const std::vector<std::string> samples = {
        "qwerty123!@#",
        "aaaaaaaaaa",
        "the quick brown fox",
        "application/json; charset=utf-8",
        "https://www.example.com/api/v1/users?id=123",
        "CamelCaseString",
        "1234567890",
        "!@#$%^&*()_+-=[]{}|;:,.<>?",
    };
    for (const auto &s : samples) {
        std::vector<uint8_t> encoded;
        ASSERT_TRUE(huffman_encode(s, encoded)) << s;
        std::string decoded;
        ASSERT_TRUE(huffman_decode(encoded.data(), encoded.size(), decoded)) << s;
        EXPECT_EQ(decoded, s) << s;
    }
}

// ====================================================================
// HPACK Decoder Tests
// ====================================================================

TEST(HPACK_Decoder, IndexedHeaderField) {
    Decoder        decoder;
    const auto     headers = decode_ok(decoder, {0x82}); // index 2 (:method GET)
    ASSERT_EQ(headers.size(), 1u);
    EXPECT_EQ(headers[0].name, ":method");
    EXPECT_EQ(headers[0].value, "GET");
}

TEST(HPACK_Decoder, LiteralHeaderWithIncrementalIndexing) {
    Decoder    decoder;
    const auto headers = decode_ok(decoder, {
                                                0x40,                         // incremental indexing, new name
                                                0x04, 'n', 'a', 'm', 'e',     // name "name"
                                                0x05, 'v', 'a', 'l', 'u', 'e' // value "value"
                                            });
    ASSERT_EQ(headers.size(), 1u);
    EXPECT_EQ(headers[0].name, "name");
    EXPECT_EQ(headers[0].value, "value");
}

TEST(HPACK_Decoder, LiteralHeaderWithIndexedName) {
    Decoder    decoder;
    const auto headers = decode_ok(decoder, {
                                                0x41, // indexed name 1 (:authority)
                                                0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'});
    ASSERT_EQ(headers.size(), 1u);
    EXPECT_EQ(headers[0].name, ":authority");
    EXPECT_EQ(headers[0].value, "example.com");
}

TEST(HPACK_Decoder, LiteralHeaderWithoutIndexing) {
    Decoder    decoder;
    const auto headers = decode_ok(decoder, {
                                                0x00,                         // without indexing, new name
                                                0x04, 't', 'e', 's', 't',     // name "test"
                                                0x05, 'v', 'a', 'l', 'u', 'e' // value "value"
                                            });
    ASSERT_EQ(headers.size(), 1u);
    EXPECT_EQ(headers[0].name, "test");
    EXPECT_EQ(headers[0].value, "value");
    EXPECT_FALSE(headers[0].sensitive);
}

TEST(HPACK_Decoder, LiteralHeaderNeverIndexed) {
    Decoder    decoder;
    const auto headers =
        decode_ok(decoder, {
                               0x10, // never indexed, new name
                               0x0D, 'a', 'u', 't', 'h', 'o', 'r', 'i', 'z', 'a', 't', 'i', 'o', 'n',
                               0x05, 't', 'o', 'k', 'e', 'n'});
    ASSERT_EQ(headers.size(), 1u);
    EXPECT_EQ(headers[0].name, "authorization");
    EXPECT_EQ(headers[0].value, "token");
    EXPECT_TRUE(headers[0].sensitive) << "never-indexed field decodes sensitive";
}

TEST(HPACK_Decoder, DynamicTableSizeUpdateProducesNoHeaders) {
    Decoder    decoder;
    const auto headers = decode_ok(decoder, {0x3F, 0xE1, 0x1F}); // update to 1024
    EXPECT_EQ(headers.size(), 0u);
}

TEST(HPACK_Decoder, MultipleHeaders) {
    Decoder    decoder;
    const auto headers = decode_ok(decoder, {
                                                0x82,                     // :method GET
                                                0x84,                     // :path /
                                                0x40,                     // incremental indexing, new name
                                                0x04, 'h', 'o', 's', 't', // name "host"
                                                0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'});
    ASSERT_EQ(headers.size(), 3u);
    EXPECT_EQ(headers[0].name, ":method");
    EXPECT_EQ(headers[0].value, "GET");
    EXPECT_EQ(headers[1].name, ":path");
    EXPECT_EQ(headers[1].value, "/");
    EXPECT_EQ(headers[2].name, "host");
    EXPECT_EQ(headers[2].value, "example.com");
}

// Huffman-encoded value in a literal: decode the well-known C.4.1 vector for
// "custom-key" as a literal-with-incremental-indexing value (H bit set).
// 0x40 (incremental, new name) + name "test" + value: H=1, len=8, then the
// 8-byte Huffman of "custom-key". Concrete decode, not result||incomplete.
TEST(HPACK_Decoder, HuffmanEncodedValueDecodesExactly) {
    Decoder    decoder;
    const auto headers =
        decode_ok(decoder, {
                               0x40, 0x04, 't', 'e', 's', 't',                                  // name "test"
                               0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f /*custom-key*/}); // value (Huffman)
    ASSERT_EQ(headers.size(), 1u);
    EXPECT_EQ(headers[0].name, "test");
    EXPECT_EQ(headers[0].value, "custom-key");
}

TEST(HPACK_Decoder, HuffmanEncodedNameAndValueDecodeExactly) {
    // RFC 7541 C.4.1 — full literal: 0x40, H-name "custom-key" (len 8), then
    // H-value "custom-header" (len 9 -> 25a849e95ae728e42d9b ... actually 9
    // bytes). Decode must yield the original ascii pair.
    Decoder    decoder;
    const auto headers = decode_ok(
        decoder, {0x40,
                  0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, // name "custom-key" Huffman
                  0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5a, 0x72, 0x8e, 0x42, 0xd9 /*custom-header*/});
    ASSERT_EQ(headers.size(), 1u);
    EXPECT_EQ(headers[0].name, "custom-key");
    EXPECT_EQ(headers[0].value, "custom-header");
}

// ====================================================================
// HPACK Encoder Tests
// ====================================================================

TEST(HPACK_Encoder, BasicEncodingRoundTrips) {
    Encoder                  encoder;
    Decoder                  decoder;
    std::vector<HeaderField> headers = {{":method", "GET"}, {":path", "/"}, {"host", "example.com"}};

    std::vector<uint8_t> encoded;
    ASSERT_TRUE(encoder.encode(headers, encoded));
    ASSERT_FALSE(encoded.empty());

    // :method GET (idx 2) and :path / (idx 4) collapse to single indexed bytes.
    EXPECT_EQ(encoded[0], 0x82);
    EXPECT_EQ(encoded[1], 0x84);

    const auto decoded = decode_ok(decoder, encoded);
    ASSERT_EQ(decoded.size(), headers.size());
    for (std::size_t i = 0; i < headers.size(); ++i) {
        EXPECT_EQ(decoded[i].name, headers[i].name);
        EXPECT_EQ(decoded[i].value, headers[i].value);
    }
}

TEST(HPACK_Encoder, StaticTableMatching) {
    Encoder                  encoder;
    std::vector<HeaderField> headers = {{":method", "GET"}, {":method", "POST"}, {":path", "/"}, {":scheme", "https"}};

    std::vector<uint8_t> encoded;
    ASSERT_TRUE(encoder.encode(headers, encoded));
    ASSERT_EQ(encoded.size(), 4u);
    EXPECT_EQ(encoded[0], 0x82); // index 2
    EXPECT_EQ(encoded[1], 0x83); // index 3
    EXPECT_EQ(encoded[2], 0x84); // index 4
    EXPECT_EQ(encoded[3], 0x87); // index 7
}

TEST(HPACK_Encoder, SensitiveHeadersNeverIndexed) {
    Encoder                  encoder;
    std::vector<HeaderField> headers = {{"authorization", "Bearer token123"}, {"cookie", "session=abc123"}, {"set-cookie", "id=xyz; HttpOnly"}};

    std::vector<uint8_t> encoded;
    ASSERT_TRUE(encoder.encode(headers, encoded));
    EXPECT_EQ(encoded[0] & 0xF0, 0x10) << "never-indexed pattern (0001xxxx)";
    EXPECT_EQ(encoder.get_dynamic_table_entry_count(), 0u) << "sensitive fields are not indexed";
}

TEST(HPACK_Encoder, PseudoHeadersNeverIndexed) {
    Encoder                  encoder;
    std::vector<HeaderField> headers = {{":custom-pseudo", "value"}};

    std::vector<uint8_t> encoded;
    ASSERT_TRUE(encoder.encode(headers, encoded));
    EXPECT_EQ(encoded[0] & 0xF0, 0x10);
    EXPECT_EQ(encoder.get_dynamic_table_entry_count(), 0u);
}

TEST(HPACK_Encoder, EmptyHeaderNameRejected) {
    Encoder                  encoder;
    std::vector<HeaderField> headers = {{"", "value"}};
    std::vector<uint8_t>     encoded;
    EXPECT_FALSE(encoder.encode(headers, encoded));
}

// ====================================================================
// Round-trip Tests (Encode then Decode)
// ====================================================================

TEST(HPACK_RoundTrip, BasicRoundTrip) {
    Encoder encoder;
    Decoder decoder;

    std::vector<HeaderField> original_headers = {
        {":method", "GET"},      {":path", "/api/v1/users"},    {":scheme", "https"},
        {":authority", "api.example.com"}, {"user-agent", "test-client/1.0"}, {"accept", "application/json"},
        {"content-type", "application/json"}};

    std::vector<uint8_t> encoded;
    ASSERT_TRUE(encoder.encode(original_headers, encoded));

    const auto decoded_headers = decode_ok(decoder, encoded);
    ASSERT_EQ(decoded_headers.size(), original_headers.size());
    for (std::size_t i = 0; i < original_headers.size(); ++i) {
        EXPECT_EQ(decoded_headers[i].name, original_headers[i].name);
        EXPECT_EQ(decoded_headers[i].value, original_headers[i].value);
    }
}

// Dynamic-table reuse: encoding the same indexable headers a second time on
// the same encoder MUST shrink the output (the path + custom header collapse
// to dynamic indices). Concrete EXPECT_LT, not a cout.
TEST(HPACK_RoundTrip, DynamicTableReuseShrinksSecondEncoding) {
    Encoder encoder;
    Decoder decoder;

    // Two fully-custom headers force two incremental-indexing inserts (the encoder keeps :method on
    // the static table and emits :path's custom value as a literal-without-indexing, so only custom
    // fields enter the dynamic table — use two of them to make the entry count deterministic).
    std::vector<HeaderField> headers1 = {
        {":method", "GET"}, {":path", "/long/dynamic/path"}, {"custom-header", "custom-value"}, {"x-trace-id", "abc-123-def"}};
    std::vector<uint8_t> encoded1;
    ASSERT_TRUE(encoder.encode(headers1, encoded1));
    EXPECT_EQ(decode_ok(decoder, encoded1).size(), 4u);
    ASSERT_GE(encoder.get_dynamic_table_entry_count(), 2u) << "both custom headers indexed";

    // Same custom headers, different (still static-indexed) method — the repeat collapses to indices.
    std::vector<HeaderField> headers2 = {
        {":method", "POST"}, {":path", "/long/dynamic/path"}, {"custom-header", "custom-value"}, {"x-trace-id", "abc-123-def"}};
    std::vector<uint8_t> encoded2;
    ASSERT_TRUE(encoder.encode(headers2, encoded2));

    EXPECT_LT(encoded2.size(), encoded1.size()) << "dynamic-table reuse must compress the repeat";
    EXPECT_EQ(decode_ok(decoder, encoded2).size(), 4u);
}

// ====================================================================
// Error Handling and Edge Cases
// ====================================================================

TEST(HPACK_ErrorHandling, InvalidIndexZero) {
    Decoder                  decoder;
    std::vector<HeaderField> headers;
    bool                     incomplete = false;
    EXPECT_FALSE(decoder.decode({0x80}, headers, incomplete)); // index 0 illegal
}

TEST(HPACK_ErrorHandling, IndexOutOfRange) {
    Decoder                  decoder;
    std::vector<HeaderField> headers;
    bool                     incomplete = false;
    EXPECT_FALSE(decoder.decode({0xFF, 0xFF}, headers, incomplete));
}

TEST(HPACK_ErrorHandling, IntegerOverflow) {
    Decoder                  decoder;
    std::vector<HeaderField> headers;
    bool                     incomplete = false;
    std::vector<uint8_t>     data       = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    EXPECT_FALSE(decoder.decode(data, headers, incomplete));
}

TEST(HPACK_ErrorHandling, IncompleteData) {
    Decoder                  decoder;
    std::vector<HeaderField> headers;
    bool                     incomplete = false;
    std::vector<uint8_t>     data       = {0x40, 0x04, 't', 'e'}; // name says 4, only 2 present
    EXPECT_FALSE(decoder.decode(data, headers, incomplete));
    EXPECT_TRUE(incomplete);
}

TEST(HPACK_ErrorHandling, UnknownInstructionRejected) {
    Decoder                  decoder;
    std::vector<HeaderField> headers;
    bool                     incomplete = false;
    EXPECT_FALSE(decoder.decode({0x18}, headers, incomplete)); // 00011000 reserved
}

// ====================================================================
// Dynamic Table Management (decoder-side limits)
// ====================================================================

TEST(HPACK_DynamicTable, EntryFitsWithinTableSizeLimit) {
    Decoder decoder;
    decoder.set_max_dynamic_table_size(100);

    std::vector<HeaderField> headers;
    bool                     incomplete = false;
    std::vector<uint8_t>     data       = {0x40, 0x04, 't', 'e', 's', 't', 0x05, 'v', 'a', 'l', 'u', 'e'};
    ASSERT_TRUE(decoder.decode(data, headers, incomplete));
    EXPECT_FALSE(incomplete);
    EXPECT_EQ(decoder.get_dynamic_table_entry_count(), 1u);
}

TEST(HPACK_DynamicTable, EncoderEvictionUnderTightBudget) {
    Encoder encoder;
    encoder.set_max_capacity(50); // room for ~1 minimal entry

    std::vector<HeaderField> headers = {{"header1", "value1"}, {"header2", "value2"}};
    std::vector<uint8_t>     encoded;
    ASSERT_TRUE(encoder.encode(headers, encoded));
    // Each entry = 7 + 6 + 32 = 45 octets; only one can be resident at a time.
    EXPECT_LE(encoder.get_dynamic_table_entry_count(), 1u);
    EXPECT_LE(encoder.get_dynamic_table_size(), 50u);
}

TEST(HPACK_DynamicTable, HeaderListSizeLimitRejectsOversizedBlock) {
    Decoder decoder;
    decoder.set_max_header_list_size(50);

    std::vector<HeaderField> headers;
    bool                     incomplete = false;
    std::vector<uint8_t>     data       = {
        0x40, 0x10, 'v', 'e', 'r', 'y', '-', 'l', 'o', 'n', 'g', '-', 'h', 'e', 'a', 'd', 'e', 'r',
        0x10, 'v', 'e', 'r', 'y', '-', 'l', 'o', 'n', 'g', '-', 'v', 'a', 'l', 'u', 'e', '-'};
    EXPECT_FALSE(decoder.decode(data, headers, incomplete));
}

// ====================================================================
// RFC 7541 Appendix C — gold vectors
// ====================================================================

TEST(HPACK_RFC7541, ExampleC2_1_LiteralIncrementalNewName) {
    Decoder decoder;
    // custom-key: custom-header
    const auto headers = decode_ok(decoder, hex_to_bytes("400a637573746f6d2d6b65790d637573746f6d2d686561646572"));
    ASSERT_EQ(headers.size(), 1u);
    EXPECT_EQ(headers[0].name, "custom-key");
    EXPECT_EQ(headers[0].value, "custom-header");
    EXPECT_EQ(decoder.get_dynamic_table_entry_count(), 1u);
}

TEST(HPACK_RFC7541, ExampleC2_4_IndexedHeaderField) {
    Decoder    decoder;
    const auto headers = decode_ok(decoder, {0x82}); // :method GET
    ASSERT_EQ(headers.size(), 1u);
    EXPECT_EQ(headers[0].name, ":method");
    EXPECT_EQ(headers[0].value, "GET");
}

// Full C.3 request sequence (no Huffman) on a shared decoder so the dynamic
// table carries across all three requests.
TEST(HPACK_RFC7541, ExampleC3_RequestSequenceWithDynamicTable) {
    Decoder decoder;

    // C.3.1
    {
        const auto out = decode_ok(decoder, hex_to_bytes("828684410f7777772e6578616d706c652e636f6d"));
        ASSERT_EQ(out.size(), 4u);
        EXPECT_EQ(out[0].name, ":method");
        EXPECT_EQ(out[0].value, "GET");
        EXPECT_EQ(out[1].name, ":scheme");
        EXPECT_EQ(out[1].value, "http");
        EXPECT_EQ(out[2].name, ":path");
        EXPECT_EQ(out[2].value, "/");
        EXPECT_EQ(out[3].name, ":authority");
        EXPECT_EQ(out[3].value, "www.example.com");
        EXPECT_EQ(decoder.get_dynamic_table_entry_count(), 1u);
        EXPECT_EQ(decoder.get_dynamic_table_size(), 57u); // 10 + 15 + 32
    }
    // C.3.2 — adds cache-control: no-cache
    {
        const auto out = decode_ok(decoder, hex_to_bytes("828684be58086e6f2d6361636865"));
        ASSERT_EQ(out.size(), 5u);
        EXPECT_EQ(out[3].name, ":authority");
        EXPECT_EQ(out[3].value, "www.example.com");
        EXPECT_EQ(out[4].name, "cache-control");
        EXPECT_EQ(out[4].value, "no-cache");
        EXPECT_EQ(decoder.get_dynamic_table_entry_count(), 2u);
    }
    // C.3.3 — custom-key: custom-value
    {
        const auto out = decode_ok(decoder, hex_to_bytes("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"));
        ASSERT_EQ(out.size(), 5u);
        EXPECT_EQ(out[1].value, "https");
        EXPECT_EQ(out[2].value, "/index.html");
        EXPECT_EQ(out[3].value, "www.example.com");
        EXPECT_EQ(out[4].name, "custom-key");
        EXPECT_EQ(out[4].value, "custom-value");
        EXPECT_EQ(decoder.get_dynamic_table_entry_count(), 3u);
    }
}

// Full C.5 response sequence (no Huffman) with a 256-octet table that forces
// eviction across the three responses.
TEST(HPACK_RFC7541, ExampleC5_ResponseSequenceWithEviction) {
    Decoder decoder;
    decoder.set_max_dynamic_table_size(256);

    // C.5.1
    {
        const auto out = decode_ok(
            decoder, hex_to_bytes("4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768"
                                  "747470733a2f2f7777772e6578616d706c652e636f6d"));
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
    // C.5.2 — :status 307, the rest indexed; insertion evicts the oldest.
    {
        const auto out = decode_ok(decoder, hex_to_bytes("4803333037c1c0bf"));
        ASSERT_EQ(out.size(), 4u);
        EXPECT_EQ(out[0].value, "307");
        EXPECT_EQ(out[1].value, "private");
        EXPECT_EQ(out[2].value, "Mon, 21 Oct 2013 20:13:21 GMT");
        EXPECT_EQ(out[3].value, "https://www.example.com");
        EXPECT_EQ(decoder.get_dynamic_table_entry_count(), 4u);
    }
}

// ====================================================================
// Integration: realistic request / response header lists round-trip
// ====================================================================

TEST(HPACK_Integration, HttpRequestHeadersRoundTrip) {
    Encoder encoder;
    Decoder decoder;

    std::vector<HeaderField> request_headers = {
        {":method", "GET"},
        {":path", "/search?q=test&category=books"},
        {":scheme", "https"},
        {":authority", "www.example.com"},
        {"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        {"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        {"accept-language", "en-US,en;q=0.5"},
        {"accept-encoding", "gzip, deflate, br"},
        {"connection", "keep-alive"},
        {"upgrade-insecure-requests", "1"}};

    std::vector<uint8_t> encoded;
    ASSERT_TRUE(encoder.encode(request_headers, encoded));
    const auto decoded = decode_ok(decoder, encoded);
    ASSERT_EQ(decoded.size(), request_headers.size());
    for (std::size_t i = 0; i < request_headers.size(); ++i) {
        EXPECT_EQ(decoded[i].name, request_headers[i].name);
        EXPECT_EQ(decoded[i].value, request_headers[i].value);
    }
}

TEST(HPACK_Integration, HttpResponseHeadersRoundTrip) {
    Encoder encoder;
    Decoder decoder;

    std::vector<HeaderField> response_headers = {
        {":status", "200"},
        {"content-type", "application/json; charset=utf-8"},
        {"content-length", "1234"},
        {"server", "nginx/1.18.0"},
        {"date", "Mon, 01 Jan 2024 12:00:00 GMT"},
        {"cache-control", "public, max-age=3600"},
        {"etag", "\"abc123def456\""},
        {"vary", "Accept-Encoding"},
        {"x-frame-options", "DENY"},
        {"x-content-type-options", "nosniff"}};

    std::vector<uint8_t> encoded;
    ASSERT_TRUE(encoder.encode(response_headers, encoded));
    const auto decoded = decode_ok(decoder, encoded);
    ASSERT_EQ(decoded.size(), response_headers.size());
    for (std::size_t i = 0; i < response_headers.size(); ++i) {
        EXPECT_EQ(decoded[i].name, response_headers[i].name);
        EXPECT_EQ(decoded[i].value, response_headers[i].value);
    }
}

// ====================================================================
// F33 — Compile-time static-table index
// ====================================================================

TEST(HPACK_StaticTableIndex, FindNameMatchReturnsFirstOccurrence) {
    EXPECT_EQ(static_table::find_name_match(std::string_view(":authority")).value(), 1u);
    EXPECT_EQ(static_table::find_name_match(std::string_view(":method")).value(), 2u);
    EXPECT_EQ(static_table::find_name_match(std::string_view(":path")).value(), 4u);
    EXPECT_EQ(static_table::find_name_match(std::string_view(":scheme")).value(), 6u);
    EXPECT_EQ(static_table::find_name_match(std::string_view(":status")).value(), 8u);
    EXPECT_EQ(static_table::find_name_match(std::string_view("accept-encoding")).value(), 16u);
    EXPECT_EQ(static_table::find_name_match(std::string_view("www-authenticate")).value(), 61u);
    EXPECT_FALSE(static_table::find_name_match(std::string_view("x-custom-header")).has_value());
    EXPECT_FALSE(static_table::find_name_match(std::string_view("")).has_value());
}

TEST(HPACK_StaticTableIndex, FindExactMatchCoversDuplicateNames) {
    EXPECT_EQ(static_table::find_exact_match(std::string_view(":method"), std::string_view("GET")).value(), 2u);
    EXPECT_EQ(static_table::find_exact_match(std::string_view(":method"), std::string_view("POST")).value(), 3u);
    EXPECT_EQ(static_table::find_exact_match(std::string_view(":path"), std::string_view("/")).value(), 4u);
    EXPECT_EQ(static_table::find_exact_match(std::string_view(":path"), std::string_view("/index.html")).value(), 5u);
    EXPECT_EQ(static_table::find_exact_match(std::string_view(":scheme"), std::string_view("http")).value(), 6u);
    EXPECT_EQ(static_table::find_exact_match(std::string_view(":scheme"), std::string_view("https")).value(), 7u);
    EXPECT_EQ(static_table::find_exact_match(std::string_view(":status"), std::string_view("200")).value(), 8u);
    EXPECT_EQ(static_table::find_exact_match(std::string_view(":status"), std::string_view("404")).value(), 13u);
    EXPECT_EQ(static_table::find_exact_match(std::string_view(":status"), std::string_view("500")).value(), 14u);
    EXPECT_EQ(static_table::find_exact_match(std::string_view("accept-encoding"), std::string_view("gzip, deflate")).value(), 16u);
    EXPECT_FALSE(static_table::find_exact_match(std::string_view(":status"), std::string_view("418")).has_value());
    EXPECT_FALSE(static_table::find_exact_match(std::string_view("x-custom"), std::string_view("v")).has_value());
}

TEST(HPACK_StaticTableIndex, EveryStaticTableEntryIsIndexed) {
    for (std::size_t i = 0; i < STATIC_TABLE.size(); ++i) {
        const auto &[name, value] = STATIC_TABLE[i];
        const auto name_idx       = static_table::find_name_match(name);
        ASSERT_TRUE(name_idx.has_value()) << "Missing name index for row " << (i + 1);
        EXPECT_LE(*name_idx, i + 1);
        const auto exact_idx = static_table::find_exact_match(name, value);
        ASSERT_TRUE(exact_idx.has_value()) << "Missing exact index for row " << (i + 1);
        EXPECT_EQ(*exact_idx, i + 1);
    }
}

TEST(HPACK_StaticTableIndex, LegacyStringOverloadsStillWork) {
    const std::string name(":method");
    const std::string value("POST");
    EXPECT_EQ(static_table::find_name_match(name).value(), 2u);
    EXPECT_EQ(static_table::find_exact_match(name, value).value(), 3u);
}

// ---------------------------------------------------------------------------
// F34 — DynamicTable ring buffer
// ---------------------------------------------------------------------------

TEST(HPACK_DynamicTable, DefaultStateIsEmpty) {
    DynamicTable table;
    EXPECT_TRUE(table.empty());
    EXPECT_EQ(table.size(), 0u);
    EXPECT_EQ(table.byte_size(), 0u);
    EXPECT_EQ(table.max_byte_size(), HPACK_DEFAULT_MAX_TABLE_SIZE);
}

TEST(HPACK_DynamicTable, AddBringsEntryToFront) {
    DynamicTable table;
    const auto   r1 = table.add("a", "1");
    EXPECT_TRUE(r1.added);
    EXPECT_EQ(r1.evicted, 0u);
    const auto r2 = table.add("b", "22");
    EXPECT_TRUE(r2.added);
    EXPECT_EQ(r2.evicted, 0u);
    ASSERT_EQ(table.size(), 2u);
    EXPECT_EQ(table[0].name, "b");
    EXPECT_EQ(table[0].value, "22");
    EXPECT_EQ(table[1].name, "a");
    EXPECT_EQ(table[1].value, "1");
    EXPECT_EQ(table.back().name, "a");
    EXPECT_EQ(table.byte_size(), (1u + 1u + HPACK_ENTRY_OVERHEAD) + (1u + 2u + HPACK_ENTRY_OVERHEAD));
}

TEST(HPACK_DynamicTable, EvictionHonoursByteBudget) {
    DynamicTable table;
    table.set_max_byte_size(70);
    table.add("a", "1");
    table.add("b", "2");
    ASSERT_EQ(table.size(), 2u);
    const auto r = table.add("c", "3");
    EXPECT_TRUE(r.added);
    EXPECT_EQ(r.evicted, 1u);
    ASSERT_EQ(table.size(), 2u);
    EXPECT_EQ(table[0].name, "c");
    EXPECT_EQ(table[1].name, "b");
    EXPECT_LE(table.byte_size(), 70u);
}

TEST(HPACK_DynamicTable, OversizedEntryClearsTableAndIsDropped) {
    DynamicTable table;
    table.set_max_byte_size(128);
    table.add("a", "1");
    table.add("b", "2");
    table.add("c", "3");
    ASSERT_EQ(table.size(), 3u);
    const auto r = table.add("name", std::string(200, 'x'));
    EXPECT_FALSE(r.added);
    EXPECT_EQ(r.evicted, 3u);
    EXPECT_TRUE(table.empty());
    EXPECT_EQ(table.byte_size(), 0u);
}

TEST(HPACK_DynamicTable, SetMaxByteSizeShrinksFromTheBack) {
    DynamicTable table;
    table.add("a", "1");
    table.add("b", "2");
    table.add("c", "3");
    ASSERT_EQ(table.size(), 3u);
    const auto evicted = table.set_max_byte_size(35);
    EXPECT_EQ(evicted, 2u);
    ASSERT_EQ(table.size(), 1u);
    EXPECT_EQ(table[0].name, "c");
    EXPECT_LE(table.byte_size(), 35u);
}

TEST(HPACK_DynamicTable, ClearReleasesEntriesButKeepsCapacity) {
    DynamicTable table;
    for (int i = 0; i < 10; ++i) {
        table.add("header-" + std::to_string(i), "value");
    }
    const std::size_t cap_before = table.capacity();
    EXPECT_GT(cap_before, 0u);
    table.clear();
    EXPECT_TRUE(table.empty());
    EXPECT_EQ(table.byte_size(), 0u);
    EXPECT_EQ(table.capacity(), cap_before);
}

TEST(HPACK_DynamicTable, RingBufferWrapsCorrectlyOverManyOperations) {
    DynamicTable table;
    table.set_max_byte_size(150);
    for (int i = 0; i < 1000; ++i) {
        table.add("k" + std::to_string(i), "v");
    }
    ASSERT_EQ(table.size(), 4u);
    for (int i = 0; i < 4; ++i) {
        EXPECT_EQ(table[i].name, "k" + std::to_string(999 - i));
    }
    EXPECT_EQ(table.capacity(), 128u);
}

TEST(HPACK_DynamicTable, GrowsCapacityWhenCountExceedsInitial) {
    DynamicTable table;
    table.set_max_byte_size(1'000'000);
    for (int i = 0; i < 200; ++i) {
        table.add("k" + std::to_string(i), "v");
    }
    ASSERT_EQ(table.size(), 200u);
    EXPECT_GE(table.capacity(), 256u);
    EXPECT_EQ(table[0].name, "k199");
    EXPECT_EQ(table[199].name, "k0");
}
