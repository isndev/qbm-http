/**
 * @file qbm/http/2/protocol/hpack_huffman.h
 * @brief HPACK Huffman coding implementation for qb-io framework
 *
 * This file provides a complete implementation of HPACK Huffman coding
 * as specified in RFC 7541 Appendix B. It includes:
 *
 * - Complete Huffman code table for all 256 octets
 * - Efficient encoding and decoding algorithms
 * - Decode tree construction for fast symbol lookup
 * - Compression ratio estimation and performance analysis
 * - Statistics collection for encoding/decoding operations
 * - Round-trip testing and validation utilities
 * - Character frequency analysis for compression optimization
 *
 * The implementation provides both high-performance encoding/decoding
 * and comprehensive analysis tools for HPACK optimization.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace qb::protocol::hpack::huffman {

/**
 * @brief Huffman code entry structure
 */
struct HuffmanCode {
    uint32_t code; ///< The Huffman code bits
    uint8_t  bits; ///< The number of bits in the code
};

/**
 * @brief HPACK static Huffman table as defined in RFC 7541 Appendix B
 *
 * This table provides the Huffman codes for all 256 octets plus the EOS symbol.
 * The codes are optimized for typical HTTP header field values.
 */
constexpr std::array<HuffmanCode, 257> HUFFMAN_TABLE = {{
    {0x1ff8, 13},    {0x7fffd8, 23},  {0xfffffe2, 28},  {0xfffffe3, 28}, {0xfffffe4, 28}, {0xfffffe5, 28},  {0xfffffe6, 28},  {0xfffffe7, 28},
    {0xfffffe8, 28}, {0xffffea, 24},  {0x3ffffffc, 30}, {0xfffffe9, 28}, {0xfffffea, 28}, {0x3ffffffd, 30}, {0xfffffeb, 28},  {0xfffffec, 28},
    {0xfffffed, 28}, {0xfffffee, 28}, {0xfffffef, 28},  {0xffffff0, 28}, {0xffffff1, 28}, {0xffffff2, 28},  {0x3ffffffe, 30}, {0xffffff3, 28},
    {0xffffff4, 28}, {0xffffff5, 28}, {0xffffff6, 28},  {0xffffff7, 28}, {0xffffff8, 28}, {0xffffff9, 28},  {0xffffffa, 28},  {0xffffffb, 28},
    {0x14, 6},       {0x3f8, 10},     {0x3f9, 10},      {0xffa, 12},     {0x1ff9, 13},    {0x15, 6},        {0xf8, 8},        {0x7fa, 11},
    {0x3fa, 10},     {0x3fb, 10},     {0xf9, 8},        {0x7fb, 11},     {0xfa, 8},       {0x16, 6},        {0x17, 6},        {0x18, 6},
    {0x0, 5},        {0x1, 5},        {0x2, 5},         {0x19, 6},       {0x1a, 6},       {0x1b, 6},        {0x1c, 6},        {0x1d, 6},
    {0x1e, 6},       {0x1f, 6},       {0x5c, 7},        {0xfb, 8},       {0x7ffc, 15},    {0x20, 6},        {0xffb, 12},      {0x3fc, 10},
    {0x1ffa, 13},    {0x21, 6},       {0x5d, 7},        {0x5e, 7},       {0x5f, 7},       {0x60, 7},        {0x61, 7},        {0x62, 7},
    {0x63, 7},       {0x64, 7},       {0x65, 7},        {0x66, 7},       {0x67, 7},       {0x68, 7},        {0x69, 7},        {0x6a, 7},
    {0x6b, 7},       {0x6c, 7},       {0x6d, 7},        {0x6e, 7},       {0x6f, 7},       {0x70, 7},        {0x71, 7},        {0x72, 7},
    {0xfc, 8},       {0x73, 7},       {0xfd, 8},        {0x1ffb, 13},    {0x7fff0, 19},   {0x1ffc, 13},     {0x3ffc, 14},     {0x22, 6},
    {0x7ffd, 15},    {0x3, 5},        {0x23, 6},        {0x4, 5},        {0x24, 6},       {0x5, 5},         {0x25, 6},        {0x26, 6},
    {0x27, 6},       {0x6, 5},        {0x74, 7},        {0x75, 7},       {0x28, 6},       {0x29, 6},        {0x2a, 6},        {0x7, 5},
    {0x2b, 6},       {0x76, 7},       {0x2c, 6},        {0x8, 5},        {0x9, 5},        {0x2d, 6},        {0x77, 7},        {0x78, 7},
    {0x79, 7},       {0x7a, 7},       {0x7b, 7},        {0x7ffe, 15},    {0x7fc, 11},     {0x3ffd, 14},     {0x1ffd, 13},     {0xffffffc, 28},
    {0xfffe6, 20},   {0x3fffd2, 22},  {0xfffe7, 20},    {0xfffe8, 20},   {0x3fffd3, 22},  {0x3fffd4, 22},   {0x3fffd5, 22},   {0x7fffd9, 23},
    {0x3fffd6, 22},  {0x7fffda, 23},  {0x7fffdb, 23},   {0x7fffdc, 23},  {0x7fffdd, 23},  {0x7fffde, 23},   {0xffffeb, 24},   {0x7fffdf, 23},
    {0xffffec, 24},  {0xffffed, 24},  {0x3fffd7, 22},   {0x7fffe0, 23},  {0xffffee, 24},  {0x7fffe1, 23},   {0x7fffe2, 23},   {0x7fffe3, 23},
    {0x7fffe4, 23},  {0x1fffdc, 21},  {0x3fffd8, 22},   {0x7fffe5, 23},  {0x3fffd9, 22},  {0x7fffe6, 23},   {0x7fffe7, 23},   {0xffffef, 24},
    {0x3fffda, 22},  {0x1fffdd, 21},  {0xfffe9, 20},    {0x3fffdb, 22},  {0x3fffdc, 22},  {0x7fffe8, 23},   {0x7fffe9, 23},   {0x1fffde, 21},
    {0x7fffea, 23},  {0x3fffdd, 22},  {0x3fffde, 22},   {0xfffff0, 24},  {0x1fffdf, 21},  {0x3fffdf, 22},   {0x7fffeb, 23},   {0x7fffec, 23},
    {0x1fffe0, 21},  {0x1fffe1, 21},  {0x3fffe0, 22},   {0x1fffe2, 21},  {0x7fffed, 23},  {0x3fffe1, 22},   {0x7fffee, 23},   {0x7fffef, 23},
    {0xfffea, 20},   {0x3fffe2, 22},  {0x3fffe3, 22},   {0x3fffe4, 22},  {0x7ffff0, 23},  {0x3fffe5, 22},   {0x3fffe6, 22},   {0x7ffff1, 23},
    {0x3ffffe0, 26}, {0x3ffffe1, 26}, {0xfffeb, 20},    {0x7fff1, 19},   {0x3fffe7, 22},  {0x7ffff2, 23},   {0x3fffe8, 22},   {0x1ffffec, 25},
    {0x3ffffe2, 26}, {0x3ffffe3, 26}, {0x3ffffe4, 26},  {0x7ffffde, 27}, {0x7ffffdf, 27}, {0x3ffffe5, 26},  {0xfffff1, 24},   {0x1ffffed, 25},
    {0x7fff2, 19},   {0x1fffe3, 21},  {0x3ffffe6, 26},  {0x7ffffe0, 27}, {0x7ffffe1, 27}, {0x3ffffe7, 26},  {0x7ffffe2, 27},  {0xfffff2, 24},
    {0x1fffe4, 21},  {0x1fffe5, 21},  {0x3ffffe8, 26},  {0x3ffffe9, 26}, {0xffffffd, 28}, {0x7ffffe3, 27},  {0x7ffffe4, 27},  {0x7ffffe5, 27},
    {0xfffec, 20},   {0xfffff3, 24},  {0xfffed, 20},    {0x1fffe6, 21},  {0x3fffe9, 22},  {0x1fffe7, 21},   {0x1fffe8, 21},   {0x7ffff3, 23},
    {0x3fffea, 22},  {0x3fffeb, 22},  {0x1ffffee, 25},  {0x1ffffef, 25}, {0xfffff4, 24},  {0xfffff5, 24},   {0x3ffffea, 26},  {0x7ffff4, 23},
    {0x3ffffeb, 26}, {0x7ffffe6, 27}, {0x3ffffec, 26},  {0x3ffffed, 26}, {0x7ffffe7, 27}, {0x7ffffe8, 27},  {0x7ffffe9, 27},  {0x7ffffea, 27},
    {0x7ffffeb, 27}, {0xffffffe, 28}, {0x7ffffec, 27},  {0x7ffffed, 27}, {0x7ffffee, 27}, {0x7ffffef, 27},  {0x7fffff0, 27},  {0x3ffffee, 26},
    {0x3fffffff, 30} // EOS symbol
}};

/**
 * @brief Huffman decode tree node
 */
struct HuffmanDecodeNode {
    bool                               is_leaf = false; ///< True if this is a leaf node
    uint16_t                           symbol  = 0;     ///< Symbol value (valid if is_leaf)
    std::unique_ptr<HuffmanDecodeNode> left;            ///< Left child (0 bit)
    std::unique_ptr<HuffmanDecodeNode> right;           ///< Right child (1 bit)
};

/**
 * @brief Build the Huffman decode tree from the static table
 * @return Root of the decode tree
 */
std::unique_ptr<HuffmanDecodeNode> build_decode_tree();

/**
 * @brief Check if Huffman encoding should be used for a string
 *
 * Accepts any contiguous byte sequence; callers holding views / spans no
 * longer need to materialise a `std::string` just to probe this function.
 *
 * @param input The string to check
 * @return true if Huffman encoding would save space
 */
bool should_use_huffman(std::string_view input) noexcept;

/**
 * @brief Encode a string using HPACK Huffman encoding
 * @param input The bytes to encode (view; no ownership)
 * @param output The output buffer (data will be appended)
 * @return true if encoding succeeded
 */
bool huffman_encode(std::string_view input, std::vector<uint8_t> &output);

/**
 * @brief Decode HPACK Huffman encoded data
 * @param input_data Pointer to encoded data
 * @param input_len Length of encoded data
 * @param output_str Output string
 * @return true if decoding succeeded
 */
bool huffman_decode(const uint8_t *input_data, size_t input_len, std::string &output_str);

/**
 * @brief Calculate the Huffman encoded size of a string
 * @param input The string to measure
 * @return Number of bytes needed for Huffman encoding
 */
std::size_t calculate_huffman_encoded_size(const std::string &input);

/**
 * @brief Test function for round-trip encoding/decoding
 * @param input Input string
 * @param output Output string (will be set to decoded result)
 * @return true if round-trip succeeded
 */
bool huffman_round_trip_test(const std::string &input, std::string &output);

/**
 * @brief Estimate compression ratio for a string
 * @param input Input string
 * @return Compression ratio (encoded_size / original_size)
 */
double estimate_compression_ratio(const std::string &input);

/**
 * @brief Validate that the Huffman table is properly constructed
 * @return true if table is valid
 */
bool validate_huffman_table();

/**
 * @brief Statistics for Huffman encoding/decoding operations
 */
struct HuffmanStats {
    std::size_t encoding_operations = 0;
    std::size_t decoding_operations = 0;
    std::size_t original_bytes      = 0;
    std::size_t encoded_bytes       = 0;
    std::size_t decoded_bytes       = 0;
    std::size_t total_bits_encoded  = 0;

    void
    reset() {
        *this = HuffmanStats{};
    }

    double
    compression_ratio() const {
        if (original_bytes == 0)
            return 1.0;
        return static_cast<double>(encoded_bytes) / original_bytes;
    }

    double
    space_savings() const {
        return 1.0 - compression_ratio();
    }
};

/**
 * @brief Encode with statistics tracking
 * @param input Input string
 * @param output Output buffer
 * @param stats Statistics to update
 * @return true if encoding succeeded
 */
bool huffman_encode_with_stats(const std::string &input, std::vector<uint8_t> &output, HuffmanStats &stats);

/**
 * @brief Decode with statistics tracking
 * @param input_data Input data
 * @param input_len Input length
 * @param output_str Output string
 * @param stats Statistics to update
 * @return true if decoding succeeded
 */
bool huffman_decode_with_stats(const uint8_t *input_data, std::size_t input_len, std::string &output_str, HuffmanStats &stats);

/**
 * @brief Batch encode multiple strings
 * @param inputs Input strings
 * @param outputs Output buffers
 * @return true if all encodings succeeded
 */
bool huffman_encode_batch(const std::vector<std::string> &inputs, std::vector<std::vector<uint8_t>> &outputs);

/**
 * @brief Analyze character frequency in a string
 * @param input Input string
 * @return Map of character frequencies
 */
std::map<char, std::size_t> analyze_character_frequency(const std::string &input);

/**
 * @brief Estimate Huffman encoding efficiency
 * @param input Input string
 * @return Efficiency ratio (0.0 to 1.0)
 */
double estimate_huffman_efficiency(const std::string &input);

/**
 * @brief Validate that encoded data can be properly decoded with strict padding rules
 * @param encoded_data Encoded data to validate
 * @return true if data is valid
 */
bool validate_huffman_encoded_data(const std::vector<uint8_t> &encoded_data);

/**
 * @brief Benchmark Huffman performance
 * @param input Input string
 * @param iterations Number of iterations
 * @return Pair of (encode_time_ms, decode_time_ms) per operation
 */
std::pair<double, double> benchmark_huffman_performance(const std::string &input, std::size_t iterations);

/**
 * @brief Get global Huffman statistics
 * @return Reference to global statistics
 */
HuffmanStats &get_global_huffman_stats();

/**
 * @brief Print Huffman code for a character
 * @param ch Character to print
 * @param os Output stream
 */
void print_huffman_code(char ch, std::ostream &os);

/**
 * @brief Print Huffman table for a string
 * @param str String to analyze
 * @param os Output stream
 */
void print_string_HUFFMAN_TABLE(const std::string &str, std::ostream &os);

} // namespace qb::protocol::hpack::huffman