/**
 * @file qbm/http/validation/rule.cpp
 * @brief Implementation of the Rule class.
 *
 * This file contains the implementation of the Rule class,
 * which is used to validate HTTP requests according to the rules defined
 * in the RequestValidator.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./rule.h"
#include <algorithm>
#include <bit>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <qb/system/container/unordered_set.h>
#include "./schema_validator.h"

namespace qb::http::validation {
namespace {

std::optional<std::size_t>
utf8_code_point_count(std::string_view text) noexcept {
    std::size_t count = 0;
    for (std::size_t i = 0; i < text.size();) {
        const auto first = static_cast<unsigned char>(text[i]);
        if (first < 0x80u) {
            // ASCII blocks count one code point per byte. memcpy permits
            // unaligned loads on every supported architecture without aliasing UB.
            constexpr std::uint64_t kHighBits = 0x8080808080808080ull;
            while (text.size() - i >= 4 * sizeof(std::uint64_t)) {
                std::uint64_t words[4];
                std::memcpy(words, text.data() + i, sizeof(words));
                if (((words[0] | words[1] | words[2] | words[3]) & kHighBits) != 0)
                    break;
                i += sizeof(words);
                count += sizeof(words);
            }
            while (text.size() - i >= sizeof(std::uint64_t)) {
                std::uint64_t bytes;
                std::memcpy(&bytes, text.data() + i, sizeof(bytes));
                if ((bytes & kHighBits) != 0)
                    break;
                i += sizeof(bytes);
                count += sizeof(bytes);
            }
            while (i < text.size() && static_cast<unsigned char>(text[i]) < 0x80u) {
                ++i;
                ++count;
            }
            continue;
        }

        if constexpr (std::endian::native == std::endian::little) {
            if (first >= 0xc2u && first <= 0xdfu) {
                // A word holds four two-byte scalars: C2-DF at even offsets,
                // 80-BF at odd offsets. Test every lead's low bits too, so
                // overlong C0/C1 cannot slip in at a later block boundary.
                const auto four_pairs_valid = [](std::uint64_t pairs) noexcept {
                    constexpr std::uint64_t kLeadMask    = 0x00e000e000e000e0ull;
                    constexpr std::uint64_t kLeadPattern = 0x00c000c000c000c0ull;
                    constexpr std::uint64_t kTailMask    = 0xc000c000c000c000ull;
                    constexpr std::uint64_t kTailPattern = 0x8000800080008000ull;
                    constexpr std::uint64_t kLeadLowBits = 0x001e001e001e001eull;
                    const auto              low_bits     = pairs & kLeadLowBits;
                    return (pairs & kLeadMask) == kLeadPattern && (pairs & kTailMask) == kTailPattern && (low_bits & 0x000000000000001eull) != 0
                           && (low_bits & 0x00000000001e0000ull) != 0 && (low_bits & 0x0000001e00000000ull) != 0
                           && (low_bits & 0x001e000000000000ull) != 0;
                };
                const auto start = i;
                while (text.size() - i >= 4 * sizeof(std::uint64_t)) {
                    std::uint64_t blocks[4];
                    std::memcpy(blocks, text.data() + i, sizeof(blocks));
                    if (!four_pairs_valid(blocks[0]) || !four_pairs_valid(blocks[1]) || !four_pairs_valid(blocks[2])
                        || !four_pairs_valid(blocks[3]))
                        break;
                    i += sizeof(blocks);
                    count += 16;
                }
                while (text.size() - i >= sizeof(std::uint64_t)) {
                    std::uint64_t pairs;
                    std::memcpy(&pairs, text.data() + i, sizeof(pairs));
                    if (!four_pairs_valid(pairs))
                        break;
                    i += sizeof(pairs);
                    count += 4;
                }
                if (i != start)
                    continue;
            }
        }

        std::size_t width = 0;
        if (first >= 0xc2u && first <= 0xdfu)
            width = 2;
        else if (first >= 0xe0u && first <= 0xefu)
            width = 3;
        else if (first >= 0xf0u && first <= 0xf4u)
            width = 4;
        else
            return std::nullopt;
        if (width > text.size() - i)
            return std::nullopt;

        const auto second = static_cast<unsigned char>(text[i + 1]);
        if ((second & 0xc0u) != 0x80u || (first == 0xe0u && second < 0xa0u) || (first == 0xedu && second > 0x9fu)
            || (first == 0xf0u && second < 0x90u) || (first == 0xf4u && second > 0x8fu))
            return std::nullopt;
        for (std::size_t j = 2; j < width; ++j)
            if ((static_cast<unsigned char>(text[i + j]) & 0xc0u) != 0x80u)
                return std::nullopt;
        i += width;
        ++count;
    }
    return count;
}

template <typename T>
int
compare_same_kind(T lhs, T rhs) noexcept {
    return static_cast<int>(lhs > rhs) - static_cast<int>(lhs < rhs);
}

std::optional<int>
compare_signed_to_double(std::int64_t lhs, double rhs) noexcept {
    if (std::isnan(rhs))
        return std::nullopt;
    constexpr double kTwoTo63 = 0x1p63;
    if (rhs < -kTwoTo63)
        return 1;
    if (rhs >= kTwoTo63)
        return -1;
    const double whole    = std::trunc(rhs);
    const auto   integral = static_cast<std::int64_t>(whole);
    if (lhs != integral)
        return compare_same_kind(lhs, integral);
    return compare_same_kind(whole, rhs);
}

std::optional<int>
compare_unsigned_to_double(std::uint64_t lhs, double rhs) noexcept {
    if (std::isnan(rhs))
        return std::nullopt;
    constexpr double kTwoTo64 = 0x1p64;
    if (rhs < 0.0)
        return 1;
    if (rhs >= kTwoTo64)
        return -1;
    const double whole    = std::trunc(rhs);
    const auto   integral = static_cast<std::uint64_t>(whole);
    if (lhs != integral)
        return compare_same_kind(lhs, integral);
    return compare_same_kind(whole, rhs);
}

std::optional<int>
compare_numbers(const qb::json &lhs, const qb::json &rhs) noexcept {
    if (lhs.is_number_unsigned()) {
        const auto value = lhs.get<qb::json::number_unsigned_t>();
        if (rhs.is_number_unsigned())
            return compare_same_kind(value, rhs.get<qb::json::number_unsigned_t>());
        if (rhs.is_number_integer()) {
            const auto other = rhs.get<qb::json::number_integer_t>();
            return other < 0 ? 1 : compare_same_kind(value, static_cast<std::uint64_t>(other));
        }
        return compare_unsigned_to_double(value, rhs.get<qb::json::number_float_t>());
    }
    if (lhs.is_number_integer()) {
        const auto value = lhs.get<qb::json::number_integer_t>();
        if (rhs.is_number_unsigned()) {
            if (value < 0)
                return -1;
            return compare_same_kind(static_cast<std::uint64_t>(value), rhs.get<qb::json::number_unsigned_t>());
        }
        if (rhs.is_number_integer())
            return compare_same_kind(value, rhs.get<qb::json::number_integer_t>());
        return compare_signed_to_double(value, rhs.get<qb::json::number_float_t>());
    }
    const auto value = lhs.get<qb::json::number_float_t>();
    if (rhs.is_number_unsigned()) {
        const auto order = compare_unsigned_to_double(rhs.get<qb::json::number_unsigned_t>(), value);
        return order ? std::optional<int>(-*order) : std::nullopt;
    }
    if (rhs.is_number_integer()) {
        const auto order = compare_signed_to_double(rhs.get<qb::json::number_integer_t>(), value);
        return order ? std::optional<int>(-*order) : std::nullopt;
    }
    const auto other = rhs.get<qb::json::number_float_t>();
    if (std::isnan(value) || std::isnan(other))
        return std::nullopt;
    return compare_same_kind(value, other);
}

bool
equal_json_values(const qb::json &lhs, const qb::json &rhs) {
    if (lhs.is_number() && rhs.is_number()) {
        const auto order = compare_numbers(lhs, rhs);
        if (order)
            return *order == 0;
        // NaN is outside JSON, but programmatic qb::json values must still
        // give the hash table a reflexive equality relation.
        return lhs.is_number_float() && rhs.is_number_float() && std::isnan(lhs.get<double>()) && std::isnan(rhs.get<double>());
    }
    if (lhs.type() != rhs.type())
        return false;
    if (lhs.is_array()) {
        if (lhs.size() != rhs.size())
            return false;
        for (std::size_t i = 0; i < lhs.size(); ++i)
            if (!equal_json_values(lhs[i], rhs[i]))
                return false;
        return true;
    }
    if (lhs.is_object()) {
        if (lhs.size() != rhs.size())
            return false;
        auto left  = lhs.begin();
        auto right = rhs.begin();
        for (; left != lhs.end(); ++left, ++right)
            if (left.key() != right.key() || !equal_json_values(left.value(), right.value()))
                return false;
        return true;
    }
    return lhs == rhs;
}

std::size_t
combine_hash(std::size_t seed, std::size_t value) noexcept {
    return seed ^ (value + 0x9e3779b9u + (seed << 6u) + (seed >> 2u));
}

std::size_t
hash_number(const qb::json &value) noexcept {
    constexpr std::size_t kNumberTag = 0x4e554d42u;
    if (value.is_number_unsigned())
        return combine_hash(kNumberTag, std::hash<std::uint64_t>{}(value.get<qb::json::number_unsigned_t>()));
    if (value.is_number_integer()) {
        const auto signed_value = value.get<qb::json::number_integer_t>();
        if (signed_value >= 0)
            return combine_hash(kNumberTag, std::hash<std::uint64_t>{}(static_cast<std::uint64_t>(signed_value)));
        return combine_hash(kNumberTag, std::hash<std::int64_t>{}(signed_value));
    }
    const auto number = value.get<qb::json::number_float_t>();
    if (std::isnan(number))
        return combine_hash(kNumberTag ^ 0x464c4f41u, 0x4e414e00u);
    if (number == 0.0)
        return combine_hash(kNumberTag, std::hash<std::uint64_t>{}(0));
    if (std::isfinite(number) && std::trunc(number) == number) {
        if (number >= 0.0 && number < 0x1p64)
            return combine_hash(kNumberTag, std::hash<std::uint64_t>{}(static_cast<std::uint64_t>(number)));
        if (number < 0.0 && number >= -0x1p63)
            return combine_hash(kNumberTag, std::hash<std::int64_t>{}(static_cast<std::int64_t>(number)));
    }
    return combine_hash(kNumberTag ^ 0x464c4f41u, std::hash<double>{}(number));
}

std::size_t
hash_json_value(const qb::json &value) {
    if (value.is_number())
        return hash_number(value);
    std::size_t seed = static_cast<std::size_t>(value.type());
    if (value.is_array()) {
        seed = combine_hash(seed, value.size());
        for (const auto &item : value)
            seed = combine_hash(seed, hash_json_value(item));
    } else if (value.is_object()) {
        seed = combine_hash(seed, value.size());
        for (auto const &[key, item] : value.items()) {
            seed = combine_hash(seed, std::hash<std::string>{}(key));
            seed = combine_hash(seed, hash_json_value(item));
        }
    } else if (value.is_string()) {
        seed = combine_hash(seed, std::hash<std::string>{}(value.get_ref<const std::string &>()));
    } else if (value.is_boolean()) {
        seed = combine_hash(seed, std::hash<bool>{}(value.get<bool>()));
    } else {
        seed = combine_hash(seed, std::hash<qb::json>{}(value));
    }
    return seed;
}

struct JsonPointerHash {
    std::size_t
    operator()(const qb::json *value) const {
        return hash_json_value(*value);
    }
};

struct JsonPointerEqual {
    bool
    operator()(const qb::json *lhs, const qb::json *rhs) const {
        return equal_json_values(*lhs, *rhs);
    }
};

} // namespace

std::string
TypeRule::data_type_to_string(DataType dt) noexcept {
    switch (dt) {
        case DataType::STRING:
            return "string";
        case DataType::INTEGER:
            return "integer";
        case DataType::NUMBER:
            return "number";
        case DataType::BOOLEAN:
            return "boolean";
        case DataType::OBJECT:
            return "object";
        case DataType::ARRAY:
            return "array";
        case DataType::NUL:
            return "null";
        case DataType::ANY:
            return "any";
        default:
            return "unknown";
    }
}

TypeRule::TypeRule(DataType expected_type)
    : _expected_type(expected_type) {
    _type_name_str = data_type_to_string(expected_type);
}

bool
TypeRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
    bool valid = false;
    switch (_expected_type) {
        case DataType::STRING:
            valid = value.is_string();
            break;
        case DataType::INTEGER:
            valid = value.is_number_integer();
            break;
        case DataType::NUMBER:
            valid = value.is_number();
            break;
        case DataType::BOOLEAN:
            valid = value.is_boolean();
            break;
        case DataType::OBJECT:
            valid = value.is_object();
            break;
        case DataType::ARRAY:
            valid = value.is_array();
            break;
        case DataType::NUL:
            valid = value.is_null();
            break;
        case DataType::ANY:
            valid = true;
            break;
    }
    if (!valid) {
        result.add_error(field_path, rule_name(), "Invalid type. Expected " + _type_name_str + ".", std::make_optional(value));
    }
    return valid;
}

bool
RequiredRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
    (void) value;
    (void) field_path;
    (void) result;
    // This rule's logic is handled by SchemaValidator::validate_required_keyword for schema validation contexts.
    // For ParameterValidator, presence is checked before rule application.
    // Thus, if this validate method is called, the value is considered present for the rule itself to pass.
    return true;
}

bool
MinLengthRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
    if (value.is_string()) {
        const auto length = utf8_code_point_count(value.get_ref<const std::string &>());
        if (!length) {
            result.add_error(field_path, rule_name(), "String is not valid UTF-8.", std::nullopt);
            return false;
        }
        if (*length < _min_length) {
            result.add_error(field_path, rule_name(), "String too short. Minimum length is " + std::to_string(_min_length) + ".",
                             std::make_optional(value));
            return false;
        }
    } else if (value.is_array()) {
        // Apply to arrays as well (minItems is preferred for arrays by JSON Schema spec)
        if (value.size() < _min_length) {
            result.add_error(field_path, rule_name(), "Array too short. Minimum items is " + std::to_string(_min_length) + ".",
                             std::make_optional(value));
            return false;
        }
    }
    // If not string or array, this rule doesn't apply / passes by default.
    return true;
}

bool
MaxLengthRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
    if (value.is_string()) {
        const auto length = utf8_code_point_count(value.get_ref<const std::string &>());
        if (!length) {
            result.add_error(field_path, rule_name(), "String is not valid UTF-8.", std::nullopt);
            return false;
        }
        if (*length > _max_length) {
            result.add_error(field_path, rule_name(), "String too long. Maximum length is " + std::to_string(_max_length) + ".",
                             std::make_optional(value));
            return false;
        }
    } else if (value.is_array()) {
        // Apply to arrays as well (maxItems is preferred for arrays by JSON Schema spec)
        if (value.size() > _max_length) {
            result.add_error(field_path, rule_name(), "Array too long. Maximum items is " + std::to_string(_max_length) + ".",
                             std::make_optional(value));
            return false;
        }
    }
    // If not string or array, this rule doesn't apply / passes by default.
    return true;
}

// Security: Maximum string length for regex validation. Two distinct DoS vectors:
//  1. Catastrophic backtracking (classic ReDoS) — bounded by capping the input.
//  2. Stack exhaustion — libstdc++'s std::regex executor is RECURSIVE (it descends one
//     frame per matched character for a repeat like `.*`/`+`), so a long input against
//     an otherwise benign pattern overflows the stack and crashes the process. Measured
//     on libstdc++ (clang-19, aarch64, default 8 MB stack): `^.*$` overflows above ~4 KiB
//     of input under ASan, and a release build crashes well before the old 256 KiB cap —
//     i.e. 256 KiB was never actually safe here. Cap at 2 KiB: comfortably under the
//     measured limit (and below it again for more-recursive patterns / smaller
//     worker-thread stacks), yet far larger than any realistic pattern-validated field
//     (emails, usernames, UUIDs, tokens). macOS libc++ does not recurse this way, which
//     is why the crash only surfaced on Linux.
constexpr std::size_t MAX_REGEX_INPUT_LENGTH = 2 * 1024; // 2 KiB
// Align with cors_security_limits::MAX_REGEX_PATTERN_LENGTH — huge patterns are rarely
// legitimate JSON Schema and are expensive to compile in libstdc++.
constexpr std::size_t MAX_REGEX_PATTERN_LENGTH = 1024;

PatternRule::PatternRule(std::string pattern_str)
    : _pattern_str(std::move(pattern_str)) {
    if (_pattern_str.length() > MAX_REGEX_PATTERN_LENGTH) {
        throw std::invalid_argument("JSON Schema pattern exceeds maximum length (" + std::to_string(MAX_REGEX_PATTERN_LENGTH)
                                    + " chars); shorten the pattern or split validation.");
    }
    try {
        _regex = std::regex(_pattern_str, std::regex_constants::ECMAScript | std::regex_constants::optimize);
    } catch (const std::regex_error &e) {
        // It's crucial that schema authors provide valid regex. This throw prevents using an invalid rule.
        throw std::invalid_argument("Invalid regex pattern in schema: '" + _pattern_str + "'. Error: " + e.what());
    }
}

bool
PatternRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
    if (!value.is_string()) {
        return true; // Pattern rule only applies to strings.
    }
    const auto &str_val = value.get<std::string>();

    // Security: ReDoS protection - limit input size for regex matching
    // Pathological regex patterns can cause exponential time complexity
    if (str_val.length() > MAX_REGEX_INPUT_LENGTH) {
        result.add_error(field_path, rule_name(),
                         "String exceeds maximum length for pattern validation (" + std::to_string(MAX_REGEX_INPUT_LENGTH)
                             + " chars). "
                               "This limit protects against ReDoS attacks.",
                         std::make_optional(value));
        return false;
    }

    // std::regex_match can THROW std::regex_error at match time — on libc++ its
    // catastrophic-backtracking guard throws "complexity exceeded" (libstdc++ has no such
    // guard, but the MAX_REGEX_INPUT_LENGTH cap above bounds its backtracking). This is
    // reached from the body-schema path (SchemaValidator::apply_primitive_rules), which has
    // NO try/catch up to ValidationMiddleware and the noexcept I/O boundary — an uncaught
    // regex_error would cross it. Treat an engine failure as a validation failure.
    try {
        if (!std::regex_match(str_val, _regex)) {
            result.add_error(field_path, rule_name(), "String does not match pattern: " + _pattern_str, std::make_optional(value));
            return false;
        }
    } catch (const std::regex_error &) {
        result.add_error(field_path, rule_name(), "Pattern could not be evaluated (regex complexity limit exceeded).",
                         std::make_optional(value));
        return false;
    }
    return true;
}

MinimumRule::MinimumRule(double min_val, bool exclusive)
    : MinimumRule(qb::json(min_val), exclusive) {}

MinimumRule::MinimumRule(qb::json min_val, bool exclusive)
    : _minimum(std::move(min_val))
    , _exclusive(exclusive) {
    if (!_minimum.is_number())
        throw std::invalid_argument("MinimumRule requires a numeric bound.");
}

bool
MinimumRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
    if (_minimum.is_number_float() && !std::isfinite(_minimum.get<double>())) {
        result.add_error(field_path, rule_name(), "Numeric bound must be finite.", std::nullopt);
        return false;
    }
    if (!value.is_number())
        return true; // Rule only applies to numbers.
    const auto order = compare_numbers(value, _minimum);
    if (_exclusive) {
        if (!order || *order <= 0) {
            result.add_error(field_path, rule_name(), "Value must be greater than " + _minimum.dump() + ".", std::make_optional(value));
            return false;
        }
    } else {
        if (!order || *order < 0) {
            result.add_error(field_path, rule_name(), "Value must be greater than or equal to " + _minimum.dump() + ".",
                             std::make_optional(value));
            return false;
        }
    }
    return true;
}

MaximumRule::MaximumRule(double max_val, bool exclusive)
    : MaximumRule(qb::json(max_val), exclusive) {}

MaximumRule::MaximumRule(qb::json max_val, bool exclusive)
    : _maximum(std::move(max_val))
    , _exclusive(exclusive) {
    if (!_maximum.is_number())
        throw std::invalid_argument("MaximumRule requires a numeric bound.");
}

bool
MaximumRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
    if (_maximum.is_number_float() && !std::isfinite(_maximum.get<double>())) {
        result.add_error(field_path, rule_name(), "Numeric bound must be finite.", std::nullopt);
        return false;
    }
    if (!value.is_number())
        return true; // Rule only applies to numbers.
    const auto order = compare_numbers(value, _maximum);
    if (_exclusive) {
        if (!order || *order >= 0) {
            result.add_error(field_path, rule_name(), "Value must be less than " + _maximum.dump() + ".", std::make_optional(value));
            return false;
        }
    } else {
        if (!order || *order > 0) {
            result.add_error(field_path, rule_name(), "Value must be less than or equal to " + _maximum.dump() + ".",
                             std::make_optional(value));
            return false;
        }
    }
    return true;
}

EnumRule::EnumRule(qb::json allowed_values)
    : _allowed_values(std::move(allowed_values)) {
    if (!_allowed_values.is_array()) {
        // This is a schema definition error, not a validation error against data.
        throw std::invalid_argument("EnumRule requires an array of allowed values.");
    }
}

bool
EnumRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
    bool found = false;
    for (const auto &allowed_val : _allowed_values) {
        if (equal_json_values(value, allowed_val)) {
            found = true;
            break;
        }
    }
    if (!found) {
        result.add_error(field_path, rule_name(), "Value is not one of the allowed enumerated values.", std::make_optional(value));
        return false;
    }
    return true;
}

bool
UniqueItemsRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
    if (!value.is_array())
        return true; // Rule only applies to arrays.

    qb::unordered_flat_set<const qb::json *, JsonPointerHash, JsonPointerEqual> seen_items;
    for (const auto &item : value) {
        if (!seen_items.insert(&item).second) {
            // .second is false if item was already present
            result.add_error(field_path, rule_name(), "Array items must be unique.", std::make_optional(value));
            // Report error on the whole array value
            return false;
        }
    }
    return true;
}

bool
MinItemsRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
    if (!value.is_array())
        return true; // Rule only applies to arrays.
    if (value.size() < _min_items) {
        result.add_error(field_path, rule_name(), "Array must contain at least " + std::to_string(_min_items) + " items.",
                         std::make_optional(value));
        return false;
    }
    return true;
}

bool
MaxItemsRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
    if (!value.is_array())
        return true; // Rule only applies to arrays.
    if (value.size() > _max_items) {
        result.add_error(field_path, rule_name(), "Array must contain at most " + std::to_string(_max_items) + " items.",
                         std::make_optional(value));
        return false;
    }
    return true;
}

bool
MinPropertiesRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
    if (!value.is_object())
        return true; // Rule only applies to objects.
    if (value.size() < _min_properties) {
        result.add_error(field_path, rule_name(), "Object must have at least " + std::to_string(_min_properties) + " properties.",
                         std::make_optional(value));
        return false;
    }
    return true;
}

bool
MaxPropertiesRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
    if (!value.is_object())
        return true; // Rule only applies to objects.
    if (value.size() > _max_properties) {
        result.add_error(field_path, rule_name(), "Object must have at most " + std::to_string(_max_properties) + " properties.",
                         std::make_optional(value));
        return false;
    }
    return true;
}

PropertyNamesRule::PropertyNamesRule(const qb::json &name_schema_definition)
    : _name_schema_definition_copy(name_schema_definition) {}

bool
PropertyNamesRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
    if (!value.is_object())
        return true; // Rule only applies to objects.

    bool            all_names_valid = true;
    SchemaValidator name_validator(_name_schema_definition_copy);

    for (auto const &[prop_name, _] : value.items()) {
        qb::json prop_name_json = prop_name; // Convert property name string to qb::json for validation
        Result   name_val_result;            // Temporary result for this specific property name's validation

        std::string name_specific_error_path =
            field_path.empty() ? std::string("<propertyName:" + prop_name + ">") : field_path + ".<propertyName:" + prop_name + ">";

        if (!name_validator.validate(prop_name_json, name_val_result)) {
            for (const auto &err : name_val_result.errors()) {
                // Prepend the specific property name context to the error path from sub-validation.
                std::string reported_path = name_specific_error_path + (err.field_path.empty() ? "" : ("." + err.field_path));
                result.add_error(reported_path, err.rule_violated, "Property name '" + prop_name + "' failed validation: " + err.message,
                                 std::make_optional(prop_name_json));
            }
            all_names_valid = false;
            // It might be desirable to collect all property name errors, so no `break` here.
        }
    }
    return all_names_valid;
}

ItemsRule::ItemsRule(ItemsRuleLogic logic, std::variant<bool, std::shared_ptr<SchemaValidator>> additional_items_policy)
    : _logic(std::move(logic))
    , _additional_items_policy(std::move(additional_items_policy)) {}

bool
ItemsRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
    // The actual validation logic for "items" and "additionalItems" is complex and handled within
    // SchemaValidator::validate_items_keyword directly. This rule class primarily serves as a data carrier
    // if we were to use it in a purely rule-driven approach, but SchemaValidator adopts a more direct keyword handling.
    // Thus, this validate method is often bypassed or not directly called for schema validation of items.
    (void) value;
    (void) field_path;
    (void) result;
    return true; // Placeholder, actual logic in SchemaValidator.
}
} // namespace qb::http::validation
