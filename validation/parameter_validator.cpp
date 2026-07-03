/**
 * @file qbm/http/validation/parameter_validator.cpp
 * @brief Implementation of the ParameterValidator class.
 *
 * This file contains the implementation of the ParameterValidator class,
 * which is used to validate HTTP parameters according to the rules defined
 * in the ParameterRuleSet.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./parameter_validator.h"
#include <algorithm>
#include <charconv>
#include <cmath>
#include <limits>
#include <qb/system/parse.h>
#include "../utility.h"
#include "./rule.h" // For TypeRule::data_type_to_string

namespace qb::http::validation {
// Changed namespace

void
ParameterValidator::add_param(ParameterRuleSet param_rules) {
    _param_definitions[param_rules.name] = std::move(param_rules);
}

qb::json
ParameterValidator::parse_value(const std::string &input_value, DataType target_type, const std::string &field_path, Result &result,
                                bool &success) const {
    success = true;
    switch (target_type) {
        case DataType::STRING:
            return input_value;
        case DataType::INTEGER: {
            long long val;
            auto      res = std::from_chars(input_value.data(), input_value.data() + input_value.size(), val);
            if (res.ec == std::errc() && res.ptr == input_value.data() + input_value.size()) {
                return val;
            }
            result.add_error(field_path, "type", "Must be a valid integer.", input_value);
            success = false;
            return nullptr;
        }
        case DataType::NUMBER: {
            std::size_t parsed_chars_count = 0;
            // Lenient parse + whole-field check preserves the prior std::stod(input,&pos)
            // semantics exactly (leading whitespace / '+' tolerated, trailing data rejected),
            // but locale-free and without throwing on representable subnormals.
            if (auto val_opt = qb::to_number_prefix<double>(input_value, &parsed_chars_count);
                val_opt && parsed_chars_count == input_value.length()) {
                const double val_double = *val_opt;
                // Reject NaN/Infinity explicitly: they are not valid JSON numbers
                // and casting them to integral types is undefined/unsafe.
                if (!std::isfinite(val_double)) {
                    result.add_error(field_path, "type", "Must be a valid finite number.", input_value);
                    success = false;
                    return nullptr;
                }

                // Preserve integer values as integer JSON when representable.
                // NB: (double)LLONG_MAX rounds UP to 2^63, which is NOT representable as a
                // long long, so a naive `val_double <= (double)LLONG_MAX` admits exactly
                // 2^63 and the subsequent static_cast<long long> is undefined behavior
                // (UBSan-flagged; -O2 yields garbage). Use a STRICT upper bound of 2^63,
                // expressed as -(double)LLONG_MIN (LLONG_MIN == -2^63 is exact, so its
                // negation is the exact 2^63). Only [-2^63, 2^63) — all representable —
                // reaches the cast.
                constexpr double ll_min_as_double = static_cast<double>(std::numeric_limits<long long>::min());
                if (val_double >= ll_min_as_double && val_double < -ll_min_as_double) {
                    const long long val_ll = static_cast<long long>(val_double);
                    if (static_cast<double>(val_ll) == val_double) {
                        return val_ll;
                    }
                }
                return val_double;
            }
            result.add_error(field_path, "type", "Must be a valid number.", input_value);
            success = false;
            return nullptr;
        }
        case DataType::BOOLEAN: {
            std::string lower_val = input_value;
            std::transform(lower_val.begin(), lower_val.end(), lower_val.begin(), [](char c) { return qb::http::utility::ascii_to_lower(c); });
            if (lower_val == "true" || lower_val == "1")
                return true;
            if (lower_val == "false" || lower_val == "0")
                return false;
            result.add_error(field_path, "type", "Must be a valid boolean (true, false, 1, 0).", input_value);
            success = false;
            return nullptr;
        }
        case DataType::ARRAY:
            // For parameters, ARRAY is often represented as a comma-separated string or multiple query params.
            // Actual parsing to a JSON array might happen higher up or be handled by a custom parser.
            // Here, we treat it as a string that might be validated by rules like minItems/maxItems if they
            // are adapted or if a custom parser converts it to a qb::json array first.
            // For basic type checking, if it's just a string, it "passes" this stage, further rules apply.
            return input_value;
        case DataType::OBJECT:
        case DataType::NUL:
        case DataType::ANY:
        default:
            result.add_error(field_path, "type", "Unsupported target type for parameter parsing: " + TypeRule::data_type_to_string(target_type),
                             input_value);
            success = false;
            return nullptr;
    }
}

qb::json
ParameterValidator::validate_single(const std::string &param_name, const std::optional<std::string> &value_opt, const ParameterRuleSet &rules,
                                    Result &result, const std::string &param_source_name) const {
    std::string field_path = param_source_name + "." + param_name;
    std::string current_value_str;
    bool        value_present = value_opt.has_value();

    if (value_present) {
        current_value_str = *value_opt;
    } else {
        if (rules.required) {
            if (rules.default_value.has_value()) {
                current_value_str = *rules.default_value;
                value_present     = true;
            } else {
                result.add_error(field_path, "required", "Parameter is required.", qb::json());
                return nullptr;
            }
        } else {
            if (rules.default_value.has_value()) {
                current_value_str = *rules.default_value;
                value_present     = true;
            } else {
                return nullptr;
            }
        }
    }

    if (!value_present)
        return nullptr;

    qb::json parsed_value;
    bool     parse_success = true;

    if (rules.custom_parser) {
        try {
            parsed_value = rules.custom_parser(current_value_str, parse_success);
        } catch (const std::exception &e) {
            result.add_error(field_path, "customParseException", "Custom parser threw exception: " + std::string(e.what()), current_value_str);
            return nullptr;
        } catch (...) {
            result.add_error(field_path, "customParseException", "Custom parser threw unknown exception.", current_value_str);
            return nullptr;
        }
        if (!parse_success) {
            // The custom parser is responsible for adding an error to 'result' if it fails.
            // However, if it didn't, but still indicated failure, add a generic one.
            if (result.success()) {
                result.add_error(field_path, "customParse", "Failed to parse using custom parser.", current_value_str);
            }
            return nullptr;
        }
    } else {
        parsed_value = parse_value(current_value_str, rules.expected_type, field_path, result, parse_success);
        if (!parse_success) {
            // parse_value already added an error.
            return nullptr;
        }
    }

    // Apply validation rules to the (potentially type-converted) value.
    bool all_rules_passed = true;
    for (const auto &rule : rules.rules) {
        try {
            if (!rule->validate(parsed_value, field_path, result)) {
                all_rules_passed = false;
                // Unlike schema keywords, for parameters, we typically stop at the first rule failure for a single parameter.
                // However, the current loop continues, which might be desired if multiple errors for one param are needed.
                // For now, let it collect all. If first-fail is desired, add 'break;' here.
            }
        } catch (const std::exception &e) {
            result.add_error(field_path, "ruleExecutionException", "Validation rule threw exception: " + std::string(e.what()), parsed_value);
            all_rules_passed = false;
        } catch (...) {
            result.add_error(field_path, "ruleExecutionException", "Validation rule threw unknown exception.", parsed_value);
            all_rules_passed = false;
        }
    }

    return all_rules_passed ? parsed_value : nullptr;
}

bool
ParameterValidator::validate(const qb::icase_unordered_map<std::string> &params, Result &result, const std::string &param_source_name) const {
    bool overall_success = true;

    // Validate defined parameters
    for (const auto &[name, rules] : _param_definitions) {
        auto                       it = params.find(name);
        std::optional<std::string> value_opt;
        if (it != params.end()) {
            value_opt = it->second;
            // Assuming single string value for simplicity here. Multi-value handled by RequestValidator.
        }

        // Inherit parent policy (ErrorValuePolicy / preview budget) for each child result.
        Result single_param_result = result.make_child();
        validate_single(name, value_opt, rules, single_param_result, param_source_name);
        if (!single_param_result.success()) {
            result.merge(single_param_result); // Merge errors into the main result
            overall_success = false;
        }
    }

    // Check for unexpected parameters if in strict mode
    if (_strict_mode) {
        for (const auto &[name_in_request, value_in_request] : params) {
            if (_param_definitions.find(name_in_request) == _param_definitions.end()) {
                result.add_error(param_source_name + "." + name_in_request, "unexpectedParameter", "Unexpected parameter provided.",
                                 value_in_request);
                overall_success = false;
            }
        }
    }

    return overall_success;
}
} // namespace qb::http::validation
