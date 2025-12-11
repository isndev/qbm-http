/**
 * @file qbm/http/validation/rule.cpp
 * @brief Implementation of the Rule class.
 *
 * This file contains the implementation of the Rule class,
 * which is used to validate HTTP requests according to the rules defined
 * in the RequestValidator.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Validaton
 */
#include "./rule.h"
#include "./schema_validator.h"
#include <qb/system/container/unordered_set.h>
#include <algorithm>

namespace qb::http::validation {
    // Implementations for TypeRule, RequiredRule, MinLengthRule, MaxLengthRule,
    // PatternRule, MinimumRule, MaximumRule, EnumRule, UniqueItemsRule,
    // MinItemsRule, MaxItemsRule, MinPropertiesRule, MaxPropertiesRule, PropertyNamesRule
    // need to use Result instead of ValidationResult in their method signatures
    // and refer to other types within qb::http::validation if necessary.

    // Example for TypeRule:
    std::string TypeRule::data_type_to_string(DataType dt) noexcept {
        switch (dt) {
            case DataType::STRING: return "string";
            case DataType::INTEGER: return "integer";
            case DataType::NUMBER: return "number";
            case DataType::BOOLEAN: return "boolean";
            case DataType::OBJECT: return "object";
            case DataType::ARRAY: return "array";
            case DataType::NUL: return "null";
            case DataType::ANY: return "any";
            default: return "unknown";
        }
    }

    TypeRule::TypeRule(DataType expected_type) : _expected_type(expected_type) {
        _type_name_str = data_type_to_string(expected_type);
    }

    bool TypeRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
        bool valid = false;
        switch (_expected_type) {
            case DataType::STRING: valid = value.is_string();
                break;
            case DataType::INTEGER: valid = value.is_number_integer();
                break;
            case DataType::NUMBER: valid = value.is_number();
                break;
            case DataType::BOOLEAN: valid = value.is_boolean();
                break;
            case DataType::OBJECT: valid = value.is_object();
                break;
            case DataType::ARRAY: valid = value.is_array();
                break;
            case DataType::NUL: valid = value.is_null();
                break;
            case DataType::ANY: valid = true;
                break;
        }
        if (!valid) {
            result.add_error(field_path, rule_name(), "Invalid type. Expected " + _type_name_str + ".", std::make_optional(value));
        }
        return valid;
    }

    bool RequiredRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
        (void) value;
        (void) field_path;
        (void) result;
        // This rule's logic is handled by SchemaValidator::validate_required_keyword for schema validation contexts.
        // For ParameterValidator, presence is checked before rule application.
        // Thus, if this validate method is called, the value is considered present for the rule itself to pass.
        return true;
    }

    bool MinLengthRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
        if (value.is_string()) {
            if (value.get<std::string>().length() < _min_length) {
                result.add_error(field_path, rule_name(),
                                 "String too short. Minimum length is " + std::to_string(_min_length) + ".", std::make_optional(value));
                return false;
            }
        } else if (value.is_array()) {
            // Apply to arrays as well (minItems is preferred for arrays by JSON Schema spec)
            if (value.size() < _min_length) {
                result.add_error(field_path, rule_name(),
                                 "Array too short. Minimum items is " + std::to_string(_min_length) + ".", std::make_optional(value));
                return false;
            }
        }
        // If not string or array, this rule doesn't apply / passes by default.
        return true;
    }

    bool MaxLengthRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
        if (value.is_string()) {
            if (value.get<std::string>().length() > _max_length) {
                result.add_error(field_path, rule_name(),
                                 "String too long. Maximum length is " + std::to_string(_max_length) + ".", std::make_optional(value));
                return false;
            }
        } else if (value.is_array()) {
            // Apply to arrays as well (maxItems is preferred for arrays by JSON Schema spec)
            if (value.size() > _max_length) {
                result.add_error(field_path, rule_name(),
                                 "Array too long. Maximum items is " + std::to_string(_max_length) + ".", std::make_optional(value));
                return false;
            }
        }
        // If not string or array, this rule doesn't apply / passes by default.
        return true;
    }

    PatternRule::PatternRule(std::string pattern_str) : _pattern_str(std::move(pattern_str)) {
        try {
            _regex = std::regex(_pattern_str, std::regex_constants::ECMAScript | std::regex_constants::optimize);
        } catch (const std::regex_error &e) {
            // It's crucial that schema authors provide valid regex. This throw prevents using an invalid rule.
            throw std::invalid_argument("Invalid regex pattern in schema: '" + _pattern_str + "'. Error: " + e.what());
        }
    }

    bool PatternRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
        if (!value.is_string()) {
            return true; // Pattern rule only applies to strings.
        }
        const auto &str_val = value.get<std::string>();
        if (!std::regex_match(str_val, _regex)) {
            result.add_error(field_path, rule_name(), "String does not match pattern: " + _pattern_str, std::make_optional(value));
            return false;
        }
        return true;
    }

    bool MinimumRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
        if (!value.is_number()) return true; // Rule only applies to numbers.
        double num_val = value.get<double>();
        if (_exclusive) {
            if (num_val <= _minimum) {
                result.add_error(field_path, rule_name(),
                                 "Value must be greater than " + std::to_string(_minimum) + ".", std::make_optional(value));
                return false;
            }
        } else {
            if (num_val < _minimum) {
                result.add_error(field_path, rule_name(),
                                 "Value must be greater than or equal to " + std::to_string(_minimum) + ".", std::make_optional(value));
                return false;
            }
        }
        return true;
    }

    bool MaximumRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
        if (!value.is_number()) return true; // Rule only applies to numbers.
        double num_val = value.get<double>();
        if (_exclusive) {
            if (num_val >= _maximum) {
                result.add_error(field_path, rule_name(), "Value must be less than " + std::to_string(_maximum) + ".",
                                 std::make_optional(value));
                return false;
            }
        } else {
            if (num_val > _maximum) {
                result.add_error(field_path, rule_name(),
                                 "Value must be less than or equal to " + std::to_string(_maximum) + ".", std::make_optional(value));
                return false;
            }
        }
        return true;
    }

    EnumRule::EnumRule(qb::json allowed_values) : _allowed_values(std::move(allowed_values)) {
        if (!_allowed_values.is_array()) {
            // This is a schema definition error, not a validation error against data.
            throw std::invalid_argument("EnumRule requires an array of allowed values.");
        }
    }

    bool EnumRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
        bool found = false;
        for (const auto &allowed_val: _allowed_values) {
            if (value == allowed_val) {
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

    bool UniqueItemsRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
        if (!value.is_array()) return true; // Rule only applies to arrays.

        qb::unordered_set<qb::json> seen_items;
        for (const auto &item: value) {
            if (!seen_items.insert(item).second) {
                // .second is false if item was already present
                result.add_error(field_path, rule_name(), "Array items must be unique.", std::make_optional(value));
                // Report error on the whole array value
                return false;
            }
        }
        return true;
    }

    bool MinItemsRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
        if (!value.is_array()) return true; // Rule only applies to arrays.
        if (value.size() < _min_items) {
            result.add_error(field_path, rule_name(),
                             "Array must contain at least " + std::to_string(_min_items) + " items.", std::make_optional(value));
            return false;
        }
        return true;
    }

    bool MaxItemsRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
        if (!value.is_array()) return true; // Rule only applies to arrays.
        if (value.size() > _max_items) {
            result.add_error(field_path, rule_name(),
                             "Array must contain at most " + std::to_string(_max_items) + " items.", std::make_optional(value));
            return false;
        }
        return true;
    }

    bool MinPropertiesRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
        if (!value.is_object()) return true; // Rule only applies to objects.
        if (value.size() < _min_properties) {
            result.add_error(field_path, rule_name(),
                             "Object must have at least " + std::to_string(_min_properties) + " properties.", std::make_optional(value));
            return false;
        }
        return true;
    }

    bool MaxPropertiesRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
        if (!value.is_object()) return true; // Rule only applies to objects.
        if (value.size() > _max_properties) {
            result.add_error(field_path, rule_name(),
                             "Object must have at most " + std::to_string(_max_properties) + " properties.", std::make_optional(value));
            return false;
        }
        return true;
    }

    PropertyNamesRule::PropertyNamesRule(const qb::json &name_schema_definition)
        : _name_schema_definition_copy(name_schema_definition) {
    }

    bool PropertyNamesRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
        if (!value.is_object()) return true; // Rule only applies to objects.

        bool all_names_valid = true;
        SchemaValidator name_validator(_name_schema_definition_copy);

        for (auto const &[prop_name, _]: value.items()) {
            qb::json prop_name_json = prop_name; // Convert property name string to qb::json for validation
            Result name_val_result; // Temporary result for this specific property name's validation

            std::string name_specific_error_path = field_path.empty()
                                                       ? std::string("<propertyName:" + prop_name + ">")
                                                       : field_path + ".<propertyName:" + prop_name + ">";

            if (!name_validator.validate(prop_name_json, name_val_result)) {
                for (const auto &err: name_val_result.errors()) {
                    // Prepend the specific property name context to the error path from sub-validation.
                    std::string reported_path = name_specific_error_path + (err.field_path.empty()
                                                                                ? ""
                                                                                : ("." + err.field_path));
                    result.add_error(reported_path, err.rule_violated,
                                     "Property name '" + prop_name + "' failed validation: " + err.message,
                                     std::make_optional(prop_name_json));
                }
                all_names_valid = false;
                // It might be desirable to collect all property name errors, so no `break` here.
            }
        }
        return all_names_valid;
    }

    ItemsRule::ItemsRule(ItemsRuleLogic logic,
                         std::variant<bool, std::shared_ptr<SchemaValidator> > additional_items_policy)
        : _logic(std::move(logic)), _additional_items_policy(std::move(additional_items_policy)) {
    }

    bool ItemsRule::validate(const qb::json &value, const std::string &field_path, Result &result) const {
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
