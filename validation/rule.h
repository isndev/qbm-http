/**
 * @file qbm/http/validation/rule.h
 * @brief Defines the Rule class for validating HTTP requests.
 *
 * This file contains the definition of the Rule class,
 * which is used to validate HTTP requests according to the rules defined
 * in the RequestValidator.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <variant>
#include <vector>
#include <qb/json.h>
#include "./error.h"

namespace qb::http::validation {

/**
 * @brief Defines the data type a rule might expect or a value might represent.
 */
enum class DataType { STRING, INTEGER, NUMBER, BOOLEAN, OBJECT, ARRAY, NUL, ANY };

/**
 * @brief Interface for a validation rule.
 *
 * Each rule operates on a qb::json value and reports errors to a Result object.
 */
class IRule {
public:
    virtual ~IRule() = default;

    /**
     * @brief Validates a qb::json value against this rule.
     * @param value The qb::json value to validate.
     * @param field_path The path to the field being validated (for error reporting).
     * @param result The Result object to store any validation errors.
     * @return True if the value is valid according to this rule, false otherwise.
     */
    virtual bool validate(const qb::json &value, const std::string &field_path, Result &result) const = 0;

    /**
     * @brief Gets the name of the rule (e.g., "minLength", "type").
     * @return The string name of the rule.
     */
    virtual std::string rule_name() const = 0;
};

// --- Concrete Rule Implementations ---

/** @brief Validates the data type of a qb::json value. */
class TypeRule : public IRule {
private:
    DataType    _expected_type;
    std::string _type_name_str;

public:
    /**
     * @brief Constructs a TypeRule expecting the given JSON data type.
     * @param expected_type The DataType the validated value must conform to.
     */
    TypeRule(DataType expected_type);

    bool validate(const qb::json &value, const std::string &field_path, Result &result) const override;

    std::string
    rule_name() const override {
        return "type";
    }

    /**
     * @brief Maps a DataType enumerator to its canonical lower-case JSON type name.
     * @param dt The data type to convert.
     * @return The type name (e.g. "string", "integer"); "unknown" for unrecognized values.
     */
    static std::string data_type_to_string(DataType dt) noexcept;
};

/** @brief Placeholder rule for "required" keyword, logic is handled by validators. */
class RequiredRule : public IRule {
public:
    bool validate(const qb::json &value, const std::string &field_path, Result &result) const override;

    std::string
    rule_name() const override {
        return "required";
    }
};

/** @brief Validates the minimum length of a string or minimum number of items in an array. */
class MinLengthRule : public IRule {
private:
    size_t _min_length;

public:
    /**
     * @brief Constructs the rule with the inclusive minimum length/item count.
     * @param min_len Minimum allowed string length or array item count.
     */
    explicit MinLengthRule(size_t min_len)
        : _min_length(min_len) {}

    bool validate(const qb::json &value, const std::string &field_path, Result &result) const override;

    std::string
    rule_name() const override {
        return "minLength";
    }
};

/** @brief Validates the maximum length of a string or maximum number of items in an array. */
class MaxLengthRule : public IRule {
private:
    size_t _max_length;

public:
    /**
     * @brief Constructs the rule with the inclusive maximum length/item count.
     * @param max_len Maximum allowed string length or array item count.
     */
    explicit MaxLengthRule(size_t max_len)
        : _max_length(max_len) {}

    bool validate(const qb::json &value, const std::string &field_path, Result &result) const override;

    std::string
    rule_name() const override {
        return "maxLength";
    }
};

/**
 * @brief Validates a string against a regular expression pattern.
 *
 * ReDoS mitigation: pattern length is capped at compile time and matching input
 * length is capped in the implementation (see `rule.cpp`). Prefer simple,
 * linear-time patterns; `std::regex` does not offer execution timeouts.
 */
class PatternRule : public IRule {
private:
    std::string _pattern_str;
    std::regex  _regex;

public:
    /**
     * @brief Compiles the given ECMAScript regular expression for matching.
     * @param pattern_str The regex pattern to match string values against.
     * @throws std::invalid_argument If the pattern exceeds the maximum allowed
     *         length (ReDoS mitigation) or fails to compile.
     */
    explicit PatternRule(std::string pattern_str);

    bool validate(const qb::json &value, const std::string &field_path, Result &result) const override;

    std::string
    rule_name() const override {
        return "pattern";
    }
};

/** @brief Validates that a number is greater than (or equal to if not exclusive) a minimum value. */
class MinimumRule : public IRule {
private:
    double _minimum;
    bool   _exclusive;

public:
    /**
     * @brief Constructs the rule with the boundary value and comparison mode.
     * @param min_val The minimum value to compare against.
     * @param exclusive If true, the value must be strictly greater than @p min_val.
     */
    MinimumRule(double min_val, bool exclusive = false)
        : _minimum(min_val)
        , _exclusive(exclusive) {}

    bool validate(const qb::json &value, const std::string &field_path, Result &result) const override;

    std::string
    rule_name() const override {
        return _exclusive ? "exclusiveMinimum" : "minimum";
    }
};

/** @brief Validates that a number is less than (or equal to if not exclusive) a maximum value. */
class MaximumRule : public IRule {
private:
    double _maximum;
    bool   _exclusive;

public:
    /**
     * @brief Constructs the rule with the boundary value and comparison mode.
     * @param max_val The maximum value to compare against.
     * @param exclusive If true, the value must be strictly less than @p max_val.
     */
    MaximumRule(double max_val, bool exclusive = false)
        : _maximum(max_val)
        , _exclusive(exclusive) {}

    bool validate(const qb::json &value, const std::string &field_path, Result &result) const override;

    std::string
    rule_name() const override {
        return _exclusive ? "exclusiveMaximum" : "maximum";
    }
};

/** @brief Validates that a value is one of a predefined set of allowed values. */
class EnumRule : public IRule {
private:
    qb::json _allowed_values;

public:
    /**
     * @brief Constructs the rule from the set of permitted values.
     * @param allowed_values A JSON array enumerating the allowed values.
     * @throws std::invalid_argument If @p allowed_values is not a JSON array.
     */
    explicit EnumRule(qb::json allowed_values);

    bool validate(const qb::json &value, const std::string &field_path, Result &result) const override;

    std::string
    rule_name() const override {
        return "enum";
    }
};

/** @brief Validates that all items in an array are unique. */
class UniqueItemsRule : public IRule {
public:
    bool validate(const qb::json &value, const std::string &field_path, Result &result) const override;

    std::string
    rule_name() const override {
        return "uniqueItems";
    }
};

/** @brief Validates the minimum number of items in an array. */
class MinItemsRule : public IRule {
private:
    size_t _min_items;

public:
    /**
     * @brief Constructs the rule with the inclusive minimum item count.
     * @param min_val Minimum number of items the array must contain.
     */
    explicit MinItemsRule(size_t min_val)
        : _min_items(min_val) {}

    bool validate(const qb::json &value, const std::string &field_path, Result &result) const override;

    std::string
    rule_name() const override {
        return "minItems";
    }
};

/** @brief Validates the maximum number of items in an array. */
class MaxItemsRule : public IRule {
private:
    size_t _max_items;

public:
    /**
     * @brief Constructs the rule with the inclusive maximum item count.
     * @param max_val Maximum number of items the array may contain.
     */
    explicit MaxItemsRule(size_t max_val)
        : _max_items(max_val) {}

    bool validate(const qb::json &value, const std::string &field_path, Result &result) const override;

    std::string
    rule_name() const override {
        return "maxItems";
    }
};

/** @brief Validates the minimum number of properties in an object. */
class MinPropertiesRule : public IRule {
private:
    size_t _min_properties;

public:
    /**
     * @brief Constructs the rule with the inclusive minimum property count.
     * @param min_props Minimum number of properties the object must contain.
     */
    explicit MinPropertiesRule(size_t min_props)
        : _min_properties(min_props) {}

    bool validate(const qb::json &value, const std::string &field_path, Result &result) const override;

    std::string
    rule_name() const override {
        return "minProperties";
    }
};

/** @brief Validates the maximum number of properties in an object. */
class MaxPropertiesRule : public IRule {
private:
    size_t _max_properties;

public:
    /**
     * @brief Constructs the rule with the inclusive maximum property count.
     * @param max_props Maximum number of properties the object may contain.
     */
    explicit MaxPropertiesRule(size_t max_props)
        : _max_properties(max_props) {}

    bool validate(const qb::json &value, const std::string &field_path, Result &result) const override;

    std::string
    rule_name() const override {
        return "maxProperties";
    }
};

// Forward declaration
class SchemaValidator;

/** @brief Validates the names of properties in an object against a sub-schema. */
class PropertyNamesRule : public IRule {
private:
    qb::json _name_schema_definition_copy; // Store the schema definition itself

public:
    /**
     * @brief Constructs the rule from a sub-schema applied to each property name.
     * @param name_schema_definition The JSON schema each property name is validated against
     *        (stored by copy).
     */
    explicit PropertyNamesRule(const qb::json &name_schema_definition);

    bool validate(const qb::json &value, const std::string &field_path, Result &result) const override;

    std::string
    rule_name() const override {
        return "propertyNames";
    }
};

using ItemsRuleLogic = std::variant<std::shared_ptr<SchemaValidator>, std::vector<std::shared_ptr<SchemaValidator>>>;

/** @brief Placeholder rule for "items" keyword; logic primarily in SchemaValidator. */
class ItemsRule : public IRule {
private:
    ItemsRuleLogic                                       _logic;
    std::variant<bool, std::shared_ptr<SchemaValidator>> _additional_items_policy;

public:
    /**
     * @brief Constructs the rule carrying the items and additionalItems schema policy.
     * @param logic Either a single sub-schema applied to every item, or a tuple of
     *        per-position sub-schemas.
     * @param additional_items_policy Policy for items beyond the tuple positions:
     *        a boolean (allow/disallow) or a sub-schema; defaults to allowing all.
     */
    explicit ItemsRule(ItemsRuleLogic logic, std::variant<bool, std::shared_ptr<SchemaValidator>> additional_items_policy = true);

    bool validate(const qb::json &value, const std::string &field_path, Result &result) const override;

    std::string
    rule_name() const override {
        return "items";
    }
};

/** @brief Allows defining a custom validation rule using a lambda or function pointer. */
class CustomRule : public IRule {
public:
    /// @brief Signature of a user-supplied validation function.
    using CustomValidateFn = std::function<bool(const qb::json &value, const std::string &field_path, Result &result)>;

private:
    CustomValidateFn _func;
    std::string      _custom_rule_name;

public:
    /**
     * @brief Constructs the rule from a user callback and a reporting name.
     * @param func The validation callback invoked by validate().
     * @param rule_name The name reported for this rule in validation errors.
     */
    CustomRule(CustomValidateFn func, std::string rule_name)
        : _func(std::move(func))
        , _custom_rule_name(std::move(rule_name)) {}

    bool
    validate(const qb::json &value, const std::string &field_path, Result &result) const override {
        return _func(value, field_path, result);
    }

    std::string
    rule_name() const override {
        return _custom_rule_name;
    }
};
} // namespace qb::http::validation
