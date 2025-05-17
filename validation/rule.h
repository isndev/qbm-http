#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <optional>
#include <variant>
#include <regex>
#include <qb/json.h>
#include "./error.h" // Updated include path

namespace qb::http::validation { // Changed namespace

// Forward declaration
// class ValueContext; // This was never used, can be removed if not planned for immediate future

/**
 * @brief Defines the data type a rule might expect or a value might represent.
 */
enum class DataType {
    STRING,
    INTEGER,
    NUMBER, 
    BOOLEAN,
    OBJECT,
    ARRAY,
    NUL, 
    ANY 
};

/**
 * @brief Interface for a validation rule.
 *
 * Each rule operates on a qb::json value and reports errors to a Result object.
 */
class IRule { // Renamed from IValidationRule
public:
    virtual ~IRule() = default;

    /**
     * @brief Validates a qb::json value against this rule.
     * @param value The qb::json value to validate.
     * @param field_path The path to the field being validated (for error reporting).
     * @param result The Result object to store any validation errors.
     * @return True if the value is valid according to this rule, false otherwise.
     */
    virtual bool validate(const qb::json& value, const std::string& field_path, Result& result) const = 0; // Changed ValidationResult to Result
    /**
     * @brief Gets the name of the rule (e.g., "minLength", "type").
     * @return The string name of the rule.
     */
    virtual std::string rule_name() const = 0;
};

// --- Concrete Rule Implementations (Namespaced, but keeping original class names for now) ---

/** @brief Validates the data type of a qb::json value. */
class TypeRule : public IRule {
private:
    DataType _expected_type;
    std::string _type_name_str;
public:
    TypeRule(DataType expected_type);
    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override;
    std::string rule_name() const override { return "type"; }
    static std::string data_type_to_string(DataType dt);
};

/** @brief Placeholder rule for "required" keyword, logic is handled by validators. */
class RequiredRule : public IRule {
public:
    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override;
    std::string rule_name() const override { return "required"; }
};

/** @brief Validates the minimum length of a string or minimum number of items in an array. */
class MinLengthRule : public IRule {
private:
    size_t _min_length;
public:
    explicit MinLengthRule(size_t min_len) : _min_length(min_len) {}
    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override;
    std::string rule_name() const override { return "minLength"; }
};

/** @brief Validates the maximum length of a string or maximum number of items in an array. */
class MaxLengthRule : public IRule {
private:
    size_t _max_length;
public:
    explicit MaxLengthRule(size_t max_len) : _max_length(max_len) {}
    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override;
    std::string rule_name() const override { return "maxLength"; }
};

/** @brief Validates a string against a regular expression pattern. */
class PatternRule : public IRule {
private:
    std::string _pattern_str;
    std::regex _regex;
public:
    explicit PatternRule(std::string pattern_str);
    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override;
    std::string rule_name() const override { return "pattern"; }
};

/** @brief Validates that a number is greater than (or equal to if not exclusive) a minimum value. */
class MinimumRule : public IRule {
private:
    double _minimum;
    bool _exclusive;
public:
    MinimumRule(double min_val, bool exclusive = false) : _minimum(min_val), _exclusive(exclusive) {}
    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override;
    std::string rule_name() const override { return _exclusive ? "exclusiveMinimum" : "minimum"; }
};

/** @brief Validates that a number is less than (or equal to if not exclusive) a maximum value. */
class MaximumRule : public IRule {
private:
    double _maximum;
    bool _exclusive;
public:
    MaximumRule(double max_val, bool exclusive = false) : _maximum(max_val), _exclusive(exclusive) {}
    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override;
    std::string rule_name() const override { return _exclusive ? "exclusiveMaximum" : "maximum"; }
};

/** @brief Validates that a value is one of a predefined set of allowed values. */
class EnumRule : public IRule {
private:
    qb::json _allowed_values; 
public:
    explicit EnumRule(qb::json allowed_values);
    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override;
    std::string rule_name() const override { return "enum"; }
};

/** @brief Validates that all items in an array are unique. */
class UniqueItemsRule : public IRule {
public:
    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override;
    std::string rule_name() const override { return "uniqueItems"; }
};

/** @brief Validates the minimum number of items in an array. */
class MinItemsRule : public IRule {
private:
    size_t _min_items;
public:
    explicit MinItemsRule(size_t min_val) : _min_items(min_val) {}
    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override;
    std::string rule_name() const override { return "minItems"; }
};

/** @brief Validates the maximum number of items in an array. */
class MaxItemsRule : public IRule {
private:
    size_t _max_items;
public:
    explicit MaxItemsRule(size_t max_val) : _max_items(max_val) {}
    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override;
    std::string rule_name() const override { return "maxItems"; }
};

/** @brief Validates the minimum number of properties in an object. */
class MinPropertiesRule : public IRule {
private:
    size_t _min_properties;
public:
    explicit MinPropertiesRule(size_t min_props) : _min_properties(min_props) {}
    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override;
    std::string rule_name() const override { return "minProperties"; }
};

/** @brief Validates the maximum number of properties in an object. */
class MaxPropertiesRule : public IRule {
private:
    size_t _max_properties;
public:
    explicit MaxPropertiesRule(size_t max_props) : _max_properties(max_props) {}
    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override;
    std::string rule_name() const override { return "maxProperties"; }
};

// Forward declaration
class SchemaValidator; 

/** @brief Validates the names of properties in an object against a sub-schema. */
class PropertyNamesRule : public IRule {
private:
    qb::json _name_schema_definition_copy; // Store the schema definition itself
public:
    explicit PropertyNamesRule(const qb::json& name_schema_definition);
    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override;
    std::string rule_name() const override { return "propertyNames"; }
};


using ItemsRuleLogic = std::variant<std::shared_ptr<SchemaValidator>, std::vector<std::shared_ptr<SchemaValidator>>>;

/** @brief Placeholder rule for "items" keyword; logic primarily in SchemaValidator. */
class ItemsRule : public IRule {
private:
    ItemsRuleLogic _logic;
    std::variant<bool, std::shared_ptr<SchemaValidator>> _additional_items_policy;
public:
    explicit ItemsRule(ItemsRuleLogic logic, std::variant<bool, std::shared_ptr<SchemaValidator>> additional_items_policy = true);
    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override;
    std::string rule_name() const override { return "items"; }
};

/** @brief Allows defining a custom validation rule using a lambda or function pointer. */
class CustomRule : public IRule {
public:
    using CustomValidateFn = std::function<bool(const qb::json& value, const std::string& field_path, Result& result)>;
private:
    CustomValidateFn _func;
    std::string _custom_rule_name;
public:
    CustomRule(CustomValidateFn func, std::string rule_name) 
        : _func(std::move(func)), _custom_rule_name(std::move(rule_name)) {}

    bool validate(const qb::json& value, const std::string& field_path, Result& result) const override {
        return _func(value, field_path, result);
    }
    std::string rule_name() const override { return _custom_rule_name; }
};


} // namespace qb::http::validation
