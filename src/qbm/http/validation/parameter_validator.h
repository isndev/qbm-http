/**
 * @file qbm/http/validation/parameter_validator.h
 * @brief Defines the ParameterValidator class for validating HTTP parameters.
 *
 * This file contains the definition of the ParameterValidator class,
 * which is used to validate HTTP parameters according to the rules defined
 * in the ParameterRuleSet.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <functional> // For std::function
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <qb/json.h>
#include <qb/system/container/unordered_map.h>
#include "./error.h"
#include "./rule.h"

namespace qb::http::validation {
/**
 * @brief Defines a set of rules and properties for a single parameter.
 *
 * Aggregates the metadata required to validate one named parameter: its
 * expected type, whether it is mandatory, an optional default value, an
 * ordered list of validation rules, and an optional custom parser. The
 * fluent `set_*`/`add_rule` methods enable builder-style configuration.
 */
struct ParameterRuleSet {
    std::string                         name;                             ///< The parameter name.
    DataType                            expected_type = DataType::STRING; ///< The expected data type for type coercion/checking.
    bool                                required      = false;            ///< Whether the parameter must be present.
    std::optional<std::string>          default_value;                    ///< Default string value applied when the parameter is absent.
    std::vector<std::shared_ptr<IRule>> rules;                            ///< Ordered validation rules applied after parsing.
    std::function<qb::json(const std::string &input_str, bool &success)>
        custom_parser; ///< Optional custom parser; sets `success` and returns the parsed value.

    /** @brief Default-constructs an empty, unnamed rule set. */
    ParameterRuleSet() = default;

    /**
     * @brief Constructs a rule set for the given parameter name.
     * @param param_name The name of the parameter this rule set applies to.
     */
    explicit ParameterRuleSet(std::string param_name)
        : name(std::move(param_name)) {}

    /**
     * @brief Sets the expected data type for the parameter.
     * @param type The expected data type.
     * @return Reference to this rule set for fluent chaining.
     */
    ParameterRuleSet &
    set_type(DataType type) {
        expected_type = type;
        return *this;
    }

    /**
     * @brief Marks the parameter as required (or optional).
     * @param req True to mark the parameter as required. Defaults to true.
     * @return Reference to this rule set for fluent chaining.
     */
    ParameterRuleSet &
    set_required(bool req = true) {
        required = req;
        return *this;
    }

    /**
     * @brief Sets a default string value applied when the parameter is not provided.
     * @param def_val The default value.
     * @return Reference to this rule set for fluent chaining.
     */
    ParameterRuleSet &
    set_default(std::string def_val) {
        default_value = std::move(def_val);
        return *this;
    }

    /**
     * @brief Adds a validation rule to this parameter.
     * @param rule The rule to add. Null pointers are ignored.
     * @return Reference to this rule set for fluent chaining.
     */
    ParameterRuleSet &
    add_rule(std::shared_ptr<IRule> rule) {
        if (rule)
            rules.push_back(std::move(rule));
        return *this;
    }

    /**
     * @brief Sets a custom parsing function for this parameter.
     * @param parser_fn The parser; it receives the raw string and a `success`
     *                  out-parameter, and returns the parsed JSON value.
     * @return Reference to this rule set for fluent chaining.
     */
    ParameterRuleSet &
    set_custom_parser(std::function<qb::json(const std::string &, bool &success)> parser_fn) {
        custom_parser = std::move(parser_fn);
        return *this;
    }
};

/**
 * @brief Validates a collection of parameters (e.g., query parameters, headers) based on defined rule sets.
 */
class ParameterValidator {
public:
    /**
     * @brief Constructs a ParameterValidator.
     * @param strict_mode If true, unexpected parameters will cause a validation error. Defaults to false.
     */
    explicit ParameterValidator(bool strict_mode = false)
        : _strict_mode(strict_mode) {}

    /** @brief Adds a rule set for a parameter. */
    void add_param(ParameterRuleSet param_rules);

    /**
     * @brief Validates a map of parameters against the defined rule sets.
     * @param params The map of parameter names to their string values.
     * @param result The Result object to store validation errors.
     * @param param_source_name A string identifying the source of the parameters (e.g., "query", "header") for error reporting.
     * @return True if all parameters are valid, false otherwise.
     */
    bool validate(const qb::icase_unordered_map<std::string> &params, Result &result, const std::string &param_source_name) const;

    /**
     * @brief Validates a single parameter value against its rule set.
     * @param param_name The name of the parameter.
     * @param value_opt The optional string value of the parameter.
     * @param rules The ParameterRuleSet for this parameter.
     * @param result The Result object to store validation errors.
     * @param param_source_name Source identifier for error reporting.
     * @return The parsed and validated qb::json value if successful, or qb::json(nullptr) if validation failed.
     */
    qb::json validate_single(const std::string &param_name, const std::optional<std::string> &value_opt, const ParameterRuleSet &rules,
                             Result &result, const std::string &param_source_name) const;

    /** @brief Gets all defined parameter rule sets. */
    [[nodiscard]] const qb::icase_unordered_map<ParameterRuleSet> &
    get_param_definitions() const {
        return _param_definitions;
    }

    /** @brief Sets the strict mode for parameter validation. */
    void
    set_strict_mode(bool strict) {
        _strict_mode = strict;
    }

    /** @brief Checks if the validator is in strict mode. */
    [[nodiscard]] bool
    is_strict_mode() const {
        return _strict_mode;
    }

private:
    qb::icase_unordered_map<ParameterRuleSet> _param_definitions;   ///< Parameter name -> rule set definitions.
    bool                                      _strict_mode = false; ///< When true, unexpected parameters are reported as errors.

    /**
     * @brief Parses a raw string value into a typed JSON value according to @p target_type.
     * @param input_value The raw string value to parse.
     * @param target_type The data type to coerce the value into.
     * @param field_path The dotted field path used for error reporting.
     * @param result The Result object to which parse errors are appended.
     * @param success Out-parameter set to true on success, false on parse failure.
     * @return The parsed JSON value on success, or qb::json(nullptr) on failure.
     */
    qb::json parse_value(const std::string &input_value, DataType target_type, const std::string &field_path, Result &result,
                         bool &success) const;
};
} // namespace qb::http::validation
