/**
 * @file qbm/http/validation/schema_validator.h
 * @brief Defines the SchemaValidator class for validating HTTP requests.
 *
 * This file contains the definition of the SchemaValidator class,
 * which is used to validate HTTP requests according to the schema defined
 * in the RequestValidator.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Validaton
 */
#pragma once

#include <string>
#include <vector>
#include <memory>
#include <qb/json.h>
#include "./rule.h"
#include "./error.h"

namespace qb::http::validation {
    /**
     * @brief Validates qb::json data against a JSON Schema definition.
     *
     * This class implements a subset of JSON Schema keywords to perform validation.
     * It supports type checking, primitive rules (e.g., minLength, maximum),
     * structural rules for objects (properties, required, additionalProperties, propertyNames),
     * structural rules for arrays (items, additionalItems), and logical combinators (allOf, anyOf, oneOf, not).
     */
    class SchemaValidator {
    public:
        /**
         * @brief Constructs a SchemaValidator with a given JSON schema definition.
         * @param schema_definition The qb::json object representing the root schema.
         * @throws std::invalid_argument if the schema_definition is not a JSON object.
         */
        explicit SchemaValidator(const qb::json &schema_definition);

        /**
         * @brief Validates qb::json data against the schema this validator was constructed with.
         * @param data_to_validate The qb::json data to be validated.
         * @param result A Result object that will be populated with any validation errors.
         * @return True if the data is valid according to the schema, false otherwise.
         */
        bool validate(const qb::json &data_to_validate, Result &result) const;

    private:
        qb::json _schema_definition; // Store a copy of the schema definition.

        // Recursive validation helper function.
        bool validate_recursive(const qb::json &current_value,
                                const qb::json &current_schema,
                                const std::string &current_path,
                                Result &result) const;

        // Keyword-specific validation methods.
        bool validate_type_keyword(const qb::json &value, const qb::json &schema_type_def, const std::string &path,
                                   Result &result) const;

        bool validate_properties_keyword(const qb::json &value, const qb::json &properties_def, const std::string &path,
                                         Result &result) const;

        bool validate_required_keyword(const qb::json &value, const qb::json &required_def, const std::string &path,
                                       Result &result) const;

        bool validate_items_keyword(const qb::json &value, const qb::json &schema_node, const std::string &path,
                                    Result &result) const;

        bool validate_additional_properties_keyword(const qb::json &value, const qb::json &schema_node,
                                                    const std::string &path, Result &result) const;

        // Note: propertyNames is handled by a PropertyNamesRule which calls back to SchemaValidator.

        // Applies rules that are not structural or type-based (e.g., minLength, maximum).
        bool apply_primitive_rules(const qb::json &value, const qb::json &schema_node, const std::string &path,
                                   Result &result) const;

        // Logical combinator validation methods.
        bool validate_allOf_keyword(const qb::json &value, const qb::json &allOf_def, const std::string &path,
                                    Result &result) const;

        bool validate_anyOf_keyword(const qb::json &value, const qb::json &anyOf_def, const std::string &path,
                                    Result &result) const;

        bool validate_oneOf_keyword(const qb::json &value, const qb::json &oneOf_def, const std::string &path,
                                    Result &result) const;

        bool validate_not_keyword(const qb::json &value, const qb::json &not_def, const std::string &path,
                                  Result &result) const;

        // Helper to create a list of IRule objects based on keywords in a schema node.
        std::vector<std::shared_ptr<IRule> >
        create_rules_for_schema_node(const qb::json &schema_node) const;
    };
} // namespace qb::http::validation 
