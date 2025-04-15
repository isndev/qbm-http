#pragma once

#include <qb/json.h>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "./validation_context.h"

namespace qb::http {

/**
 * @brief Validator for JSON Schema
 * 
 * Implements JSON Schema validation for request bodies.
 * Supports a subset of JSON Schema draft-07.
 */
class JsonSchemaValidator {
public:
    /**
     * @brief Constructor with JSON schema
     * @param schema JSON schema
     */
    explicit JsonSchemaValidator(const qb::json& schema);
    
    /**
     * @brief Constructor with JSON schema from string
     * @param schema_str JSON schema as string
     */
    explicit JsonSchemaValidator(const std::string& schema_str);
    
    /**
     * @brief Validate a JSON value against the schema
     * @param value JSON value to validate
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate(const qb::json& value, ValidationContext& ctx) const;
    
    /**
     * @brief Get the schema
     * @return JSON schema
     */
    [[nodiscard]] const qb::json& schema() const {
        return _schema;
    }
    
private:
    qb::json _schema;
    
    /**
     * @brief Validate a value against a schema
     * @param value JSON value to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_value(const qb::json& value, const qb::json& schema, 
                      const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate a value's type
     * @param value JSON value to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_type(const qb::json& value, const qb::json& schema,
                     const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "required" constraint
     * @param value JSON object to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_required(const qb::json& value, const qb::json& schema,
                         const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "properties" constraint
     * @param value JSON object to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_properties(const qb::json& value, const qb::json& schema,
                           const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "additionalProperties" constraint
     * @param value JSON object to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_additional_properties(const qb::json& value, const qb::json& schema,
                                      const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "minLength" constraint
     * @param value JSON string to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_min_length(const qb::json& value, const qb::json& schema,
                           const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "maxLength" constraint
     * @param value JSON string to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_max_length(const qb::json& value, const qb::json& schema,
                           const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "pattern" constraint
     * @param value JSON string to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_pattern(const qb::json& value, const qb::json& schema,
                        const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "enum" constraint
     * @param value JSON value to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_enum(const qb::json& value, const qb::json& schema,
                     const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "minimum" constraint
     * @param value JSON number to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_minimum(const qb::json& value, const qb::json& schema,
                        const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "maximum" constraint
     * @param value JSON number to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_maximum(const qb::json& value, const qb::json& schema,
                        const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "items" constraint
     * @param value JSON array to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_items(const qb::json& value, const qb::json& schema,
                      const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "minItems" constraint
     * @param value JSON array to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_min_items(const qb::json& value, const qb::json& schema,
                          const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "maxItems" constraint
     * @param value JSON array to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_max_items(const qb::json& value, const qb::json& schema,
                          const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "uniqueItems" constraint
     * @param value JSON array to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_unique_items(const qb::json& value, const qb::json& schema,
                             const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "oneOf" constraint
     * @param value JSON value to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_one_of(const qb::json& value, const qb::json& schema,
                       const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "anyOf" constraint
     * @param value JSON value to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_any_of(const qb::json& value, const qb::json& schema,
                       const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "allOf" constraint
     * @param value JSON value to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_all_of(const qb::json& value, const qb::json& schema,
                       const std::string& path, ValidationContext& ctx) const;
    
    /**
     * @brief Validate against "not" constraint
     * @param value JSON value to validate
     * @param schema Schema to validate against
     * @param path JSON pointer path for error reporting
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_not(const qb::json& value, const qb::json& schema,
                    const std::string& path, ValidationContext& ctx) const;
};

} // namespace qb::http 