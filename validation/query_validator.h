#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <qb/system/container/unordered_map.h>

#include "./validation_context.h"
#include "./validation_types.h"

namespace qb::http {

/**
 * @brief Validator for query parameters
 * 
 * Validates query parameters against defined rules.
 */
class QueryValidator {
public:
    /**
     * @brief Default constructor
     */
    QueryValidator() = default;
    
    /**
     * @brief Add validation rules for a parameter
     * @param param_name Name of the parameter
     * @param rules Validation rules
     */
    void add_param(const std::string& param_name, const QueryParamRules& rules);
    
    /**
     * @brief Validate query parameters
     * @param params Query parameters map
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate(const std::unordered_map<std::string, std::string>& params, 
                ValidationContext& ctx) const;
    
    /**
     * @brief Get all parameter rules
     * @return Map of parameter names to their rules
     */
    [[nodiscard]] const std::unordered_map<std::string, QueryParamRules>& 
    param_rules() const {
        return _param_rules;
    }
    
private:
    std::unordered_map<std::string, QueryParamRules> _param_rules;
    
    /**
     * @brief Validate a parameter value
     * @param param_name Parameter name
     * @param value Parameter value
     * @param rules Validation rules
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool validate_param(const std::string& param_name, 
                      const std::string& value,
                      const QueryParamRules& rules, 
                      ValidationContext& ctx) const;
    
    /**
     * @brief Convert a string to the type specified in the rules
     * @param value String value
     * @param type Parameter type to convert to
     * @param param_name Parameter name for error reporting
     * @param ctx Validation context for error reporting
     * @return true if conversion succeeded, false otherwise
     */
    bool convert_value(const std::string& value, 
                     ParamType type,
                     const std::string& param_name,
                     ValidationContext& ctx) const;
    
    /**
     * @brief Apply a validation rule to a parameter
     * @param param_name Parameter name
     * @param value Parameter value
     * @param rule Validation rule
     * @param ctx Validation context for error reporting
     * @return true if validation passed, false otherwise
     */
    bool apply_rule(const std::string& param_name,
                  const std::string& value,
                  const QueryParamRule& rule,
                  ValidationContext& ctx) const;
};

} // namespace qb::http 