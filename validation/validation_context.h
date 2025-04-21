#pragma once

#include <qb/system/container/unordered_map.h>
#include <string>
#include <unordered_map>
#include <vector>

namespace qb::http {

/**
 * @brief Type definition for field-level validation errors
 * 
 * Maps error codes to error messages for a specific field.
 */
using FieldErrors = qb::unordered_map<std::string, std::string>;

/**
 * @brief Type definition for validation errors
 * 
 * Maps field names to their validation errors.
 */
using ValidationErrors = qb::unordered_map<std::string, FieldErrors>;

/**
 * @brief Context for validation operations
 * 
 * Tracks validation errors and provides methods for error reporting.
 */
class ValidationContext {
public:
    /**
     * @brief Default constructor
     */
    ValidationContext() = default;
    
    /**
     * @brief Add a validation error
     * @param field Field name
     * @param code Error code
     * @param message Error message
     */
    void add_error(const std::string& field, const std::string& code, const std::string& message) {
        _errors[field][code] = message;
    }
    
    /**
     * @brief Check if validation has errors
     * @return true if there are errors, false otherwise
     */
    [[nodiscard]] bool has_errors() const {
        return !_errors.empty();
    }
    
    /**
     * @brief Check if a specific field has errors
     * @param field Field name
     * @return true if the field has errors, false otherwise
     */
    [[nodiscard]] bool has_field_error(const std::string& field) const {
        return _errors.find(field) != _errors.end();
    }
    
    /**
     * @brief Get all validation errors
     * @return Validation errors map
     */
    [[nodiscard]] const ValidationErrors& errors() const {
        return _errors;
    }
    
    /**
     * @brief Clear all validation errors
     */
    void clear() {
        _errors.clear();
    }

private:
    ValidationErrors _errors;
};

} // namespace qb::http 