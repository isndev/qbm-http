#pragma once

#include "./validation/validator.h"
#include "./validation/json_schema.h"
#include "./validation/query_validator.h"
#include "./validation/sanitizer.h"
#include "./validation/validation_context.h"
#include "./validation/validation_types.h"

// This is the main include file for all validation-related types
namespace qb::http {
    // Re-export all validation types and functions for easier access
    using ValidationContext = qb::http::ValidationContext;
    using ValidationErrors = qb::http::ValidationErrors;
    using FieldErrors = qb::http::FieldErrors;
    using JsonSchemaValidator = qb::http::JsonSchemaValidator;
    using QueryValidator = qb::http::QueryValidator;
    using QueryParamRule = qb::http::QueryParamRule;
    using QueryParamRules = qb::http::QueryParamRules;
    using Sanitizer = qb::http::Sanitizer;
    using SanitizerFunc = qb::http::SanitizerFunc;
    using ParamType = qb::http::ParamType;
    
    // Define sanitizer functions in their own namespace
    namespace sanitizers {
        // Function wrappers for CommonSanitizers static methods
        inline std::string trim(const std::string& input) {
            return CommonSanitizers::trim(input);
        }
        
        inline std::string to_lower(const std::string& input) {
            return CommonSanitizers::to_lower(input);
        }
        
        inline std::string to_upper(const std::string& input) {
            return CommonSanitizers::to_upper(input);
        }
        
        inline std::string escape_html(const std::string& input) {
            return CommonSanitizers::escape_html(input);
        }
        
        inline std::string strip_html(const std::string& input) {
            return CommonSanitizers::strip_html(input);
        }
        
        inline std::string alphanumeric_only(const std::string& input) {
            return CommonSanitizers::alphanumeric_only(input);
        }
    }
}