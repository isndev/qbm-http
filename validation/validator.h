#pragma once

#include <qb/json.h>
#include <qb/system/container/unordered_map.h>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "../request.h"
#include "../response.h"
#include "../routing/context.h"
#include "./json_schema.h"
#include "./query_validator.h"
#include "./sanitizer.h"
#include "./validation_context.h"
#include "./validation_types.h"

namespace qb::http {

/**
 * @brief Main validator class for HTTP requests
 *
 * This class provides a fluent API for defining and applying validation rules
 * to HTTP requests. It supports JSON schema validation, query parameter validation,
 * and input sanitization.
 *
 * @tparam Session HTTP session type
 * @tparam String String type (std::string or std::string_view)
 */
template <typename Session, typename String = std::string>
class Validator {
public:
    using Context = RouterContext<Session, String>;
    using RuleCallback = std::function<bool(ValidationContext&, const TRequest<String>&)>;
    
    /**
     * @brief Default constructor
     */
    Validator() = default;
    
    /**
     * @brief Constructor with JSON schema
     * @param schema JSON schema for request body validation
     */
    explicit Validator(const qb::json& schema) {
        with_json_schema(schema);
    }
    
    /**
     * @brief Constructor with JSON schema from string
     * @param schema_str JSON schema as string
     */
    explicit Validator(const std::string& schema_str) {
        with_json_schema(qb::json::parse(schema_str));
    }
    
    /**
     * @brief Add JSON schema validation for the request body
     * @param schema JSON schema
     * @return Reference to this validator
     */
    Validator& with_json_schema(const qb::json& schema) {
        _json_schema_validator = std::make_shared<JsonSchemaValidator>(schema);
        return *this;
    }
    
    /**
     * @brief Add query parameter validation
     * @param param_name Parameter name
     * @param rules Validation rules for the parameter
     * @return Reference to this validator
     */
    Validator& with_query_param(const std::string& param_name, const QueryParamRules& rules) {
        if (!_query_validator) {
            _query_validator = std::make_shared<QueryValidator>();
        }
        _query_validator->add_param(param_name, rules);
        return *this;
    }
    
    /**
     * @brief Add sanitization rule for a field
     * @param field_path JSON pointer path to the field (e.g., "/name")
     * @param sanitizer Sanitizer function
     * @return Reference to this validator
     */
    Validator& with_sanitizer(const std::string& field_path, SanitizerFunc sanitizer) {
        if (!_sanitizer) {
            _sanitizer = std::make_shared<Sanitizer>();
        }
        _sanitizer->add_rule(field_path, sanitizer);
        return *this;
    }
    
    /**
     * @brief Add a custom validation rule
     * @param rule_name Name of the rule (for error reporting)
     * @param callback Validation callback function
     * @return Reference to this validator
     */
    Validator& with_custom_rule(const std::string& rule_name, RuleCallback callback) {
        _custom_rules.emplace_back(rule_name, callback);
        return *this;
    }
    
    /**
     * @brief Set validation error handler
     * @param handler Error handler function
     * @return Reference to this validator
     */
    Validator& with_error_handler(std::function<void(Context&, const ValidationErrors&)> handler) {
        _error_handler = std::move(handler);
        return *this;
    }
    
    /**
     * @brief Validate a request in the given context
     * @param ctx Router context containing the request
     * @return true if validation passed, false otherwise
     */
    bool validate(Context& ctx) const {
        ValidationContext validation_ctx;
        const auto& request = ctx.request;
        bool valid = true;
        
        // Apply JSON schema validation if configured
        if (_json_schema_validator && !request.body().raw().empty()) {
            try {
                auto body_json = qb::json::parse(request.body().raw());
                valid = _json_schema_validator->validate(body_json, validation_ctx) && valid;
                
                // Apply sanitization if validation passed and sanitizer is configured
                if (valid && _sanitizer) {
                    _sanitizer->sanitize(body_json);
                    // Update the request body with sanitized JSON
                    ctx.request.body() = body_json.dump();
                }
            } catch (const qb::json::exception& e) {
                validation_ctx.add_error("body", "json_parse_error", "Invalid JSON in request body");
                valid = false;
            }
        }
        
        // Apply query parameter validation if configured
        if (_query_validator) {
            // Convert URI query parameters to the format needed by the validator
            std::unordered_map<std::string, std::string> query_params;
            for (const auto& [param, values] : request.queries()) {
                if (!values.empty()) {
                    query_params[param] = values[0];
                }
            }
            valid = _query_validator->validate(query_params, validation_ctx) && valid;
        }
        
        // Apply custom rules
        for (const auto& [rule_name, callback] : _custom_rules) {
            if (!callback(validation_ctx, request)) {
                valid = false;
            }
        }
        
        // Handle validation errors
        if (!valid) {
            if (_error_handler) {
                _error_handler(ctx, validation_ctx.errors());
            } else {
                // Default error handler
                default_error_handler(ctx, validation_ctx.errors());
            }
        }
        
        return valid;
    }
    
    /**
     * @brief Create a middleware function for the router
     * @return Middleware function that performs validation
     */
    auto middleware() const {
        return [this](Context& ctx) {
            return validate(ctx);
        };
    }
    
private:
    std::shared_ptr<JsonSchemaValidator> _json_schema_validator;
    std::shared_ptr<QueryValidator> _query_validator;
    std::shared_ptr<Sanitizer> _sanitizer;
    std::vector<std::pair<std::string, RuleCallback>> _custom_rules;
    std::function<void(Context&, const ValidationErrors&)> _error_handler;
    
    /**
     * @brief Default error handler for validation errors
     * @param ctx Router context
     * @param errors Validation errors
     */
    static void default_error_handler(Context& ctx, const ValidationErrors& errors) {
        qb::json response = {
            {"status", "error"},
            {"message", "Validation failed"},
            {"errors", qb::json::array()}
        };
        
        for (const auto& [field, field_errors] : errors) {
            for (const auto& [code, message] : field_errors) {
                response["errors"].push_back({
                    {"field", field},
                    {"code", code},
                    {"message", message}
                });
            }
        }
        
        ctx.response.status_code = HTTP_STATUS_BAD_REQUEST;
        ctx.response.add_header("Content-Type", "application/json");
        ctx.response.body() = response.dump();
        ctx.mark_handled();
    }
};

/**
 * @brief Create a validator with JSON schema
 * @param schema JSON schema
 * @return Validator instance
 */
template <typename Session, typename String = std::string>
inline auto validate_with_schema(const qb::json& schema) {
    return Validator<Session, String>(schema);
}

/**
 * @brief Create a validator with JSON schema from string
 * @param schema_str JSON schema as string
 * @return Validator instance
 */
template <typename Session, typename String = std::string>
inline auto validate_with_schema(const std::string& schema_str) {
    return Validator<Session, String>(schema_str);
}

/**
 * @brief Create a middleware that validates request against a JSON schema
 * @param schema JSON schema
 * @return Middleware function
 */
template <typename Session, typename String = std::string>
inline auto validate_middleware(const qb::json& schema) {
    return Validator<Session, String>(schema).middleware();
}

} // namespace qb::http 