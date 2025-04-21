#pragma once

#include <memory>
#include <string>
#include "./middleware_interface.h"
#include "../validation/validator.h"

namespace qb::http {

/**
 * @brief Middleware for request validation
 * 
 * This middleware validates HTTP requests using the Validator class from the validation
 * framework. It supports JSON schema validation, query parameter validation, and sanitization.
 * 
 * @tparam Session HTTP session type
 * @tparam String String type (std::string or std::string_view)
 */
template <typename Session, typename String = std::string>
class ValidatorMiddleware : public ISyncMiddleware<Session, String> {
public:
    using Context = typename ISyncMiddleware<Session, String>::Context;
    using ValidatorType = Validator<Session, String>;
    
    /**
     * @brief Default constructor
     */
    ValidatorMiddleware() 
        : _validator(std::make_shared<ValidatorType>())
        , _name("ValidatorMiddleware") {}
    
    /**
     * @brief Constructor with JSON schema
     * @param schema JSON schema for request body validation
     * @param name Middleware name
     */
    explicit ValidatorMiddleware(
        const qb::json& schema,
        std::string name = "SchemaValidatorMiddleware"
    ) : _validator(std::make_shared<ValidatorType>(schema))
      , _name(std::move(name)) {}
    
    /**
     * @brief Constructor with JSON schema from string
     * @param schema_str JSON schema as string
     * @param name Middleware name
     */
    explicit ValidatorMiddleware(
        const std::string& schema_str,
        std::string name = "SchemaValidatorMiddleware"
    ) : _validator(std::make_shared<ValidatorType>(schema_str))
      , _name(std::move(name)) {}
    
    /**
     * @brief Process a request
     * @param ctx Request context
     * @return Middleware result
     */
    MiddlewareResult process(Context& ctx) override {
        if (_validator->validate(ctx)) {
            return MiddlewareResult::Continue();
        }
        return MiddlewareResult::Stop();
    }
    
    /**
     * @brief Get the middleware name
     */
    std::string name() const override {
        return _name;
    }
    
    /**
     * @brief Add JSON schema validation
     * @param schema JSON schema
     * @return Reference to this middleware
     */
    ValidatorMiddleware& with_json_schema(const qb::json& schema) {
        _validator->with_json_schema(schema);
        return *this;
    }
    
    /**
     * @brief Add query parameter validation
     * @param param_name Parameter name
     * @param rules Validation rules
     * @return Reference to this middleware
     */
    ValidatorMiddleware& with_query_param(const std::string& param_name, const QueryParamRules& rules) {
        _validator->with_query_param(param_name, rules);
        return *this;
    }
    
    /**
     * @brief Add sanitization for a field
     * @param field_path JSON pointer path to the field
     * @param sanitizer Sanitizer function
     * @return Reference to this middleware
     */
    ValidatorMiddleware& with_sanitizer(const std::string& field_path, SanitizerFunc sanitizer) {
        _validator->with_sanitizer(field_path, sanitizer);
        return *this;
    }
    
    /**
     * @brief Add custom validation rule
     * @param rule_name Rule name
     * @param callback Validation callback
     * @return Reference to this middleware
     */
    ValidatorMiddleware& with_custom_rule(
        const std::string& rule_name,
        typename ValidatorType::RuleCallback callback
    ) {
        _validator->with_custom_rule(rule_name, callback);
        return *this;
    }
    
    /**
     * @brief Set error handler for validation failures
     * @param handler Error handler function
     * @return Reference to this middleware
     */
    ValidatorMiddleware& with_error_handler(
        typename ValidatorType::ErrorHandler handler
    ) {
        _validator->with_error_handler(std::move(handler));
        return *this;
    }
    
    /**
     * @brief Get the underlying validator instance
     * @return Shared pointer to validator
     */
    std::shared_ptr<ValidatorType> validator() const {
        return _validator;
    }
    
private:
    std::shared_ptr<ValidatorType> _validator;
    std::string _name;
};

/**
 * @brief Create a validator middleware with default configuration
 * 
 * @tparam Session HTTP session type
 * @tparam String String type
 * @return Validator middleware adapter
 */
template <typename Session, typename String = std::string>
auto validator_middleware() {
    auto middleware = std::make_shared<ValidatorMiddleware<Session, String>>();
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

/**
 * @brief Create a validator middleware with JSON schema
 * 
 * @tparam Session HTTP session type
 * @tparam String String type
 * @param schema JSON schema for validation
 * @return Validator middleware adapter
 */
template <typename Session, typename String = std::string>
auto validator_middleware(const qb::json& schema) {
    auto middleware = std::make_shared<ValidatorMiddleware<Session, String>>(schema);
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

/**
 * @brief Create a validator middleware with JSON schema from string
 * 
 * @tparam Session HTTP session type
 * @tparam String String type
 * @param schema_str JSON schema as string
 * @return Validator middleware adapter
 */
template <typename Session, typename String = std::string>
auto validator_middleware(const std::string& schema_str) {
    auto middleware = std::make_shared<ValidatorMiddleware<Session, String>>(schema_str);
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

/**
 * @brief Create a validator middleware for form validation
 * 
 * This is a specialized validator for form data with common validations.
 * 
 * @tparam Session HTTP session type
 * @tparam String String type
 * @return Validator middleware adapter
 */
template <typename Session, typename String = std::string>
auto form_validator_middleware() {
    auto middleware = std::make_shared<ValidatorMiddleware<Session, String>>();
    // Common form validations could be added here
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

/**
 * @brief Create a validator middleware for API request validation
 * 
 * This is a specialized validator for API requests with JSON validation.
 * 
 * @tparam Session HTTP session type
 * @tparam String String type
 * @param schema JSON schema for API validation
 * @return Validator middleware adapter
 */
template <typename Session, typename String = std::string>
auto api_validator_middleware(const qb::json& schema) {
    auto middleware = std::make_shared<ValidatorMiddleware<Session, String>>(
        schema, "ApiValidatorMiddleware");
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

} // namespace qb::http 