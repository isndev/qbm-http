/**
 * @file qbm/http/validation/request_validator.h
 * @brief Defines the RequestValidator class for validating HTTP requests.
 *
 * This file contains the definition of the RequestValidator class,
 * which is used to validate HTTP requests according to the rules defined
 * in the RequestValidator.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Validaton
 */
#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "../request.h"
#include "../routing/path_parameters.h"
#include "./error.h"
#include "./parameter_validator.h"
#include "./sanitizer.h"
#include "./schema_validator.h"

namespace qb::http::validation {
/**
 * @brief Validates incoming HTTP requests against defined schemas and rules.
 *
 * Allows defining validation rules for request body (JSON schema),
 * query parameters, headers, and path parameters. Also supports sanitization.
 */
class RequestValidator {
public:
    RequestValidator() = default;

    /**
     * @brief Defines a JSON schema for validating the request body.
     * @param schema_definition The qb::json object representing the schema.
     * @return Reference to this RequestValidator for chaining.
     */
    RequestValidator &for_body(const qb::json &schema_definition);

    /**
     * @brief Defines rules for a query parameter.
     * @param param_name The name of the query parameter.
     * @param rules The ParameterRuleSet defining validation for this parameter.
     * @return Reference to this RequestValidator for chaining.
     */
    RequestValidator &for_query_param(const std::string &param_name, ParameterRuleSet rules);

    /**
     * @brief Defines rules for an HTTP header.
     * @param header_name The name of the header.
     * @param rules The ParameterRuleSet defining validation for this header.
     * @return Reference to this RequestValidator for chaining.
     */
    RequestValidator &for_header(const std::string &header_name, ParameterRuleSet rules);

    /**
     * @brief Defines rules for a path parameter.
     * @param param_name The name of the path parameter (as defined in the route).
     * @param rules The ParameterRuleSet defining validation for this parameter.
     * @return Reference to this RequestValidator for chaining.
     */
    RequestValidator &for_path_param(const std::string &param_name, ParameterRuleSet rules);

    /**
     * @brief Adds a sanitizer function for a specific field in the request body.
     * @param field_path JSON pointer-like path to the field in the body.
     * @param func The SanitizerFunction to apply.
     * @return Reference to this RequestValidator for chaining.
     */
    RequestValidator &add_body_sanitizer(const std::string &field_path, SanitizerFunction func);

    /**
     * @brief Adds a sanitizer function for a specific query parameter.
     * @param param_name The name of the query parameter.
     * @param func The SanitizerFunction to apply to the parameter's value(s).
     * @return Reference to this RequestValidator for chaining.
     */
    RequestValidator &add_query_param_sanitizer(const std::string &param_name, SanitizerFunction func);

    /**
     * @brief Adds a sanitizer function for a specific HTTP header.
     * @param header_name The name of the header.
     * @param func The SanitizerFunction to apply to the header's value(s).
     * @return Reference to this RequestValidator for chaining.
     */
    RequestValidator &add_header_sanitizer(const std::string &header_name, SanitizerFunction func);

    /**
     * @brief Validates an HTTP request.
     *
     * Sanitizers are applied first, then validations are performed.
     * For query parameters and headers with multiple values, each value is sanitized and validated individually.
     *
     * @param request The qb::http::Request object to validate (may be modified by sanitizers).
     * @param result The Result object to store validation errors.
     * @param path_params Optional pointer to PathParameters if path parameter validation is needed.
     * @return True if the request is valid according to all defined rules, false otherwise.
     */
    bool validate(qb::http::Request &request, Result &result, const qb::http::PathParameters *path_params = nullptr);

    /**
     * @brief F48 &mdash; configure the default error-value policy applied
     *        to the `Result` passed to `validate()`. The policy is forwarded
     *        to the underlying body schema validator and to any parameter
     *        validators. Callers can still override the policy on the
     *        `Result` after `validate()` returns (but that only affects
     *        future errors; the errors already stored keep their shape).
     */
    RequestValidator &
    set_error_value_policy(Result::ErrorValuePolicy policy, std::size_t preview_bytes = 256) noexcept {
        _error_value_policy = policy;
        // Clamp to the same bounds `Result` uses to keep behaviour identical.
        constexpr std::size_t kMinPreview = 16;
        constexpr std::size_t kMaxPreview = 64 * 1024;
        if (preview_bytes < kMinPreview)
            preview_bytes = kMinPreview;
        if (preview_bytes > kMaxPreview)
            preview_bytes = kMaxPreview;
        _error_value_preview_bytes = preview_bytes;
        return *this;
    }

    [[nodiscard]] Result::ErrorValuePolicy
    error_value_policy() const noexcept {
        return _error_value_policy;
    }

    [[nodiscard]] std::size_t
    offending_value_preview_bytes() const noexcept {
        return _error_value_preview_bytes;
    }

private:
    Result::ErrorValuePolicy _error_value_policy{Result::ErrorValuePolicy::Full};
    std::size_t              _error_value_preview_bytes{256};

    std::optional<SchemaValidator>    _body_schema_validator;
    std::optional<ParameterValidator> _query_param_validator;
    std::optional<ParameterValidator> _header_validator;
    std::optional<ParameterValidator> _path_param_validator;

    std::optional<Sanitizer>                                _body_sanitizer;
    qb::icase_unordered_map<std::vector<SanitizerFunction>> _query_param_sanitizers;
    qb::icase_unordered_map<std::vector<SanitizerFunction>> _header_sanitizers;
};
} // namespace qb::http::validation
