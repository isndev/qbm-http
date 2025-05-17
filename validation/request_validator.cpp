#include "./request_validator.h"
// #include "../utility.h" // Not directly used now

namespace qb::http::validation { // Changed namespace

RequestValidator& RequestValidator::for_body(const qb::json& schema_definition) {
    _body_schema_validator.emplace(schema_definition);
    return *this;
}

RequestValidator& RequestValidator::for_query_param(const std::string& param_name, ParameterRuleSet rules) {
    if (!_query_param_validator) {
        _query_param_validator.emplace(false); // Default to non-strict for query params unless specified
    }
    rules.name = param_name; 
    _query_param_validator->add_param(std::move(rules));
    return *this;
}

RequestValidator& RequestValidator::for_header(const std::string& header_name, ParameterRuleSet rules) {
    if (!_header_validator) {
        _header_validator.emplace(false); // Default to non-strict for headers unless specified
    }
    rules.name = header_name; 
    _header_validator->add_param(std::move(rules));
    return *this;
}

RequestValidator& RequestValidator::for_path_param(const std::string& param_name, ParameterRuleSet rules) {
    if (!_path_param_validator) {
        _path_param_validator.emplace(true); // Path parameters are inherently strict; all defined must exist.
    }
    rules.name = param_name; 
    _path_param_validator->add_param(std::move(rules));
    return *this;
}


RequestValidator& RequestValidator::add_body_sanitizer(const std::string& field_path, SanitizerFunction func) {
    if (!_body_sanitizer) {
        _body_sanitizer.emplace();
    }
    _body_sanitizer->add_rule(field_path, std::move(func));
    return *this;
}

RequestValidator& RequestValidator::add_query_param_sanitizer(const std::string& param_name, SanitizerFunction func) {
    _query_param_sanitizers[param_name].push_back(std::move(func));
    return *this;
}

RequestValidator& RequestValidator::add_header_sanitizer(const std::string& header_name, SanitizerFunction func) {
    _header_sanitizers[header_name].push_back(std::move(func));
    return *this;
}


bool RequestValidator::validate(qb::http::Request& request, Result& result, const qb::http::PathParameters* path_params) {
    bool overall_valid = true;

    // 1. Apply Sanitizers
    if (!_query_param_sanitizers.empty()) {
        auto& queries_map = request.uri().queries(); // mutable reference
        for (auto& query_pair : queries_map) {
            const auto& param_name = query_pair.first;
            auto it_sanitizers = _query_param_sanitizers.find(param_name);
            if (it_sanitizers != _query_param_sanitizers.end()) {
                for (std::string& value_str : query_pair.second) { // mutable reference to each value string
                    for (const auto& sanitizer_func : it_sanitizers->second) {
                        value_str = sanitizer_func(value_str);
                    }
                }
            }
        }
    }

    if (!_header_sanitizers.empty()) {
        auto& headers_map = request.headers(); // mutable reference
        for (auto& header_pair : headers_map) {
            const auto& header_name = header_pair.first;
            auto it_sanitizers = _header_sanitizers.find(header_name);
            if (it_sanitizers != _header_sanitizers.end()) {
                for (std::string& value_str : header_pair.second) { // mutable reference
                    for (const auto& sanitizer_func : it_sanitizers->second) {
                        value_str = sanitizer_func(value_str);
                    }
                }
            }
        }
    }

    if (_body_sanitizer && !request.body().empty()) {
        Result sanitize_body_result;
        try {
            qb::json body_json = qb::json::parse(request.body().as<std::string_view>());
            _body_sanitizer->sanitize(body_json);
            request.body() = body_json.dump(); // Update request body with sanitized version
        } catch (const qb::json::parse_error& e) {
            sanitize_body_result.add_error("body", "invalidFormat.sanitize", "Request body is not valid JSON, cannot apply body sanitizers. Error: " + std::string(e.what()), request.body().as<std::string_view>());
            overall_valid = false; 
        }
        result.merge(sanitize_body_result); // Merge even if only parse error, to report it
    }

    // 2. Perform Validations
    if (_body_schema_validator) { 
        Result body_val_result;
        if (request.body().empty()) {
            // If schema expects an object/array but body is empty, this is usually an error.
            // A common case is a schema like `{"type": "object", "properties": {...}}`
            // Validating `nullptr` against such a schema will correctly produce a type error.
            qb::json null_json_value = nullptr; 
            if (!_body_schema_validator->validate(null_json_value, body_val_result)) {
                overall_valid = false;
                // Check if the error is specifically about expecting an object/array but getting null.
                // If not, or if errors are empty (shouldn't happen if validate returned false),
                // add a more generic "contentRequired" error.
                bool type_error_related_to_null = false;
                for(const auto& err : body_val_result.errors()) {
                    if (err.rule_violated == "type" && 
                        (err.message.find("null") != std::string::npos || err.message.find("object") != std::string::npos || err.message.find("array") != std::string::npos) ) {
                        type_error_related_to_null = true;
                        break;
                    }
                }
                // If validate returned false but no specific type error was found (or errors empty), add a general one.
                if (body_val_result.errors().empty() || !type_error_related_to_null) {
                    body_val_result.clear(); // Clear potentially misleading errors if we add a more generic one
                    body_val_result.add_error("body", "contentRequired", "Request body is empty, but the schema expects a non-null structure (e.g., object or array).", nullptr);
                }
            }
        } else { 
            try {
                qb::json body_json = qb::json::parse(request.body().as<std::string_view>());
                if (!_body_schema_validator->validate(body_json, body_val_result)) {
                    overall_valid = false;
                }
            } catch (const qb::json::parse_error& e) {
                body_val_result.add_error("body", "invalidFormat.validate", "Request body is not valid JSON. Error: " + std::string(e.what()), request.body().as<std::string_view>());
                overall_valid = false;
            }
        }
        result.merge(body_val_result);
    }

    // Validate Query Parameters (handles multi-value internally by iterating)
    if (_query_param_validator) {
        // The ParameterValidator::validate method itself handles defined fields, required checks, defaults, and strict mode.
        // We just need to adapt the Request's query map to what ParameterValidator::validate expects.
        // For multi-value query params (e.g., ids=1&ids=2), we validate each occurrence.
        qb::icase_unordered_map<std::string> single_value_query_params_for_strict_check;
        Result query_param_val_result; 

        for (const auto& [param_name_defined, rules] : _query_param_validator->get_param_definitions()) {
            auto it_query = request.queries().find(param_name_defined);
            if (it_query != request.queries().end() && !it_query->second.empty()) {
                single_value_query_params_for_strict_check[param_name_defined] = it_query->second.front(); // For strict check, one instance is enough
                for (const std::string& value_str : it_query->second) {
                    Result single_value_result;
                    _query_param_validator->validate_single(param_name_defined, std::make_optional(value_str), rules, single_value_result, "query");
                    if (!single_value_result.success()) {
                        query_param_val_result.merge(single_value_result);
                        overall_valid = false;
                    }
                }
            } else { // Parameter not present in request
                Result single_value_result; // For required/default checks
                _query_param_validator->validate_single(param_name_defined, std::nullopt, rules, single_value_result, "query");
                if (!single_value_result.success()) {
                    query_param_val_result.merge(single_value_result);
                    overall_valid = false;
                }
            }
        }
        // Strict mode check for unexpected query parameters
        if (_query_param_validator->is_strict_mode()) {
            for (const auto& [name_in_request, value_list_in_request] : request.queries()) {
                if (!value_list_in_request.empty() && _query_param_validator->get_param_definitions().find(name_in_request) == _query_param_validator->get_param_definitions().end()) {
                    query_param_val_result.add_error("query." + name_in_request, "unexpectedParameter", "Unexpected query parameter provided.", value_list_in_request.front());
                    overall_valid = false;
                }
            }
        }
        result.merge(query_param_val_result);
    }

    // Validate Headers (similar logic to query params)
    if (_header_validator) {
        Result header_val_result;
        for (const auto& [header_name_defined, rules] : _header_validator->get_param_definitions()) {
            auto it_header = request.headers().find(header_name_defined);
            if (it_header != request.headers().end() && !it_header->second.empty()) {
                for (const std::string& value_str : it_header->second) {
                    Result single_value_result;
                    _header_validator->validate_single(header_name_defined, std::make_optional(value_str), rules, single_value_result, "header");
                    if (!single_value_result.success()) {
                        header_val_result.merge(single_value_result);
                        overall_valid = false;
                    }
                }
            } else {
                Result single_value_result;
                _header_validator->validate_single(header_name_defined, std::nullopt, rules, single_value_result, "header");
                 if (!single_value_result.success()) {
                    header_val_result.merge(single_value_result);
                    overall_valid = false;
                }
            }
        }
        if (_header_validator->is_strict_mode()) {
            for (const auto& [name_in_request, value_list_in_request] : request.headers()) {
                 if (!value_list_in_request.empty() && _header_validator->get_param_definitions().find(name_in_request) == _header_validator->get_param_definitions().end()) {
                    header_val_result.add_error("header." + name_in_request, "unexpectedParameter", "Unexpected header provided.", value_list_in_request.front());
                    overall_valid = false;
                }
            }
        }
        result.merge(header_val_result);
    }

    // Validate Path Parameters
    if (_path_param_validator && path_params) {
        Result path_param_val_result;
        for (const auto& [param_name_defined, rules] : _path_param_validator->get_param_definitions()) {
             std::optional<std::string_view> sv_opt = path_params->get(rules.name); 
             std::optional<std::string> string_opt;
             if (sv_opt.has_value()) {
                 string_opt = std::string(sv_opt.value());
             }

            Result single_value_result;
            _path_param_validator->validate_single(rules.name, string_opt, rules, single_value_result, "path");

            if (!single_value_result.success()) {
                path_param_val_result.merge(single_value_result);
                overall_valid = false;
            }
        }
        result.merge(path_param_val_result);
    } else {
        // PathParam section SKIPPED (logging removed)
    }
    return overall_valid;
}

} // namespace qb::http::validation 