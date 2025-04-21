#include "query_validator.h"
#include <regex>
#include <stdexcept>
#include <string>

namespace qb::http {

void QueryValidator::add_param(const std::string& param_name, const QueryParamRules& rules) {
    _param_rules[param_name] = rules;
}

bool QueryValidator::validate(const qb::unordered_map<std::string, std::string>& params,
                            ValidationContext& ctx) const {
    bool valid = true;
    
    // First, check that all required parameters are present
    for (const auto& [param_name, rules] : _param_rules) {
        bool is_required = false;
        std::string default_value;
        
        // Check if the parameter is required
        for (const auto& rule : rules.rules) {
            if (rule.type == QueryParamRule::Type::Required) {
                if (std::get<bool>(rule.value)) {
                    is_required = true;
                }
            } else if (rule.type == QueryParamRule::Type::Default) {
                default_value = std::get<std::string>(rule.value);
            }
        }
        
        if (is_required && params.find(param_name) == params.end() && default_value.empty()) {
            ctx.add_error(param_name, "required", "Required parameter missing");
            valid = false;
        }
    }
    
    // Then validate each parameter
    for (const auto& [param_name, value] : params) {
        auto it = _param_rules.find(param_name);
        if (it != _param_rules.end()) {
            valid = validate_param(param_name, value, it->second, ctx) && valid;
        }
    }
    
    return valid;
}

bool QueryValidator::validate_param(const std::string& param_name,
                                  const std::string& value,
                                  const QueryParamRules& rules,
                                  ValidationContext& ctx) const {
    // First check if we can convert the value to the expected type
    if (!convert_value(value, rules.type, param_name, ctx)) {
        return false;
    }
    
    bool valid = true;
    
    // Apply each rule
    for (const auto& rule : rules.rules) {
        valid = apply_rule(param_name, value, rule, ctx) && valid;
    }
    
    return valid;
}

bool QueryValidator::convert_value(const std::string& value,
                                 ParamType type,
                                 const std::string& param_name,
                                 ValidationContext& ctx) const {
    switch (type) {
        case ParamType::String:
            // Any string is valid
            return true;
            
        case ParamType::Integer:
            try {
                std::stoll(value);
                return true;
            } catch (const std::exception&) {
                ctx.add_error(param_name, "type", "Must be an integer");
                return false;
            }
            
        case ParamType::Float:
            try {
                std::stod(value);
                return true;
            } catch (const std::exception&) {
                ctx.add_error(param_name, "type", "Must be a number");
                return false;
            }
            
        case ParamType::Boolean:
            if (value == "true" || value == "false" || value == "1" || value == "0") {
                return true;
            } else {
                ctx.add_error(param_name, "type", "Must be a boolean (true, false, 1, 0)");
                return false;
            }
            
        case ParamType::Array:
            // Simple comma-separated array validation
            return true;
            
        case ParamType::Object:
            // For query parameters, we don't support objects
            ctx.add_error(param_name, "type", "Object type not supported for query parameters");
            return false;
    }
    
    return false;
}

bool QueryValidator::apply_rule(const std::string& param_name,
                              const std::string& value,
                              const QueryParamRule& rule,
                              ValidationContext& ctx) const {
    switch (rule.type) {
        case QueryParamRule::Type::Required:
        case QueryParamRule::Type::Optional:
        case QueryParamRule::Type::Default:
            // These are handled elsewhere
            return true;
            
        case QueryParamRule::Type::MinLength: {
            int64_t min_length = std::get<int64_t>(rule.value);
            if (value.length() < static_cast<size_t>(min_length)) {
                ctx.add_error(param_name, "min_length", 
                             "Must be at least " + std::to_string(min_length) + " characters long");
                return false;
            }
            return true;
        }
            
        case QueryParamRule::Type::MaxLength: {
            int64_t max_length = std::get<int64_t>(rule.value);
            if (value.length() > static_cast<size_t>(max_length)) {
                ctx.add_error(param_name, "max_length", 
                             "Must be at most " + std::to_string(max_length) + " characters long");
                return false;
            }
            return true;
        }
            
        case QueryParamRule::Type::MinValue: {
            if (rule.value.index() == 2) { // int64_t
                int64_t min_value = std::get<int64_t>(rule.value);
                try {
                    int64_t val = std::stoll(value);
                    if (val < min_value) {
                        ctx.add_error(param_name, "min_value", 
                                     "Must be at least " + std::to_string(min_value));
                        return false;
                    }
                } catch (const std::exception&) {
                    // This should be caught by type conversion
                    return false;
                }
            } else if (rule.value.index() == 3) { // double
                double min_value = std::get<double>(rule.value);
                try {
                    double val = std::stod(value);
                    if (val < min_value) {
                        ctx.add_error(param_name, "min_value", 
                                     "Must be at least " + std::to_string(min_value));
                        return false;
                    }
                } catch (const std::exception&) {
                    // This should be caught by type conversion
                    return false;
                }
            }
            return true;
        }
            
        case QueryParamRule::Type::MaxValue: {
            if (rule.value.index() == 2) { // int64_t
                int64_t max_value = std::get<int64_t>(rule.value);
                try {
                    int64_t val = std::stoll(value);
                    if (val > max_value) {
                        ctx.add_error(param_name, "max_value", 
                                     "Must be at most " + std::to_string(max_value));
                        return false;
                    }
                } catch (const std::exception&) {
                    // This should be caught by type conversion
                    return false;
                }
            } else if (rule.value.index() == 3) { // double
                double max_value = std::get<double>(rule.value);
                try {
                    double val = std::stod(value);
                    if (val > max_value) {
                        ctx.add_error(param_name, "max_value", 
                                     "Must be at most " + std::to_string(max_value));
                        return false;
                    }
                } catch (const std::exception&) {
                    // This should be caught by type conversion
                    return false;
                }
            }
            return true;
        }
            
        case QueryParamRule::Type::Pattern: {
            std::string pattern = std::get<std::string>(rule.value);
            try {
                std::regex regex(pattern);
                if (!std::regex_match(value, regex)) {
                    ctx.add_error(param_name, "pattern", 
                                 "Must match pattern: " + pattern);
                    return false;
                }
            } catch (const std::regex_error&) {
                // Invalid regex pattern
                ctx.add_error(param_name, "pattern_error", 
                             "Invalid pattern specified in validation rule");
                return false;
            }
            return true;
        }
            
        case QueryParamRule::Type::Enum: {
            const auto& allowed_values = std::get<std::vector<std::string>>(rule.value);
            bool valid = false;
            for (const auto& allowed : allowed_values) {
                if (value == allowed) {
                    valid = true;
                    break;
                }
            }
            if (!valid) {
                std::string values_str;
                for (size_t i = 0; i < allowed_values.size(); ++i) {
                    if (i > 0) {
                        values_str += ", ";
                    }
                    values_str += "'" + allowed_values[i] + "'";
                }
                ctx.add_error(param_name, "enum", 
                             "Must be one of: " + values_str);
                return false;
            }
            return true;
        }
            
        case QueryParamRule::Type::Custom: {
            const auto& validator = std::get<std::function<bool(const std::string&, std::string&)>>(rule.value);
            std::string error_message;
            if (!validator(value, error_message)) {
                ctx.add_error(param_name, "custom", 
                             error_message.empty() ? "Failed custom validation" : error_message);
                return false;
            }
            return true;
        }
    }
    
    return true;
}

} // namespace qb::http::validation 