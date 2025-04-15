#include "json_schema.h"
#include <regex>
#include <stdexcept>
#include <string>
#include <unordered_set>

namespace qb::http {

JsonSchemaValidator::JsonSchemaValidator(const qb::json& schema)
    : _schema(schema) {
    // Validate that the schema itself is valid
    if (!_schema.is_object()) {
        throw std::invalid_argument("JSON Schema must be an object");
    }
}

JsonSchemaValidator::JsonSchemaValidator(const std::string& schema_str)
    : _schema(qb::json::parse(schema_str)) {
    // Validate that the schema itself is valid
    if (!_schema.is_object()) {
        throw std::invalid_argument("JSON Schema must be an object");
    }
}

bool JsonSchemaValidator::validate(const qb::json& value, ValidationContext& ctx) const {
    return validate_value(value, _schema, "", ctx);
}

bool JsonSchemaValidator::validate_value(const qb::json& value, const qb::json& schema,
                                       const std::string& path, ValidationContext& ctx) const {
    bool valid = true;
    
    // Type validation
    if (schema.contains("type")) {
        valid = validate_type(value, schema, path, ctx) && valid;
    }
    
    // Required properties
    if (schema.contains("required") && value.is_object()) {
        valid = validate_required(value, schema, path, ctx) && valid;
    }
    
    // Properties validation
    if (schema.contains("properties") && value.is_object()) {
        valid = validate_properties(value, schema, path, ctx) && valid;
    }
    
    // Additional properties
    if (schema.contains("additionalProperties") && value.is_object()) {
        valid = validate_additional_properties(value, schema, path, ctx) && valid;
    }
    
    // String validations
    if (value.is_string()) {
        // minLength
        if (schema.contains("minLength")) {
            valid = validate_min_length(value, schema, path, ctx) && valid;
        }
        
        // maxLength
        if (schema.contains("maxLength")) {
            valid = validate_max_length(value, schema, path, ctx) && valid;
        }
        
        // pattern
        if (schema.contains("pattern")) {
            valid = validate_pattern(value, schema, path, ctx) && valid;
        }
    }
    
    // Number validations
    if (value.is_number()) {
        // minimum
        if (schema.contains("minimum")) {
            valid = validate_minimum(value, schema, path, ctx) && valid;
        }
        
        // maximum
        if (schema.contains("maximum")) {
            valid = validate_maximum(value, schema, path, ctx) && valid;
        }
    }
    
    // Array validations
    if (value.is_array()) {
        // items
        if (schema.contains("items")) {
            valid = validate_items(value, schema, path, ctx) && valid;
        }
        
        // minItems
        if (schema.contains("minItems")) {
            valid = validate_min_items(value, schema, path, ctx) && valid;
        }
        
        // maxItems
        if (schema.contains("maxItems")) {
            valid = validate_max_items(value, schema, path, ctx) && valid;
        }
        
        // uniqueItems
        if (schema.contains("uniqueItems")) {
            valid = validate_unique_items(value, schema, path, ctx) && valid;
        }
    }
    
    // Enum validation
    if (schema.contains("enum")) {
        valid = validate_enum(value, schema, path, ctx) && valid;
    }
    
    // Logical validations
    if (schema.contains("oneOf")) {
        valid = validate_one_of(value, schema, path, ctx) && valid;
    }
    
    if (schema.contains("anyOf")) {
        valid = validate_any_of(value, schema, path, ctx) && valid;
    }
    
    if (schema.contains("allOf")) {
        valid = validate_all_of(value, schema, path, ctx) && valid;
    }
    
    if (schema.contains("not")) {
        valid = validate_not(value, schema, path, ctx) && valid;
    }
    
    return valid;
}

bool JsonSchemaValidator::validate_type(const qb::json& value, const qb::json& schema,
                                      const std::string& path, ValidationContext& ctx) const {
    const auto& type = schema["type"];
    
    auto check_type = [&](const std::string& expected_type) -> bool {
        if (expected_type == "null" && value.is_null()) {
            return true;
        } else if (expected_type == "boolean" && value.is_boolean()) {
            return true;
        } else if (expected_type == "object" && value.is_object()) {
            return true;
        } else if (expected_type == "array" && value.is_array()) {
            return true;
        } else if (expected_type == "number" && value.is_number()) {
            return true;
        } else if (expected_type == "integer" && value.is_number_integer()) {
            return true;
        } else if (expected_type == "string" && value.is_string()) {
            return true;
        }
        return false;
    };
    
    if (type.is_string()) {
        if (!check_type(type.get<std::string>())) {
            ctx.add_error(path.empty() ? "value" : path.substr(1), "type", 
                          "Expected " + type.get<std::string>());
            return false;
        }
    } else if (type.is_array()) {
        bool valid_type = false;
        for (const auto& t : type) {
            if (check_type(t.get<std::string>())) {
                valid_type = true;
                break;
            }
        }
        
        if (!valid_type) {
            std::string expected_types;
            for (size_t i = 0; i < type.size(); ++i) {
                if (i > 0) {
                    expected_types += " or ";
                }
                expected_types += type[i].get<std::string>();
            }
            
            ctx.add_error(path.empty() ? "value" : path.substr(1), "type", 
                          "Expected " + expected_types);
            return false;
        }
    }
    
    return true;
}

bool JsonSchemaValidator::validate_required(const qb::json& value, const qb::json& schema,
                                          const std::string& path, ValidationContext& ctx) const {
    const auto& required = schema["required"];
    bool valid = true;
    
    for (const auto& prop : required) {
        const std::string prop_name = prop.get<std::string>();
        if (!value.contains(prop_name)) {
            std::string error_path = path.empty() ? prop_name : path.substr(1) + "." + prop_name;
            ctx.add_error(error_path, "required", "Required property missing");
            valid = false;
        }
    }
    
    return valid;
}

bool JsonSchemaValidator::validate_properties(const qb::json& value, const qb::json& schema,
                                            const std::string& path, ValidationContext& ctx) const {
    const auto& properties = schema["properties"];
    bool valid = true;
    
    for (const auto& [prop_name, prop_schema] : properties.items()) {
        if (value.contains(prop_name)) {
            std::string new_path = path + "/" + prop_name;
            valid = validate_value(value[prop_name], prop_schema, new_path, ctx) && valid;
        }
    }
    
    return valid;
}

bool JsonSchemaValidator::validate_additional_properties(const qb::json& value, const qb::json& schema,
                                                       const std::string& path, ValidationContext& ctx) const {
    const auto& additional_properties = schema["additionalProperties"];
    
    // If additionalProperties is false, then no properties beyond those defined in the
    // properties schema keyword are allowed
    if (additional_properties.is_boolean() && !additional_properties.get<bool>()) {
        std::unordered_set<std::string> defined_properties;
        
        if (schema.contains("properties")) {
            for (const auto& [prop_name, _] : schema["properties"].items()) {
                defined_properties.insert(prop_name);
            }
        }
        
        for (const auto& [prop_name, _] : value.items()) {
            if (defined_properties.find(prop_name) == defined_properties.end()) {
                std::string error_path = path.empty() ? prop_name : path.substr(1) + "." + prop_name;
                ctx.add_error(error_path, "additionalProperties", "Additional property not allowed");
                return false;
            }
        }
    } else if (additional_properties.is_object()) {
        // If additionalProperties is an object, it's a schema that all additional properties must validate against
        std::unordered_set<std::string> defined_properties;
        
        if (schema.contains("properties")) {
            for (const auto& [prop_name, _] : schema["properties"].items()) {
                defined_properties.insert(prop_name);
            }
        }
        
        bool valid = true;
        
        for (const auto& [prop_name, prop_value] : value.items()) {
            if (defined_properties.find(prop_name) == defined_properties.end()) {
                std::string new_path = path + "/" + prop_name;
                valid = validate_value(prop_value, additional_properties, new_path, ctx) && valid;
            }
        }
        
        return valid;
    }
    
    return true;
}

bool JsonSchemaValidator::validate_min_length(const qb::json& value, const qb::json& schema,
                                            const std::string& path, ValidationContext& ctx) const {
    const auto& min_length = schema["minLength"];
    const auto& str_value = value.get<std::string>();
    
    if (str_value.length() < min_length.get<size_t>()) {
        ctx.add_error(path.empty() ? "value" : path.substr(1), "minLength", 
                      "String is too short (minimum length: " + std::to_string(min_length.get<size_t>()) + ")");
        return false;
    }
    
    return true;
}

bool JsonSchemaValidator::validate_max_length(const qb::json& value, const qb::json& schema,
                                            const std::string& path, ValidationContext& ctx) const {
    const auto& max_length = schema["maxLength"];
    const auto& str_value = value.get<std::string>();
    
    if (str_value.length() > max_length.get<size_t>()) {
        ctx.add_error(path.empty() ? "value" : path.substr(1), "maxLength", 
                      "String is too long (maximum length: " + std::to_string(max_length.get<size_t>()) + ")");
        return false;
    }
    
    return true;
}

bool JsonSchemaValidator::validate_pattern(const qb::json& value, const qb::json& schema,
                                         const std::string& path, ValidationContext& ctx) const {
    const auto& pattern = schema["pattern"].get<std::string>();
    const auto& str_value = value.get<std::string>();
    
    try {
        std::regex regex(pattern);
        if (!std::regex_match(str_value, regex)) {
            ctx.add_error(path.empty() ? "value" : path.substr(1), "pattern", 
                          "String does not match pattern: " + pattern);
            return false;
        }
    } catch (const std::regex_error& e) {
        // This is a schema error, not a validation error
        ctx.add_error(path.empty() ? "value" : path.substr(1), "pattern_error", 
                      "Invalid regex pattern in schema: " + pattern);
        return false;
    }
    
    return true;
}

bool JsonSchemaValidator::validate_enum(const qb::json& value, const qb::json& schema,
                                      const std::string& path, ValidationContext& ctx) const {
    const auto& enum_values = schema["enum"];
    
    for (const auto& enum_value : enum_values) {
        if (value == enum_value) {
            return true;
        }
    }
    
    ctx.add_error(path.empty() ? "value" : path.substr(1), "enum", 
                  "Value must be one of the enumerated values");
    return false;
}

bool JsonSchemaValidator::validate_minimum(const qb::json& value, const qb::json& schema,
                                         const std::string& path, ValidationContext& ctx) const {
    const auto& minimum = schema["minimum"];
    bool exclusive = false;
    
    if (schema.contains("exclusiveMinimum")) {
        exclusive = schema["exclusiveMinimum"].get<bool>();
    }
    
    if (exclusive) {
        if (value <= minimum) {
            ctx.add_error(path.empty() ? "value" : path.substr(1), "minimum", 
                          "Value must be greater than " + minimum.dump());
            return false;
        }
    } else {
        if (value < minimum) {
            ctx.add_error(path.empty() ? "value" : path.substr(1), "minimum", 
                          "Value must be greater than or equal to " + minimum.dump());
            return false;
        }
    }
    
    return true;
}

bool JsonSchemaValidator::validate_maximum(const qb::json& value, const qb::json& schema,
                                         const std::string& path, ValidationContext& ctx) const {
    const auto& maximum = schema["maximum"];
    bool exclusive = false;
    
    if (schema.contains("exclusiveMaximum")) {
        exclusive = schema["exclusiveMaximum"].get<bool>();
    }
    
    if (exclusive) {
        if (value >= maximum) {
            ctx.add_error(path.empty() ? "value" : path.substr(1), "maximum", 
                          "Value must be less than " + maximum.dump());
            return false;
        }
    } else {
        if (value > maximum) {
            ctx.add_error(path.empty() ? "value" : path.substr(1), "maximum", 
                          "Value must be less than or equal to " + maximum.dump());
            return false;
        }
    }
    
    return true;
}

bool JsonSchemaValidator::validate_items(const qb::json& value, const qb::json& schema,
                                       const std::string& path, ValidationContext& ctx) const {
    const auto& items = schema["items"];
    bool valid = true;
    
    if (items.is_object()) {
        // All items must validate against the schema
        for (size_t i = 0; i < value.size(); ++i) {
            std::string new_path = path + "/" + std::to_string(i);
            valid = validate_value(value[i], items, new_path, ctx) && valid;
        }
    } else if (items.is_array()) {
        // Each item must validate against the corresponding schema
        for (size_t i = 0; i < std::min(value.size(), items.size()); ++i) {
            std::string new_path = path + "/" + std::to_string(i);
            valid = validate_value(value[i], items[i], new_path, ctx) && valid;
        }
        
        // If additionalItems is false, then the number of items in the array must be less than
        // or equal to the number of items in the schema
        if (schema.contains("additionalItems")) {
            const auto& additional_items = schema["additionalItems"];
            
            if (additional_items.is_boolean() && !additional_items.get<bool>()) {
                if (value.size() > items.size()) {
                    ctx.add_error(path.empty() ? "value" : path.substr(1), "additionalItems", 
                                  "Additional items not allowed");
                    valid = false;
                }
            } else if (additional_items.is_object()) {
                // Additional items must validate against this schema
                for (size_t i = items.size(); i < value.size(); ++i) {
                    std::string new_path = path + "/" + std::to_string(i);
                    valid = validate_value(value[i], additional_items, new_path, ctx) && valid;
                }
            }
        }
    }
    
    return valid;
}

bool JsonSchemaValidator::validate_min_items(const qb::json& value, const qb::json& schema,
                                           const std::string& path, ValidationContext& ctx) const {
    const auto& min_items = schema["minItems"].get<size_t>();
    
    if (value.size() < min_items) {
        ctx.add_error(path.empty() ? "value" : path.substr(1), "minItems", 
                      "Array is too short (minimum items: " + std::to_string(min_items) + ")");
        return false;
    }
    
    return true;
}

bool JsonSchemaValidator::validate_max_items(const qb::json& value, const qb::json& schema,
                                           const std::string& path, ValidationContext& ctx) const {
    const auto& max_items = schema["maxItems"].get<size_t>();
    
    if (value.size() > max_items) {
        ctx.add_error(path.empty() ? "value" : path.substr(1), "maxItems", 
                      "Array is too long (maximum items: " + std::to_string(max_items) + ")");
        return false;
    }
    
    return true;
}

bool JsonSchemaValidator::validate_unique_items(const qb::json& value, const qb::json& schema,
                                              const std::string& path, ValidationContext& ctx) const {
    const auto& unique_items = schema["uniqueItems"].get<bool>();
    
    if (unique_items) {
        std::unordered_set<std::string> seen;
        for (const auto& item : value) {
            std::string serialized = item.dump();
            if (seen.find(serialized) != seen.end()) {
                ctx.add_error(path.empty() ? "value" : path.substr(1), "uniqueItems", 
                              "Array items must be unique");
                return false;
            }
            seen.insert(serialized);
        }
    }
    
    return true;
}

bool JsonSchemaValidator::validate_one_of(const qb::json& value, const qb::json& schema,
                                        const std::string& path, ValidationContext& ctx) const {
    const auto& one_of = schema["oneOf"];
    
    // Track how many schemas the value validates against
    int valid_count = 0;
    
    for (const auto& sub_schema : one_of) {
        ValidationContext temp_ctx;
        if (validate_value(value, sub_schema, path, temp_ctx)) {
            valid_count++;
        }
        
        if (valid_count > 1) {
            break;
        }
    }
    
    if (valid_count != 1) {
        ctx.add_error(path.empty() ? "value" : path.substr(1), "oneOf", 
                      "Value must validate against exactly one schema");
        return false;
    }
    
    return true;
}

bool JsonSchemaValidator::validate_any_of(const qb::json& value, const qb::json& schema,
                                        const std::string& path, ValidationContext& ctx) const {
    const auto& any_of = schema["anyOf"];
    
    for (const auto& sub_schema : any_of) {
        ValidationContext temp_ctx;
        if (validate_value(value, sub_schema, path, temp_ctx)) {
            return true;
        }
    }
    
    ctx.add_error(path.empty() ? "value" : path.substr(1), "anyOf", 
                  "Value must validate against at least one schema");
    return false;
}

bool JsonSchemaValidator::validate_all_of(const qb::json& value, const qb::json& schema,
                                        const std::string& path, ValidationContext& ctx) const {
    const auto& all_of = schema["allOf"];
    bool valid = true;
    
    for (const auto& sub_schema : all_of) {
        valid = validate_value(value, sub_schema, path, ctx) && valid;
    }
    
    return valid;
}

bool JsonSchemaValidator::validate_not(const qb::json& value, const qb::json& schema,
                                     const std::string& path, ValidationContext& ctx) const {
    const auto& not_schema = schema["not"];
    
    ValidationContext temp_ctx;
    if (validate_value(value, not_schema, path, temp_ctx)) {
        ctx.add_error(path.empty() ? "value" : path.substr(1), "not", 
                      "Value must not validate against the schema");
        return false;
    }
    
    return true;
}

} // namespace qb::http::validation 