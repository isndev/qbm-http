/**
 * @file qbm/http/validation/schema_validator.cpp
 * @brief Implementation of the SchemaValidator class.
 *
 * This file contains the implementation of the SchemaValidator class,
 * which is used to validate HTTP requests according to the schema defined
 * in the RequestValidator.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Validaton
 */
#include "./schema_validator.h"
#include "./rule.h" // For access to concrete rule classes like TypeRule, MinLengthRule, etc.
#include <algorithm> 
#include <qb/system/container/unordered_set.h> // Already included in rule.cpp, but good for clarity if directly used here

namespace qb::http::validation { // Changed namespace

SchemaValidator::SchemaValidator(const qb::json& schema_definition)
    : _schema_definition(schema_definition) {
    if (!_schema_definition.is_object()) {
        throw std::invalid_argument("Schema definition must be a JSON object.");
    }
}

bool SchemaValidator::validate(const qb::json& data_to_validate, Result& result) const {
    return validate_recursive(data_to_validate, _schema_definition, "", result);
}

std::vector<std::shared_ptr<IRule>> 
SchemaValidator::create_rules_for_schema_node(const qb::json& schema_node) const {
    std::vector<std::shared_ptr<IRule>> rules;
    
    if (schema_node.contains("minLength") && schema_node["minLength"].is_number_integer()) {
        long long val = schema_node["minLength"].get<long long>();
        if (val >= 0) {
            rules.push_back(std::make_shared<MinLengthRule>(static_cast<size_t>(val)));
        }
    }
    if (schema_node.contains("maxLength") && schema_node["maxLength"].is_number_integer()) {
        long long val = schema_node["maxLength"].get<long long>();
        if (val >= 0) {
            rules.push_back(std::make_shared<MaxLengthRule>(static_cast<size_t>(val)));
        }
    }
    if (schema_node.contains("pattern") && schema_node["pattern"].is_string()) {
        rules.push_back(std::make_shared<PatternRule>(schema_node["pattern"].get<std::string>()));
    }
    if (schema_node.contains("minimum") && schema_node["minimum"].is_number()) {
        bool exclusive = schema_node.value("exclusiveMinimum", false);
        rules.push_back(std::make_shared<MinimumRule>(schema_node["minimum"].get<double>(), exclusive));
    }
    if (schema_node.contains("maximum") && schema_node["maximum"].is_number()) {
        bool exclusive = schema_node.value("exclusiveMaximum", false);
        rules.push_back(std::make_shared<MaximumRule>(schema_node["maximum"].get<double>(), exclusive));
    }
    if (schema_node.contains("enum") && schema_node["enum"].is_array()) {
        rules.push_back(std::make_shared<EnumRule>(schema_node["enum"]));
    }
    if (schema_node.contains("minItems") && schema_node["minItems"].is_number_integer()) {
        long long val = schema_node["minItems"].get<long long>();
        if (val >= 0) {
            rules.push_back(std::make_shared<MinItemsRule>(static_cast<size_t>(val)));
        }
    }
    if (schema_node.contains("maxItems") && schema_node["maxItems"].is_number_integer()) {
        long long val = schema_node["maxItems"].get<long long>();
        if (val >= 0) {
            rules.push_back(std::make_shared<MaxItemsRule>(static_cast<size_t>(val)));
        }
    }
    if (schema_node.contains("uniqueItems") && schema_node["uniqueItems"].is_boolean() && schema_node["uniqueItems"].get<bool>()) {
        rules.push_back(std::make_shared<UniqueItemsRule>());
    }
    if (schema_node.contains("minProperties") && schema_node["minProperties"].is_number_integer()) {
        long long val = schema_node["minProperties"].get<long long>();
        if (val >= 0) {
            rules.push_back(std::make_shared<MinPropertiesRule>(static_cast<size_t>(val)));
        }
    }
    if (schema_node.contains("maxProperties") && schema_node["maxProperties"].is_number_integer()) {
        long long val = schema_node["maxProperties"].get<long long>();
        if (val >= 0) {
            rules.push_back(std::make_shared<MaxPropertiesRule>(static_cast<size_t>(val)));
        }
    }
    // PropertyNamesRule is handled structurally in validate_recursive
    return rules;
}

bool SchemaValidator::apply_primitive_rules(const qb::json& value, const qb::json& schema_node, const std::string& path, Result& result) const {
    bool all_rules_passed = true;
    auto rules = create_rules_for_schema_node(schema_node);

    for (const auto& rule : rules) {
        if (!rule->validate(value, path, result)) {
            all_rules_passed = false;
        }
    }
    return all_rules_passed;
}


bool SchemaValidator::validate_recursive(const qb::json& current_value, 
                                       const qb::json& current_schema, 
                                       const std::string& current_path, 
                                       Result& result) const {
    size_t errors_before_this_level = result.errors().size();

    if (!current_schema.is_object()) {
        result.add_error(current_path.empty() ? "_schema" : current_path + "._schema", 
                         "invalidSchemaType", 
                         "Schema definition at this level must be an object.", 
                         current_schema);
        return false; 
    }

    bool type_ok = true;
    if (current_schema.contains("type")) {
        if (!validate_type_keyword(current_value, current_schema["type"], current_path, result)) {
            type_ok = false;
        }
    }
    
    bool primitives_ok = true;
    if (type_ok) { 
        if (!apply_primitive_rules(current_value, current_schema, current_path, result)) {
            primitives_ok = false;
        }
    } else {
      primitives_ok = false; 
    }

    bool structural_ok = true;
    if (type_ok) { 
        if (current_value.is_object()) { 
            bool properties_check_passed = true;
            bool required_check_passed = true;
            bool additional_properties_check_passed = true;
            bool property_names_check_passed = true;

            if (current_schema.contains("properties")) {
                if (!validate_properties_keyword(current_value, current_schema["properties"], current_path, result)) {
                    properties_check_passed = false;
                }
            }
            
            if (current_schema.contains("required")) { 
                if (!validate_required_keyword(current_value, current_schema["required"], current_path, result)) {
                    required_check_passed = false;
                }
            }
            
            if (current_schema.contains("additionalProperties")) {
                if (!validate_additional_properties_keyword(current_value, current_schema, current_path, result)) {
                    additional_properties_check_passed = false;
                }
            } 
            
            if (current_schema.contains("propertyNames") && current_schema["propertyNames"].is_object()) {
                PropertyNamesRule prop_names_rule(current_schema["propertyNames"]);
                if (!prop_names_rule.validate(current_value, current_path, result)) {
                    property_names_check_passed = false;
                }
            }
            structural_ok = properties_check_passed && required_check_passed && additional_properties_check_passed && property_names_check_passed;

        }
        else if (current_value.is_array()) { 
            if (current_schema.contains("items")) { 
                if (!validate_items_keyword(current_value, current_schema, current_path, result)) {
                    structural_ok = false; 
                }
            }
        }
    } else {
        structural_ok = false; 
    }

    bool logical_combinators_ok = true;
    if (current_schema.contains("allOf")) {
        if (!validate_allOf_keyword(current_value, current_schema["allOf"], current_path, result)) logical_combinators_ok = false;
    }
    if (logical_combinators_ok && current_schema.contains("anyOf")) { 
        if (!validate_anyOf_keyword(current_value, current_schema["anyOf"], current_path, result)) logical_combinators_ok = false;
    }
    if (logical_combinators_ok && current_schema.contains("oneOf")) {
        if (!validate_oneOf_keyword(current_value, current_schema["oneOf"], current_path, result)) logical_combinators_ok = false;
    }
    if (logical_combinators_ok && current_schema.contains("not")) {
        if (!validate_not_keyword(current_value, current_schema["not"], current_path, result)) logical_combinators_ok = false;
    }

    bool all_checks_passed_bool = type_ok && primitives_ok && structural_ok && logical_combinators_ok;
    
    if (result.errors().size() > errors_before_this_level) {
        return false; 
    }

    return all_checks_passed_bool; 
}

bool SchemaValidator::validate_type_keyword(const qb::json& value, const qb::json& schema_type_def, const std::string& path, Result& result) const {
    if (schema_type_def.is_string()) {
        std::string type_str = schema_type_def.get<std::string>();
        DataType dt = DataType::ANY; 
        if (type_str == "string") dt = DataType::STRING;
        else if (type_str == "integer") dt = DataType::INTEGER;
        else if (type_str == "number") dt = DataType::NUMBER;
        else if (type_str == "boolean") dt = DataType::BOOLEAN;
        else if (type_str == "object") dt = DataType::OBJECT;
        else if (type_str == "array") dt = DataType::ARRAY;
        else if (type_str == "null") dt = DataType::NUL;
        else {
            result.add_error(path, "type", "Unknown type specified in schema: " + type_str, schema_type_def);
            return false;
        }
        return TypeRule(dt).validate(value, path, result);
    } else if (schema_type_def.is_array()) {
        for (const auto& type_option_json : schema_type_def) {
            if (type_option_json.is_string()) {
                std::string type_str = type_option_json.get<std::string>();
                DataType dt = DataType::ANY;
                if (type_str == "string") dt = DataType::STRING;
                else if (type_str == "integer") dt = DataType::INTEGER;
                else if (type_str == "number") dt = DataType::NUMBER;
                else if (type_str == "boolean") dt = DataType::BOOLEAN;
                else if (type_str == "object") dt = DataType::OBJECT;
                else if (type_str == "array") dt = DataType::ARRAY;
                else if (type_str == "null") dt = DataType::NUL;
                else { continue; }
                
                Result temp_result_for_type_array_check;
                if (TypeRule(dt).validate(value, path, temp_result_for_type_array_check)) {
                    return true; 
                }
            }
        }
        result.add_error(path, "type", "Value does not match any of the allowed types: " + schema_type_def.dump(), value);
        return false;
    }
    result.add_error(path, "type", "Schema 'type' keyword must be a string or an array of strings.", schema_type_def);
    return false; 
}


bool SchemaValidator::validate_properties_keyword(const qb::json& value, const qb::json& properties_def, const std::string& path, Result& result) const {
    if (!value.is_object()) return true; 
    if (!properties_def.is_object()) {
        result.add_error(path, "schemaError.properties", "'properties' keyword must be an object.", properties_def);
        return false; 
    }
    bool all_local_properties_valid = true;
    for (auto const& [prop_name, prop_schema] : properties_def.items()) {
        if (value.contains(prop_name)) {
            std::string prop_path = path.empty() ? prop_name : path + "." + prop_name;
            if (!validate_recursive(value[prop_name], prop_schema, prop_path, result)) {
                all_local_properties_valid = false;
            }
        }
    }
    return all_local_properties_valid; 
}

bool SchemaValidator::validate_required_keyword(const qb::json& value, const qb::json& required_def, const std::string& path, Result& result) const {
    if (!value.is_object()) return true; 
    if (!required_def.is_array()) {
        result.add_error(path, "schemaError.required", "'required' keyword must be an array of strings.", required_def);
        return false; 
    }

    bool all_required_present = true;
    for (const auto& required_prop_json : required_def) {
        if (!required_prop_json.is_string()) {
            result.add_error(path, "schemaError.required", "Elements in 'required' array must be strings.", required_prop_json);
            all_required_present = false; 
            continue;
        }
        std::string required_prop_name = required_prop_json.get<std::string>();
        if (!value.contains(required_prop_name)) {
            std::string prop_path = path.empty() ? required_prop_name : path + "." + required_prop_name;
            result.add_error(prop_path, "required", "Property is required.", qb::json()); 
            all_required_present = false;
        }
    }
    return all_required_present;
}

bool SchemaValidator::validate_items_keyword(const qb::json& value, const qb::json& schema_node, const std::string& path, Result& result) const {
    if (!value.is_array()) return true; 
    if (!schema_node.contains("items")) return true; 
    
    const qb::json& items_def = schema_node["items"];
    bool is_valid = true;

    if (items_def.is_object()) { // Single schema for all items
        for (size_t i = 0; i < value.size(); ++i) {
            std::string item_path = path + "[" + std::to_string(i) + "]";
            if (!validate_recursive(value[i], items_def, item_path, result)) {
                is_valid = false;
            }
        }
    } else if (items_def.is_array()) { // Tuple validation: array of schemas
        for (size_t i = 0; i < value.size(); ++i) {
            std::string item_path = path + "[" + std::to_string(i) + "]";
            if (i < items_def.size()) { // Validate against corresponding schema
                if (!validate_recursive(value[i], items_def[i], item_path, result)) {
                    is_valid = false;
                }
            } else { // Past the defined tuple schemas, check additionalItems
                if (schema_node.contains("additionalItems")) {
                    const qb::json& additional_items_def = schema_node["additionalItems"];
                    if (additional_items_def.is_boolean() && !additional_items_def.get<bool>()) {
                        result.add_error(item_path, "additionalItems", "Additional items not allowed.", value[i]);
                        is_valid = false;
                        break; 
                    } else if (additional_items_def.is_object()) {
                        if (!validate_recursive(value[i], additional_items_def, item_path, result)) {
                            is_valid = false;
                        }
                    }
                } 
            }
        }
    } else {
        result.add_error(path.empty() ? "_schema.items" : path + "._schema.items", "schemaError.items", "'items' keyword must be an object (schema) or an array of schemas.", items_def);
        return false; // Schema error itself
    }
    return is_valid;
}

bool SchemaValidator::validate_additional_properties_keyword(
    const qb::json& value, 
    const qb::json& schema_node, 
    const std::string& path, 
    Result& result) const {
    
    if (!value.is_object()) return true; 

    // Ensure additionalProperties is present in the schema node itself, not its parent
    if (!schema_node.contains("additionalProperties")) return true; // No restriction if not present

    const qb::json& additional_props_def = schema_node["additionalProperties"];
    qb::unordered_set<std::string> defined_props;
    if (schema_node.contains("properties") && schema_node["properties"].is_object()) {
        for (auto const& [prop_name, _] : schema_node["properties"].items()) {
            defined_props.insert(prop_name);
        }
    }

    bool is_valid = true;
    for (auto const& [key, val] : value.items()) {
        if (defined_props.count(key)) {
            continue; 
        }

        std::string prop_path = path.empty() ? key : path + "." + key;
        if (additional_props_def.is_boolean()) {
            if (!additional_props_def.get<bool>()) {
                result.add_error(prop_path, "additionalProperties", "Additional property '" + key + "' not allowed.", val);
                is_valid = false;
            }
        } else if (additional_props_def.is_object()) {
            SchemaValidator additional_validator(additional_props_def);
            Result sub_result;
            if (!additional_validator.validate(val, sub_result)) {
                for (const auto& err : sub_result.errors()) {
                    std::string new_path = prop_path;
                    if (!err.field_path.empty()) {
                        if (prop_path.length() > 0 && prop_path.back() == '.' && err.field_path.front() == '.') {
                             new_path += err.field_path.substr(1);
                        } else if (prop_path.length() > 0 && err.field_path.length() > 0 && prop_path.back() != '.' && err.field_path.front() != '.') {
                             new_path += ".";
                             new_path += err.field_path;
                        } else {
                            new_path += err.field_path;
                        }
                    }
                     result.add_error(new_path, err.rule_violated, err.message, err.offending_value);
                }
                is_valid = false;
            }
        } else {
             result.add_error(path, "schemaError.additionalProperties", "'additionalProperties' must be a boolean or a schema object.", additional_props_def);
             return false; 
        }
    }
    return is_valid;
}

bool SchemaValidator::validate_allOf_keyword(const qb::json& value, const qb::json& allOf_def, const std::string& path, Result& result) const {
    bool all_sub_schemas_passed = true;
    if (!allOf_def.is_array() || allOf_def.empty()) { 
        result.add_error(path, "schemaError.allOf", "'allOf' must be a non-empty array of schemas.", allOf_def);
        return false; 
    }

    for (size_t i = 0; i < allOf_def.size(); ++i) { 
        const auto& sub_schema = allOf_def[i];
        if (!sub_schema.is_object()) {
            result.add_error(path, "schemaError.allOf.item", "Items in 'allOf' array must be schema objects (at index " + std::to_string(i) + ").", sub_schema);
            all_sub_schemas_passed = false; 
            continue; 
        }
        if (!validate_recursive(value, sub_schema, path, result)) { 
            all_sub_schemas_passed = false;
        }
    }

    if (!all_sub_schemas_passed) {
         result.add_error(path, "allOf", "Value does not validate against all specified schemas.", value); 
         return false; 
    }
    return true;
}

bool SchemaValidator::validate_anyOf_keyword(const qb::json& value, const qb::json& anyOf_def, const std::string& path, Result& result) const {
    if (!anyOf_def.is_array() || anyOf_def.empty()) {
        result.add_error(path, "schemaError.anyOf", "'anyOf' must be a non-empty array of schemas.", anyOf_def);
        return false; 
    }
    
    for (const auto& sub_schema : anyOf_def) {
        Result temp_sub_result; // Each sub-schema validation gets a fresh Result
        if (validate_recursive(value, sub_schema, path, temp_sub_result)) {
            return true; // One passed, anyOf is satisfied. No errors added to main result from this anyOf check.
        }
    }

    // If we get here, no sub_schema passed. Add a general anyOf error to the main result.
    result.add_error(path, "anyOf", "Value does not validate against any of the specified schemas.", value);
    return false;
}

bool SchemaValidator::validate_oneOf_keyword(const qb::json& value, const qb::json& oneOf_def, const std::string& path, Result& result) const {
    if (!oneOf_def.is_array() || oneOf_def.empty()) {
        result.add_error(path, "schemaError.oneOf", "'oneOf' must be a non-empty array of schemas.", oneOf_def);
        return false; 
    }
    int S_VAL_P_151_S_1_E_151_S_1 = 0;
    for (const auto& sub_schema : oneOf_def) {
        if (!sub_schema.is_object()) {
            result.add_error(path, "schemaError.oneOf.item", "Items in 'oneOf' array must be schema objects.", sub_schema);
            continue;
        }
        Result temp_sub_result; // Fresh result for each sub-schema attempt
        if (validate_recursive(value, sub_schema, path, temp_sub_result)) {
            S_VAL_P_151_S_1_E_151_S_1++;
        }
    }
    if (S_VAL_P_151_S_1_E_151_S_1 == 1) {
        return true;
    }
    if (S_VAL_P_151_S_1_E_151_S_1 == 0) {
        result.add_error(path, "oneOf", "Value does not validate against exactly one of the specified schemas (matched 0).", value);
    } else {
        result.add_error(path, "oneOf", "Value validates against more than one of the specified schemas (matched " + std::to_string(S_VAL_P_151_S_1_E_151_S_1) + ").", value);
    }
    return false;
}

bool SchemaValidator::validate_not_keyword(const qb::json& value, const qb::json& not_def, const std::string& path, Result& result) const {
    if (!not_def.is_object()) {
        result.add_error(path, "schemaError.not", "'not' keyword must be a schema object.", not_def);
        return false; 
    }
    Result temp_sub_result; // Validate against the "not" schema with a temporary result
    if (validate_recursive(value, not_def, path, temp_sub_result)) {
        // If it *validates* against the not_def, then the "not" keyword fails.
        result.add_error(path, "not", "Value must not validate against the specified schema.", value);
        return false;
    }
    return true; // It did not validate against not_def, so "not" keyword passes.
}

} // namespace qb::http::validation 