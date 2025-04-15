#pragma once

#include <qb/json.h>
#include <functional>
#include <string>
#include <unordered_map>

#include "./validation_types.h"

namespace qb::http {

/**
 * @brief Sanitizer for cleaning user input
 * 
 * Applies sanitization rules to JSON data to clean user input.
 */
class Sanitizer {
public:
    /**
     * @brief Default constructor
     */
    Sanitizer() = default;
    
    /**
     * @brief Add a sanitization rule
     * @param field_path JSON pointer path to the field (e.g., "/name")
     * @param sanitizer Sanitizer function
     */
    void add_rule(const std::string& field_path, SanitizerFunc sanitizer);
    
    /**
     * @brief Add a sanitization rule with a predefined sanitizer
     * @param field_path JSON pointer path to the field
     * @param sanitizer_name Name of the predefined sanitizer
     */
    void add_rule(const std::string& field_path, const std::string& sanitizer_name);
    
    /**
     * @brief Sanitize a JSON value in-place
     * @param json JSON value to sanitize
     */
    void sanitize(qb::json& json) const;
    
    /**
     * @brief Get a predefined sanitizer by name
     * @param name Sanitizer name
     * @return Sanitizer function or nullptr if not found
     */
    [[nodiscard]] static SanitizerFunc get_predefined_sanitizer(const std::string& name);
    
private:
    std::unordered_map<std::string, SanitizerFunc> _rules;
    
    /**
     * @brief Apply a sanitizer to a JSON value at the specified path
     * @param json JSON value to sanitize
     * @param path JSON pointer path
     * @param sanitizer Sanitizer function
     */
    static void apply_sanitizer(qb::json& json, const std::string& path, 
                              const SanitizerFunc& sanitizer);
    
    /**
     * @brief Get a JSON value at the specified path
     * @param json JSON value to search in
     * @param path JSON pointer path
     * @return Reference to the value at the path, or null if not found
     */
    static qb::json& get_json_at_path(qb::json& json, const std::string& path);
};

} // namespace qb::http 