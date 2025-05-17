#pragma once

#include <string>
#include <vector>
#include <functional>
#include <map> // Not strictly needed by this header anymore, qb::unordered_map is used in .cpp
#include <qb/json.h>
#include <qb/system/container/unordered_map.h> // For _rules member

namespace qb::http::validation {

/**
 * @brief Defines a function that takes a string input and returns a sanitized string.
 */
using SanitizerFunction = std::function<std::string(const std::string& input)>;

/**
 * @brief Manages and applies sanitization rules to qb::json data or string values.
 *
 * Sanitizers can be applied to specific fields within a JSON structure,
 * identified by a JSON pointer-like path (e.g., "user.address.street", "tags[*]", "items[0].name").
 * When used with RequestValidator for query/header parameters, paths are typically simple names.
 */
class Sanitizer {
public:
    Sanitizer() = default;

    /**
     * @brief Adds a sanitization rule for a specific field path.
     * @param field_path A JSON pointer-like path string. For arrays, `[*]` denotes all elements,
     *                   and `[N]` denotes a specific index.
     * @param func The SanitizerFunction to apply to the field(s) found at the path.
     */
    void add_rule(const std::string& field_path, SanitizerFunction func);

    /**
     * @brief Applies all registered sanitization rules to the provided qb::json data.
     * @param data The qb::json object to sanitize. It will be modified in place.
     */
    void sanitize(qb::json& data) const;

private:
    // Stores sanitization functions mapped by field path.
    qb::unordered_map<std::string, std::vector<SanitizerFunction>> _rules;

    // Applies a list of sanitizer functions to a single qb::json node if it's a string.
    void apply_sanitizers_to_node(qb::json& node, const std::vector<SanitizerFunction>& funcs) const;
    
    // Recursively traverses the qb::json data according to path segments to find nodes for sanitization.
    void traverse_and_apply(qb::json& current_node, 
                              const std::vector<std::string>& path_segments, 
                              size_t segment_idx, 
                              const std::vector<SanitizerFunction>& funcs_to_apply) const;
};

/**
 * @brief Provides a collection of common, predefined sanitizer functions.
 */
namespace PredefinedSanitizers {
    /** @brief Trims leading and trailing whitespace. */
    SanitizerFunction trim();
    /** @brief Converts string to lower case. */
    SanitizerFunction to_lower_case();
    /** @brief Converts string to upper case. */
    SanitizerFunction to_upper_case();
    /** @brief Escapes HTML special characters (&, <, >, ", '). */
    SanitizerFunction escape_html();
    /** @brief Strips HTML tags from a string. (Basic, not for security use against XSS). */
    SanitizerFunction strip_html_tags();
    /** @brief Removes all non-alphanumeric characters. */
    SanitizerFunction alphanumeric_only();
    /** @brief Normalizes whitespace: trims ends, collapses multiple internal spaces to one. */
    SanitizerFunction normalize_whitespace();
    /** @brief Escapes SQL LIKE wildcards (%, _) and single quotes ('). (NOT for general SQL injection prevention). */
    SanitizerFunction escape_sql_like(); 
} 

} // namespace qb::http::validation 