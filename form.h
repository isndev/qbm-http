#pragma once

#include <string>
#include <vector>
#include <optional> // For std::optional in get_first
#include <string_view> // If Form methods accept string_view, else not strictly needed here
#include <qb/system/container/unordered_map.h>

namespace qb::http {

/**
 * @brief Represents x-www-form-urlencoded data
 *
 * This class stores key-value pairs from a URL-encoded form.
 * Keys can have multiple values.
 */
class Form {
    qb::unordered_map<std::string, std::vector<std::string>> _fields;

public:
    Form() = default;

    /**
     * @brief Add a field to the form
     * @param key The field name
     * @param value The field value
     */
    void add(const std::string& key, const std::string& value) {
        _fields[key].push_back(value);
    }
    // Overload for string_view if desired for efficiency, e.g.:
    // void add(std::string_view key, std::string_view value) {
    //     _fields[std::string(key)].push_back(std::string(value));
    // }

    /**
     * @brief Get values for a specific key
     * @param key The field name
     * @return A vector of string values, or an empty vector if key not found
     */
    [[nodiscard]] std::vector<std::string> get(const std::string& key) const {
        auto it = _fields.find(key);
        if (it != _fields.end()) {
            return it->second;
        }
        return {};
    }

    /**
     * @brief Get the first value for a specific key
     * @param key The field name
     * @return An optional string value
     */
    [[nodiscard]] std::optional<std::string> get_first(const std::string& key) const {
        auto it = _fields.find(key);
        if (it != _fields.end() && !it->second.empty()) {
            return it->second.front();
        }
        return std::nullopt;
    }

    /**
     * @brief Get all fields
     * @return A map of all fields
     */
    [[nodiscard]] const qb::unordered_map<std::string, std::vector<std::string>>& fields() const {
        return _fields;
    }

    /**
     * @brief Clear all fields
     */
    void clear() {
        _fields.clear();
    }

    /**
     * @brief Check if the form is empty
     * @return true if the form has no fields, false otherwise
     */
    [[nodiscard]] bool empty() const {
        return _fields.empty();
    }
};
using form = Form;

} // namespace qb::http 