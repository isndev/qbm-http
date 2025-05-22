/**
 * @file qbm/http/form.h
 * @brief Defines the Form class for handling URL-encoded form data.
 *
 * This file contains the `Form` class, designed to parse, store, and provide
 * access to data submitted in `application/x-www-form-urlencoded` format,
 * commonly used in HTTP POST requests from HTML forms.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <string>
#include <vector>
#include <optional>    // For std::optional
#include <utility>     // For std::move
#include <qb/system/container/unordered_map.h> // For qb::unordered_map

namespace qb::http {

/**
 * @brief Represents `x-www-form-urlencoded` data.
 *
 * This class stores key-value pairs parsed from a URL-encoded form string.
 * It supports multiple values for a single key, storing them as a vector of strings.
 * Field names (keys) are case-sensitive.
 */
class Form {
    /** @brief Internal storage for form fields. Maps a field name to a vector of its values. */
    qb::unordered_map<std::string, std::vector<std::string>> _fields;

public:
    /**
     * @brief Default constructor. Creates an empty Form object.
     */
    Form() = default;

    /**
     * @brief Adds a field (key-value pair) to the form.
     *
     * If the key already exists, the new value is appended to the list of existing values for that key.
     * @param key The field name (key). An lvalue reference to a string.
     * @param value The field value. An lvalue reference to a string.
     */
    void add(const std::string& key, const std::string& value) {
        _fields[key].push_back(value);
    }

    /**
     * @brief Adds a field (key-value pair) to the form using move semantics.
     *
     * If the key already exists, the new value is appended to the list of existing values for that key.
     * This overload is efficient when `key` and `value` are rvalues (e.g., temporary strings).
     * @param key The field name (key). An rvalue reference, will be moved.
     * @param value The field value. An rvalue reference, will be moved.
     */
    void add(std::string&& key, std::string&& value) {
        _fields[std::move(key)].push_back(std::move(value));
    }

    /**
     * @brief Retrieves all values associated with a specific key.
     * @param key The field name (key) for which to retrieve values.
     * @return A `std::vector<std::string>` containing all values for the key.
     *         If the key is not found, an empty vector is returned.
     */
    [[nodiscard]] std::vector<std::string> get(const std::string& key) const {
        auto it = _fields.find(key);
        if (it != _fields.end()) {
            return it->second; // Returns a copy of the vector
        }
        return {}; // Return empty vector if key not found
    }

    /**
     * @brief Retrieves the first value associated with a specific key.
     * @param key The field name (key) for which to retrieve the first value.
     * @return An `std::optional<std::string>` containing the first value if the key exists
     *         and has at least one value. Otherwise, returns `std::nullopt`.
     */
    [[nodiscard]] std::optional<std::string> get_first(const std::string& key) const {
        auto it = _fields.find(key);
        if (it != _fields.end() && !it->second.empty()) {
            return it->second.front(); // Returns a copy of the first string value
        }
        return std::nullopt;
    }

    /**
     * @brief Provides access to all fields stored in the form.
     * @return A constant reference to the underlying map storing all form fields and their values.
     */
    [[nodiscard]] const qb::unordered_map<std::string, std::vector<std::string>>& fields() const noexcept {
        return _fields;
    }

    /**
     * @brief Removes all fields from the form, making it empty.
     */
    void clear() noexcept {
        _fields.clear();
    }

    /**
     * @brief Checks if the form contains any fields.
     * @return `true` if the form has no fields, `false` otherwise.
     */
    [[nodiscard]] bool empty() const noexcept {
        return _fields.empty();
    }
};

/**
 * @brief Alias for `qb::http::Form`.
 *
 * Provides a convenient shorthand for the `Form` class.
 */
using form = Form;

} // namespace qb::http 