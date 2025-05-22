/**
 * @file qbm/http/validation/error.h
 * @brief Defines classes and functions for HTTP validation error management.
 *
 * This file provides the `Error` class to represent individual validation errors,
 * the `Result` class for managing collections of validation errors, and utility
 * functions for parsing `Error` and `Result` headers according to RFC 6265.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Validaton
 */
#pragma once

#include <string>
#include <vector>
#include <optional>
#include <qb/json.h> // Added for qb::json in ValidationError

namespace qb::http::validation { // Changed namespace

/**
 * @brief Represents a single validation error.
 */
struct Error { // Renamed from ValidationError for brevity within namespace
    std::string field_path;      
    std::string rule_violated;   
    std::string message;         
    std::optional<qb::json> offending_value; 

    Error(std::string path, 
          std::string rule, 
          std::string msg, 
          std::optional<qb::json> value = std::nullopt)
        : field_path(std::move(path)), 
          rule_violated(std::move(rule)), 
          message(std::move(msg)), 
          offending_value(std::move(value)) {}
};

/**
 * @brief Stores the result of a validation process.
 */
class Result { // Renamed from ValidationResult
private:
    std::vector<Error> _errors;

public:
    Result() = default;

    /**
     * @brief Checks if the validation was successful (no errors).
     * @return True if no errors were recorded, false otherwise.
     */
    [[nodiscard]] bool success() const {
        return _errors.empty();
    }

    /**
     * @brief Retrieves all recorded validation errors.
     * @return A constant reference to the vector of errors.
     */
    [[nodiscard]] const std::vector<Error>& errors() const {
        return _errors;
    }

    /**
     * @brief Adds a new validation error.
     * @param field_path JSON pointer-like path to the field that failed validation.
     * @param rule_violated Name of the rule that was violated.
     * @param message Descriptive message for the error.
     * @param offending_value Optional qb::json value that caused the error.
     */
    void add_error(std::string field_path, 
                   std::string rule_violated, 
                   std::string message, 
                   std::optional<qb::json> offending_value = std::nullopt) {
        _errors.emplace_back(std::move(field_path), std::move(rule_violated), std::move(message), std::move(offending_value));
    }
    
    /**
     * @brief Adds a pre-constructed Error object.
     * @param validation_error The Error object to add.
     */
    void add_error(Error validation_error) {
        _errors.push_back(std::move(validation_error));
    }

    /**
     * @brief Clears all recorded validation errors.
     */
    void clear() {
        _errors.clear();
    }

    /**
     * @brief Merges errors from another Result object into this one.
     * @param other The Result object whose errors are to be merged.
     */
    void merge(const Result& other) {
        if (other._errors.empty()) return;
        _errors.insert(_errors.end(), other._errors.begin(), other._errors.end());
    }
};

} // namespace qb::http::validation 