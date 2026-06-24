/**
 * @file qbm/http/validation/error.h
 * @brief Defines classes and functions for HTTP validation error management.
 *
 * This file provides the `Error` class to represent individual validation errors
 * and the `Result` class for managing collections of validation errors together
 * with an `ErrorValuePolicy` that controls how the offending value of each error
 * is captured.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <optional>
#include <string>
#include <vector>
#include <qb/json.h> // Added for qb::json in ValidationError

namespace qb::http::validation {
// Changed namespace

/**
 * @brief Represents a single validation error.
 */
struct Error {
    // Renamed from ValidationError for brevity within namespace
    std::string             field_path;
    std::string             rule_violated;
    std::string             message;
    std::optional<qb::json> offending_value;

    /**
     * @brief Constructs a validation error.
     * @param path  Dotted path of the field that failed validation.
     * @param rule  Identifier of the rule that was violated.
     * @param msg   Human-readable description of the violation.
     * @param value Optional offending value associated with the error.
     */
    Error(std::string path, std::string rule, std::string msg, std::optional<qb::json> value = std::nullopt)
        : field_path(std::move(path))
        , rule_violated(std::move(rule))
        , message(std::move(msg))
        , offending_value(std::move(value)) {}
};

/**
 * @brief Stores the result of a validation process.
 *
 * F48 &mdash; the `Result` owns an `ErrorValuePolicy` which applies to
 * every `Error` appended through `add_error(field, rule, message, value)`.
 * Rules and validators should use that overload; pre-constructed `Error`
 * objects passed to `add_error(Error)` are trusted as-is so the caller can
 * opt out of the policy when they really want the full payload (e.g. a
 * synthetic "root schema" error).
 */
class Result {
public:
    /**
     * @brief Controls how the `offending_value` of each appended `Error`
     *        is captured.
     *  - `Full`    : deep-copy the value (legacy behaviour).
     *  - `Preview` : serialise and truncate to `preview_bytes`.
     *  - `None`    : omit the value entirely; the `field_path` remains the
     *                only way to locate the offending data.
     */
    enum class ErrorValuePolicy { Full, Preview, None };

private:
    std::vector<Error> _errors;
    ErrorValuePolicy   _policy{ErrorValuePolicy::Full};
    std::size_t        _preview_bytes{256};

public:
    Result() = default;

    /**
     * @brief Configure how subsequent `add_error(...)` invocations capture
     *        their offending value payload (F48).
     * @param policy        Capture policy to apply to future errors.
     * @param preview_bytes Maximum byte budget for `Preview` mode; clamped to
     *                      the inclusive range [16, 65536].
     * @return Reference to this `Result` for chaining.
     */
    Result &set_error_value_policy(ErrorValuePolicy policy, std::size_t preview_bytes = 256) noexcept;

    /**
     * @brief Returns the active error-value capture policy.
     */
    [[nodiscard]] ErrorValuePolicy
    error_value_policy() const noexcept {
        return _policy;
    }

    /**
     * @brief Returns the byte budget used by `Preview` capture mode.
     */
    [[nodiscard]] std::size_t
    offending_value_preview_bytes() const noexcept {
        return _preview_bytes;
    }

    /**
     * @brief Checks if the validation was successful (no errors).
     */
    [[nodiscard]] bool
    success() const {
        return _errors.empty();
    }

    /**
     * @brief Retrieves all recorded validation errors.
     */
    [[nodiscard]] const std::vector<Error> &
    errors() const {
        return _errors;
    }

    /**
     * @brief Appends a validation error, applying the active error-value
     *        policy to the supplied `offending_value`.
     * @param field_path      Dotted path of the field that failed validation.
     * @param rule_violated   Identifier of the rule that was violated.
     * @param message         Human-readable description of the violation.
     * @param offending_value Optional offending value, shaped by the active policy.
     */
    void add_error(std::string field_path, std::string rule_violated, std::string message,
                   std::optional<qb::json> offending_value = std::nullopt);

    /**
     * @brief Appends a pre-constructed Error object without touching its
     *        `offending_value`. Use this when the caller has already
     *        shaped the payload explicitly.
     */
    void
    add_error(Error validation_error) {
        _errors.push_back(std::move(validation_error));
    }

    /**
     * @brief Clears all recorded validation errors (keeps the policy).
     */
    void
    clear() {
        _errors.clear();
    }

    /**
     * @brief Merges errors from another Result object into this one.
     *        The other result's policy is irrelevant here; we copy the
     *        already-shaped errors verbatim.
     * @param other Source result whose errors are appended to this one.
     */
    void merge(const Result &other);

    /**
     * @brief Create an empty `Result` that inherits this result's
     *        error-value policy. Useful for sub-validations whose errors
     *        will later be merged back into the parent `Result`.
     * @return A fresh empty `Result` carrying this result's policy settings.
     */
    [[nodiscard]] Result make_child() const;

private:
    /**
     * @brief Applies the active capture policy to a candidate offending value.
     * @param value Candidate offending value.
     * @return The value shaped according to the active policy (full, previewed,
     *         or omitted).
     */
    [[nodiscard]] std::optional<qb::json> apply_policy(std::optional<qb::json> value) const;
};
} // namespace qb::http::validation
