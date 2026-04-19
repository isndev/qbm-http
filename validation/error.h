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

namespace qb::http::validation {
    // Changed namespace

    /**
     * @brief Represents a single validation error.
     */
    struct Error {
        // Renamed from ValidationError for brevity within namespace
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
              offending_value(std::move(value)) {
        }
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
        ErrorValuePolicy _policy{ErrorValuePolicy::Full};
        std::size_t _preview_bytes{256};

    public:
        Result() = default;

        /**
         * @brief Configure how subsequent `add_error(...)` invocations capture
         *        their offending value payload (F48).
         */
        Result &set_error_value_policy(ErrorValuePolicy policy,
                                       std::size_t preview_bytes = 256) noexcept {
            constexpr std::size_t kMinPreview = 16;
            constexpr std::size_t kMaxPreview = 64 * 1024;
            if (preview_bytes < kMinPreview) preview_bytes = kMinPreview;
            if (preview_bytes > kMaxPreview) preview_bytes = kMaxPreview;
            _policy = policy;
            _preview_bytes = preview_bytes;
            return *this;
        }

        [[nodiscard]] ErrorValuePolicy error_value_policy() const noexcept { return _policy; }

        [[nodiscard]] std::size_t offending_value_preview_bytes() const noexcept {
            return _preview_bytes;
        }

        /**
         * @brief Checks if the validation was successful (no errors).
         */
        [[nodiscard]] bool success() const { return _errors.empty(); }

        /**
         * @brief Retrieves all recorded validation errors.
         */
        [[nodiscard]] const std::vector<Error> &errors() const { return _errors; }

        /**
         * @brief Appends a validation error, applying the active error-value
         *        policy to the supplied `offending_value`.
         */
        void add_error(std::string field_path,
                       std::string rule_violated,
                       std::string message,
                       std::optional<qb::json> offending_value = std::nullopt) {
            _errors.emplace_back(std::move(field_path), std::move(rule_violated),
                                 std::move(message), apply_policy(std::move(offending_value)));
        }

        /**
         * @brief Appends a pre-constructed Error object without touching its
         *        `offending_value`. Use this when the caller has already
         *        shaped the payload explicitly.
         */
        void add_error(Error validation_error) {
            _errors.push_back(std::move(validation_error));
        }

        /**
         * @brief Clears all recorded validation errors (keeps the policy).
         */
        void clear() { _errors.clear(); }

        /**
         * @brief Merges errors from another Result object into this one.
         *        The other result's policy is irrelevant here; we copy the
         *        already-shaped errors verbatim.
         */
        void merge(const Result &other) {
            if (other._errors.empty()) return;
            _errors.insert(_errors.end(), other._errors.begin(), other._errors.end());
        }

        /**
         * @brief Create an empty `Result` that inherits this result's
         *        error-value policy. Useful for sub-validations whose errors
         *        will later be merged back into the parent `Result`.
         */
        [[nodiscard]] Result make_child() const {
            Result r;
            r._policy = _policy;
            r._preview_bytes = _preview_bytes;
            return r;
        }

    private:
        [[nodiscard]] std::optional<qb::json>
        apply_policy(std::optional<qb::json> value) const {
            if (!value.has_value() || _policy == ErrorValuePolicy::Full) {
                return value;
            }
            if (_policy == ErrorValuePolicy::None) {
                return std::nullopt;
            }
            // Preview: cheap kinds pass through, compound kinds are truncated.
            const qb::json &v = *value;
            if (v.is_null() || v.is_boolean() || v.is_number()) {
                return value;
            }
            if (v.is_string()) {
                const auto &s = v.get_ref<const std::string &>();
                if (s.size() <= _preview_bytes) return value;
                return qb::json(s.substr(0, _preview_bytes));
            }
            std::string dumped = v.dump();
            if (dumped.size() <= _preview_bytes) return value;
            dumped.resize(_preview_bytes);
            return qb::json{{"_truncated", true},
                            {"preview", std::move(dumped)},
                            {"original_kind", v.type_name()}};
        }
    };
} // namespace qb::http::validation 
