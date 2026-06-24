/**
 * @file qbm/http/validation/schema_validator.h
 * @brief Defines the SchemaValidator class for validating HTTP requests.
 *
 * This file contains the definition of the SchemaValidator class,
 * which is used to validate HTTP requests according to the schema defined
 * in the RequestValidator.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Validaton
 */
#pragma once

#include <memory>
#include <string>
#include <unordered_map> // Node-based map: stable references to cached rule vectors (see member note).
#include <vector>
#include <qb/json.h>
#include "./error.h"
#include "./rule.h"

namespace qb::http::validation {
/**
 * @brief Validates qb::json data against a JSON Schema definition.
 *
 * This class implements a subset of JSON Schema keywords to perform validation.
 * It supports type checking, primitive rules (e.g., minLength, maximum),
 * structural rules for objects (properties, required, additionalProperties, propertyNames),
 * structural rules for arrays (items, additionalItems), and logical combinators (allOf, anyOf, oneOf, not).
 */
class SchemaValidator {
public:
    /**
     * @brief Policy controlling how much of the offending value is copied
     *        into each `Error` record (F48).
     *
     * A single failed validation can produce a long chain of `Error`
     * records, each carrying a `std::optional<qb::json>` captured at the
     * failure site. For deep schemas, copying the full subtree per error
     * dominates the validator's allocation profile. This enum lets the
     * caller trade debug detail for memory:
     *   - `Full`    &mdash; capture the offending subtree verbatim (legacy
     *                  behaviour, kept as default for back-compat).
     *   - `Preview` &mdash; store a serialised preview truncated to
     *                  `max_offending_value_bytes`. Useful in production
     *                  where error logs are forwarded to external systems
     *                  with strict payload budgets.
     *   - `None`    &mdash; omit the value entirely; the error still
     *                  carries `field_path` (JSON-pointer-ish) that the
     *                  caller can use to resolve the value lazily from the
     *                  original document.
     */
    enum class ErrorValuePolicy { Full, Preview, None };

    /**
     * @brief Constructs a SchemaValidator with a given JSON schema definition.
     * @param schema_definition The qb::json object representing the root schema.
     * @throws std::invalid_argument if the schema_definition is not a JSON object.
     */
    explicit SchemaValidator(const qb::json &schema_definition);

    /**
     * @brief Validates qb::json data against the schema this validator was constructed with.
     * @param data_to_validate The qb::json data to be validated.
     * @param result A Result object that will be populated with any validation errors.
     * @return True if the data is valid according to the schema, false otherwise.
     */
    bool validate(const qb::json &data_to_validate, Result &result) const;

    /**
     * @brief Configure how offending values are stored in `Error` records (F48).
     *
     * @param policy       One of `Full`, `Preview`, `None`.
     * @param preview_bytes Cap (in bytes of the `dump()` output) used when
     *                     `policy == Preview`. Ignored otherwise. Defaults
     *                     to 256 which comfortably fits a log line.
     */
    SchemaValidator &set_error_value_policy(ErrorValuePolicy policy, std::size_t preview_bytes = 256) noexcept;

    [[nodiscard]] ErrorValuePolicy
    error_value_policy() const noexcept {
        return _error_value_policy;
    }

    [[nodiscard]] std::size_t
    offending_value_preview_bytes() const noexcept {
        return _offending_value_preview_bytes;
    }

    /**
     * @brief Builds an `offending_value` payload respecting the active
     *        policy. Exposed publicly so that external rule implementations
     *        can honour the same policy.
     */
    [[nodiscard]] std::optional<qb::json> make_offending_value(const qb::json &value) const;

private:
    qb::json _schema_definition; // Store a copy of the schema definition.

    // Recursive validation helper function.
    bool validate_recursive(const qb::json &current_value, const qb::json &current_schema, const std::string &current_path,
                            Result &result) const;

    // Keyword-specific validation methods.
    bool validate_type_keyword(const qb::json &value, const qb::json &schema_type_def, const std::string &path, Result &result) const;

    bool validate_properties_keyword(const qb::json &value, const qb::json &properties_def, const std::string &path, Result &result) const;

    bool validate_required_keyword(const qb::json &value, const qb::json &required_def, const std::string &path, Result &result) const;

    bool validate_items_keyword(const qb::json &value, const qb::json &schema_node, const std::string &path, Result &result) const;

    bool validate_additional_properties_keyword(const qb::json &value, const qb::json &schema_node, const std::string &path,
                                                Result &result) const;

    // Note: propertyNames is handled by a PropertyNamesRule which calls back to SchemaValidator.

    // Applies rules that are not structural or type-based (e.g., minLength, maximum).
    bool apply_primitive_rules(const qb::json &value, const qb::json &schema_node, const std::string &path, Result &result) const;

    // Logical combinator validation methods.
    bool validate_allOf_keyword(const qb::json &value, const qb::json &allOf_def, const std::string &path, Result &result) const;

    bool validate_anyOf_keyword(const qb::json &value, const qb::json &anyOf_def, const std::string &path, Result &result) const;

    bool validate_oneOf_keyword(const qb::json &value, const qb::json &oneOf_def, const std::string &path, Result &result) const;

    bool validate_not_keyword(const qb::json &value, const qb::json &not_def, const std::string &path, Result &result) const;

    // Helper to create a list of IRule objects based on keywords in a schema node.
    // The returned vector is cached per schema-node pointer so we only pay the
    // compilation cost once per route (F46). Callers must not keep the reference
    // past the validator's lifetime.
    const std::vector<std::shared_ptr<IRule>> &rules_for_schema_node(const qb::json &schema_node) const;

    static std::vector<std::shared_ptr<IRule>> build_rules_for_schema_node(const qb::json &schema_node);

    /// Cache of pre-compiled rule lists keyed by schema-node pointer.
    /// `_schema_definition` is stored by value and never mutated after
    /// construction, which keeps those pointers stable for the full lifetime
    /// of the validator. Deliberately `std::unordered_map` (not `qb::unordered_map`):
    /// node-based layout preserves references to mapped `vector`s across rehash;
    /// `rules_for_schema_node` returns those references into recursion.
    mutable std::unordered_map<const qb::json *, std::vector<std::shared_ptr<IRule>>> _rules_cache;

    /// F48 &mdash; offending-value policy. Default is `Full` (legacy).
    ErrorValuePolicy _error_value_policy{ErrorValuePolicy::Full};
    std::size_t      _offending_value_preview_bytes{256};
};
} // namespace qb::http::validation
