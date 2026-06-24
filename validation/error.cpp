/**
 * @file qbm/http/validation/error.cpp
 * @brief Out-of-line definitions for HTTP validation error management.
 *
 * Implements the non-trivial `Result` members declared in `error.h`:
 * policy configuration, error appending under the active capture policy,
 * merging, child creation, and the offending-value policy application.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "error.h"

namespace qb::http::validation {

Result &
Result::set_error_value_policy(ErrorValuePolicy policy, std::size_t preview_bytes) noexcept {
    constexpr std::size_t kMinPreview = 16;
    constexpr std::size_t kMaxPreview = 64 * 1024;
    if (preview_bytes < kMinPreview)
        preview_bytes = kMinPreview;
    if (preview_bytes > kMaxPreview)
        preview_bytes = kMaxPreview;
    _policy        = policy;
    _preview_bytes = preview_bytes;
    return *this;
}

void
Result::add_error(std::string field_path, std::string rule_violated, std::string message, std::optional<qb::json> offending_value) {
    _errors.emplace_back(std::move(field_path), std::move(rule_violated), std::move(message), apply_policy(std::move(offending_value)));
}

void
Result::merge(const Result &other) {
    if (other._errors.empty())
        return;
    _errors.insert(_errors.end(), other._errors.begin(), other._errors.end());
}

Result
Result::make_child() const {
    Result r;
    r._policy        = _policy;
    r._preview_bytes = _preview_bytes;
    return r;
}

std::optional<qb::json>
Result::apply_policy(std::optional<qb::json> value) const {
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
        if (s.size() <= _preview_bytes)
            return value;
        return qb::json(s.substr(0, _preview_bytes));
    }
    std::string dumped = v.dump();
    if (dumped.size() <= _preview_bytes)
        return value;
    dumped.resize(_preview_bytes);
    return qb::json{{"_truncated", true}, {"preview", std::move(dumped)}, {"original_kind", v.type_name()}};
}

} // namespace qb::http::validation
