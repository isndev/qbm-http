#include "sanitizer.h"
#include <algorithm>
#include <regex>
#include <string>
#include <unordered_map>

#include "validation_types.h"

namespace qb::http {

void Sanitizer::add_rule(const std::string& field_path, SanitizerFunc sanitizer) {
    _rules[field_path] = std::move(sanitizer);
}

void Sanitizer::add_rule(const std::string& field_path, const std::string& sanitizer_name) {
    auto sanitizer = get_predefined_sanitizer(sanitizer_name);
    if (sanitizer) {
        _rules[field_path] = sanitizer;
    }
}

void Sanitizer::sanitize(qb::json& json) const {
    for (const auto& [path, sanitizer] : _rules) {
        apply_sanitizer(json, path, sanitizer);
    }
}

SanitizerFunc Sanitizer::get_predefined_sanitizer(const std::string& name) {
    if (name == "trim") {
        return CommonSanitizers::trim;
    } else if (name == "to_lower") {
        return CommonSanitizers::to_lower;
    } else if (name == "to_upper") {
        return CommonSanitizers::to_upper;
    } else if (name == "escape_html") {
        return CommonSanitizers::escape_html;
    } else if (name == "strip_html") {
        return CommonSanitizers::strip_html;
    } else if (name == "alphanumeric_only") {
        return CommonSanitizers::alphanumeric_only;
    }
    return nullptr;
}

void Sanitizer::apply_sanitizer(qb::json& json, const std::string& path, const SanitizerFunc& sanitizer) {
    auto& value = get_json_at_path(json, path);
    if (value.is_string()) {
        std::string sanitized = sanitizer(value.get<std::string>());
        value = sanitized;
    } else if (value.is_array()) {
        for (auto& item : value) {
            if (item.is_string()) {
                std::string sanitized = sanitizer(item.get<std::string>());
                item = sanitized;
            }
        }
    }
}

qb::json& Sanitizer::get_json_at_path(qb::json& json, const std::string& path) {
    if (path.empty() || path == "/") {
        return json;
    }

    std::string current_path = path;
    if (current_path[0] == '/') {
        current_path = current_path.substr(1);
    }

    size_t pos = current_path.find('/');
    std::string key = (pos != std::string::npos) ? current_path.substr(0, pos) : current_path;
    std::string remaining = (pos != std::string::npos) ? current_path.substr(pos) : "";

    if (remaining.empty()) {
        if (json.contains(key)) {
            return json[key];
        } else {
            return json; // Return root if path not found
        }
    } else {
        if (json.contains(key) && (json[key].is_object() || json[key].is_array())) {
            return get_json_at_path(json[key], remaining);
        } else {
            return json; // Return root if path not found
        }
    }
}

} // namespace qb::http::validation 