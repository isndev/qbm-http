#include "./sanitizer.h"
#include <algorithm> 
#include <cctype>    
#include <regex>   

namespace qb::http::validation { // Changed namespace

void Sanitizer::add_rule(const std::string& field_path, SanitizerFunction func) {
    if (func) {
        _rules[field_path].push_back(std::move(func));
    }
}

// Helper to split path string like "user.address.street" or "user.tags[*]" or "user.tags[0]"
static std::vector<std::string> split_path_for_sanitizer(const std::string& path) {
    std::vector<std::string> parts;
    std::string current_part;
    bool in_bracket = false;
    for (char ch : path) {
        if (ch == '.' && !in_bracket) {
            if (!current_part.empty()) parts.push_back(current_part);
            current_part.clear();
        } else if (ch == '[') {
            if (!current_part.empty()) parts.push_back(current_part);
            current_part.clear();
            in_bracket = true;
        } else if (ch == ']' && in_bracket) {
            if (!current_part.empty()) parts.push_back(current_part);
            current_part.clear();
            in_bracket = false;
        } else {
            current_part += ch;
        }
    }
    if (!current_part.empty()) parts.push_back(current_part);
    return parts;
}

void Sanitizer::apply_sanitizers_to_node(qb::json& node, const std::vector<SanitizerFunction>& funcs) const {
    if (node.is_string()) {
        std::string val = node.get<std::string>();
        for (const auto& func : funcs) {
            val = func(val);
        }
        node = val;
    }
}

void Sanitizer::traverse_and_apply(qb::json& current_node, const std::vector<std::string>& path_segments, size_t segment_idx, const std::vector<SanitizerFunction>& funcs_to_apply) const {
    if (segment_idx >= path_segments.size()) { // Path exhausted, apply to current node
        apply_sanitizers_to_node(current_node, funcs_to_apply);
        return;
    }

    const std::string& segment = path_segments[segment_idx];

    if (current_node.is_object() && current_node.contains(segment)) {
        traverse_and_apply(current_node[segment], path_segments, segment_idx + 1, funcs_to_apply);
    } else if (current_node.is_array()) {
        if (segment == "*") { // Wildcard for all array elements
            for (auto& item : current_node) {
                traverse_and_apply(item, path_segments, segment_idx + 1, funcs_to_apply);
            }
        } else {
            try {
                size_t index = std::stoul(segment);
                if (index < current_node.size()) {
                    traverse_and_apply(current_node[index], path_segments, segment_idx + 1, funcs_to_apply);
                }
            } catch (const std::invalid_argument&) { /* Not a number, not an index */ }
              catch (const std::out_of_range&) { /* Number too large for size_t */ }
        }
    }
}

void Sanitizer::sanitize(qb::json& data) const {
    for (const auto& [path_key, funcs_to_apply] : _rules) {
        if (funcs_to_apply.empty()) continue;
        std::vector<std::string> path_segments = split_path_for_sanitizer(path_key);
        if (!path_segments.empty()) {
            traverse_and_apply(data, path_segments, 0, funcs_to_apply);
        }
    }
}

namespace PredefinedSanitizers {

SanitizerFunction trim() {
    return [](const std::string& input) -> std::string {
        // Find the first non-whitespace character
        auto first_char = std::find_if_not(input.begin(), input.end(), [](unsigned char c){ return std::isspace(c); });
        // If the string is all whitespace, return an empty string
        if (first_char == input.end()) {
            return "";
        }
        // Find the last non-whitespace character
        auto last_char = std::find_if_not(input.rbegin(), input.rend(), [](unsigned char c){ return std::isspace(c); }).base();
        return std::string(first_char, last_char);
    };
}

SanitizerFunction to_lower_case() {
    return [](const std::string& input) -> std::string {
        std::string output = input;
        std::transform(output.begin(), output.end(), output.begin(), [](unsigned char c){ return std::tolower(c); });
        return output;
    };
}

SanitizerFunction to_upper_case() {
    return [](const std::string& input) -> std::string {
        std::string output = input;
        std::transform(output.begin(), output.end(), output.begin(), [](unsigned char c){ return std::toupper(c); });
        return output;
    };
}

SanitizerFunction escape_html() {
    return [](const std::string& input) -> std::string {
        std::string buffer;
        buffer.reserve(input.size()); // Avoid multiple reallocations
        for(char c : input) {
            switch(c) {
                case '&':  buffer.append("&amp;");       break;
                case '<':  buffer.append("&lt;");        break;
                case '>':  buffer.append("&gt;");        break;
                case '\"': buffer.append("&quot;");      break;
                case '\'': buffer.append("&#39;");       break; 
                default:   buffer.push_back(c);            break;
            }
        }
        return buffer;
    };
}

SanitizerFunction strip_html_tags() {
    return [](const std::string& input) -> std::string {
        // Basic regex to remove anything that looks like a tag. 
        // For robust HTML sanitization, a proper HTML parser would be better, but this is common for simple stripping.
        static const std::regex html_tags_regex("<[^>]*>", std::regex_constants::ECMAScript | std::regex_constants::icase);
        return std::regex_replace(input, html_tags_regex, "");
    };
}

SanitizerFunction alphanumeric_only() {
    return [](const std::string& input) -> std::string {
        std::string output;
        output.reserve(input.length());
        for(char c : input) {
            if(std::isalnum(static_cast<unsigned char>(c))) {
                output += c;
            }
        }
        return output;
    };
}

SanitizerFunction normalize_whitespace() {
    return [](const std::string& input) -> std::string {
        std::string trimmed = trim()(input); // First, trim leading/trailing whitespace
        if (trimmed.empty()) return "";

        std::string output;
        output.reserve(trimmed.length());
        bool last_was_space = false;
        for (char c : trimmed) {
            if (std::isspace(static_cast<unsigned char>(c))) {
                if (!last_was_space) {
                    output += ' '; // Replace multiple spaces with a single space
                    last_was_space = true;
                }
            } else {
                output += c;
                last_was_space = false;
            }
        }
        // The trim() at the beginning handles potential trailing space from this logic, but a final check can be done too.
        // However, the initial trim should make it unnecessary.
        return output;
    };
}

SanitizerFunction escape_sql_like() {
    // Basic escaping for SQL LIKE wildcards and single quotes.
    // IMPORTANT: This is NOT a comprehensive SQL injection prevention method.
    // Always use parameterized queries or a proper SQL escaping library for database interactions.
    return [](const std::string& input) -> std::string {
        std::string output = input;
        // Escape LIKE wildcards % and _
        std::string temp_wildcards;
        temp_wildcards.reserve(output.length());
        for(char c : output) {
            if (c == '%' || c == '_') {
                temp_wildcards += '\\'; // Prepend backslash for typical SQL LIKE escaping
            }
            temp_wildcards += c;
        }
        output = temp_wildcards;

        // Escape single quotes by doubling them ''
        std::string temp_quotes;
        temp_quotes.reserve(output.length()); 
        for(char c : output) {
            if (c == '\'') {
                temp_quotes += "''";
            } else {
                temp_quotes += c;
            }
        }
        return temp_quotes;
    };
}

} // namespace PredefinedSanitizers

} // namespace qb::http::validation 