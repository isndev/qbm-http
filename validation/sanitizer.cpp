/**
 * @file qbm/http/validation/sanitizer.cpp
 * @brief Implementation of the Sanitizer class and predefined sanitization functions.
 *
 * This file provides the method definitions for the `Sanitizer` class, which is responsible
 * for applying registered sanitization rules to `qb::json` data. It also contains the
 * implementations for common sanitization routines provided in the `PredefinedSanitizers` namespace,
 * such as trimming whitespace, escaping HTML, case conversion, and basic tag stripping.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Validaton
 */
#include "./sanitizer.h"
#include <algorithm>
#include <cctype>
#include <regex>

namespace qb::http::validation {
    // Changed namespace

    void Sanitizer::add_rule(const std::string &field_path, SanitizerFunction func) {
        if (func) {
            _rules[field_path].push_back(std::move(func));
        }
    }

    // Helper to split path string like "user.address.street" or "user.tags[*]" or "user.tags[0]"
    static std::vector<std::string> split_path_for_sanitizer(const std::string &path) {
        std::vector<std::string> parts;
        std::string current_part;
        bool in_bracket = false;
        for (char ch: path) {
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

    void Sanitizer::apply_sanitizers_to_node(qb::json &node, const std::vector<SanitizerFunction> &funcs) const {
        if (node.is_string()) {
            std::string val = node.get<std::string>();
            for (const auto &func: funcs) {
                val = func(val);
            }
            node = val;
        }
    }

    void Sanitizer::traverse_and_apply(qb::json &current_node, const std::vector<std::string> &path_segments,
                                       size_t segment_idx, const std::vector<SanitizerFunction> &funcs_to_apply) const {
        if (segment_idx >= path_segments.size()) {
            // Path exhausted, apply to current node
            apply_sanitizers_to_node(current_node, funcs_to_apply);
            return;
        }

        const std::string &segment = path_segments[segment_idx];

        if (current_node.is_object() && current_node.contains(segment)) {
            traverse_and_apply(current_node[segment], path_segments, segment_idx + 1, funcs_to_apply);
        } else if (current_node.is_array()) {
            if (segment == "*") {
                // Wildcard for all array elements
                for (auto &item: current_node) {
                    traverse_and_apply(item, path_segments, segment_idx + 1, funcs_to_apply);
                }
            } else {
                try {
                    size_t index = std::stoul(segment);
                    if (index < current_node.size()) {
                        traverse_and_apply(current_node[index], path_segments, segment_idx + 1, funcs_to_apply);
                    }
                } catch (const std::invalid_argument &) {
                    /* Not a number, not an index */
                }
                catch (const std::out_of_range &) {
                    /* Number too large for size_t */
                }
            }
        }
    }

    void Sanitizer::sanitize(qb::json &data) const {
        for (const auto &[path_key, funcs_to_apply]: _rules) {
            if (funcs_to_apply.empty()) continue;
            std::vector<std::string> path_segments = split_path_for_sanitizer(path_key);
            if (!path_segments.empty()) {
                traverse_and_apply(data, path_segments, 0, funcs_to_apply);
            }
        }
    }

    namespace PredefinedSanitizers {
        SanitizerFunction trim() noexcept {
            return [](const std::string &input) -> std::string {
                // Find the first non-whitespace character
                auto first_char = std::find_if_not(input.begin(), input.end(), [](unsigned char c) {
                    return std::isspace(c);
                });
                // If the string is all whitespace, return an empty string
                if (first_char == input.end()) {
                    return "";
                }
                // Find the last non-whitespace character
                auto last_char = std::find_if_not(input.rbegin(), input.rend(), [](unsigned char c) {
                    return std::isspace(c);
                }).base();
                return std::string(first_char, last_char);
            };
        }

        SanitizerFunction to_lower_case() noexcept {
            return [](const std::string &input) -> std::string {
                std::string output = input;
                std::transform(output.begin(), output.end(), output.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                return output;
            };
        }

        SanitizerFunction to_upper_case() noexcept {
            return [](const std::string &input) -> std::string {
                std::string output = input;
                std::transform(output.begin(), output.end(), output.begin(),
                               [](unsigned char c) { return std::toupper(c); });
                return output;
            };
        }

        SanitizerFunction escape_html() noexcept {
            return [](const std::string &input) -> std::string {
                std::string buffer;
                buffer.reserve(input.size()); // Avoid multiple reallocations
                for (char c: input) {
                    switch (c) {
                        case '&': buffer.append("&amp;");
                            break;
                        case '<': buffer.append("&lt;");
                            break;
                        case '>': buffer.append("&gt;");
                            break;
                        case '\"': buffer.append("&quot;");
                            break;
                        case '\'': buffer.append("&#39;");
                            break;
                        default: buffer.push_back(c);
                            break;
                    }
                }
                return buffer;
            };
        }

        SanitizerFunction strip_html_tags() noexcept {
            return [](const std::string &input) -> std::string {
                // SECURITY FIX: State-machine based HTML tag removal
                // Replaces vulnerable regex approach with proper parsing
                // Handles nested tags, attributes with '>' in quotes, and comments
                
                std::string output;
                output.reserve(input.size()); // Pre-allocate for performance
                
                enum class State { TEXT, TAG_START, TAG_NAME, IN_TAG, COMMENT, COMMENT_END };
                State state = State::TEXT;
                size_t i = 0;
                
                while (i < input.size()) {
                    char c = input[i];
                    
                    switch (state) {
                        case State::TEXT:
                            if (c == '<') {
                                state = State::TAG_START;
                            } else {
                                output.push_back(c);
                            }
                            break;
                            
                        case State::TAG_START:
                            if (c == '!') {
                                // Potential comment start <!--
                                if (i + 2 < input.size() && input[i + 1] == '-' && input[i + 2] == '-') {
                                    state = State::COMMENT;
                                    i += 2; // Skip the two dashes
                                } else {
                                    state = State::TAG_NAME; // DOCTYPE or other declaration
                                }
                            } else if (c == '/' || std::isalnum(static_cast<unsigned char>(c))) {
                                state = State::TAG_NAME;
                            } else {
                                // Not a valid tag start, treat as text
                                output.push_back('<');
                                output.push_back(c);
                                state = State::TEXT;
                            }
                            break;
                            
                        case State::TAG_NAME:
                        case State::IN_TAG:
                            if (c == '"' || c == '\'') {
                                // Skip quoted strings in attributes (handles '>' in quotes)
                                char quote = c;
                                ++i;
                                while (i < input.size() && input[i] != quote) {
                                    ++i;
                                }
                                // Continue in tag state
                            } else if (c == '>') {
                                // End of tag
                                state = State::TEXT;
                            }
                            // Otherwise stay in tag state
                            break;
                            
                        case State::COMMENT:
                            if (c == '-' && i + 1 < input.size() && input[i + 1] == '-') {
                                state = State::COMMENT_END;
                                ++i; // Skip one dash, next iteration will handle second
                            }
                            break;
                            
                        case State::COMMENT_END:
                            if (c == '>') {
                                state = State::TEXT;
                            } else if (c != '-') {
                                // Not actually end of comment, back to comment state
                                state = State::COMMENT;
                            }
                            break;
                    }
                    ++i;
                }
                
                // Handle unclosed tags - output remaining content as text
                if (state != State::TEXT) {
                    // Find last '<' and output from there
                    size_t last_lt = output.find_last_of('<');
                    if (last_lt != std::string::npos) {
                        output.erase(last_lt);
                    }
                }
                
                return output;
            };
        }

        SanitizerFunction alphanumeric_only() noexcept {
            return [](const std::string &input) -> std::string {
                std::string output;
                output.reserve(input.length());
                for (char c: input) {
                    if (std::isalnum(static_cast<unsigned char>(c))) {
                        output += c;
                    }
                }
                return output;
            };
        }

        SanitizerFunction normalize_whitespace() noexcept {
            return [](const std::string &input) -> std::string {
                std::string trimmed = trim()(input); // First, trim leading/trailing whitespace
                if (trimmed.empty()) return "";

                std::string output;
                output.reserve(trimmed.length());
                bool last_was_space = false;
                for (char c: trimmed) {
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

        SanitizerFunction escape_sql_like() noexcept {
            // Basic escaping for SQL LIKE wildcards and single quotes.
            // IMPORTANT: This is NOT a comprehensive SQL injection prevention method.
            // Always use parameterized queries or a proper SQL escaping library for database interactions.
            return [](const std::string &input) -> std::string {
                std::string output = input;
                // Escape LIKE wildcards % and _
                std::string temp_wildcards;
                temp_wildcards.reserve(output.length());
                for (char c: output) {
                    if (c == '%' || c == '_') {
                        temp_wildcards += '\\'; // Prepend backslash for typical SQL LIKE escaping
                    }
                    temp_wildcards += c;
                }
                output = temp_wildcards;

                // Escape single quotes by doubling them ''
                std::string temp_quotes;
                temp_quotes.reserve(output.length());
                for (char c: output) {
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
