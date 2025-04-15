#pragma once

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>
#include <regex>

namespace qb::http {

/**
 * @brief Parameter type for query validation
 */
enum class ParamType {
    String,
    Integer,
    Float,
    Boolean,
    Array,
    Object
};

/**
 * @brief Query parameter validation rule
 */
struct QueryParamRule {
    enum class Type {
        Required,
        Optional,
        Default,
        MinLength,
        MaxLength,
        MinValue,
        MaxValue,
        Pattern,
        Enum,
        Custom
    };
    
    Type type;
    std::variant<
        std::monostate,
        bool,
        int64_t,
        double,
        std::string,
        std::vector<std::string>,
        std::function<bool(const std::string&, std::string&)>
    > value;
    
    // Convenience constructors
    static QueryParamRule required(bool req = true) {
        return {Type::Required, req};
    }
    
    static QueryParamRule optional() {
        return {Type::Optional, true};
    }
    
    static QueryParamRule default_value(const std::string& def) {
        return {Type::Default, def};
    }
    
    static QueryParamRule min_length(size_t min) {
        return {Type::MinLength, static_cast<int64_t>(min)};
    }
    
    static QueryParamRule max_length(size_t max) {
        return {Type::MaxLength, static_cast<int64_t>(max)};
    }
    
    static QueryParamRule min_value(int64_t min) {
        return {Type::MinValue, min};
    }
    
    static QueryParamRule min_value(double min) {
        return {Type::MinValue, min};
    }
    
    static QueryParamRule max_value(int64_t max) {
        return {Type::MaxValue, max};
    }
    
    static QueryParamRule max_value(double max) {
        return {Type::MaxValue, max};
    }
    
    static QueryParamRule pattern(const std::string& regex) {
        return {Type::Pattern, regex};
    }
    
    static QueryParamRule enum_values(const std::vector<std::string>& values) {
        return {Type::Enum, values};
    }
    
    static QueryParamRule custom(std::function<bool(const std::string&, std::string&)> validator) {
        return {Type::Custom, validator};
    }
};

/**
 * @brief Collection of validation rules for a query parameter
 */
struct QueryParamRules {
    ParamType type = ParamType::String;
    std::vector<QueryParamRule> rules;
    
    // Builder pattern for fluent API
    QueryParamRules& as_string() {
        type = ParamType::String;
        return *this;
    }
    
    QueryParamRules& as_integer() {
        type = ParamType::Integer;
        return *this;
    }
    
    QueryParamRules& as_float() {
        type = ParamType::Float;
        return *this;
    }
    
    QueryParamRules& as_boolean() {
        type = ParamType::Boolean;
        return *this;
    }
    
    QueryParamRules& as_array() {
        type = ParamType::Array;
        return *this;
    }
    
    QueryParamRules& required(bool req = true) {
        rules.push_back(QueryParamRule::required(req));
        return *this;
    }
    
    QueryParamRules& optional() {
        rules.push_back(QueryParamRule::optional());
        return *this;
    }
    
    QueryParamRules& default_value(const std::string& def) {
        rules.push_back(QueryParamRule::default_value(def));
        return *this;
    }
    
    QueryParamRules& min_length(size_t min) {
        rules.push_back(QueryParamRule::min_length(min));
        return *this;
    }
    
    QueryParamRules& max_length(size_t max) {
        rules.push_back(QueryParamRule::max_length(max));
        return *this;
    }
    
    QueryParamRules& length(size_t min, size_t max) {
        rules.push_back(QueryParamRule::min_length(min));
        rules.push_back(QueryParamRule::max_length(max));
        return *this;
    }
    
    QueryParamRules& min_value(int64_t min) {
        rules.push_back(QueryParamRule::min_value(min));
        return *this;
    }
    
    QueryParamRules& min_value(double min) {
        rules.push_back(QueryParamRule::min_value(min));
        return *this;
    }
    
    QueryParamRules& max_value(int64_t max) {
        rules.push_back(QueryParamRule::max_value(max));
        return *this;
    }
    
    QueryParamRules& max_value(double max) {
        rules.push_back(QueryParamRule::max_value(max));
        return *this;
    }
    
    QueryParamRules& range(int64_t min, int64_t max) {
        rules.push_back(QueryParamRule::min_value(min));
        rules.push_back(QueryParamRule::max_value(max));
        return *this;
    }
    
    QueryParamRules& range(double min, double max) {
        rules.push_back(QueryParamRule::min_value(min));
        rules.push_back(QueryParamRule::max_value(max));
        return *this;
    }
    
    QueryParamRules& pattern(const std::string& regex) {
        rules.push_back(QueryParamRule::pattern(regex));
        return *this;
    }
    
    QueryParamRules& email() {
        // Simple email regex pattern (basic validation only)
        return pattern(R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
    }
    
    QueryParamRules& uuid() {
        // UUID regex pattern
        return pattern(R"(^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$)");
    }
    
    QueryParamRules& one_of(const std::vector<std::string>& values) {
        rules.push_back(QueryParamRule::enum_values(values));
        return *this;
    }
    
    QueryParamRules& custom(std::function<bool(const std::string&, std::string&)> validator) {
        rules.push_back(QueryParamRule::custom(validator));
        return *this;
    }
};

/**
 * @brief Type for sanitization functions
 */
using SanitizerFunc = std::function<std::string(const std::string&)>;

/**
 * @brief Common sanitization functions
 */
class CommonSanitizers {
public:
    /**
     * @brief Trim whitespace from a string
     * @param input Input string
     * @return Trimmed string
     */
    static std::string trim(const std::string& input) {
        auto start = input.begin();
        auto end = input.end();
        
        // Trim leading whitespace
        while (start != end && std::isspace(*start)) {
            ++start;
        }
        
        // Trim trailing whitespace
        while (start != end && std::isspace(*(end - 1))) {
            --end;
        }
        
        return std::string(start, end);
    }
    
    /**
     * @brief Convert a string to lowercase
     * @param input Input string
     * @return Lowercase string
     */
    static std::string to_lower(const std::string& input) {
        std::string result = input;
        std::transform(result.begin(), result.end(), result.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        return result;
    }
    
    /**
     * @brief Convert a string to uppercase
     * @param input Input string
     * @return Uppercase string
     */
    static std::string to_upper(const std::string& input) {
        std::string result = input;
        std::transform(result.begin(), result.end(), result.begin(),
                       [](unsigned char c) { return std::toupper(c); });
        return result;
    }
    
    /**
     * @brief Escape HTML special characters
     * @param input Input string
     * @return HTML-escaped string
     */
    static std::string escape_html(const std::string& input) {
        std::string result;
        result.reserve(input.size());
        
        for (char c : input) {
            switch (c) {
                case '&': result += "&amp;"; break;
                case '<': result += "&lt;"; break;
                case '>': result += "&gt;"; break;
                case '"': result += "&quot;"; break;
                case '\'': result += "&#39;"; break;
                default: result += c; break;
            }
        }
        
        return result;
    }
    
    /**
     * @brief Remove all HTML tags from a string
     * @param input Input string
     * @return String with HTML tags removed
     */
    static std::string strip_html(const std::string& input) {
        std::regex html_tag_regex("<[^>]*>");
        return std::regex_replace(input, html_tag_regex, "");
    }
    
    /**
     * @brief Remove non-alphanumeric characters
     * @param input Input string
     * @return Alphanumeric-only string
     */
    static std::string alphanumeric_only(const std::string& input) {
        std::string result;
        result.reserve(input.size());
        
        for (char c : input) {
            if (std::isalnum(c)) {
                result += c;
            }
        }
        
        return result;
    }
};

} // namespace qb::http 