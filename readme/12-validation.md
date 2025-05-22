# 12: Validation System (`qb::http::validation`)

Ensuring the integrity and correctness of incoming data is paramount for robust HTTP applications. The `qb::http::validation` namespace provides a comprehensive suite of tools for validating request bodies (typically JSON), query parameters, headers, and path parameters. It also includes mechanisms for data sanitization.

This system revolves around:

-   **Rules (`IRule` and concrete implementations)**: Define specific validation criteria (e.g., type, minLength, pattern).
-   **Schema Validator (`SchemaValidator`)**: Validates `qb::json` data against a JSON Schema-like definition.
-   **Parameter Validator (`ParameterValidator`)**: Validates collections of key-value string parameters (like query params or headers) against defined rule sets, including type conversion.
-   **Sanitizers (`Sanitizer`, `SanitizerFunction`)**: Modify data before validation (e.g., trim whitespace, escape HTML).
-   **Request Validator (`RequestValidator`)**: Orchestrates validation and sanitization for different parts of an HTTP request.
-   **Error Reporting (`Error`, `Result`)**: Structures for collecting and representing validation errors.

These components are typically used together within the `qb::http::ValidationMiddleware`.

## Defining Validation Rules (`IRule`)

At the heart of the validation system is the `qb::http::validation::IRule` interface. Concrete rule classes implement this interface to perform specific checks.

```cpp
// From http/validation/rule.h
class IRule {
public:
    virtual ~IRule() = default;
    virtual bool validate(const qb::json& value, const std::string& field_path, Result& result) const = 0;
    virtual std::string rule_name() const = 0;
};
```

Commonly used rule implementations include:

-   `TypeRule(DataType)`: Checks if a JSON value matches the expected `DataType` (STRING, INTEGER, NUMBER, BOOLEAN, OBJECT, ARRAY, NUL, ANY).
-   `MinLengthRule(size_t)`: For strings (minimum character length) or arrays (minimum item count).
-   `MaxLengthRule(size_t)`: For strings or arrays.
-   `PatternRule(std::string regex_str)`: Validates a string against a regular expression.
-   `MinimumRule(double min_val, bool exclusive = false)`: For numbers.
-   `MaximumRule(double max_val, bool exclusive = false)`: For numbers.
-   `EnumRule(qb::json allowed_values_array)`: Value must be one of the predefined values.
-   `MinItemsRule(size_t)`: Minimum number of items in an array.
-   `MaxItemsRule(size_t)`: Maximum number of items in an array.
-   `UniqueItemsRule()`: All items in an array must be unique.
-   `MinPropertiesRule(size_t)`: Minimum number of properties in an object.
-   `MaxPropertiesRule(size_t)`: Maximum number of properties in an object.
-   `PropertyNamesRule(qb::json name_schema)`: Validates property names of an object against a sub-schema.
-   `CustomRule(CustomValidateFn fn, std::string name)`: Allows defining ad-hoc validation logic via a lambda.

These rules are typically not used directly by application developers but are instantiated by `SchemaValidator` or `ParameterValidator` based on schema definitions or rule sets.

## Schema Validation (`SchemaValidator`)

`qb::http::validation::SchemaValidator` (`http/validation/schema_validator.h`) is used to validate a `qb::json` data structure against a JSON Schema-like definition (also provided as `qb::json`). It supports a significant subset of JSON Schema keywords:

-   **Type Checking**: `type` (string or array of types like "string", "integer", "object", etc.)
-   **String Constraints**: `minLength`, `maxLength`, `pattern`.
-   **Numeric Constraints**: `minimum`, `exclusiveMinimum`, `maximum`, `exclusiveMaximum`.
-   **Generic Constraints**: `enum` (value must be one of a list).
-   **Array Constraints**: `items` (can be a single schema for all items or an array of schemas for tuple validation), `additionalItems` (boolean or schema), `minItems`, `maxItems`, `uniqueItems`.
-   **Object Constraints**: `properties` (map of property names to schemas), `required` (array of required property names), `additionalProperties` (boolean or schema), `minProperties`, `maxProperties`, `propertyNames` (schema for property names).
-   **Logical Combinators**: `allOf`, `anyOf`, `oneOf`, `not`.

```cpp
#include <http/validation/schema_validator.h>
#include <http/validation/error.h> // For Result
#include <qb/json.h>

// Define a schema
qb::json user_schema = {
    {"type", "object"},
    {
        "properties", {
            {"username", {{"type", "string"}, {"minLength", 3}}},
            {"email", {{"type", "string"}, {"pattern", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"]}},
            {"age", {{"type", "integer"}, {"minimum", 0}, {"maximum", 120}}},
            {"roles", {{"type", "array"}, {"items", {{"type", "string"}}}, {"minItems", 1}, {"uniqueItems", true}}}
        }
    },
    {"required", {"username", "email"}}
};

qb::http::validation::SchemaValidator validator(user_schema);
qb::http::validation::Result validation_result;

qb::json user_data = {{"username", "tester"}, {"email", "test@example.com"}, {"age", 30}, {"roles", {"user", "editor"}}};

if (validator.validate(user_data, validation_result)) {
    std::cout << "User data is valid." << std::endl;
} else {
    std::cout << "User data is invalid:" << std::endl;
    for (const auto& error : validation_result.errors()) {
        std::cout << "  - Field: " << error.field_path
                  << ", Rule: " << error.rule_violated
                  << ", Message: " << error.message;
        if (error.offending_value.has_value()) {
            std::cout << ", Value: " << error.offending_value->dump();
        }
        std::cout << std::endl;
    }
}
```

Validation errors are collected in the `Result` object, detailing the path, violated rule, and a message.

## Parameter Validation (`ParameterValidator`)

HTTP requests often contain parameters in query strings, headers, or URL paths. These are typically strings and may need type conversion before validation. `qb::http::validation::ParameterValidator` (`http/validation/parameter_validator.h`) handles this.

It uses `ParameterRuleSet` to define expectations for each parameter:

```cpp
struct ParameterRuleSet {
    std::string name;                     // Parameter name
    DataType expected_type = DataType::STRING; // Target type after parsing
    bool required = false;
    std::optional<std::string> default_value; // Default if not provided (as string)
    std::vector<std::shared_ptr<IRule>> rules; // Rules to apply *after* type conversion
    // Custom function to parse string value to qb::json, bool& success
    std::function<qb::json(const std::string&, bool&)> custom_parser; 

    // Fluent setters: set_type, set_required, set_default, add_rule, set_custom_parser
};
```

The `ParameterValidator` can parse string values into `STRING`, `INTEGER`, `NUMBER`, or `BOOLEAN` `qb::json` types. After parsing (and potential type conversion), it applies the specified `IRule`s.

```cpp
#include <http/validation/parameter_validator.h>

qb::http::validation::ParameterValidator query_validator;

query_validator.add_param(
    ParameterRuleSet("page")
        .set_type(DataType::INTEGER)
        .set_default("1")
        .add_rule(std::make_shared<MinimumRule>(1))
);
query_validator.add_param(
    ParameterRuleSet("limit")
        .set_type(DataType::INTEGER)
        .set_default("20")
        .add_rule(std::make_shared<MinimumRule>(1))
        .add_rule(std::make_shared<MaximumRule>(100))
);
query_validator.add_param(
    ParameterRuleSet("sort_by")
        .set_required(true)
        .add_rule(std::make_shared<EnumRule>(qb::json::array({"name", "date"})))
);

qb::http::validation::Result param_results;
qb::icase_unordered_map<std::string> query_params_from_request = {
    {"sort_by", "name"}, {"limit", "50"} // "page" will use default
};

if (query_validator.validate(query_params_from_request, param_results, "query")) {
    std::cout << "Query parameters are valid." << std::endl;
} else {
    // Handle errors in param_results
}
```

`ParameterValidator` can operate in `strict_mode` (constructor argument), where unexpected parameters cause validation failure.

## Data Sanitization (`Sanitizer`)

Before validation, it's often useful to sanitize input data. The `qb::http::validation::Sanitizer` (`http/validation/sanitizer.h`) allows applying `SanitizerFunction`s (`std::function<std::string(const std::string&)>`) to string fields within a `qb::json` object or directly to string values.

Field paths use a dot-notation (e.g., `"user.address.street"`) and can include array wildcards (`"tags[*]"`) or specific indices (`"comments[0].text"`).

`PredefinedSanitizers` namespace offers common sanitizers:
-   `trim()`: Removes leading/trailing whitespace.
-   `to_lower_case()`, `to_upper_case()`
-   `escape_html()`: Escapes `&`, `<`, `>`, `"`, `'`.
-   `strip_html_tags()`: Basic removal of HTML-like tags (not for security against XSS).
-   `alphanumeric_only()`
-   `normalize_whitespace()`: Trims ends, collapses multiple internal spaces to one.
-   `escape_sql_like()`: Basic escaping for SQL LIKE wildcards and single quotes (NOT for general SQL injection prevention).

```cpp
#include <http/validation/sanitizer.h>

qb::http::validation::Sanitizer sanitizer;
sanitizer.add_rule("comment_text", PredefinedSanitizers::trim());
sanitizer.add_rule("comment_text", PredefinedSanitizers::escape_html());
sanitizer.add_rule("tags[*]", PredefinedSanitizers::to_lower_case());

qb::json data = {{"comment_text", "  <script>alert('XSS');</script>  "}, {"tags", {"TAGA", "TagB"}}};
sanitizer.sanitize(data);

// data["comment_text"] is now "&lt;script&gt;alert(&#39;XSS&#39;);&lt;/script&gt;"
// data["tags"] is now ["taga", "tagb"]
```

## Orchestration: `RequestValidator` & `ValidationMiddleware`

`qb::http::validation::RequestValidator` (`http/validation/request_validator.h`) orchestrates the validation of different parts of an HTTP request:

-   **Body**: `for_body(const qb::json& schema_definition)` uses a `SchemaValidator`.
-   **Query Parameters**: `for_query_param(name, ParameterRuleSet)` uses a `ParameterValidator`.
-   **Headers**: `for_header(name, ParameterRuleSet)` uses a `ParameterValidator`.
-   **Path Parameters**: `for_path_param(name, ParameterRuleSet)` uses a `ParameterValidator`.

It also manages sanitizers for body, query parameters, and headers.

```cpp
#include <http/validation/request_validator.h>

auto request_validator = std::make_shared<qb::http::validation::RequestValidator>();

// Body schema
request_validator->for_body({
    {"type", "object"},
    {"properties", {{"message", {{"type", "string"}}}}}
});

// Query parameter rule
request_validator->for_query_param("id", 
    ParameterRuleSet("id").set_type(DataType::INTEGER).set_required()
);

// Header sanitizer
request_validator->add_header_sanitizer("X-Custom-Input", PredefinedSanitizers::trim());

// ... then use this request_validator with ValidationMiddleware ...
```

The `qb::http::ValidationMiddleware` (`http/middleware/validation.h`) integrates a `RequestValidator` into the middleware chain. If validation fails, it automatically sends a 400 Bad Request (or similar) with a JSON body detailing the errors.

```cpp
// In router setup:
auto my_validator = std::make_shared<qb::http::validation::RequestValidator>();
// ... configure my_validator ...

auto validation_mw = qb::http::validation_middleware<MySession>(my_validator);
router.use(validation_mw);

router.post("/validated_endpoint", [](auto ctx) {
    // If this handler is reached, validation passed.
    // Sanitized values (if any) are reflected in ctx->request().
    ctx->response().body() = "Validation successful!";
    ctx->complete();
});
```

This layered system provides a powerful and flexible way to ensure data correctness and apply transformations within your `qb::http` application.

Previous: [Authentication System](./11-authentication.md)
Next: [Error Handling Strategies](./13-error-handling.md)

---
Return to [Index](./README.md) 