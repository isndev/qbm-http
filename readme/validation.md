# `qbm-http`: Request Validation

(`qbm/http/validation/`, `qbm/http/middleware/validator.h`)

The HTTP module provides a validation system to ensure incoming requests conform to expected formats and constraints before they reach your route handlers.

## Core Components (`qbm/http/validation/`)

*   **`qb::http::ValidationContext` (`validation_context.h`):**
    *   Collects validation errors.
    *   `add_error(field, code, message)`: Records an error.
    *   `has_errors()`, `errors()`: Check and retrieve errors.
    *   `ValidationErrors`: Type alias for `qb::unordered_map<std::string, FieldErrors>`.
    *   `FieldErrors`: Type alias for `qb::unordered_map<std::string, std::string>`.
*   **`qb::http::JsonSchemaValidator` (`json_schema.h`):**
    *   Validates a `qb::json` object against a JSON Schema (draft-07 subset).
    *   `JsonSchemaValidator(schema_json)` / `JsonSchemaValidator(schema_string)`: Constructor.
    *   `validate(value_json, ValidationContext&)`: Performs validation.
    *   Supports: `type`, `required`, `properties`, `additionalProperties`, `minLength`, `maxLength`, `pattern`, `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `items`, `minItems`, `maxItems`, `uniqueItems`, `enum`, `oneOf`, `anyOf`, `allOf`, `not`.
*   **`qb::http::QueryValidator` (`query_validator.h`):**
    *   Validates query parameters extracted from the URI.
    *   `add_param(name, QueryParamRules)`: Defines rules for a specific query parameter.
    *   `validate(params_map, ValidationContext&)`: Validates a map of query parameters.
*   **`qb::http::QueryParamRules` (`validation_types.h`):**
    *   Fluent builder for defining query parameter rules.
    *   `as_string()`, `as_integer()`, `as_float()`, `as_boolean()`: Set expected type.
    *   `required()`, `optional()`, `default_value()`.
    *   `min_length()`, `max_length()`, `length()`.
    *   `min_value()`, `max_value()`, `range()`.
    *   `pattern(regex)`, `email()`, `uuid()`.
    *   `one_of(vector)`.
    *   `custom(lambda)`.
*   **`qb::http::Sanitizer` (`sanitizer.h`):**
    *   Applies sanitization functions to JSON data.
    *   `add_rule(json_pointer_path, SanitizerFunc)`: Add a rule.
    *   `add_rule(path, sanitizer_name)`: Add using predefined names (e.g., "trim", "to_lower", "strip_html").
    *   `sanitize(json_object)`: Applies rules in-place.
*   **`qb::http::Validator<Session, String>` (`validator.h`):**
    *   The main orchestrator class, typically used via `ValidatorMiddleware`.
    *   Combines JSON schema validation, query parameter validation, custom rules, and sanitization.
    *   `validate(Context&)`: Runs all configured validations.
    *   `with_json_schema()`, `with_query_param()`, `with_sanitizer()`, `with_custom_rule()`, `with_error_handler()`: Configuration methods.

## Validation Middleware (`ValidatorMiddleware`)

(`middleware/validator.h`)

This middleware integrates the `Validator` class into the request processing chain.

*   **Creation:**
    ```cpp
    #include <qbm/http/middleware/validator.h>

    // 1. Create middleware, then configure validator
    auto validator_mw = qb::http::validator_middleware<MySession>();
    validator_mw->validator()->with_json_schema(my_schema);
    validator_mw->validator()->with_query_param("page", /*...*/);

    // 2. Create middleware with initial JSON schema
    // auto validator_mw = qb::http::validator_middleware<MySession>(my_schema);

    // router.use(validator_mw);
    ```
*   **Functionality:**
    1.  In its `process()` method, it calls `validator->validate(ctx)`.
    2.  If validation passes, it calls `MiddlewareResult::Continue()`.
    3.  If validation fails:
        *   It calls the configured error handler (or the default one).
        *   The error handler typically sets a `400 Bad Request` or `422 Unprocessable Entity` status code and includes error details in the response body.
        *   It calls `ctx.mark_handled()` and returns `MiddlewareResult::Stop()`.

## Usage Examples

### Validating Request Body with JSON Schema

```cpp
#include <qb/http.h>
#include <qbm/http/middleware/validator.h>
#include <qbm/http/validation/validation.h>

// Define your JSON schema
qb::json user_schema = {
    {"type", "object"},
    {"properties", {
        {"username", {{"type", "string"}, {"minLength", 5}}},
        {"email", {{"type", "string"}, {"pattern", ".+@.+\..+"}}},
        {"age", {{"type", "integer"}, {"minimum", 0}}}
    }},
    {"required", {"username", "email"}}
};

// ... inside server setup ...

// Apply validator middleware
router.use(qb::http::validator_middleware<MySession>(user_schema));

router.post("/register", [](Context& ctx) {
    // If execution reaches here, the body has already been validated
    // against the schema by the middleware.
    qb::json validated_body = ctx.request.body().as<qb::json>();

    // Process validated data
    // ...

    ctx.response.status_code = HTTP_STATUS_CREATED;
    ctx.response.body() = "User registered";
    ctx.complete();
});
```

### Validating Query Parameters

```cpp
#include <qb/http.h>
#include <qbm/http/middleware/validator.h>
#include <qbm/http/validation/validation.h>

// ... inside server setup ...

auto validator_mw = qb::http::validator_middleware<MySession>();

// Define rules for query parameters
validator_mw->validator()
    ->with_query_param("limit", qb::http::QueryParamRules()
                                     .as_integer()
                                     .range(1, 100) // Min 1, Max 100
                                     .default_value("10"))
    ->with_query_param("offset", qb::http::QueryParamRules()
                                      .as_integer()
                                      .min_value(0)
                                      .optional())
    ->with_query_param("status", qb::http::QueryParamRules()
                                      .as_string()
                                      .one_of({"active", "inactive", "pending"})
                                      .required());

router.use(validator_mw);

router.get("/items", [](Context& ctx) {
    // Access potentially validated/defaulted query params
    // Note: Accessing original query params via ctx.request.query() is still possible,
    // but the validator doesn't modify the request context directly by default.
    // You might store validated params in ctx.set() if needed downstream.

    std::string status = ctx.request.query("status"); // Assume validated by middleware
    int limit = std::stoi(ctx.request.query("limit", 0, "10")); // Use default if missing

    ctx.response.body() = "Items list";
    ctx.complete();
});
```

### Input Sanitization

```cpp
#include <qb/http.h>
#include <qbm/http/middleware/validator.h>
#include <qbm/http/validation/validation.h>

// ... inside server setup ...

// Assume user_schema is defined
auto validator_mw = qb::http::validator_middleware<MySession>(user_schema);

// Add sanitization rules (applied *after* schema validation if schema is present)
validator_mw->validator()
    ->with_sanitizer("/username", qb::http::sanitizers::trim)
    ->with_sanitizer("/email", qb::http::sanitizers::to_lower)
    ->with_sanitizer("/comment", qb::http::sanitizers::strip_html);

router.use(validator_mw);

router.post("/comments", [](Context& ctx) {
    // Request body JSON fields will have been sanitized by the middleware
    qb::json sanitized_body = ctx.request.body().as<qb::json>();
    // ... process sanitized_body ...
    ctx.complete();
});
``` 