/**
 * @file qbm/http/tests/unit/validation/validation-schema.cpp
 * @brief Unit tests for qb::http::validation::SchemaValidator (JSON-Schema subset).
 *
 * Pure-logic coverage of the schema engine: object/array/tuple shapes, required,
 * additionalProperties / additionalItems, the logical combinators (allOf/anyOf/
 * oneOf/not), min/maxProperties, propertyNames, malformed-keyword diagnostics,
 * and error-value-policy propagation through nested schemas. No socket, no loop.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <vector>

#include <qb/json.h>

#include <qbm/http/validation.h>

using namespace qb::http::validation;

class ValidationSchemaTest : public ::testing::Test {
protected:
    Result result;

    void
    SetUp() override {
        result.clear();
    }
};

// Renders a validation error list to JSON for readable assertion failure messages.
// Kept local to this TU: SchemaValidatorOneOf is its only consumer.
static qb::json
validation_errors_to_json(const std::vector<qb::http::validation::Error> &errors) {
    qb::json errors_array = qb::json::array();
    for (const auto &err : errors) {
        qb::json err_obj;
        err_obj["field_path"]    = err.field_path;
        err_obj["rule_violated"] = err.rule_violated;
        err_obj["message"]       = err.message;
        if (err.offending_value.has_value()) {
            err_obj["offending_value"] = err.offending_value.value();
        }
        errors_array.push_back(err_obj);
    }
    return errors_array;
}

// --- Object schemas ----------------------------------------------------------

TEST_F(ValidationSchemaTest, BasicObject) {
    qb::json schema = {
        {"type", "object"},
        {"properties", {{"name", {{"type", "string"}, {"minLength", 3}}}, {"age", {{"type", "integer"}, {"minimum", 18}}}}},
        {"required", {"name"}}
    };
    SchemaValidator validator(schema);

    result.clear();
    qb::json valid_data = {{"name", "Alice"}, {"age", 30}};
    EXPECT_TRUE(validator.validate(valid_data, result));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json invalid_name_short = {{"name", "Al"}, {"age", 30}};
    EXPECT_FALSE(validator.validate(invalid_name_short, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "name");
    EXPECT_EQ(result.errors()[0].rule_violated, "minLength");

    result.clear();
    qb::json invalid_age = {{"name", "Bob"}, {"age", 17}};
    EXPECT_FALSE(validator.validate(invalid_age, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "age");
    EXPECT_EQ(result.errors()[0].rule_violated, "minimum");

    result.clear();
    qb::json missing_required = {{"age", 25}};
    EXPECT_FALSE(validator.validate(missing_required, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "name");
    EXPECT_EQ(result.errors()[0].rule_violated, "required");

    result.clear();
    qb::json wrong_type = {{"name", 123}, {"age", 30}};
    EXPECT_FALSE(validator.validate(wrong_type, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "name");
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
}

TEST_F(ValidationSchemaTest, NestedObject) {
    qb::json schema = {
        {"type", "object"},
        {"properties",
         {{"user",
           {{"type", "object"},
            {"properties", {{"id", {{"type", "integer"}}}, {"username", {{"type", "string"}}}}},
            {"required", {"id", "username"}}}}}}
    };
    SchemaValidator validator(schema);

    result.clear();
    qb::json valid_data = {{"user", {{"id", 1}, {"username", "testuser"}}}};
    EXPECT_TRUE(validator.validate(valid_data, result));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json invalid_nested = {{"user", {{"id", "not-an-int"}}}};
    EXPECT_FALSE(validator.validate(invalid_nested, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 2);

    bool id_type_error_found           = false;
    bool username_required_error_found = false;
    for (const auto &err : result.errors()) {
        if (err.field_path == "user.id" && err.rule_violated == "type")
            id_type_error_found = true;
        if (err.field_path == "user.username" && err.rule_violated == "required")
            username_required_error_found = true;
    }
    EXPECT_TRUE(id_type_error_found);
    EXPECT_TRUE(username_required_error_found);
}

// --- Array schemas -----------------------------------------------------------

TEST_F(ValidationSchemaTest, ArrayItems) {
    qb::json        schema = {{"type", "array"}, {"items", {{"type", "integer"}, {"minimum", 0}}}, {"minItems", 1}};
    SchemaValidator validator(schema);

    result.clear();
    qb::json valid_data = {1, 2, 3};
    EXPECT_TRUE(validator.validate(valid_data, result));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json invalid_item_type = {1, "not-an-int", 3};
    EXPECT_FALSE(validator.validate(invalid_item_type, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "[1]");
    EXPECT_EQ(result.errors()[0].rule_violated, "type");

    result.clear();
    qb::json invalid_item_value = {1, -5, 3};
    EXPECT_FALSE(validator.validate(invalid_item_value, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "[1]");
    EXPECT_EQ(result.errors()[0].rule_violated, "minimum");

    result.clear();
    qb::json too_few_items = qb::json::array();
    EXPECT_FALSE(validator.validate(too_few_items, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "");
    EXPECT_EQ(result.errors()[0].rule_violated, "minItems");
}

TEST_F(ValidationSchemaTest, TupleItemsAndAdditionalItems) {
    qb::json        schema = {{"type", "array"}, {"items", {{{"type", "string"}}, {{"type", "integer"}}}}, {"additionalItems", false}};
    SchemaValidator validator(schema);

    result.clear();
    qb::json valid_tuple = {"hello", 123};
    EXPECT_TRUE(validator.validate(valid_tuple, result));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json too_many_items = {"hello", 123, "extra"};
    EXPECT_FALSE(validator.validate(too_many_items, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "[2]");
    EXPECT_EQ(result.errors()[0].rule_violated, "additionalItems");

    result.clear();
    qb::json wrong_type_in_tuple = {"hello", "not-an-int"};
    EXPECT_FALSE(validator.validate(wrong_type_in_tuple, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "[1]");
    EXPECT_EQ(result.errors()[0].rule_violated, "type");

    qb::json schema_additional_schema = {{"type", "array"}, {"items", {{{"type", "string"}}}}, {"additionalItems", {{"type", "boolean"}}}};
    SchemaValidator validator2(schema_additional_schema);

    result.clear();
    qb::json valid_additional = {"first", true, false};
    EXPECT_TRUE(validator2.validate(valid_additional, result));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json invalid_additional = {"first", true, "not-a-bool"};
    EXPECT_FALSE(validator2.validate(invalid_additional, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "[2]");
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
}

TEST_F(ValidationSchemaTest, AdditionalItemsAsSchema) {
    qb::json schema = {{"type", "array"}, {"items", qb::json::array({{{"type", "string"}}})}, {"additionalItems", {{"type", "integer"}}}};
    SchemaValidator validator(schema);

    // Overflow item [1] is a string, but additionalItems requires integer -> error at [1].
    result.clear();
    EXPECT_FALSE(validator.validate(qb::json::array({"head", "not-an-int"}), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "[1]");
    EXPECT_EQ(result.errors()[0].rule_violated, "type");

    result.clear();
    EXPECT_TRUE(validator.validate(qb::json::array({"head", 1, 2}), result));
    EXPECT_TRUE(result.success());
}

TEST_F(ValidationSchemaTest, AdditionalProperties) {
    qb::json schema_no_additional = {{"type", "object"}, {"properties", {{"name", {{"type", "string"}}}}}, {"additionalProperties", false}};
    SchemaValidator validator_no_add(schema_no_additional);
    result.clear();
    EXPECT_TRUE(validator_no_add.validate({{"name", "test"}}, result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(validator_no_add.validate({{"name", "test"}, {"extra", 1}}, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "extra");
    EXPECT_EQ(result.errors()[0].rule_violated, "additionalProperties");

    qb::json schema_with_additional_schema = {
        {"type", "object"}, {"properties", {{"id", {{"type", "integer"}}}}}, {"additionalProperties", {{"type", "string"}}}
    };
    SchemaValidator validator_add_schema(schema_with_additional_schema);
    result.clear();
    EXPECT_TRUE(validator_add_schema.validate({{"id", 1}, {"description", "text"}}, result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(validator_add_schema.validate({{"id", 1}, {"count", 5}}, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "count");
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
}

// --- Logical combinators -----------------------------------------------------

TEST_F(ValidationSchemaTest, AllOf) {
    qb::json schema = {
        {"allOf",
         {{{"type", "object"}, {"properties", {{"a", {{"type", "string"}}}}}},
          {{"type", "object"}, {"properties", {{"b", {{"type", "integer"}}}}}}}}
    };
    SchemaValidator validator(schema);

    result.clear();
    qb::json valid_data = {{"a", "text"}, {"b", 123}};
    EXPECT_TRUE(validator.validate(valid_data, result));
    EXPECT_TRUE(result.success());

    qb::json schema_refined = {
        {"allOf",
         {{{"properties", {{"a", {{"type", "string"}}}}}, {"required", {"a"}}},
          {{"properties", {{"b", {{"type", "integer"}}}}}, {"required", {"b"}}}}}
    };
    SchemaValidator validator_refined(schema_refined);
    result.clear();
    EXPECT_TRUE(validator_refined.validate(valid_data, result));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json invalid_missing_b = {{"a", "text"}};
    EXPECT_FALSE(validator_refined.validate(invalid_missing_b, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 2);
    bool all_of_error_found     = false;
    bool required_b_error_found = false;
    for (const auto &err : result.errors()) {
        if (err.rule_violated == "allOf")
            all_of_error_found = true;
        if (err.field_path == "b" && err.rule_violated == "required")
            required_b_error_found = true;
    }
    EXPECT_TRUE(all_of_error_found);
    EXPECT_TRUE(required_b_error_found);
}

TEST_F(ValidationSchemaTest, AnyOf) {
    qb::json        schema = {{"anyOf", {{{"type", "string"}, {"minLength", 5}}, {{"type", "integer"}, {"minimum", 10}}}}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_TRUE(validator.validate(qb::json("longstring"), result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(validator.validate(qb::json(15), result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(validator.validate(qb::json(10), result));
    EXPECT_TRUE(result.success());

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json("shrt"), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "anyOf");

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json(5), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "anyOf");
}

TEST_F(ValidationSchemaTest, AnyOfRejectsNonObjectSchemaItems) {
    qb::json        schema = {{"anyOf", qb::json::array({qb::json::object({{"type", "string"}}), 42})}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json("value"), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "schemaError.anyOf.item");
}

TEST_F(ValidationSchemaTest, OneOf) {
    qb::json        schema = {{"oneOf", {{{"type", "string"}, {"pattern", "^abc$"}}, {{"type", "string"}, {"pattern", "^def$"}}}}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_TRUE(validator.validate(qb::json("abc"), result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(validator.validate(qb::json("def"), result));
    EXPECT_TRUE(result.success());

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json("ghi"), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "oneOf");

    // Exactly one branch matches -> success, no errors.
    qb::json        schema_ambiguous = {{"oneOf", {{{"type", "string"}, {"minLength", 2}}, {{"type", "string"}, {"maxLength", 5}}}}};
    SchemaValidator validator_amb(schema_ambiguous);
    result.clear();
    qb::json longstring_json = "longstring"; // length 10: matches minLength:2, fails maxLength:5
    EXPECT_TRUE(validator_amb.validate(longstring_json, result))
        << "'longstring' should match exactly one oneOf branch. Errors: " << validation_errors_to_json(result.errors()).dump(2);
    EXPECT_TRUE(result.success());
    EXPECT_EQ(result.errors().size(), 0u);
}

TEST_F(ValidationSchemaTest, OneOfNonObjectItemAndAmbiguous) {
    // Non-object item is skipped with a schemaError.oneOf.item error; the remaining
    // single string schema still matches.
    {
        qb::json        schema = {{"oneOf", qb::json::array({42, {{"type", "string"}}})}};
        SchemaValidator validator(schema);
        result.clear();
        validator.validate(qb::json("hello"), result);
        bool item_error = false;
        for (const auto &err : result.errors()) {
            if (err.rule_violated == "schemaError.oneOf.item")
                item_error = true;
        }
        EXPECT_TRUE(item_error);
    }

    // Ambiguous oneOf: value validates against two schemas -> "matched 2".
    {
        qb::json schema = {{"oneOf", qb::json::array({{{"type", "string"}, {"minLength", 1}}, {{"type", "string"}, {"maxLength", 100}}})}};
        SchemaValidator validator(schema);
        result.clear();
        EXPECT_FALSE(validator.validate(qb::json("hello"), result));
        ASSERT_FALSE(result.success());
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].rule_violated, "oneOf");
        EXPECT_NE(result.errors()[0].message.find("matched 2"), std::string::npos);
    }
}

TEST_F(ValidationSchemaTest, Not) {
    qb::json        schema = {{"not", {{"type", "integer"}}}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_TRUE(validator.validate(qb::json("string"), result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(validator.validate(qb::json(true), result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(validator.validate(qb::json(10.5), result));
    EXPECT_TRUE(result.success());

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json(10), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "not");
}

// additionalProperties bound to an OBJECT sub-schema: a dynamic key whose NESTED
// property fails carries a non-empty inner field_path, which must be re-prefixed
// under the dynamic key ("key.inner"). The existing AdditionalProperties test
// only uses a scalar sub-schema (empty inner path), so this hits the join branch.
TEST_F(ValidationSchemaTest, AdditionalPropertiesObjectSchemaRepathsNestedError) {
    qb::json schema = {
        {"type", "object"},
        {"properties", {{"id", {{"type", "integer"}}}}},
        {"additionalProperties", {{"type", "object"}, {"properties", {{"port", {{"type", "integer"}}}}}}}
    };
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json{{"id", 1}, {"svc", {{"port", "nope"}}}}, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1u);
    EXPECT_EQ(result.errors()[0].field_path, "svc.port"); // dynamic key joined with inner field
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
}

// A malformed "anyOf"/"oneOf" definition (not a non-empty array) is a schema
// error, distinct from the per-item non-object check the existing tests cover.
TEST_F(ValidationSchemaTest, AnyOfMalformedNonArrayOrEmpty) {
    for (const qb::json &bad : {qb::json::object(), qb::json(qb::json::array())}) {
        SchemaValidator validator(qb::json{{"anyOf", bad}});
        result.clear();
        EXPECT_FALSE(validator.validate(qb::json("x"), result));
        ASSERT_FALSE(result.success());
        ASSERT_EQ(result.errors().size(), 1u);
        EXPECT_EQ(result.errors()[0].rule_violated, "schemaError.anyOf");
    }
}

TEST_F(ValidationSchemaTest, OneOfMalformedNonArrayOrEmpty) {
    for (const qb::json &bad : {qb::json::object(), qb::json(qb::json::array())}) {
        SchemaValidator validator(qb::json{{"oneOf", bad}});
        result.clear();
        EXPECT_FALSE(validator.validate(qb::json("x"), result));
        ASSERT_FALSE(result.success());
        ASSERT_EQ(result.errors().size(), 1u);
        EXPECT_EQ(result.errors()[0].rule_violated, "schemaError.oneOf");
    }
}

// --- type-array / min-max / propertyNames ------------------------------------

TEST_F(ValidationSchemaTest, TypeArrayRejectsUnknownTypeEntries) {
    qb::json        schema = {{"type", qb::json::array({"string", "mystery"})}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json("hello"), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "schemaError.type");
}

TEST_F(ValidationSchemaTest, MinMaxProperties) {
    qb::json schema = {
        {"type", "object"},
        {"minProperties", 2},
        {"maxProperties", 3},
        {"properties", {{"a", {{"type", "string"}}}, {"b", {{"type", "integer"}}}, {"c", {{"type", "boolean"}}}, {"d", {{"type", "string"}}}}}
    };
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_TRUE(validator.validate(qb::json{{"a", "val"}, {"b", 1}}, result));
    EXPECT_TRUE(result.success());

    result.clear();
    EXPECT_TRUE(validator.validate(qb::json{{"a", "val"}, {"b", 1}, {"c", true}}, result));
    EXPECT_TRUE(result.success());

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json{{"a", "val"}}, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "minProperties");

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json{{"a", "v"}, {"b", 1}, {"c", false}, {"d", "extra"}}, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "maxProperties");
}

TEST_F(ValidationSchemaTest, PropertyNames) {
    qb::json schema = {
        {"type", "object"},
        {"propertyNames", {{"type", "string"}, {"pattern", "^[a-z_]+$"}}},
        {"properties", {{"valid_name", {{"type", "integer"}}}, {"another_ok", {{"type", "boolean"}}}}}
    };
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_TRUE(validator.validate(qb::json{{"valid_name", 123}, {"another_ok", true}}, result));
    EXPECT_TRUE(result.success());

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json{{"ValidName", 456}}, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "<propertyName:ValidName>");
    EXPECT_EQ(result.errors()[0].rule_violated, "pattern");

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json{{"name_with_!", 789}}, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "<propertyName:name_with_!>");
    EXPECT_EQ(result.errors()[0].rule_violated, "pattern");

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json::array(), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
    EXPECT_EQ(result.errors()[0].field_path, "");
}

// --- Constructor / malformed-keyword diagnostics -----------------------------

TEST_F(ValidationSchemaTest, CtorRejectsNonObjectSchemas) {
    EXPECT_THROW({ SchemaValidator v(qb::json::array({1, 2, 3})); }, std::invalid_argument);
    EXPECT_THROW({ SchemaValidator v(qb::json(42)); }, std::invalid_argument);
}

TEST_F(ValidationSchemaTest, UnknownSingleTypeString) {
    qb::json        schema = {{"type", "mystery"}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json("anything"), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
    EXPECT_NE(result.errors()[0].message.find("Unknown type"), std::string::npos);
}

TEST_F(ValidationSchemaTest, TypeKeywordWrongJsonType) {
    qb::json        schema = {{"type", 123}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json("anything"), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
    EXPECT_NE(result.errors()[0].message.find("must be a string or an array"), std::string::npos);
}

TEST_F(ValidationSchemaTest, SingleTypeNumberAcceptsFloatAndInteger) {
    qb::json        schema = {{"type", "number"}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_TRUE(validator.validate(qb::json(2.5), result));
    EXPECT_TRUE(result.success());

    result.clear();
    EXPECT_TRUE(validator.validate(qb::json(7), result)); // integers are numbers
    EXPECT_TRUE(result.success());

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json("not-a-number"), result));
    ASSERT_FALSE(result.success());
}

TEST_F(ValidationSchemaTest, SingleTypeNullAcceptsOnlyNull) {
    qb::json        schema = {{"type", "null"}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_TRUE(validator.validate(qb::json(nullptr), result));
    EXPECT_TRUE(result.success());

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json(0), result));
    ASSERT_FALSE(result.success());
}

TEST_F(ValidationSchemaTest, MalformedSchemaKeywords) {
    // required must be an array of strings.
    {
        qb::json        schema = {{"type", "object"}, {"required", "name"}};
        SchemaValidator validator(schema);
        result.clear();
        EXPECT_FALSE(validator.validate(qb::json::object({{"name", "x"}}), result));
        ASSERT_FALSE(result.success());
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].rule_violated, "schemaError.required");
    }

    // properties must be an object.
    {
        qb::json        schema = {{"type", "object"}, {"properties", qb::json::array({1, 2})}};
        SchemaValidator validator(schema);
        result.clear();
        EXPECT_FALSE(validator.validate(qb::json::object({{"k", "v"}}), result));
        ASSERT_FALSE(result.success());
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].rule_violated, "schemaError.properties");
    }

    // items must be an object (schema) or an array of schemas.
    {
        qb::json        schema = {{"type", "array"}, {"items", 42}};
        SchemaValidator validator(schema);
        result.clear();
        EXPECT_FALSE(validator.validate(qb::json::array({1, 2}), result));
        ASSERT_FALSE(result.success());
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].rule_violated, "schemaError.items");
    }

    // additionalProperties must be a boolean or a schema object.
    {
        qb::json        schema = {{"type", "object"}, {"properties", {{"id", {{"type", "integer"}}}}}, {"additionalProperties", 42}};
        SchemaValidator validator(schema);
        result.clear();
        EXPECT_FALSE(validator.validate(qb::json::object({{"id", 1}, {"extra", "x"}}), result));
        ASSERT_FALSE(result.success());
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].rule_violated, "schemaError.additionalProperties");
    }
}

TEST_F(ValidationSchemaTest, RequiredNonStringElement) {
    qb::json        schema = {{"type", "object"}, {"required", qb::json::array({"name", 123})}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json::object({{"name", "x"}}), result));
    ASSERT_FALSE(result.success());
    bool found = false;
    for (const auto &err : result.errors()) {
        if (err.rule_violated == "schemaError.required")
            found = true;
    }
    EXPECT_TRUE(found);
}

TEST_F(ValidationSchemaTest, AllOfMalformed) {
    // Empty allOf array.
    {
        qb::json        schema = {{"allOf", qb::json::array()}};
        SchemaValidator validator(schema);
        result.clear();
        EXPECT_FALSE(validator.validate(qb::json("x"), result));
        ASSERT_FALSE(result.success());
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].rule_violated, "schemaError.allOf");
    }

    // Non-object item inside allOf.
    {
        qb::json        schema = {{"allOf", qb::json::array({{{"type", "string"}}, 42})}};
        SchemaValidator validator(schema);
        result.clear();
        EXPECT_FALSE(validator.validate(qb::json("x"), result));
        ASSERT_FALSE(result.success());
        bool item_error = false;
        for (const auto &err : result.errors()) {
            if (err.rule_violated == "schemaError.allOf.item")
                item_error = true;
        }
        EXPECT_TRUE(item_error);
    }
}

TEST_F(ValidationSchemaTest, NotKeywordNonObject) {
    qb::json        schema = {{"not", 42}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json("anything"), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "schemaError.not");
}

TEST_F(ValidationSchemaTest, NestedSchemaNodeNotObject) {
    qb::json        schema = {{"type", "object"}, {"properties", {{"x", 42}}}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json::object({{"x", "value"}}), result));
    ASSERT_FALSE(result.success());
    bool found = false;
    for (const auto &err : result.errors()) {
        if (err.rule_violated == "invalidSchemaType")
            found = true;
    }
    EXPECT_TRUE(found);
}

// --- Error-value-policy propagation ------------------------------------------

TEST_F(ValidationSchemaTest, PropagatesErrorValuePolicy) {
    qb::json        schema = {{"type", "object"}, {"properties", {{"name", {{"type", "string"}, {"minLength", 3}}}}}, {"required", {"name"}}};
    SchemaValidator v(schema);
    v.set_error_value_policy(SchemaValidator::ErrorValuePolicy::None);

    Result   out;
    qb::json data = {{"name", "ab"}};
    EXPECT_FALSE(v.validate(data, out));
    ASSERT_FALSE(out.success());
    ASSERT_FALSE(out.errors().empty());
    for (const auto &err : out.errors()) {
        EXPECT_FALSE(err.offending_value.has_value());
    }
}

TEST_F(ValidationSchemaTest, AdditionalPropertiesInheritsErrorValuePolicy) {
    qb::json        schema = {{"type", "object"}, {"additionalProperties", {{"type", "integer"}}}};
    SchemaValidator validator(schema);
    validator.set_error_value_policy(SchemaValidator::ErrorValuePolicy::None);

    Result   out;
    qb::json data = {{"dynamicField", "not-integer"}};
    EXPECT_FALSE(validator.validate(data, out));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "dynamicField");
    EXPECT_FALSE(out.errors().front().offending_value.has_value());
}

TEST_F(ValidationSchemaTest, PreviewPolicyTruncatesOffendingValue) {
    qb::json        schema = {{"type", "integer"}};
    SchemaValidator validator(schema);
    validator.set_error_value_policy(SchemaValidator::ErrorValuePolicy::Preview, 32);

    result.clear();
    qb::json huge_string = std::string(1024, 'a'); // not an integer -> type error
    EXPECT_FALSE(validator.validate(huge_string, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
    ASSERT_TRUE(result.errors()[0].offending_value.has_value());
    ASSERT_TRUE(result.errors()[0].offending_value->is_string());
    EXPECT_EQ(result.errors()[0].offending_value->get<std::string>().size(), 32u);
}

// ===========================================================================
// Multi-type `type` arrays: success path for every keyword + non-string entry
// ===========================================================================

TEST_F(ValidationSchemaTest, TypeArrayAcceptsAnyListedType) {
    // Drives the full string→DataType mapping inside the `type`-array branch
    // (integer/number/boolean/object/array/null) and the success short-circuit
    // once a candidate type matches.
    qb::json        schema = {{"type", qb::json::array({"integer", "number", "boolean", "object", "array", "null", "string"})}};
    SchemaValidator validator(schema);

    for (const qb::json &v :
         {qb::json(7), qb::json(3.5), qb::json(true), qb::json(qb::json::object()), qb::json(qb::json::array()), qb::json(nullptr),
          qb::json("text")}) {
        result.clear();
        EXPECT_TRUE(validator.validate(v, result)) << "value: " << v.dump();
        EXPECT_TRUE(result.success());
    }
}

TEST_F(ValidationSchemaTest, TypeArrayRejectsValueMatchingNoneOfTheTypes) {
    qb::json        schema = {{"type", qb::json::array({"integer", "boolean"})}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json("a string"), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
    EXPECT_NE(result.errors()[0].message.find("does not match any"), std::string::npos);
}

TEST_F(ValidationSchemaTest, TypeArrayRejectsNonStringEntry) {
    // A non-string element in the `type` array is a schema error.
    qb::json        schema = {{"type", qb::json::array({"string", 123})}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json("hello"), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "schemaError.type");
    EXPECT_NE(result.errors()[0].message.find("must be strings"), std::string::npos);
}

// ===========================================================================
// Array constraints: maxItems + uniqueItems
// ===========================================================================

TEST_F(ValidationSchemaTest, MaxItemsRejectsTooManyElements) {
    qb::json        schema = {{"type", "array"}, {"maxItems", 2}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_TRUE(validator.validate(qb::json::array({1, 2}), result));
    EXPECT_TRUE(result.success());

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json::array({1, 2, 3}), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "maxItems");
}

TEST_F(ValidationSchemaTest, MinItemsRejectsTooFewElements) {
    qb::json        schema = {{"type", "array"}, {"minItems", 2}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json::array({1}), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "minItems");
}

TEST_F(ValidationSchemaTest, UniqueItemsRejectsDuplicates) {
    qb::json        schema = {{"type", "array"}, {"uniqueItems", true}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_TRUE(validator.validate(qb::json::array({1, 2, 3}), result));
    EXPECT_TRUE(result.success());

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json::array({1, 2, 2}), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "uniqueItems");
}

// ===========================================================================
// preview_bytes clamping in set_error_value_policy (min 16, max 64K)
// ===========================================================================

TEST_F(ValidationSchemaTest, PreviewBytesClampedToMinimum) {
    qb::json        schema = {{"type", "integer"}};
    SchemaValidator validator(schema);
    // A requested preview below the 16-byte floor is clamped UP to 16.
    validator.set_error_value_policy(SchemaValidator::ErrorValuePolicy::Preview, 1);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json(std::string(1024, 'z')), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    ASSERT_TRUE(result.errors()[0].offending_value.has_value());
    ASSERT_TRUE(result.errors()[0].offending_value->is_string());
    EXPECT_EQ(result.errors()[0].offending_value->get<std::string>().size(), 16u);
}

TEST_F(ValidationSchemaTest, PreviewBytesClampedToMaximum) {
    qb::json        schema = {{"type", "integer"}};
    SchemaValidator validator(schema);
    // A requested preview beyond the 64K ceiling is clamped DOWN; a short value
    // is unaffected (we assert the policy still applies and the value survives).
    validator.set_error_value_policy(SchemaValidator::ErrorValuePolicy::Preview, 1024u * 1024u);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json(std::string(100, 'q')), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    ASSERT_TRUE(result.errors()[0].offending_value.has_value());
    EXPECT_EQ(result.errors()[0].offending_value->get<std::string>().size(), 100u);
}

// ===========================================================================
// additionalProperties as a SUB-SCHEMA (nested validator + path-merge)
// ===========================================================================

TEST_F(ValidationSchemaTest, AdditionalPropertiesSchemaValidatesDynamicValues) {
    // additionalProperties bound to a schema: each non-declared property is run
    // through a nested SchemaValidator and its errors are re-pathed under the key.
    qb::json schema = {
        {"type", "object"}, {"properties", {{"id", {{"type", "integer"}}}}}, {"additionalProperties", {{"type", "string"}, {"minLength", 3}}}
    };
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_TRUE(validator.validate(qb::json{{"id", 1}, {"name", "abcd"}}, result));
    EXPECT_TRUE(result.success());

    result.clear();
    // "tag" is too short → nested validator fails → error re-pathed under "tag".
    EXPECT_FALSE(validator.validate(qb::json{{"id", 1}, {"tag", "ab"}}, result));
    ASSERT_FALSE(result.success());
    ASSERT_GE(result.errors().size(), 1u);
    EXPECT_NE(result.errors()[0].field_path.find("tag"), std::string::npos);
}
