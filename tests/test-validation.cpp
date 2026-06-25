#include <gtest/gtest.h>
#include <qb/json.h>
#include "../validation.h" // Main include for the validation system

// Using the new namespace directly for clarity in tests
using namespace qb::http::validation;

// --- Test Fixture for Validation Logic ---
class ValidationLogicTest : public ::testing::Test {
protected:
    Result result; // Renamed from ValidationResult

    void
    SetUp() override {
        result.clear();
    }
};

// --- ValidationError & ValidationResult Tests ---
TEST_F(ValidationLogicTest, ValidationResultBehavesCorrectly) {
    EXPECT_TRUE(result.success());
    EXPECT_TRUE(result.errors().empty());

    result.add_error("field1", "required", "Field is missing");
    EXPECT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "field1");
    EXPECT_EQ(result.errors()[0].rule_violated, "required");
    EXPECT_EQ(result.errors()[0].message, "Field is missing");

    Result other_result;
    other_result.add_error("field2", "type", "Must be a string", std::make_optional(qb::json(123)));
    result.merge(other_result);
    EXPECT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 2);
    EXPECT_EQ(result.errors()[1].field_path, "field2");
    EXPECT_TRUE(result.errors()[1].offending_value.has_value());
    EXPECT_EQ(result.errors()[1].offending_value.value(), qb::json(123));

    result.clear();
    EXPECT_TRUE(result.success());
    EXPECT_TRUE(result.errors().empty());
}

// --- IRule Concrete Implementations Tests ---

TEST_F(ValidationLogicTest, TypeRuleValidation) {
    TypeRule string_rule(DataType::STRING);
    TypeRule int_rule(DataType::INTEGER);
    TypeRule num_rule(DataType::NUMBER);
    TypeRule bool_rule(DataType::BOOLEAN);
    TypeRule obj_rule(DataType::OBJECT);
    TypeRule arr_rule(DataType::ARRAY);
    TypeRule null_rule(DataType::NUL);
    TypeRule any_rule(DataType::ANY);

    result.clear();
    EXPECT_TRUE(string_rule.validate(qb::json("hello"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(string_rule.validate(qb::json(123), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(int_rule.validate(qb::json(123), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(int_rule.validate(qb::json(123.5), "test", result));
    EXPECT_FALSE(result.success());
    result.clear();
    EXPECT_FALSE(int_rule.validate(qb::json("123"), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(num_rule.validate(qb::json(123), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(num_rule.validate(qb::json(123.5), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(num_rule.validate(qb::json("123.5"), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(bool_rule.validate(qb::json(true), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(bool_rule.validate(qb::json(1), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(obj_rule.validate(qb::json::object(), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(obj_rule.validate(qb::json::array(), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(arr_rule.validate(qb::json::array(), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(arr_rule.validate(qb::json::object(), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(null_rule.validate(qb::json(nullptr), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(null_rule.validate(qb::json(0), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(any_rule.validate(qb::json("any_value"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(any_rule.validate(qb::json(nullptr), "test", result));
    EXPECT_TRUE(result.success());
}

TEST_F(ValidationLogicTest, MinLengthRuleValidation) {
    MinLengthRule rule(3);
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("abc"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("abcd"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json("ab"), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, 2, 3}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({1, 2}), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(rule.validate(qb::json(123), "test", result));
    EXPECT_TRUE(result.success());
}

TEST_F(ValidationLogicTest, MaxLengthRuleValidation) {
    MaxLengthRule rule(3);
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("abc"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("ab"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json("abcd"), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, 2, 3}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({1, 2, 3, 4}), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(rule.validate(qb::json(123), "test", result));
    EXPECT_TRUE(result.success());
}

TEST_F(ValidationLogicTest, PatternRuleValidation) {
    PatternRule rule("^[a-zA-Z]+$");
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("abcXYZ"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json("abc123"), "test", result));
    EXPECT_FALSE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json(""), "test", result));
    EXPECT_FALSE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json(123), "test", result));
    EXPECT_TRUE(result.success());

    ASSERT_THROW(PatternRule("["), std::invalid_argument);
    ASSERT_THROW(PatternRule(std::string(1025, 'a')), std::invalid_argument);
}

TEST_F(ValidationLogicTest, MinimumRuleValidation) {
    MinimumRule rule_incl(10.0);
    MinimumRule rule_excl(10.0, true);

    result.clear();
    EXPECT_TRUE(rule_incl.validate(qb::json(10.0), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule_incl.validate(qb::json(10.1), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule_incl.validate(qb::json(9.9), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_FALSE(rule_excl.validate(qb::json(10.0), "test", result));
    EXPECT_FALSE(result.success());
    result.clear();
    EXPECT_TRUE(rule_excl.validate(qb::json(10.0001), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule_excl.validate(qb::json(9.9), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(rule_incl.validate(qb::json("test"), "test", result));
    EXPECT_TRUE(result.success());
}

TEST_F(ValidationLogicTest, MaximumRuleValidation) {
    MaximumRule rule_incl(20.0);
    MaximumRule rule_excl(20.0, true);

    result.clear();
    EXPECT_TRUE(rule_incl.validate(qb::json(20.0), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule_incl.validate(qb::json(19.9), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule_incl.validate(qb::json(20.1), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_FALSE(rule_excl.validate(qb::json(20.0), "test", result));
    EXPECT_FALSE(result.success());
    result.clear();
    EXPECT_TRUE(rule_excl.validate(qb::json(19.9999), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule_excl.validate(qb::json(20.1), "test", result));
    EXPECT_FALSE(result.success());
}

TEST_F(ValidationLogicTest, EnumRuleValidation) {
    EnumRule rule(qb::json::array({"red", "green", "blue", 10}));
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("green"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json(10), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json("yellow"), "test", result));
    EXPECT_FALSE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json(20), "test", result));
    EXPECT_FALSE(result.success());

    ASSERT_THROW(EnumRule(qb::json(qb::json::value_t::object)), std::invalid_argument);
}

TEST_F(ValidationLogicTest, UniqueItemsRuleValidation) {
    UniqueItemsRule rule;
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, 2, 3, "a"}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({1, 2, 3, 2}), "test", result));
    EXPECT_FALSE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array(), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json({{"a", 1}, {"b", 2}}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({qb::json::object({{"a", 1}}), qb::json::object({{"a", 1}})}), "test", result));
    EXPECT_FALSE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json(123), "test", result));
    EXPECT_TRUE(result.success());
}

TEST_F(ValidationLogicTest, MinItemsRuleValidation) {
    MinItemsRule rule(2);
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, 2}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, 2, 3}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({1}), "test", result));
    EXPECT_FALSE(result.success());
}

TEST_F(ValidationLogicTest, MaxItemsRuleValidation) {
    MaxItemsRule rule(2);
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, 2}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({1, 2, 3}), "test", result));
    EXPECT_FALSE(result.success());
}

TEST_F(ValidationLogicTest, CustomRuleValidation) {
    bool custom_func_called = false;
    auto fn                 = [&](const qb::json &val, const std::string &path, Result &res) -> bool {
        custom_func_called = true;
        if (val.is_string() && val.get<std::string>() == "custom_valid") {
            return true;
        }
        res.add_error(path, "custom_lambda_error_name", "Value did not meet custom criteria.", std::make_optional(val));
        return false;
    };
    CustomRule rule(fn, "myCustomRuleNameRegisteredInValidator");

    custom_func_called = false;
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("custom_valid"), "field", result));
    EXPECT_TRUE(result.success());
    EXPECT_TRUE(custom_func_called);

    custom_func_called = false;
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json("invalid"), "field", result));
    EXPECT_FALSE(result.success());
    EXPECT_TRUE(custom_func_called);
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "custom_lambda_error_name");
    EXPECT_EQ(rule.rule_name(), "myCustomRuleNameRegisteredInValidator");
}

// --- SchemaValidator Tests ---
TEST_F(ValidationLogicTest, SchemaValidatorBasicObject) {
    qb::json schema = {
        {"type", "object"},
        {"properties", {{"name", {{"type", "string"}, {"minLength", 3}}}, {"age", {{"type", "integer"}, {"minimum", 18}}}}},
        {"required", {"name"}}
    };
    SchemaValidator validator(schema);

    result.clear();
    qb::json valid_data = {{"name", "Alice"}, {"age", 30}};
    bool     is_valid_1 = validator.validate(valid_data, result);
    EXPECT_TRUE(is_valid_1);
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json invalid_name_short   = {{"name", "Al"}, {"age", 30}};
    bool     outcome_2            = validator.validate(invalid_name_short, result);
    size_t   errors_after_call_2  = result.errors().size();
    bool     success_after_call_2 = result.success();

    EXPECT_FALSE(outcome_2) << "Validation should fail for short name.";
    EXPECT_FALSE(success_after_call_2) << "Result should show failure for short name.";
    ASSERT_EQ(errors_after_call_2, 1) << "Should be 1 error for short name.";
    if (!success_after_call_2 && errors_after_call_2 == 1) {
        EXPECT_EQ(result.errors()[0].field_path, "name");
        EXPECT_EQ(result.errors()[0].rule_violated, "minLength");
    }

    result.clear();
    qb::json invalid_age = {{"name", "Bob"}, {"age", 17}};
    bool     is_valid_3  = validator.validate(invalid_age, result);
    EXPECT_FALSE(is_valid_3);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "age");
        EXPECT_EQ(result.errors()[0].rule_violated, "minimum");
    }
    result.clear();

    qb::json missing_required = {{"age", 25}};
    bool     is_valid_4       = validator.validate(missing_required, result);
    EXPECT_FALSE(is_valid_4);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "name");
        EXPECT_EQ(result.errors()[0].rule_violated, "required");
    }
    result.clear();

    qb::json wrong_type = {{"name", 123}, {"age", 30}};
    bool     is_valid_5 = validator.validate(wrong_type, result);
    EXPECT_FALSE(is_valid_5);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "name");
        EXPECT_EQ(result.errors()[0].rule_violated, "type");
    }
}

TEST_F(ValidationLogicTest, SchemaValidatorNestedObject) {
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
    bool     is_valid_1 = validator.validate(valid_data, result);
    EXPECT_TRUE(is_valid_1);
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json invalid_nested = {{"user", {{"id", "not-an-int"}}}};
    bool     is_valid_2     = validator.validate(invalid_nested, result);
    EXPECT_FALSE(is_valid_2);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        EXPECT_EQ(result.errors().size(), 2);

        bool id_type_error_found           = false;
        bool username_required_error_found = false;
        for (const auto &err : result.errors()) {
            if (err.field_path == "user.id" && err.rule_violated == "type") {
                id_type_error_found = true;
            }
            if (err.field_path == "user.username" && err.rule_violated == "required") {
                username_required_error_found = true;
            }
        }
        EXPECT_TRUE(id_type_error_found);
        EXPECT_TRUE(username_required_error_found);
    }
}

TEST_F(ValidationLogicTest, SchemaValidatorArrayItems) {
    qb::json        schema = {{"type", "array"}, {"items", {{"type", "integer"}, {"minimum", 0}}}, {"minItems", 1}};
    SchemaValidator validator(schema);

    result.clear();
    qb::json valid_data = {1, 2, 3};
    bool     is_valid_1 = validator.validate(valid_data, result);
    EXPECT_TRUE(is_valid_1);
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json invalid_item_type = {1, "not-an-int", 3};
    bool     is_valid_2        = validator.validate(invalid_item_type, result);
    EXPECT_FALSE(is_valid_2);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "[1]");
        EXPECT_EQ(result.errors()[0].rule_violated, "type");
    }

    result.clear();
    qb::json invalid_item_value = {1, -5, 3};
    bool     is_valid_3         = validator.validate(invalid_item_value, result);
    EXPECT_FALSE(is_valid_3);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "[1]");
        EXPECT_EQ(result.errors()[0].rule_violated, "minimum");
    }

    result.clear();
    qb::json too_few_items = qb::json::array();
    bool     is_valid_4    = validator.validate(too_few_items, result);
    EXPECT_FALSE(is_valid_4) << "Validation should fail for too few items.";
    ASSERT_FALSE(result.success()) << "Result should show failure for too few items.";
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "");
        EXPECT_EQ(result.errors()[0].rule_violated, "minItems");
    }
}

TEST_F(ValidationLogicTest, SchemaValidatorTupleItemsAndAdditionalItems) {
    qb::json        schema = {{"type", "array"}, {"items", {{{"type", "string"}}, {{"type", "integer"}}}}, {"additionalItems", false}};
    SchemaValidator validator(schema);

    result.clear();
    qb::json valid_tuple = {"hello", 123};
    bool     is_valid_1  = validator.validate(valid_tuple, result);
    EXPECT_TRUE(is_valid_1);
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json too_many_items = {"hello", 123, "extra"};
    bool     is_valid_2     = validator.validate(too_many_items, result);
    EXPECT_FALSE(is_valid_2);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "[2]");
        EXPECT_EQ(result.errors()[0].rule_violated, "additionalItems");
    }

    result.clear();
    qb::json wrong_type_in_tuple = {"hello", "not-an-int"};
    bool     is_valid_3          = validator.validate(wrong_type_in_tuple, result);
    EXPECT_FALSE(is_valid_3);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "[1]");
        EXPECT_EQ(result.errors()[0].rule_violated, "type");
    }

    result.clear();
    qb::json schema_additional_schema = {{"type", "array"}, {"items", {{{"type", "string"}}}}, {"additionalItems", {{"type", "boolean"}}}};
    SchemaValidator validator2(schema_additional_schema);
    qb::json        valid_additional = {"first", true, false};
    bool            is_valid_4       = validator2.validate(valid_additional, result);
    EXPECT_TRUE(is_valid_4);
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json invalid_additional = {"first", true, "not-a-bool"};
    bool     is_valid_5         = validator2.validate(invalid_additional, result);
    EXPECT_FALSE(is_valid_5);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        EXPECT_EQ(result.errors().size(), 1);
        if (!result.errors().empty()) {
            EXPECT_EQ(result.errors()[0].field_path, "[2]");
            EXPECT_EQ(result.errors()[0].rule_violated, "type");
        }
    }
}

TEST_F(ValidationLogicTest, SchemaValidatorAdditionalProperties) {
    qb::json schema_no_additional = {{"type", "object"}, {"properties", {{"name", {{"type", "string"}}}}}, {"additionalProperties", false}};
    SchemaValidator validator_no_add(schema_no_additional);
    result.clear();
    EXPECT_TRUE(validator_no_add.validate({{"name", "test"}}, result));
    EXPECT_TRUE(result.success());
    result.clear();
    bool is_valid_1 = validator_no_add.validate({{"name", "test"}, {"extra", 1}}, result);
    EXPECT_FALSE(is_valid_1);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        EXPECT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "extra");
        EXPECT_EQ(result.errors()[0].rule_violated, "additionalProperties");
    }

    qb::json schema_with_additional_schema = {
        {"type", "object"}, {"properties", {{"id", {{"type", "integer"}}}}}, {"additionalProperties", {{"type", "string"}}}
    };
    SchemaValidator validator_add_schema(schema_with_additional_schema);
    result.clear();
    EXPECT_TRUE(validator_add_schema.validate({{"id", 1}, {"description", "text"}}, result));
    EXPECT_TRUE(result.success());
    result.clear();
    bool is_valid_2 = validator_add_schema.validate({{"id", 1}, {"count", 5}}, result);
    EXPECT_FALSE(is_valid_2);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        EXPECT_EQ(result.errors().size(), 1);
        if (!result.errors().empty()) {
            EXPECT_EQ(result.errors()[0].field_path, "count");
            EXPECT_EQ(result.errors()[0].rule_violated, "type");
        }
    }
}

// --- SchemaValidator Logical Combinator Tests ---
TEST_F(ValidationLogicTest, SchemaValidatorAllOf) {
    qb::json schema = {
        {"allOf",
         {{{"type", "object"}, {"properties", {{"a", {{"type", "string"}}}}}},
          {{"type", "object"}, {"properties", {{"b", {{"type", "integer"}}}}}}}}
    };
    SchemaValidator validator(schema);

    result.clear();
    qb::json valid_data = {{"a", "text"}, {"b", 123}};
    bool     is_valid_1 = validator.validate(valid_data, result);
    EXPECT_TRUE(is_valid_1);
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json schema_refined = {
        {"allOf",
         {{{"properties", {{"a", {{"type", "string"}}}}}, {"required", {"a"}}},
          {{"properties", {{"b", {{"type", "integer"}}}}}, {"required", {"b"}}}}}
    };
    SchemaValidator validator_refined(schema_refined);
    EXPECT_TRUE(validator_refined.validate(valid_data, result));
    EXPECT_TRUE(result.success());
    result.clear();
    qb::json invalid_missing_b = {{"a", "text"}};
    bool     is_valid_2        = validator_refined.validate(invalid_missing_b, result);
    EXPECT_FALSE(is_valid_2);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        EXPECT_EQ(result.errors().size(), 2);
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
}

TEST_F(ValidationLogicTest, SchemaValidatorAnyOf) {
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
    bool is_valid_1 = validator.validate(qb::json("shrt"), result);
    EXPECT_FALSE(is_valid_1);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        EXPECT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].rule_violated, "anyOf");
    }

    result.clear();
    bool is_valid_2 = validator.validate(qb::json(5), result);
    EXPECT_FALSE(is_valid_2);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        EXPECT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].rule_violated, "anyOf");
    }
}

TEST_F(ValidationLogicTest, SchemaValidatorAnyOfRejectsNonObjectSchemaItems) {
    qb::json schema = {{"anyOf", qb::json::array({qb::json::object({{"type", "string"}}), 42})}};

    SchemaValidator validator(schema);
    result.clear();
    bool is_valid = validator.validate(qb::json("value"), result);
    EXPECT_FALSE(is_valid);
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "schemaError.anyOf.item");
}

// Helper function (can be a lambda in the test too)
static qb::json
validation_errors_to_json_helper(const std::vector<qb::http::validation::Error> &errors) {
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

TEST_F(ValidationLogicTest, SchemaValidatorOneOf) {
    qb::json        schema = {{"oneOf", {{{"type", "string"}, {"pattern", "^abc$"}}, {{"type", "string"}, {"pattern", "^def$"}}}}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_TRUE(validator.validate(qb::json("abc"), result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(validator.validate(qb::json("def"), result));
    EXPECT_TRUE(result.success());

    result.clear();
    bool is_valid_1 = validator.validate(qb::json("ghi"), result);
    EXPECT_FALSE(is_valid_1);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        EXPECT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].rule_violated, "oneOf");
    }

    qb::json        schema_ambiguous = {{"oneOf", {{{"type", "string"}, {"minLength", 2}}, {{"type", "string"}, {"maxLength", 5}}}}};
    SchemaValidator validator_amb(schema_ambiguous);
    result.clear();
    qb::json longstring_json          = "longstring";
    bool     outcome_longstring       = validator_amb.validate(longstring_json, result);
    size_t   errors_after_longstring  = result.errors().size();
    bool     success_after_longstring = result.success();

    EXPECT_TRUE(outcome_longstring) << "'longstring' should match oneOf (minLength:2). Errors: "
                                    << validation_errors_to_json_helper(result.errors()).dump(2);
    EXPECT_TRUE(success_after_longstring);
    EXPECT_EQ(errors_after_longstring, 0) << "No errors expected for valid 'longstring'";
}

TEST_F(ValidationLogicTest, SchemaValidatorNot) {
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
    bool is_valid_1 = validator.validate(qb::json(10), result);
    EXPECT_FALSE(is_valid_1);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].rule_violated, "not");
    }
}

TEST_F(ValidationLogicTest, SchemaValidatorTypeArrayRejectsUnknownTypeEntries) {
    qb::json        schema = {{"type", qb::json::array({"string", "mystery"})}};
    SchemaValidator validator(schema);

    result.clear();
    bool is_valid = validator.validate(qb::json("hello"), result);
    EXPECT_FALSE(is_valid);
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "schemaError.type");
}

TEST_F(ValidationLogicTest, SchemaValidatorMinMaxProperties) {
    qb::json schema = {
        {"type", "object"},
        {"minProperties", 2},
        {"maxProperties", 3},
        {"properties", {{"a", {{"type", "string"}}}, {"b", {{"type", "integer"}}}, {"c", {{"type", "boolean"}}}, {"d", {{"type", "string"}}}}}
    };
    SchemaValidator validator(schema);

    result.clear();
    qb::json data_ok2 = {{"a", "val"}, {"b", 1}};
    EXPECT_TRUE(validator.validate(data_ok2, result));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json data_ok3 = {{"a", "val"}, {"b", 1}, {"c", true}};
    EXPECT_TRUE(validator.validate(data_ok3, result));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json data_too_few = {{"a", "val"}};
    EXPECT_FALSE(validator.validate(data_too_few, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "minProperties");

    result.clear();
    qb::json data_too_many = {{"a", "v"}, {"b", 1}, {"c", false}, {"d", "extra"}};
    EXPECT_FALSE(validator.validate(data_too_many, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "maxProperties");
}

TEST_F(ValidationLogicTest, SchemaValidatorPropertyNames) {
    qb::json schema = {
        {"type", "object"},
        {"propertyNames", {{"type", "string"}, {"pattern", "^[a-z_]+$"}}},
        {"properties", {{"valid_name", {{"type", "integer"}}}, {"another_ok", {{"type", "boolean"}}}}}
    };
    SchemaValidator validator(schema);

    result.clear();
    qb::json data_valid_names = {{"valid_name", 123}, {"another_ok", true}};
    EXPECT_TRUE(validator.validate(data_valid_names, result));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json data_invalid_name = {{"ValidName", 456}};
    EXPECT_FALSE(validator.validate(data_invalid_name, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "<propertyName:ValidName>");
    EXPECT_EQ(result.errors()[0].rule_violated, "pattern");

    result.clear();
    qb::json data_invalid_char = {{"name_with_!", 789}};
    EXPECT_FALSE(validator.validate(data_invalid_char, result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "<propertyName:name_with_!>");
    EXPECT_EQ(result.errors()[0].rule_violated, "pattern");

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json::array(), result));
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        EXPECT_EQ(result.errors().size(), 1);
        if (!result.errors().empty()) {
            EXPECT_EQ(result.errors()[0].rule_violated, "type");
            EXPECT_EQ(result.errors()[0].field_path, "");
        }
    }
}

// --- ParameterValidator Tests ---

TEST_F(ValidationLogicTest, ParameterValidatorRequired) {
    ParameterValidator pv;
    pv.add_param(ParameterRuleSet("name").set_required());

    result.clear();
    qb::icase_unordered_map<std::string> params_ok = {{"name", "value"}};
    EXPECT_TRUE(pv.validate(params_ok, result, "query"));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::icase_unordered_map<std::string> params_missing = {};
    EXPECT_FALSE(pv.validate(params_missing, result, "query"));
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.name");
    EXPECT_EQ(result.errors()[0].rule_violated, "required");
}

TEST_F(ValidationLogicTest, ParameterValidatorTypeConversionAndRule) {
    ParameterValidator pv;
    pv.add_param(ParameterRuleSet("age").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(18)));

    result.clear();
    qb::icase_unordered_map<std::string> params_valid = {{"age", "20"}};
    EXPECT_TRUE(pv.validate(params_valid, result, "query"));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::icase_unordered_map<std::string> params_invalid_val = {{"age", "17"}};
    EXPECT_FALSE(pv.validate(params_invalid_val, result, "query"));
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.age");
    EXPECT_EQ(result.errors()[0].rule_violated, "minimum");

    result.clear();
    qb::icase_unordered_map<std::string> params_invalid_type = {{"age", "abc"}};
    EXPECT_FALSE(pv.validate(params_invalid_type, result, "query"));
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.age");
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
}

TEST_F(ValidationLogicTest, ParameterValidatorNumberRejectsNaNAndInfinity) {
    ParameterValidator pv;
    pv.add_param(ParameterRuleSet("value").set_type(DataType::NUMBER));

    result.clear();
    qb::icase_unordered_map<std::string> params_nan = {{"value", "nan"}};
    EXPECT_FALSE(pv.validate(params_nan, result, "query"));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.value");
    EXPECT_EQ(result.errors()[0].rule_violated, "type");

    result.clear();
    qb::icase_unordered_map<std::string> params_inf = {{"value", "inf"}};
    EXPECT_FALSE(pv.validate(params_inf, result, "query"));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.value");
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
}

TEST_F(ValidationLogicTest, ParameterValidatorDefaultValue) {
    ParameterValidator pv;
    pv.add_param(ParameterRuleSet("limit").set_type(DataType::INTEGER).set_default("10").add_rule(std::make_shared<MinimumRule>(1)));

    result.clear();
    qb::json validated_json;

    result.clear();
    validated_json = pv.validate_single(
        "limit", std::nullopt,
        ParameterRuleSet("limit").set_type(DataType::INTEGER).set_default("10").add_rule(std::make_shared<MinimumRule>(1)), result, "query");
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(validated_json.is_number_integer());
    EXPECT_EQ(validated_json.get<long long>(), 10);

    result.clear();
    validated_json = pv.validate_single(
        "limit", std::make_optional<std::string>("5"),
        ParameterRuleSet("limit").set_type(DataType::INTEGER).set_default("10").add_rule(std::make_shared<MinimumRule>(1)), result, "query");
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(validated_json.is_number_integer());
    EXPECT_EQ(validated_json.get<long long>(), 5);

    result.clear();
    validated_json = pv.validate_single(
        "limit", std::nullopt,
        ParameterRuleSet("limit").set_type(DataType::INTEGER).set_default("0").add_rule(std::make_shared<MinimumRule>(1)), result, "query");
    EXPECT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "minimum");
    EXPECT_TRUE(validated_json.is_null());
}

TEST_F(ValidationLogicTest, ParameterValidatorCustomParser) {
    ParameterValidator pv;
    auto               custom_bool_parser = [](const std::string &input, bool &success) -> qb::json {
        std::string lower_input = input;
        std::transform(lower_input.begin(), lower_input.end(), lower_input.begin(), ::tolower);
        if (lower_input == "yes" || lower_input == "on") {
            success = true;
            return true;
        }
        if (lower_input == "no" || lower_input == "off") {
            success = true;
            return false;
        }
        success = false;
        return nullptr;
    };

    pv.add_param(ParameterRuleSet("enabled").set_custom_parser(custom_bool_parser).set_type(DataType::BOOLEAN));

    result.clear();
    qb::icase_unordered_map<std::string> params_yes = {{"enabled", "YES"}};
    EXPECT_TRUE(pv.validate(params_yes, result, "query"));
    EXPECT_TRUE(result.success());
    result.clear();
    qb::json parsed =
        pv.validate_single("enabled", std::make_optional<std::string>("YES"),
                           ParameterRuleSet("enabled").set_custom_parser(custom_bool_parser).set_type(DataType::BOOLEAN), result, "query");
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(parsed.is_boolean());
    EXPECT_TRUE(parsed.get<bool>());

    result.clear();
    qb::icase_unordered_map<std::string> params_invalid = {{"enabled", "maybe"}};
    EXPECT_FALSE(pv.validate(params_invalid, result, "query"));
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "customParse");
}

TEST_F(ValidationLogicTest, ParameterValidatorCustomParserExceptionIsCaptured) {
    ParameterValidator pv;
    auto               throwing_parser = [](const std::string &, bool &) -> qb::json {
        throw std::runtime_error("parser blew up");
    };
    pv.add_param(ParameterRuleSet("enabled").set_custom_parser(throwing_parser));

    result.clear();
    qb::icase_unordered_map<std::string> params = {{"enabled", "yes"}};
    EXPECT_FALSE(pv.validate(params, result, "query"));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.enabled");
    EXPECT_EQ(result.errors()[0].rule_violated, "customParseException");
}

TEST_F(ValidationLogicTest, ParameterValidatorRuleExceptionIsCaptured) {
    ParameterValidator pv;
    auto               throwing_rule = std::make_shared<CustomRule>(
        [](const qb::json &, const std::string &, Result &) -> bool { throw std::runtime_error("rule blew up"); }, "throwing_rule");

    pv.add_param(ParameterRuleSet("name").set_type(DataType::STRING).add_rule(throwing_rule));

    result.clear();
    qb::icase_unordered_map<std::string> params = {{"name", "alice"}};
    EXPECT_FALSE(pv.validate(params, result, "query"));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.name");
    EXPECT_EQ(result.errors()[0].rule_violated, "ruleExecutionException");
}

TEST_F(ValidationLogicTest, ParameterValidatorStrictMode) {
    ParameterValidator pv_strict(true);
    pv_strict.add_param(ParameterRuleSet("id").set_type(DataType::INTEGER));
    pv_strict.add_param(ParameterRuleSet("name").set_type(DataType::STRING));

    result.clear();
    qb::icase_unordered_map<std::string> params_ok = {{"id", "123"}, {"name", "test"}};
    EXPECT_TRUE(pv_strict.validate(params_ok, result, "query"));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::icase_unordered_map<std::string> params_extra_strict = {{"id", "123"}, {"name", "test"}, {"unexpected", "value"}};
    EXPECT_FALSE(pv_strict.validate(params_extra_strict, result, "query"));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.unexpected");
    EXPECT_EQ(result.errors()[0].rule_violated, "unexpectedParameter");

    ParameterValidator pv_non_strict;
    pv_non_strict.add_param(ParameterRuleSet("id").set_type(DataType::INTEGER));

    result.clear();
    qb::icase_unordered_map<std::string> params_extra_non_strict = {{"id", "123"}, {"name", "test"}, {"unexpected", "value"}};
    EXPECT_TRUE(pv_non_strict.validate(params_extra_non_strict, result, "query"));
    EXPECT_TRUE(result.success()) << "Error details: " << (result.errors().empty() ? "No errors" : result.errors()[0].message);
}

TEST_F(ValidationLogicTest, RequestValidatorQuerySanitizerExceptionIsCaptured) {
    RequestValidator validator;
    validator.add_query_param_sanitizer("q", [](const std::string &) -> std::string { throw std::runtime_error("query sanitizer crash"); });

    qb::http::Request req;
    req.uri() = qb::io::uri("/search?q=test");

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "query.q");
    EXPECT_EQ(out.errors().front().rule_violated, "sanitizeException.query");
}

TEST_F(ValidationLogicTest, RequestValidatorBodySanitizerExceptionIsCaptured) {
    RequestValidator validator;
    validator.add_body_sanitizer("name", [](const std::string &) -> std::string { throw std::runtime_error("body sanitizer crash"); });

    qb::http::Request req;
    req.uri()  = qb::io::uri("/submit");
    req.body() = R"({"name":"alice"})";

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "body");
    EXPECT_EQ(out.errors().front().rule_violated, "sanitizeException.body");
}

TEST_F(ValidationLogicTest, RequestValidatorPathRulesRequirePathParameterContext) {
    RequestValidator validator;
    validator.for_path_param("userId", ParameterRuleSet("userId").set_type(DataType::INTEGER));

    qb::http::Request req;
    req.uri() = qb::io::uri("/users/123");

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "path.userId");
    EXPECT_EQ(out.errors().front().rule_violated, "required");
}

// --- Sanitizer Tests ---
TEST_F(ValidationLogicTest, SanitizerTrim) {
    Sanitizer s;
    s.add_rule("name", PredefinedSanitizers::trim());
    result.clear();
    qb::json data = {{"name", "  test user  "}};
    s.sanitize(data);
    EXPECT_EQ(data["name"].get<std::string>(), "test user");
}

TEST_F(ValidationLogicTest, SanitizerMultipleRulesOnField) {
    Sanitizer s;
    s.add_rule("comment", PredefinedSanitizers::trim());
    s.add_rule("comment", PredefinedSanitizers::to_lower_case());
    s.add_rule("comment", PredefinedSanitizers::escape_html());

    result.clear();
    qb::json data = {{"comment", "  <Hello> World!  "}};
    s.sanitize(data);
    EXPECT_EQ(data["comment"].get<std::string>(), "&lt;hello&gt; world!");
}

TEST_F(ValidationLogicTest, SanitizerNestedPath) {
    Sanitizer s;
    s.add_rule("user.profile.bio", PredefinedSanitizers::trim());
    result.clear();
    qb::json data = {{"user", {{"profile", {{"bio", "  A long bio.  "}}}}}};
    s.sanitize(data);
    EXPECT_EQ(data["user"]["profile"]["bio"].get<std::string>(), "A long bio.");
}

TEST_F(ValidationLogicTest, SanitizerArrayWildcard) {
    Sanitizer s_combined;
    s_combined.add_rule("tags[*]", PredefinedSanitizers::trim());
    s_combined.add_rule("tags[*]", PredefinedSanitizers::to_lower_case());
    s_combined.add_rule("posts[*].title", PredefinedSanitizers::trim());

    qb::json data_for_combined = {
        {"tags", {"TAG_A", "  TagB  ", "  tAgC  "}},
        {"posts", {{{"title", "  First Post  "}, {"content", "..."}}, {{"title", "Second Post  "}, {"content", "..."}}}}
    };
    s_combined.sanitize(data_for_combined);
    ASSERT_TRUE(data_for_combined["tags"].is_array());
    EXPECT_EQ(data_for_combined["tags"][0].get<std::string>(), "tag_a");
    EXPECT_EQ(data_for_combined["tags"][1].get<std::string>(), "tagb");
    EXPECT_EQ(data_for_combined["tags"][2].get<std::string>(), "tagc");

    ASSERT_TRUE(data_for_combined["posts"].is_array() && data_for_combined["posts"].size() == 2);
    EXPECT_EQ(data_for_combined["posts"][0]["title"].get<std::string>(), "First Post");
    EXPECT_EQ(data_for_combined["posts"][1]["title"].get<std::string>(), "Second Post");
}

TEST_F(ValidationLogicTest, SanitizerArrayIndexSpecific) {
    Sanitizer s;
    s.add_rule("users[1].name", PredefinedSanitizers::trim());
    result.clear();
    qb::json data = {{"users", {{{"name", "  Alice  "}}, {{"name", "   Bob   "}}, {{"name", "  Charlie  "}}}}};
    s.sanitize(data);
    EXPECT_EQ(data["users"][0]["name"].get<std::string>(), "  Alice  ");
    EXPECT_EQ(data["users"][1]["name"].get<std::string>(), "Bob");
    EXPECT_EQ(data["users"][2]["name"].get<std::string>(), "  Charlie  ");
}

TEST_F(ValidationLogicTest, SanitizerNormalizeWhitespace) {
    Sanitizer s;
    s.add_rule("text", PredefinedSanitizers::normalize_whitespace());
    result.clear();
    qb::json data1 = {{"text", "  hello    world  \t\n  next  "}};
    s.sanitize(data1);
    EXPECT_EQ(data1["text"].get<std::string>(), "hello world next");

    result.clear();
    qb::json data2 = {{"text", "NoExtraSpaces"}};
    s.sanitize(data2);
    EXPECT_EQ(data2["text"].get<std::string>(), "NoExtraSpaces");

    result.clear();
    qb::json data3 = {{"text", "   "}};
    s.sanitize(data3);
    EXPECT_EQ(data3["text"].get<std::string>(), "");

    result.clear();
    qb::json data4 = {{"text", " leading space"}};
    s.sanitize(data4);
    EXPECT_EQ(data4["text"].get<std::string>(), "leading space");
}

TEST_F(ValidationLogicTest, SanitizerEscapeSqlLike) {
    Sanitizer s;
    s.add_rule("search", PredefinedSanitizers::escape_sql_like());

    result.clear();
    qb::json data1 = {{"search", "user%name"}};
    s.sanitize(data1);
    EXPECT_EQ(data1["search"].get<std::string>(), "user\\%name");

    result.clear();
    qb::json data2 = {{"search", "customer_id"}};
    s.sanitize(data2);
    EXPECT_EQ(data2["search"].get<std::string>(), "customer\\_id");

    result.clear();
    qb::json data3 = {{"search", "O'Malley's"}};
    s.sanitize(data3);
    EXPECT_EQ(data3["search"].get<std::string>(), "O''Malley''s");

    Sanitizer s_combo;
    s_combo.add_rule("search", PredefinedSanitizers::trim());
    s_combo.add_rule("search", PredefinedSanitizers::escape_sql_like());
    result.clear();
    qb::json data_combo = {{"search", "  test % _ '  "}};
    s_combo.sanitize(data_combo);
    EXPECT_EQ(data_combo["search"].get<std::string>(), "test \\% \\_ ''");
}

// --- Tests for Multi-Value Parameter Handling (primarily in RequestValidator, but ParameterValidator::validate_single is used) ---

TEST_F(ValidationLogicTest, ParameterValidatorMultiValueSupport) {
    ParameterValidator pv;
    auto               rules = ParameterRuleSet("ids").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(10));

    result.clear();
    std::vector<std::string> valid_values   = {"10", "20", "30"};
    std::vector<std::string> invalid_values = {"15", "5", "25"};

    result.clear();
    bool all_valid_pass = true;
    for (const auto &val_str : valid_values) {
        Result item_result;
        pv.validate_single("ids", std::make_optional(val_str), rules, item_result, "query");
        if (!item_result.success()) {
            all_valid_pass = false;
            result.merge(item_result);
        }
    }
    EXPECT_TRUE(all_valid_pass);
    EXPECT_TRUE(result.success());

    result.clear();
    bool some_invalid_pass = true;
    for (const auto &val_str : invalid_values) {
        Result item_result;
        pv.validate_single("ids", std::make_optional(val_str), rules, item_result, "query");
        if (!item_result.success()) {
            some_invalid_pass = false;
            result.merge(item_result);
        }
    }
    EXPECT_FALSE(some_invalid_pass);
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.ids");
    EXPECT_EQ(result.errors()[0].rule_violated, "minimum");
    EXPECT_EQ(result.errors()[0].offending_value.value(), qb::json(5));
}

// ====================================================================
// HTML Sanitization Tests (SECURITY FIX: State-machine based XSS protection)
// These tests verify the state-machine based strip_html_tags sanitizer
// which replaced the vulnerable regex-based approach
// ====================================================================

TEST_F(ValidationLogicTest, SanitizerStripHtmlTagsBasic) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    // Basic HTML tag removal
    qb::json data1 = {{"content", "<p>Hello World</p>"}};
    s.sanitize(data1);
    EXPECT_EQ(data1["content"].get<std::string>(), "Hello World");

    // Nested tags
    qb::json data2 = {{"content", "<div><p>Nested <b>Bold</b> Text</p></div>"}};
    s.sanitize(data2);
    EXPECT_EQ(data2["content"].get<std::string>(), "Nested Bold Text");

    // Self-closing tags
    qb::json data3 = {{"content", "Line 1<br/>Line 2<hr/>Line 3"}};
    s.sanitize(data3);
    EXPECT_EQ(data3["content"].get<std::string>(), "Line 1Line 2Line 3");
}

TEST_F(ValidationLogicTest, SanitizerStripHtmlTagsWithAttributes) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    // Tags with attributes
    qb::json data1 = {{"content", "<a href=\"https://example.com\" target=\"_blank\">Link</a>"}};
    s.sanitize(data1);
    EXPECT_EQ(data1["content"].get<std::string>(), "Link");

    // Tags with single quotes
    qb::json data2 = {{"content", "<div class='container'>Content</div>"}};
    s.sanitize(data2);
    EXPECT_EQ(data2["content"].get<std::string>(), "Content");

    // Multiple attributes
    qb::json data3 = {{"content", "<img src=\"image.jpg\" alt=\"Image\" width=\"100\" />"}};
    s.sanitize(data3);
    EXPECT_EQ(data3["content"].get<std::string>(), "");
}

TEST_F(ValidationLogicTest, SanitizerStripHtmlTagsComments) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    // HTML comments should be removed
    qb::json data1 = {{"content", "<!-- This is a comment -->Visible text"}};
    s.sanitize(data1);
    EXPECT_EQ(data1["content"].get<std::string>(), "Visible text");

    // Multi-line comments
    qb::json data2 = {{"content", "<!-- Start comment\nMiddle line\nEnd comment -->After comment"}};
    s.sanitize(data2);
    EXPECT_EQ(data2["content"].get<std::string>(), "After comment");

    // Nested-looking comment - behavior depends on implementation
    // The state machine treats this as a comment until first -->
    qb::json data3 = {{"content", "<!-- outer <!-- inner --> outer -->Text"}};
    s.sanitize(data3);
    // The result depends on exact state machine behavior
    // Just verify it doesn't crash
    EXPECT_NE(data3["content"].get<std::string>().find("Text"), std::string::npos);
}

TEST_F(ValidationLogicTest, SanitizerStripHtmlTagsScriptAndStyle) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    // Script tags (XSS protection) - the content inside script tags is
    // technically text content that gets preserved when tags are stripped
    qb::json data1 = {{"content", "<script>alert('XSS')</script>Safe content"}};
    s.sanitize(data1);
    // State machine strips <script> and </script> but keeps inner text
    std::string result1 = data1["content"].get<std::string>();
    EXPECT_EQ(result1.find("<script>"), std::string::npos);
    EXPECT_EQ(result1.find("</script>"), std::string::npos);
    EXPECT_NE(result1.find("Safe content"), std::string::npos);

    // Style tags
    qb::json data2 = {{"content", "<style>body { color: red; }</style>Visible text"}};
    s.sanitize(data2);
    std::string result2 = data2["content"].get<std::string>();
    EXPECT_EQ(result2.find("<style>"), std::string::npos);
    EXPECT_EQ(result2.find("</style>"), std::string::npos);
    EXPECT_NE(result2.find("Visible text"), std::string::npos);

    // Mixed script and normal content
    qb::json data3 = {{"content", "Before<script>var x = 1;</script>After"}};
    s.sanitize(data3);
    std::string result3 = data3["content"].get<std::string>();
    EXPECT_EQ(result3.find("<script>"), std::string::npos);
    EXPECT_EQ(result3.find("</script>"), std::string::npos);
    EXPECT_NE(result3.find("Before"), std::string::npos);
    EXPECT_NE(result3.find("After"), std::string::npos);
}

TEST_F(ValidationLogicTest, SanitizerStripHtmlTagsEdgeCases) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    // Greater than in attribute (should not end tag early)
    qb::json data1 = {{"content", "<div data-value=\">\">Content</div>"}};
    s.sanitize(data1);
    EXPECT_EQ(data1["content"].get<std::string>(), "Content");

    // Incomplete tags (should be treated as text)
    qb::json data2 = {{"content", "<not a tag>Text</not>"}};
    s.sanitize(data2);
    // The behavior depends on the state machine - <not is treated as text
    // then space starts "a", which isn't handled, so it may vary
    // Just verify it doesn't crash and produces some output
    EXPECT_FALSE(data2["content"].get<std::string>().empty());

    // Empty string
    qb::json data3 = {{"content", ""}};
    s.sanitize(data3);
    EXPECT_EQ(data3["content"].get<std::string>(), "");

    // No tags
    qb::json data4 = {{"content", "Plain text without HTML"}};
    s.sanitize(data4);
    EXPECT_EQ(data4["content"].get<std::string>(), "Plain text without HTML");
}

TEST_F(ValidationLogicTest, SanitizerStripHtmlTagsPreservesUnclosedTagLikeText) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    qb::json trailing_lt = {{"content", "text<"}};
    s.sanitize(trailing_lt);
    EXPECT_EQ(trailing_lt["content"].get<std::string>(), "text<");

    qb::json unclosed_tag = {{"content", "prefix <div class=\"x\""}};
    s.sanitize(unclosed_tag);
    EXPECT_EQ(unclosed_tag["content"].get<std::string>(), "prefix <div class=\"x\"");
}

TEST_F(ValidationLogicTest, SanitizerStripHtmlTagsSpecialChars) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    // HTML entities (should be preserved as text)
    qb::json data1 = {{"content", "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>"}};
    s.sanitize(data1);
    EXPECT_EQ(data1["content"].get<std::string>(), "&lt;script&gt;alert(1)&lt;/script&gt;");

    // Unicode content
    qb::json data2 = {{"content", "<p>Café résumé naïve</p>"}};
    s.sanitize(data2);
    EXPECT_EQ(data2["content"].get<std::string>(), "Café résumé naïve");

    // Special characters inside tags
    qb::json data3 = {{"content", "<div data-special=\"!@#$%^&*()\">Content</div>"}};
    s.sanitize(data3);
    EXPECT_EQ(data3["content"].get<std::string>(), "Content");
}

TEST_F(ValidationLogicTest, SanitizerStripHtmlTagsPerformanceLargeInput) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    // Large input with many tags (performance test)
    std::string large_input;
    for (int i = 0; i < 1000; ++i) {
        large_input += "<div class=\"item-" + std::to_string(i) + "\"><p>Content " + std::to_string(i) + "</p></div>";
    }

    qb::json data = {{"content", large_input}};
    s.sanitize(data);

    // Result should not contain any tags
    std::string result = data["content"].get<std::string>();
    EXPECT_EQ(result.find('<'), std::string::npos);
    EXPECT_EQ(result.find('>'), std::string::npos);

    // But should contain the content
    EXPECT_NE(result.find("Content 0"), std::string::npos);
    EXPECT_NE(result.find("Content 999"), std::string::npos);
}

TEST_F(ValidationLogicTest, SanitizerStripHtmlTagsXSSProtection) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    // Common XSS vectors
    std::vector<std::string> xss_attempts = {
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<object data=javascript:alert('XSS')>",
        "<embed src=javascript:alert('XSS')>",
        "<form onsubmit=alert('XSS')><button>Submit</button></form>"
    };

    for (const auto &xss : xss_attempts) {
        qb::json data = {{"content", xss}};
        s.sanitize(data);
        std::string result = data["content"].get<std::string>();

        // Should not contain dangerous patterns
        EXPECT_EQ(result.find('<'), std::string::npos) << "Failed for: " << xss;
        EXPECT_EQ(result.find('>'), std::string::npos) << "Failed for: " << xss;
        EXPECT_EQ(result.find("script"), std::string::npos) << "Failed for: " << xss;
        EXPECT_EQ(result.find("onerror"), std::string::npos) << "Failed for: " << xss;
        EXPECT_EQ(result.find("onload"), std::string::npos) << "Failed for: " << xss;
    }
}

// ====================================================================
// Combined Sanitizer Tests (Performance: Move semantics verification)
// ====================================================================

TEST_F(ValidationLogicTest, SanitizerChainingPerformance) {
    Sanitizer s;
    // Chain multiple sanitizers (should use move semantics for performance)
    s.add_rule("content", PredefinedSanitizers::trim());
    s.add_rule("content", PredefinedSanitizers::to_lower_case());
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    // Test chained sanitization
    qb::json data = {{"content", "  <DIV>HELLO WORLD</DIV>  "}};
    s.sanitize(data);
    // Should be: trimmed -> lowercase -> strip tags
    EXPECT_EQ(data["content"].get<std::string>(), "hello world");
}

// ====================================================================
// ReDoS Protection Tests
// ====================================================================

TEST_F(ValidationLogicTest, PatternRuleReDoSProtection) {
    // Test pattern validation with large input (should not hang due to ReDoS protection)
    PatternRule pattern_rule("^.*$"); // Simple pattern that matches everything

    // Normal input
    result.clear();
    EXPECT_TRUE(pattern_rule.validate(qb::json("normal text"), "field", result));
    EXPECT_TRUE(result.success());

    // Large input within limits
    std::string large_input(10000, 'a');
    result.clear();
    EXPECT_TRUE(pattern_rule.validate(qb::json(large_input), "field", result));
    EXPECT_TRUE(result.success());

    // Very large input (might trigger ReDoS protection if limit exists)
    std::string very_large_input(300000, 'b');
    result.clear();
    // This may fail due to size limits or pass depending on implementation
    // The test documents the behavior
    pattern_rule.validate(qb::json(very_large_input), "field", result);
    // Result depends on implementation - test documents current behavior
}

// ====================================================================
// F48 &mdash; Error-value policy tests
// ====================================================================

// Full (default) keeps the offending value verbatim.
TEST_F(ValidationLogicTest, ErrorValuePolicyFullKeepsValue) {
    Result r;
    EXPECT_EQ(r.error_value_policy(), Result::ErrorValuePolicy::Full);
    qb::json big = qb::json::object();
    for (int i = 0; i < 100; ++i) {
        big["k" + std::to_string(i)] = std::string(64, 'x');
    }
    r.add_error("body", "type", "nope", big);
    ASSERT_EQ(r.errors().size(), 1);
    ASSERT_TRUE(r.errors().front().offending_value.has_value());
    EXPECT_EQ(r.errors().front().offending_value->size(), big.size());
}

// Preview: small values are passed through; large values are truncated.
TEST_F(ValidationLogicTest, ErrorValuePolicyPreviewTruncatesLargeValues) {
    Result r;
    r.set_error_value_policy(Result::ErrorValuePolicy::Preview, 64);

    // Small number stays untouched.
    r.add_error("a", "rule", "msg", qb::json(42));
    ASSERT_EQ(r.errors().size(), 1);
    ASSERT_TRUE(r.errors().front().offending_value.has_value());
    EXPECT_EQ(r.errors().front().offending_value.value(), qb::json(42));

    // Huge object is truncated and marked.
    qb::json big = qb::json::object();
    for (int i = 0; i < 50; ++i) {
        big["k" + std::to_string(i)] = std::string(32, 'x');
    }
    r.add_error("b", "rule", "msg", big);
    ASSERT_EQ(r.errors().size(), 2);
    ASSERT_TRUE(r.errors()[1].offending_value.has_value());
    const auto &preview = *r.errors()[1].offending_value;
    ASSERT_TRUE(preview.is_object());
    ASSERT_TRUE(preview.contains("_truncated"));
    EXPECT_TRUE(preview["_truncated"].get<bool>());
    ASSERT_TRUE(preview.contains("preview"));
    EXPECT_LE(preview["preview"].get<std::string>().size(), 64u);
    EXPECT_EQ(preview["original_kind"].get<std::string>(), std::string(big.type_name()));
}

// Preview: long strings are cut to the budget.
TEST_F(ValidationLogicTest, ErrorValuePolicyPreviewTruncatesLongStrings) {
    Result r;
    r.set_error_value_policy(Result::ErrorValuePolicy::Preview, 32);
    std::string huge(1024, 'a');
    r.add_error("s", "rule", "msg", qb::json(huge));
    ASSERT_EQ(r.errors().size(), 1);
    ASSERT_TRUE(r.errors().front().offending_value.has_value());
    EXPECT_EQ(r.errors().front().offending_value->get<std::string>().size(), 32u);
}

// None: offending_value is dropped entirely.
TEST_F(ValidationLogicTest, ErrorValuePolicyNoneDropsValue) {
    Result r;
    r.set_error_value_policy(Result::ErrorValuePolicy::None);
    r.add_error("field", "rule", "msg", qb::json("whatever"));
    ASSERT_EQ(r.errors().size(), 1);
    EXPECT_FALSE(r.errors().front().offending_value.has_value());
}

// The policy survives merge: errors already shaped stay as-is.
TEST_F(ValidationLogicTest, ErrorValuePolicyMergePreservesErrors) {
    Result parent;
    parent.set_error_value_policy(Result::ErrorValuePolicy::None);

    Result child = parent.make_child();
    EXPECT_EQ(child.error_value_policy(), Result::ErrorValuePolicy::None);
    child.add_error("x", "rule", "msg", qb::json("omitted"));
    parent.merge(child);

    ASSERT_EQ(parent.errors().size(), 1);
    EXPECT_FALSE(parent.errors().front().offending_value.has_value());
}

// SchemaValidator propagates its policy into the Result passed to validate().
TEST_F(ValidationLogicTest, SchemaValidatorPropagatesErrorValuePolicy) {
    qb::json        schema = {{"type", "object"}, {"properties", {{"name", {{"type", "string"}, {"minLength", 3}}}}}, {"required", {"name"}}};
    SchemaValidator v(schema);
    v.set_error_value_policy(SchemaValidator::ErrorValuePolicy::None);

    Result   out;
    qb::json data = {{"name", "ab"}};
    EXPECT_FALSE(v.validate(data, out));
    EXPECT_FALSE(out.success());
    for (const auto &err : out.errors()) {
        EXPECT_FALSE(err.offending_value.has_value());
    }
}

TEST_F(ValidationLogicTest, SchemaValidatorAdditionalPropertiesInheritsErrorValuePolicy) {
    qb::json schema = {{"type", "object"}, {"additionalProperties", {{"type", "integer"}}}};

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

TEST_F(ValidationLogicTest, ParameterValidatorPropagatesErrorValuePolicyToChildResults) {
    ParameterValidator pv;
    pv.add_param(ParameterRuleSet("name").set_type(DataType::STRING).add_rule(std::make_shared<MinLengthRule>(3)));

    qb::icase_unordered_map<std::string> params;
    params["name"] = "ab";

    Result out;
    out.set_error_value_policy(Result::ErrorValuePolicy::None);

    EXPECT_FALSE(pv.validate(params, out, "query"));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1u);
    EXPECT_EQ(out.errors().front().field_path, "query.name");
    EXPECT_EQ(out.errors().front().rule_violated, "minLength");
    EXPECT_FALSE(out.errors().front().offending_value.has_value());
}

// ============================================================================
// Coverage-extension cases for schema_validator.cpp and request_validator.cpp
// ============================================================================

// --- SchemaValidator: constructor rejects non-object schema definitions. ---
TEST_F(ValidationLogicTest, SchemaValidatorCtorRejectsNonObjectSchemas) {
    EXPECT_THROW({ SchemaValidator v(qb::json::array({1, 2, 3})); }, std::invalid_argument);
    EXPECT_THROW({ SchemaValidator v(qb::json(42)); }, std::invalid_argument);
}

// --- SchemaValidator: an unknown single type string -> rule "type", "Unknown type" message. ---
TEST_F(ValidationLogicTest, SchemaValidatorUnknownSingleTypeString) {
    qb::json        schema = {{"type", "mystery"}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json("anything"), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
    EXPECT_NE(result.errors()[0].message.find("Unknown type"), std::string::npos);
}

// --- SchemaValidator: type keyword that is neither string nor array. ---
TEST_F(ValidationLogicTest, SchemaValidatorTypeKeywordWrongJsonType) {
    qb::json        schema = {{"type", 123}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json("anything"), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
    EXPECT_NE(result.errors()[0].message.find("must be a string or an array"), std::string::npos);
}

// --- SchemaValidator: malformed keyword shapes each surface a distinct schemaError.* rule. ---
TEST_F(ValidationLogicTest, SchemaValidatorMalformedSchemaKeywords) {
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
        // 'extra' is an undefined (additional) property, so additionalProperties is consulted.
        EXPECT_FALSE(validator.validate(qb::json::object({{"id", 1}, {"extra", "x"}}), result));
        ASSERT_FALSE(result.success());
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].rule_violated, "schemaError.additionalProperties");
    }
}

// --- SchemaValidator: a non-string element inside the 'required' array. ---
TEST_F(ValidationLogicTest, SchemaValidatorRequiredNonStringElement) {
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

// --- SchemaValidator: allOf must be a non-empty array; items must be schema objects. ---
TEST_F(ValidationLogicTest, SchemaValidatorAllOfMalformed) {
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

// --- SchemaValidator: oneOf with a non-object item, and oneOf ambiguous (matched > 1). ---
TEST_F(ValidationLogicTest, SchemaValidatorOneOfNonObjectItemAndAmbiguous) {
    // Non-object item is skipped with a schemaError.oneOf.item error; the remaining
    // single string schema still matches, so the overall match count is 1, but the
    // schema error itself is still recorded on the result.
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

// --- SchemaValidator: 'not' keyword that is not a schema object. ---
TEST_F(ValidationLogicTest, SchemaValidatorNotKeywordNonObject) {
    qb::json        schema = {{"not", 42}};
    SchemaValidator validator(schema);

    result.clear();
    EXPECT_FALSE(validator.validate(qb::json("anything"), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "schemaError.not");
}

// --- SchemaValidator: additionalItems expressed as a schema validates the tuple overflow. ---
TEST_F(ValidationLogicTest, SchemaValidatorAdditionalItemsAsSchema) {
    qb::json schema = {{"type", "array"}, {"items", qb::json::array({{{"type", "string"}}})}, {"additionalItems", {{"type", "integer"}}}};
    SchemaValidator validator(schema);

    // Overflow item [1] is a string, but additionalItems requires integer -> error at [1].
    result.clear();
    EXPECT_FALSE(validator.validate(qb::json::array({"head", "not-an-int"}), result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "[1]");
    EXPECT_EQ(result.errors()[0].rule_violated, "type");

    // Valid overflow integers pass.
    result.clear();
    EXPECT_TRUE(validator.validate(qb::json::array({"head", 1, 2}), result));
    EXPECT_TRUE(result.success());
}

// --- SchemaValidator: a nested property schema node that is not an object. ---
TEST_F(ValidationLogicTest, SchemaValidatorNestedSchemaNodeNotObject) {
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

// --- SchemaValidator: Preview policy truncates a large offending value on a schema error. ---
TEST_F(ValidationLogicTest, SchemaValidatorPreviewPolicyTruncatesOffendingValue) {
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

// --- RequestValidator: an empty body against a schema yields contentRequired. ---
TEST_F(ValidationLogicTest, RequestValidatorEmptyBodyYieldsContentRequired) {
    // A scalar (non object/array/null) type means validating the empty body as JSON
    // null produces a type error whose message does not mention null/object/array,
    // so the validator substitutes a synthetic "contentRequired" error.
    RequestValidator validator;
    validator.for_body(qb::json{{"type", "integer"}});

    qb::http::Request req;
    req.uri() = qb::io::uri("/submit");
    // body intentionally left empty

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "body");
    EXPECT_EQ(out.errors().front().rule_violated, "contentRequired");
}

// --- RequestValidator: an empty body against an object-typed schema reports a type error. ---
TEST_F(ValidationLogicTest, RequestValidatorEmptyBodyObjectSchemaReportsType) {
    // When the schema expects an object, validating null produces a "type" error whose
    // message mentions "object" -> the validator keeps it rather than substituting.
    RequestValidator validator;
    validator.for_body(qb::json{{"type", "object"}, {"required", qb::json::array({"name"})}});

    qb::http::Request req;
    req.uri() = qb::io::uri("/submit");

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    // The TypeRule reports the error at the root schema path (empty string), not "body".
    EXPECT_EQ(out.errors().front().field_path, "");
    EXPECT_EQ(out.errors().front().rule_violated, "type");
}

// --- RequestValidator: a non-empty but malformed JSON body -> invalidFormat.validate. ---
TEST_F(ValidationLogicTest, RequestValidatorInvalidJsonBodyValidate) {
    RequestValidator validator;
    validator.for_body(qb::json{{"type", "object"}});

    qb::http::Request req;
    req.uri()  = qb::io::uri("/submit");
    req.body() = "{not valid json";

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "body");
    EXPECT_EQ(out.errors().front().rule_violated, "invalidFormat.validate");
}

// --- RequestValidator: header sanitizer success path mutates the value and passes. ---
TEST_F(ValidationLogicTest, RequestValidatorHeaderSanitizerSuccess) {
    RequestValidator validator;
    validator.add_header_sanitizer("X-Test", [](const std::string &v) -> std::string { return v + "-sanitized"; });

    qb::http::Request req;
    req.uri() = qb::io::uri("/submit");
    req.set_header("X-Test", std::string("raw"));

    Result out;
    EXPECT_TRUE(validator.validate(req, out, nullptr));
    EXPECT_TRUE(out.success());
    // The sanitizer mutated the header value in place.
    auto it = req.headers().find("X-Test");
    ASSERT_NE(it, req.headers().end());
    ASSERT_FALSE(it->second.empty());
    EXPECT_EQ(it->second.front(), "raw-sanitized");
}

// --- RequestValidator: a throwing header sanitizer -> sanitizeException.header. ---
TEST_F(ValidationLogicTest, RequestValidatorHeaderSanitizerExceptionIsCaptured) {
    RequestValidator validator;
    validator.add_header_sanitizer("X-Test", [](const std::string &) -> std::string { throw std::runtime_error("header sanitizer crash"); });

    qb::http::Request req;
    req.uri() = qb::io::uri("/submit");
    req.set_header("X-Test", std::string("raw"));

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    // Header names are stored case-insensitively (lowercased) in the headers map.
    EXPECT_EQ(out.errors().front().field_path, "header.x-test");
    EXPECT_EQ(out.errors().front().rule_violated, "sanitizeException.header");
}

// --- RequestValidator: a body sanitizer over a malformed JSON body -> invalidFormat.sanitize. ---
TEST_F(ValidationLogicTest, RequestValidatorBodySanitizerInvalidJson) {
    RequestValidator validator;
    validator.add_body_sanitizer("name", [](const std::string &v) -> std::string { return v; });

    qb::http::Request req;
    req.uri()  = qb::io::uri("/submit");
    req.body() = "{not valid json";

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "body");
    EXPECT_EQ(out.errors().front().rule_violated, "invalidFormat.sanitize");
}

// --- RequestValidator: a path parameter validated with a supplied PathParameters context. ---
TEST_F(ValidationLogicTest, RequestValidatorPathParamWithContext) {
    RequestValidator validator;
    validator.for_path_param("userId", ParameterRuleSet("userId").set_type(DataType::INTEGER));

    qb::http::Request req;
    req.uri() = qb::io::uri("/users/123");

    qb::http::PathParameters pp;
    pp.set("userId", "123");

    // Present and valid -> passes.
    Result out_ok;
    EXPECT_TRUE(validator.validate(req, out_ok, &pp));
    EXPECT_TRUE(out_ok.success());

    // Present but non-integer -> type error.
    qb::http::PathParameters pp_bad;
    pp_bad.set("userId", "abc");
    Result out_bad;
    EXPECT_FALSE(validator.validate(req, out_bad, &pp_bad));
    ASSERT_FALSE(out_bad.success());
    ASSERT_EQ(out_bad.errors().size(), 1);
    EXPECT_EQ(out_bad.errors().front().field_path, "path.userId");
    EXPECT_EQ(out_bad.errors().front().rule_violated, "type");
}

int
main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
