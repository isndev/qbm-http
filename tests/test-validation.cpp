#include <gtest/gtest.h>
#include "../validation.h" // Main include for the validation system
#include <qb/json.h>

// Using the new namespace directly for clarity in tests
using namespace qb::http::validation;

// --- Test Fixture for Validation Logic ---
class ValidationLogicTest : public ::testing::Test {
protected:
    Result result; // Renamed from ValidationResult

    void SetUp() override {
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
    other_result.add_error("field2", "type", "Must be a string", qb::json(123));
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
    EXPECT_TRUE(rule.validate(qb::json::array({1,2,3}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({1,2}), "test", result));
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
    EXPECT_TRUE(rule.validate(qb::json::array({1,2,3}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({1,2,3,4}), "test", result));
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
    EXPECT_TRUE(rule.validate(qb::json({{"a",1}, {"b",2}}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(
        rule.validate(qb::json::array({qb::json::object({{"a",1}}), qb::json::object({{"a",1}})}), "test", result));
    EXPECT_FALSE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json(123), "test", result));
    EXPECT_TRUE(result.success());
}

TEST_F(ValidationLogicTest, MinItemsRuleValidation) {
    MinItemsRule rule(2);
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1,2}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1,2,3}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({1}), "test", result));
    EXPECT_FALSE(result.success());
}

TEST_F(ValidationLogicTest, MaxItemsRuleValidation) {
    MaxItemsRule rule(2);
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1,2}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({1,2,3}), "test", result));
    EXPECT_FALSE(result.success());
}

TEST_F(ValidationLogicTest, CustomRuleValidation) {
    bool custom_func_called = false;
    auto fn = [&](const qb::json &val, const std::string &path, Result &res) -> bool {
        custom_func_called = true;
        if (val.is_string() && val.get<std::string>() == "custom_valid") {
            return true;
        }
        res.add_error(path, "custom_lambda_error_name", "Value did not meet custom criteria.", val);
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
        {
            "properties", {
                {"name", {{"type", "string"}, {"minLength", 3}}},
                {"age", {{"type", "integer"}, {"minimum", 18}}}
            }
        },
        {"required", {"name"}}
    };
    SchemaValidator validator(schema);

    result.clear();
    qb::json valid_data = {{"name", "Alice"}, {"age", 30}};
    bool is_valid_1 = validator.validate(valid_data, result);
    EXPECT_TRUE(is_valid_1);
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json invalid_name_short = {{"name", "Al"}, {"age", 30}};
    bool outcome_2 = validator.validate(invalid_name_short, result);
    size_t errors_after_call_2 = result.errors().size();
    bool success_after_call_2 = result.success();

    EXPECT_FALSE(outcome_2) << "Validation should fail for short name.";
    EXPECT_FALSE(success_after_call_2) << "Result should show failure for short name.";
    ASSERT_EQ(errors_after_call_2, 1) << "Should be 1 error for short name.";
    if (!success_after_call_2 && errors_after_call_2 == 1) {
        EXPECT_EQ(result.errors()[0].field_path, "name");
        EXPECT_EQ(result.errors()[0].rule_violated, "minLength");
    }

    result.clear();
    qb::json invalid_age = {{"name", "Bob"}, {"age", 17}};
    bool is_valid_3 = validator.validate(invalid_age, result);
    EXPECT_FALSE(is_valid_3);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "age");
        EXPECT_EQ(result.errors()[0].rule_violated, "minimum");
    }
    result.clear();

    qb::json missing_required = {{"age", 25}};
    bool is_valid_4 = validator.validate(missing_required, result);
    EXPECT_FALSE(is_valid_4);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "name");
        EXPECT_EQ(result.errors()[0].rule_violated, "required");
    }
    result.clear();

    qb::json wrong_type = {{"name", 123}, {"age", 30}};
    bool is_valid_5 = validator.validate(wrong_type, result);
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
        {
            "properties", {
                {
                    "user", {
                        {"type", "object"},
                        {
                            "properties", {
                                {"id", {{"type", "integer"}}},
                                {"username", {{"type", "string"}}}
                            }
                        },
                        {"required", {"id", "username"}}
                    }
                }
            }
        }
    };
    SchemaValidator validator(schema);

    result.clear();
    qb::json valid_data = {{"user", {{"id", 1}, {"username", "testuser"}}}};
    bool is_valid_1 = validator.validate(valid_data, result);
    EXPECT_TRUE(is_valid_1);
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json invalid_nested = {{"user", {{"id", "not-an-int"}}}};
    bool is_valid_2 = validator.validate(invalid_nested, result);
    EXPECT_FALSE(is_valid_2);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        EXPECT_EQ(result.errors().size(), 2);

        bool id_type_error_found = false;
        bool username_required_error_found = false;
        for (const auto &err: result.errors()) {
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
    qb::json schema = {
        {"type", "array"},
        {
            "items", {
                {"type", "integer"},
                {"minimum", 0}
            }
        },
        {"minItems", 1}
    };
    SchemaValidator validator(schema);

    result.clear();
    qb::json valid_data = {1, 2, 3};
    bool is_valid_1 = validator.validate(valid_data, result);
    EXPECT_TRUE(is_valid_1);
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json invalid_item_type = {1, "not-an-int", 3};
    bool is_valid_2 = validator.validate(invalid_item_type, result);
    EXPECT_FALSE(is_valid_2);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "[1]");
        EXPECT_EQ(result.errors()[0].rule_violated, "type");
    }

    result.clear();
    qb::json invalid_item_value = {1, -5, 3};
    bool is_valid_3 = validator.validate(invalid_item_value, result);
    EXPECT_FALSE(is_valid_3);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "[1]");
        EXPECT_EQ(result.errors()[0].rule_violated, "minimum");
    }

    result.clear();
    qb::json too_few_items = qb::json::array();
    bool is_valid_4 = validator.validate(too_few_items, result);
    EXPECT_FALSE(is_valid_4) << "Validation should fail for too few items.";
    ASSERT_FALSE(result.success()) << "Result should show failure for too few items.";
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "");
        EXPECT_EQ(result.errors()[0].rule_violated, "minItems");
    }
}

TEST_F(ValidationLogicTest, SchemaValidatorTupleItemsAndAdditionalItems) {
    qb::json schema = {
        {"type", "array"},
        {
            "items", {
                {{"type", "string"}},
                {{"type", "integer"}}
            }
        },
        {"additionalItems", false}
    };
    SchemaValidator validator(schema);

    result.clear();
    qb::json valid_tuple = {"hello", 123};
    bool is_valid_1 = validator.validate(valid_tuple, result);
    EXPECT_TRUE(is_valid_1);
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json too_many_items = {"hello", 123, "extra"};
    bool is_valid_2 = validator.validate(too_many_items, result);
    EXPECT_FALSE(is_valid_2);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "[2]");
        EXPECT_EQ(result.errors()[0].rule_violated, "additionalItems");
    }

    result.clear();
    qb::json wrong_type_in_tuple = {"hello", "not-an-int"};
    bool is_valid_3 = validator.validate(wrong_type_in_tuple, result);
    EXPECT_FALSE(is_valid_3);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        ASSERT_EQ(result.errors().size(), 1);
        EXPECT_EQ(result.errors()[0].field_path, "[1]");
        EXPECT_EQ(result.errors()[0].rule_violated, "type");
    }

    result.clear();
    qb::json schema_additional_schema = {
        {"type", "array"},
        {"items", {{{"type", "string"}}}},
        {"additionalItems", {{"type", "boolean"}}}
    };
    SchemaValidator validator2(schema_additional_schema);
    qb::json valid_additional = {"first", true, false};
    bool is_valid_4 = validator2.validate(valid_additional, result);
    EXPECT_TRUE(is_valid_4);
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json invalid_additional = {"first", true, "not-a-bool"};
    bool is_valid_5 = validator2.validate(invalid_additional, result);
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
    qb::json schema_no_additional = {
        {"type", "object"},
        {
            "properties", {
                {"name", {{"type", "string"}}}
            }
        },
        {"additionalProperties", false}
    };
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
        {"type", "object"},
        {
            "properties", {
                {"id", {{"type", "integer"}}}
            }
        },
        {"additionalProperties", {{"type", "string"}}}
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
        {
            "allOf", {
                {{"type", "object"}, {"properties", {{"a", {{"type", "string"}}}}}},
                {{"type", "object"}, {"properties", {{"b", {{"type", "integer"}}}}}}
            }
        }
    };
    SchemaValidator validator(schema);

    result.clear();
    qb::json valid_data = {{"a", "text"}, {"b", 123}};
    bool is_valid_1 = validator.validate(valid_data, result);
    EXPECT_TRUE(is_valid_1);
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json schema_refined = {
        {
            "allOf", {
                {{"properties", {{"a", {{"type", "string"}}}}}, {"required", {"a"}}},
                {{"properties", {{"b", {{"type", "integer"}}}}}, {"required", {"b"}}}
            }
        }
    };
    SchemaValidator validator_refined(schema_refined);
    EXPECT_TRUE(validator_refined.validate(valid_data, result));
    EXPECT_TRUE(result.success());
    result.clear();
    qb::json invalid_missing_b = {{"a", "text"}};
    bool is_valid_2 = validator_refined.validate(invalid_missing_b, result);
    EXPECT_FALSE(is_valid_2);
    ASSERT_FALSE(result.success());
    if (!result.success()) {
        EXPECT_EQ(result.errors().size(), 2);
        bool all_of_error_found = false;
        bool required_b_error_found = false;
        for (const auto &err: result.errors()) {
            if (err.rule_violated == "allOf") all_of_error_found = true;
            if (err.field_path == "b" && err.rule_violated == "required") required_b_error_found = true;
        }
        EXPECT_TRUE(all_of_error_found);
        EXPECT_TRUE(required_b_error_found);
    }
}

TEST_F(ValidationLogicTest, SchemaValidatorAnyOf) {
    qb::json schema = {
        {
            "anyOf", {
                {{"type", "string"}, {"minLength", 5}},
                {{"type", "integer"}, {"minimum", 10}}
            }
        }
    };
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

// Helper function (can be a lambda in the test too)
static qb::json validation_errors_to_json_helper(const std::vector<qb::http::validation::Error> &errors) {
    qb::json errors_array = qb::json::array();
    for (const auto &err: errors) {
        qb::json err_obj;
        err_obj["field_path"] = err.field_path;
        err_obj["rule_violated"] = err.rule_violated;
        err_obj["message"] = err.message;
        if (err.offending_value.has_value()) {
            err_obj["offending_value"] = err.offending_value.value();
        }
        errors_array.push_back(err_obj);
    }
    return errors_array;
}

TEST_F(ValidationLogicTest, SchemaValidatorOneOf) {
    qb::json schema = {
        {
            "oneOf", {
                {{"type", "string"}, {"pattern", "^abc$"}},
                {{"type", "string"}, {"pattern", "^def$"}}
            }
        }
    };
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

    qb::json schema_ambiguous = {
        {
            "oneOf", {
                {{"type", "string"}, {"minLength", 2}},
                {{"type", "string"}, {"maxLength", 5}}
            }
        }
    };
    SchemaValidator validator_amb(schema_ambiguous);
    result.clear();
    qb::json longstring_json = "longstring";
    bool outcome_longstring = validator_amb.validate(longstring_json, result);
    size_t errors_after_longstring = result.errors().size();
    bool success_after_longstring = result.success();

    EXPECT_TRUE(outcome_longstring) << "'longstring' should match oneOf (minLength:2). Errors: " <<
 validation_errors_to_json_helper(result.errors()).dump(2);
    EXPECT_TRUE(success_after_longstring);
}

TEST_F(ValidationLogicTest, SchemaValidatorNot) {
    qb::json schema = {
        {
            "not", {
                {"type", "integer"}
            }
        }
    };
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

TEST_F(ValidationLogicTest, SchemaValidatorMinMaxProperties) {
    qb::json schema = {
        {"type", "object"},
        {"minProperties", 2},
        {"maxProperties", 3},
        {
            "properties", {
                {"a", {{"type", "string"}}},
                {"b", {{"type", "integer"}}},
                {"c", {{"type", "boolean"}}},
                {"d", {{"type", "string"}}}
            }
        }
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
        {
            "propertyNames", {
                {"type", "string"},
                {"pattern", "^[a-z_]+$"}
            }
        },
        {
            "properties", {
                {"valid_name", {{"type", "integer"}}},
                {"another_ok", {{"type", "boolean"}}}
            }
        }
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

TEST_F(ValidationLogicTest, ParameterValidatorDefaultValue) {
    ParameterValidator pv;
    pv.add_param(
        ParameterRuleSet("limit").set_type(DataType::INTEGER).set_default("10").add_rule(
            std::make_shared<MinimumRule>(1)));

    result.clear();
    qb::json validated_json;
    bool success_flag;

    result.clear();
    validated_json = pv.validate_single("limit", std::nullopt,
                                        ParameterRuleSet("limit").set_type(DataType::INTEGER).set_default("10").
                                        add_rule(std::make_shared<MinimumRule>(1)), result, "query");
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(validated_json.is_number_integer());
    EXPECT_EQ(validated_json.get<long long>(), 10);

    result.clear();
    validated_json = pv.validate_single("limit", std::make_optional<std::string>("5"),
                                        ParameterRuleSet("limit").set_type(DataType::INTEGER).set_default("10").
                                        add_rule(std::make_shared<MinimumRule>(1)), result, "query");
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(validated_json.is_number_integer());
    EXPECT_EQ(validated_json.get<long long>(), 5);

    result.clear();
    validated_json = pv.validate_single("limit", std::nullopt,
                                        ParameterRuleSet("limit").set_type(DataType::INTEGER).set_default("0").add_rule(
                                            std::make_shared<MinimumRule>(1)), result, "query");
    EXPECT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "minimum");
    EXPECT_TRUE(validated_json.is_null());
}

TEST_F(ValidationLogicTest, ParameterValidatorCustomParser) {
    ParameterValidator pv;
    auto custom_bool_parser = [](const std::string &input, bool &success) -> qb::json {
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
    qb::json parsed = pv.validate_single("enabled", std::make_optional<std::string>("YES"),
                                         ParameterRuleSet("enabled").set_custom_parser(custom_bool_parser).set_type(
                                             DataType::BOOLEAN),
                                         result, "query");
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(parsed.is_boolean());
    EXPECT_TRUE(parsed.get<bool>());

    result.clear();
    qb::icase_unordered_map<std::string> params_invalid = {{"enabled", "maybe"}};
    EXPECT_FALSE(pv.validate(params_invalid, result, "query"));
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "customParse");
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
    qb::icase_unordered_map<std::string> params_extra_strict = {
        {"id", "123"}, {"name", "test"}, {"unexpected", "value"}
    };
    EXPECT_FALSE(pv_strict.validate(params_extra_strict, result, "query"));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.unexpected");
    EXPECT_EQ(result.errors()[0].rule_violated, "unexpectedParameter");

    ParameterValidator pv_non_strict;
    pv_non_strict.add_param(ParameterRuleSet("id").set_type(DataType::INTEGER));

    result.clear();
    qb::icase_unordered_map<std::string> params_extra_non_strict = {
        {"id", "123"}, {"name", "test"}, {"unexpected", "value"}
    };
    EXPECT_TRUE(pv_non_strict.validate(params_extra_non_strict, result, "query"));
    EXPECT_TRUE(result.success()) << "Error details: " << (result.errors().empty()
                                                               ? "No errors"
                                                               : result.errors()[0].message);
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
        {
            "posts", {
                {{"title", "  First Post  "}, {"content", "..."}},
                {{"title", "Second Post  "}, {"content", "..."}}
            }
        }
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
    qb::json data = {
        {
            "users", {
                {{"name", "  Alice  "}},
                {{"name", "   Bob   "}},
                {{"name", "  Charlie  "}}
            }
        }
    };
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
    auto rules = ParameterRuleSet("ids").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(10));

    result.clear();
    std::vector<std::string> valid_values = {"10", "20", "30"};
    std::vector<std::string> invalid_values = {"15", "5", "25"};

    result.clear();
    bool all_valid_pass = true;
    for (const auto &val_str: valid_values) {
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
    for (const auto &val_str: invalid_values) {
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
