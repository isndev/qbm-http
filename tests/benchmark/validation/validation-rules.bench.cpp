/**
 * @file qbm/http/tests/benchmark/validation/validation-rules.bench.cpp
 * @brief Cost of JSON Schema length, pattern, numeric bound, and uniqueness validation.
 *
 * Fixtures and schema caches are prepared before timing. Each case verifies its
 * verdict before reporting a number; the timed loop measures repeated validation
 * of an immutable value, as on a warmed HTTP request validator.
 *
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */

#include <benchmark/benchmark.h>
#include <cstdint>
#include <string>

#include <qbm/http/validation.h>

namespace {

using qb::http::validation::Result;
using qb::http::validation::SchemaValidator;

void
run_schema(benchmark::State &state, const qb::json &schema, const qb::json &value, bool expected, const qb::json *counterexample = nullptr) {
    SchemaValidator validator(schema);
    Result          probe;
    if (validator.validate(value, probe) != expected || probe.success() != expected) {
        state.SkipWithError("schema validation returned an unexpected verdict");
        return;
    }
    if (counterexample) {
        Result opposite;
        if (validator.validate(*counterexample, opposite) == expected || opposite.success() == expected) {
            state.SkipWithError("schema validation returned the wrong counterexample verdict");
            return;
        }
    }
    for (auto _ : state) {
        Result result;
        bool   valid = validator.validate(value, result);
        benchmark::DoNotOptimize(valid);
        benchmark::DoNotOptimize(result);
    }
    Result final;
    if (validator.validate(value, final) != expected || final.success() != expected) {
        state.SkipWithError("schema validation verdict changed during measurement");
        return;
    }
    state.SetItemsProcessed(state.iterations());
}

void
BM_Validation_AsciiLength(benchmark::State &state) {
    const auto size = static_cast<std::size_t>(state.range(0));
    run_schema(state, {{"type", "string"}, {"minLength", size}, {"maxLength", size}}, std::string(size, 'a'), true);
}

void
BM_Validation_Utf8Length(benchmark::State &state) {
    const auto  size = static_cast<std::size_t>(state.range(0));
    std::string value;
    value.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i)
        value += "\xC3\xA9";
    run_schema(state, {{"type", "string"}, {"minLength", size}, {"maxLength", size}}, value, true);
}

void
BM_Validation_ExactIntegerBound(benchmark::State &state) {
    constexpr std::uint64_t kTwoTo53 = std::uint64_t{1} << 53;
    run_schema(state, {{"type", "integer"}, {"minimum", kTwoTo53}}, kTwoTo53 + 1, true);
}

void
BM_Validation_UniqueScalars(benchmark::State &state) {
    const auto size   = static_cast<std::size_t>(state.range(0));
    qb::json   values = qb::json::array();
    for (std::size_t i = 0; i < size; ++i)
        values.push_back(i);
    run_schema(state, {{"type", "array"}, {"uniqueItems", true}}, values, true);
}

void
BM_Validation_UniqueObjects(benchmark::State &state) {
    const auto size   = static_cast<std::size_t>(state.range(0));
    qb::json   values = qb::json::array();
    for (std::size_t i = 0; i < size; ++i)
        values.push_back(qb::json{{"id", i}, {"label", "entry"}});
    run_schema(state, {{"type", "array"}, {"uniqueItems", true}}, values, true);
}

// Identical verdict and input on the full-match baseline and search-based schema
// implementation. Construction/compilation stays outside the measured span.
void
BM_Validation_AnchoredPattern(benchmark::State &state) {
    const auto     size     = static_cast<std::size_t>(state.range(0));
    const qb::json rejected = std::string(size, 'A');
    run_schema(state, {{"type", "string"}, {"pattern", "^[a-z]+$"}}, std::string(size, 'a'), true, &rejected);
}

void
BM_Validation_UnanchoredPatternFullInput(benchmark::State &state) {
    const auto     size     = static_cast<std::size_t>(state.range(0));
    const qb::json rejected = std::string(size, 'A');
    run_schema(state, {{"type", "string"}, {"pattern", "[a-z]+"}}, std::string(size, 'a'), true, &rejected);
}

void
BM_Validation_AnchoredPatternNoMatch(benchmark::State &state) {
    const auto     size     = static_cast<std::size_t>(state.range(0));
    const qb::json accepted = std::string(size, 'a');
    run_schema(state, {{"type", "string"}, {"pattern", "^[a-z]+$"}}, std::string(size, 'A'), false, &accepted);
}

void
BM_Validation_UnanchoredPatternNoMatch(benchmark::State &state) {
    const auto     size     = static_cast<std::size_t>(state.range(0));
    const qb::json accepted = std::string(size, 'a');
    run_schema(state, {{"type", "string"}, {"pattern", "[a-z]+"}}, std::string(size, 'A'), false, &accepted);
}

void
run_pattern_rule(benchmark::State &state, bool expected) {
    qb::http::validation::PatternRule rule("[a-z]+");
    const auto                        size  = static_cast<std::size_t>(state.range(0));
    const qb::json                    value = std::string(size, expected ? 'a' : 'A');
    Result                            probe;
    if (rule.validate(value, "value", probe) != expected || probe.success() != expected) {
        state.SkipWithError("full-match pattern rule returned an unexpected verdict");
        return;
    }
    Result opposite;
    if (rule.validate(std::string(size, expected ? 'A' : 'a'), "value", opposite) == expected || opposite.success() == expected) {
        state.SkipWithError("full-match pattern rule returned the wrong counterexample verdict");
        return;
    }
    for (auto _ : state) {
        Result     result;
        const bool valid = rule.validate(value, "value", result);
        benchmark::DoNotOptimize(valid);
        benchmark::DoNotOptimize(result);
    }
    Result final;
    if (rule.validate(value, "value", final) != expected || final.success() != expected) {
        state.SkipWithError("full-match pattern rule verdict changed during measurement");
        return;
    }
    state.SetItemsProcessed(state.iterations());
}

void
BM_Validation_PatternRuleFullMatch(benchmark::State &state) {
    run_pattern_rule(state, true);
}

void
BM_Validation_PatternRuleNoMatch(benchmark::State &state) {
    run_pattern_rule(state, false);
}

} // namespace

BENCHMARK(BM_Validation_AsciiLength)->Arg(32)->Arg(1024)->Arg(65536);
BENCHMARK(BM_Validation_Utf8Length)->Arg(32)->Arg(1024)->Arg(32768);
BENCHMARK(BM_Validation_ExactIntegerBound);
BENCHMARK(BM_Validation_UniqueScalars)->Arg(16)->Arg(128)->Arg(1024);
BENCHMARK(BM_Validation_UniqueObjects)->Arg(16)->Arg(128)->Arg(1024);
BENCHMARK(BM_Validation_AnchoredPattern)->Arg(16)->Arg(256)->Arg(2048);
BENCHMARK(BM_Validation_UnanchoredPatternFullInput)->Arg(16)->Arg(256)->Arg(2048);
BENCHMARK(BM_Validation_PatternRuleFullMatch)->Arg(16)->Arg(256)->Arg(2048);
BENCHMARK(BM_Validation_AnchoredPatternNoMatch)->Arg(16)->Arg(256)->Arg(2048);
BENCHMARK(BM_Validation_UnanchoredPatternNoMatch)->Arg(16)->Arg(256)->Arg(2048);
BENCHMARK(BM_Validation_PatternRuleNoMatch)->Arg(16)->Arg(256)->Arg(2048);

BENCHMARK_MAIN();
