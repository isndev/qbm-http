/**
 * @file qbm/http/tests/benchmark/validation/validation-rules.bench.cpp
 * @brief Cost of JSON Schema length, numeric bound, and uniqueness validation.
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
run_schema(benchmark::State &state, const qb::json &schema, const qb::json &value, bool expected) {
    SchemaValidator validator(schema);
    Result          probe;
    if (validator.validate(value, probe) != expected || probe.success() != expected) {
        state.SkipWithError("schema validation returned an unexpected verdict");
        return;
    }
    for (auto _ : state) {
        Result result;
        bool   valid = validator.validate(value, result);
        benchmark::DoNotOptimize(valid);
        benchmark::DoNotOptimize(result);
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
    run_schema(state, {{"type", "string"}, {"minLength", 1}, {"maxLength", size * 2}}, value, true);
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

} // namespace

BENCHMARK(BM_Validation_AsciiLength)->Arg(32)->Arg(1024)->Arg(65536);
BENCHMARK(BM_Validation_Utf8Length)->Arg(32)->Arg(1024)->Arg(32768);
BENCHMARK(BM_Validation_ExactIntegerBound);
BENCHMARK(BM_Validation_UniqueScalars)->Arg(16)->Arg(128)->Arg(1024);
BENCHMARK(BM_Validation_UniqueObjects)->Arg(16)->Arg(128)->Arg(1024);

BENCHMARK_MAIN();
