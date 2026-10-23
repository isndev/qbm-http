/**
 * @file qbm/http/tests/benchmark/middleware/static-files.bench.cpp
 * @brief Warm local-file middleware: request/context lifecycle, metadata and response preparation.
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 *
 * No socket or router lookup. The file and middleware are prepared outside timing;
 * each operation constructs a context, processes it and destroys it. Filesystem
 * metadata calls and, for GET, the complete file read remain inside the timed span.
 * Both revisions use this fixture; strong and weak ETags are accepted by the probe.
 */
#include <benchmark/benchmark.h>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <qb/uuid.h>
#include <qbm/http/routing.h>
#include <qbm/http/middleware/static_files.h>

namespace static_files_bench {

struct Session {
    qb::http::Response response;
    qb::http::Response &
    get_response_ref() {
        return response;
    }
    Session &
    operator<<(const qb::http::Response &value) {
        response = value;
        return *this;
    }
};

struct File {
    std::filesystem::path root;
    std::string           payload;

    explicit File(std::size_t size)
        : root(std::filesystem::temp_directory_path() / ("qb-static-bench-" + uuids::to_string(qb::generate_random_uuid())))
        , payload(size, 'x') {
        if (!std::filesystem::create_directory(root))
            throw std::runtime_error("Benchmark directory already exists");
        std::ofstream stream(root / "data.txt", std::ios::binary);
        stream.write(payload.data(), static_cast<std::streamsize>(payload.size()));
        stream.close();
        if (!stream) {
            std::error_code error;
            std::filesystem::remove_all(root, error);
            throw std::runtime_error("Could not write benchmark file");
        }
    }
    ~File() {
        std::error_code error;
        std::filesystem::remove_all(root, error);
    }
};

using Context = qb::http::Context<Session>;

std::shared_ptr<Context>
context(const std::shared_ptr<Session> &session, bool head, const std::string &etag, bool range = false) {
    qb::http::Request request;
    request.method()      = head ? qb::http::method::HEAD : qb::http::method::GET;
    request.uri()         = qb::io::uri("/data.txt");
    request.major_version = 1;
    request.minor_version = 1;
    if (!etag.empty())
        request.set_header("If-None-Match", etag);
    if (range)
        request.set_header("Range", "bytes=0-7");
    return std::make_shared<Context>(
        std::move(request), qb::http::Response{}, session, [](Context &) {}, std::weak_ptr<qb::http::RouterCore<Session>>{});
}

bool
matches(const std::shared_ptr<Context> &ctx, const std::string &payload, bool head, bool conditional, bool range = false) {
    const auto &response = ctx->response();
    const auto  status   = conditional ? qb::http::status::NOT_MODIFIED : (range ? qb::http::status::PARTIAL_CONTENT : qb::http::status::OK);
    return ctx->is_completed() && ctx->completion_count() == 1 && response.status() == status
           && response.body().as<std::string>() == (head || conditional ? std::string{} : (range ? payload.substr(0, 8) : payload))
           && !response.header("ETag").empty()
           && (conditional || response.header("Content-Length") == std::to_string(range ? 8 : payload.size()))
           && (!range || response.header("Content-Range") == "bytes 0-7/" + std::to_string(payload.size()));
}

// Outside the measured loop. Decode only the canonical producer forms, then
// replay the historic decimal validator; do not approximate filesystem clocks.
std::string
legacy_etag_from_current(std::string_view tag) {
    if (tag.starts_with("W/"))
        tag.remove_prefix(2);
    if (tag.size() < 3 || tag.front() != '"' || tag.back() != '"')
        throw std::runtime_error("Static-file ETag is not a quoted canonical value");
    const auto opaque    = tag.substr(1, tag.size() - 2);
    const bool compact   = opaque.find(':') != std::string_view::npos;
    const char separator = compact ? ':' : '-';
    const auto split     = opaque.find(separator);
    if (split == std::string_view::npos || split == 0 || split + 1 == opaque.size())
        throw std::runtime_error("Static-file ETag is missing a metadata field");
    const auto                size_text   = opaque.substr(0, split);
    const auto                time_text   = opaque.substr(split + 1);
    std::uintmax_t            size        = 0;
    std::chrono::seconds::rep modified    = 0;
    const int                 base        = compact ? 16 : 10;
    const auto                size_result = std::from_chars(size_text.data(), size_text.data() + size_text.size(), size, base);
    const auto                time_result = std::from_chars(time_text.data(), time_text.data() + time_text.size(), modified, base);
    if (size_result.ec != std::errc{} || size_result.ptr != size_text.data() + size_text.size() || time_result.ec != std::errc{}
        || time_result.ptr != time_text.data() + time_text.size())
        throw std::runtime_error("Static-file ETag metadata is invalid or out of range");
    // Round-trip each parsed field to reject padding, uppercase, -0 and prefixes.
    // Binary value bits plus sign room also bound the selected bases.
    const auto canonical = [base](auto value) {
        char       storage[std::numeric_limits<decltype(value)>::digits + 2];
        const auto result = std::to_chars(storage, storage + sizeof(storage), value, base);
        if (result.ec != std::errc{})
            throw std::runtime_error("Static-file ETag canonicalization overflow");
        return std::string(storage, result.ptr);
    };
    if (canonical(size) != size_text || canonical(modified) != time_text)
        throw std::runtime_error("Static-file ETag metadata is not canonical");
    return "\"" + std::to_string(size) + "-" + std::to_string(modified) + "\"";
}

void
run(benchmark::State &state, bool head, bool conditional, bool range = false, bool legacy = false) {
    try {
        File file(static_cast<std::size_t>(state.range(0)));
        auto middleware = qb::http::static_files_middleware<Session>(qb::http::StaticFilesOptions(file.root));
        auto session    = std::make_shared<Session>();
        auto initial    = context(session, false, {});
        middleware->process(initial);
        if (!matches(initial, file.payload, false, false) || matches(initial, std::string(file.payload.size(), 'y'), false, false)) {
            state.SkipWithError("static file response or same-size corruption oracle failed");
            return;
        }
        const std::string etag  = conditional ? (legacy ? legacy_etag_from_current(initial->response().header("ETag"))
                                                        : std::string(initial->response().header("ETag")))
                                              : std::string{};
        auto              probe = context(session, head, etag, range);
        middleware->process(probe);
        if (!matches(probe, file.payload, head, conditional, range)) {
            state.SkipWithError("static file HEAD/conditional/range response failed");
            return;
        }
        for (auto _ : state) {
            auto ctx = context(session, head, etag, range);
            middleware->process(ctx);
            benchmark::DoNotOptimize(ctx->response());
        }
        auto final = context(session, head, etag, range);
        middleware->process(final);
        if (!matches(final, file.payload, head, conditional, range)) {
            state.SkipWithError("static file response changed during measurement");
            return;
        }
        state.SetItemsProcessed(state.iterations());
    } catch (const std::exception &error) {
        state.SkipWithError(error.what());
    }
}

void
BM_StaticFiles_Get(benchmark::State &state) {
    run(state, false, false);
}
void
BM_StaticFiles_Head(benchmark::State &state) {
    run(state, true, false);
}
void
BM_StaticFiles_NotModified(benchmark::State &state) {
    run(state, false, true);
}

void
BM_StaticFiles_NotModifiedLegacy(benchmark::State &state) {
    run(state, false, true, false, true);
}

void
BM_StaticFiles_Range(benchmark::State &state) {
    run(state, false, false, true);
}

} // namespace static_files_bench

BENCHMARK(static_files_bench::BM_StaticFiles_Get)->Arg(16)->Arg(4096)->UseRealTime();
BENCHMARK(static_files_bench::BM_StaticFiles_Head)->Arg(16)->UseRealTime();
BENCHMARK(static_files_bench::BM_StaticFiles_NotModified)->Arg(16)->UseRealTime();
BENCHMARK(static_files_bench::BM_StaticFiles_NotModifiedLegacy)->Arg(16)->Arg(4096)->UseRealTime();
BENCHMARK(static_files_bench::BM_StaticFiles_Range)->Arg(16)->Arg(4096)->UseRealTime();
BENCHMARK_MAIN();
