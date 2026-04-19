/**
 * @file qbm/http/tests/test-context-slots.cpp
 * @brief Unit tests for the `Context` typed-slot API (F23).
 *
 * These tests exercise the strongly-typed `qb::http::Slot<T>` overloads of
 * `Context::set / get / get_if / get_or / emplace / contains / remove` in
 * isolation from the router, using a direct-constructed `Context`.
 */

#include <gtest/gtest.h>
#include "../http.h"
#include "../routing/context.h"
#include "../routing/slot.h"

#include <memory>
#include <string>
#include <vector>

// Minimal session stub sufficient to parameterise Context<T>.
struct SlotTestSession {
    qb::http::Response _response;
    SlotTestSession &operator<<(const qb::http::Response &r) { _response = r; return *this; }
};

using TestContext = qb::http::Context<SlotTestSession>;

namespace {
    // Slot declarations are intentionally at namespace scope with `inline
    // constexpr` so they mirror real-world usage (slots shared between
    // middleware and handlers).
    struct UserProfile {
        std::string id;
        std::string email;
        int         role = 0;

        bool operator==(const UserProfile&) const = default;
    };

    inline constexpr qb::http::Slot<int>         kRequestCount{"metrics.requests"};
    inline constexpr qb::http::Slot<std::string> kTraceId{"trace.id"};
    inline constexpr qb::http::Slot<UserProfile> kAuthUser{"auth.user"};

    // Helper that builds a bare-bones Context for the tests. The returned
    // shared_ptr owns the context; the tests never drive it through the
    // router, so no finalised-state invariant is tripped.
    std::shared_ptr<TestContext> make_ctx() {
        auto session = std::make_shared<SlotTestSession>();
        return std::make_shared<TestContext>(
            qb::http::Request{},
            qb::http::Response{},
            session,
            [](TestContext&) {},
            std::weak_ptr<qb::http::RouterCore<SlotTestSession>>{}
        );
    }
}

TEST(ContextSlots, SetThenGetReturnsValue) {
    auto ctx = make_ctx();
    ctx->set(kRequestCount, 42);

    auto v = ctx->get(kRequestCount);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 42);
}

TEST(ContextSlots, GetIfReturnsStablePointer) {
    auto ctx = make_ctx();
    ctx->set(kTraceId, std::string{"req-abc-123"});

    auto* p = ctx->get_if(kTraceId);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(*p, "req-abc-123");

    // Mutation through the returned pointer must be observable on re-fetch.
    *p += "-mutated";
    const auto* cp = std::as_const(*ctx).get_if(kTraceId);
    ASSERT_NE(cp, nullptr);
    EXPECT_EQ(*cp, "req-abc-123-mutated");
}

TEST(ContextSlots, GetIfReturnsNullWhenAbsent) {
    auto ctx = make_ctx();
    EXPECT_EQ(ctx->get_if(kTraceId), nullptr);
    EXPECT_FALSE(ctx->get(kTraceId).has_value());
}

TEST(ContextSlots, ContainsTracksPresence) {
    auto ctx = make_ctx();
    EXPECT_FALSE(ctx->contains(kRequestCount));

    ctx->set(kRequestCount, 7);
    EXPECT_TRUE(ctx->contains(kRequestCount));

    ctx->remove(kRequestCount);
    EXPECT_FALSE(ctx->contains(kRequestCount));
}

TEST(ContextSlots, GetOrReturnsFallbackWhenAbsent) {
    auto ctx = make_ctx();
    EXPECT_EQ(ctx->get_or(kRequestCount, -1), -1);

    ctx->set(kRequestCount, 99);
    EXPECT_EQ(ctx->get_or(kRequestCount, -1), 99);
}

TEST(ContextSlots, EmplaceConstructsInPlaceAndReturnsReference) {
    auto ctx = make_ctx();

    UserProfile& u = ctx->emplace(kAuthUser, "u-1", "alice@example.com", 3);
    EXPECT_EQ(u.id, "u-1");
    EXPECT_EQ(u.email, "alice@example.com");
    EXPECT_EQ(u.role, 3);

    // Mutation via the returned reference must round-trip through get_if.
    u.role = 5;
    const auto* stored = std::as_const(*ctx).get_if(kAuthUser);
    ASSERT_NE(stored, nullptr);
    EXPECT_EQ(stored->role, 5);
}

TEST(ContextSlots, RemoveReturnsTrueOnlyWhenPresent) {
    auto ctx = make_ctx();
    EXPECT_FALSE(ctx->remove(kTraceId));

    ctx->set(kTraceId, std::string{"t"});
    EXPECT_TRUE(ctx->remove(kTraceId));
    EXPECT_FALSE(ctx->remove(kTraceId));
}

TEST(ContextSlots, InteropWithLegacyStringKeyedApi) {
    // A typed slot and a legacy string key pointing to the same name must
    // round-trip the same value: the typed API is strictly a façade over the
    // shared `CustomDataMap`.
    auto ctx = make_ctx();

    ctx->set(kRequestCount, 123);

    auto legacy = ctx->get<int>("metrics.requests");
    ASSERT_TRUE(legacy.has_value());
    EXPECT_EQ(*legacy, 123);

    ctx->set<std::string>("trace.id", std::string{"legacy-written"});
    const auto* typed = ctx->get_if(kTraceId);
    ASSERT_NE(typed, nullptr);
    EXPECT_EQ(*typed, "legacy-written");
}

TEST(ContextSlots, DifferentSlotNamesAreIndependent) {
    auto ctx = make_ctx();

    ctx->set(kRequestCount, 1);
    ctx->set(kTraceId, std::string{"a"});

    EXPECT_EQ(ctx->get_or(kRequestCount, 0), 1);
    ASSERT_NE(ctx->get_if(kTraceId), nullptr);
    EXPECT_EQ(*ctx->get_if(kTraceId), "a");

    ctx->remove(kRequestCount);
    EXPECT_FALSE(ctx->contains(kRequestCount));
    EXPECT_TRUE(ctx->contains(kTraceId));
}

TEST(ContextSlots, GetReturnsNulloptOnLegacyTypeMismatch) {
    // If a slot key is (mis)used with the legacy string API under a different
    // type, the typed read must fail gracefully rather than undefined-cast.
    auto ctx = make_ctx();
    ctx->set<double>("metrics.requests", 3.14);

    // Type mismatch between stored double and slot-declared int.
    EXPECT_FALSE(ctx->get(kRequestCount).has_value());
    EXPECT_EQ(ctx->get_if(kRequestCount), nullptr);
    // contains() is purely name-based, so it still reports true.
    EXPECT_TRUE(ctx->contains(kRequestCount));
}

// Compile-time check: a Slot<int> cannot be used to set a std::string.
// This is not runtime-testable (it would not compile), but we assert the
// equality contract on Slot's value_type that user code may rely on.
static_assert(std::is_same_v<qb::http::Slot<UserProfile>::value_type, UserProfile>);
static_assert(noexcept(std::declval<const TestContext&>().contains(kRequestCount)));
