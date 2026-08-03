/**
 * @file qbm/http/tests/unit/routing/handler-node-extra.cpp
 * @brief Complementary unit tests for routing/handler_node.h — the path-helper
 *        rows and IHandlerNode branches NOT already pinned by handler-node.cpp.
 *
 * The first wave (handler-node.cpp) pinned the documented example table for
 * `normalize_path_segment` / `join_paths`, basic parent wiring, null-middleware
 * rejection, and the two simplest `combine_tasks` shapes. This file deliberately
 * does NOT repeat any of those rows; it reaches the branches they leave cold:
 *
 *  1. `join_paths` permutations that exercise BOTH normalize sides simultaneously
 *     (parent + segment each carrying surrounding slashes), inner-slash retention
 *     on a multi-segment parent, and the "segment-only" vs "parent-only" arms of
 *     the slash-insertion logic in isolation.
 *  2. `build_full_path` driven through those same multi-segment / parameterised /
 *     wildcard shapes (it forwards straight to `join_paths`, so the node-level
 *     behaviour must match the helper byte-for-byte).
 *  3. `combine_tasks` growth path: a long inherited chain plus several own
 *     middleware (forcing the `reserve`/`insert` to actually grow), and the
 *     "own middleware but EMPTY inherited" arm — neither shape appears in wave 1.
 *  4. Node identity for empty / parameterised / wildcard segments via
 *     `get_path_segment` + `get_node_name`, and that `add_middleware` accumulates
 *     in insertion order across several real tasks.
 *
 * Pure logic: no router instance, no socket, no event loop.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "../../shared/mock_session.h" // qb::http::test::MockSession + the http umbrella

#include <qbm/http/routing/async_task.h>
#include <qbm/http/routing/handler_node.h>
#include <qbm/http/routing/route.h> // RouteLambdaTask — a concrete IAsyncTask for middleware ordering

using qb::http::test::MockSession;
using Node = qb::http::IHandlerNode<MockSession>;
using Task = qb::http::IAsyncTask<MockSession>;

namespace {

// ===========================================================================
// detail::join_paths — rows NOT in wave 1's example table.
// ===========================================================================
TEST(HandlerNodeExtraPathHelpers, JoinPathsBothSidesNormalized) {
    using qb::http::detail::join_paths;
    // Both parent AND segment carry surrounding slashes — exercises the two
    // normalize calls together, then the parent-then-slash-then-segment assembly.
    EXPECT_EQ(join_paths("/api/", "/users/"), "/api/users");
    EXPECT_EQ(join_paths("///api///", "///users///"), "/api/users");
    // Inner slashes inside a multi-segment parent are retained (only outer ones
    // are stripped), then the child is appended with a single separator.
    EXPECT_EQ(join_paths("/api/v1", "users"), "/api/v1/users");
    EXPECT_EQ(join_paths("/api/v1/", "/users"), "/api/v1/users");
    // A segment that itself contains an inner slash is opaque to the joiner.
    EXPECT_EQ(join_paths("/files", "a/b/c"), "/files/a/b/c");
}

TEST(HandlerNodeExtraPathHelpers, JoinPathsParentOnlyAndSegmentOnly) {
    using qb::http::detail::join_paths;
    // Parent-only arm: non-empty parent, segment normalizes to empty → just "/parent".
    EXPECT_EQ(join_paths("/api/v1/", "///"), "/api/v1");
    EXPECT_EQ(join_paths("users", ""), "/users");
    // Segment-only arm: parent normalizes to empty, segment survives → "/segment"
    // (no leading separator emitted for the absent parent).
    EXPECT_EQ(join_paths("///", "users"), "/users");
    EXPECT_EQ(join_paths("", "/users/"), "/users");
}

// ===========================================================================
// IHandlerNode via a minimal concrete subclass (distinct from wave 1's cases).
// ===========================================================================

class TestNode : public Node {
public:
    explicit TestNode(std::string segment)
        : Node(std::move(segment)) {}

    void
    compile_tasks_and_register(qb::http::RouterCore<MockSession> &, const std::string &, const std::vector<std::shared_ptr<Task>> &) override {
        // Not under test here; intentionally a no-op.
    }

    [[nodiscard]] std::string
    get_node_name() const override {
        return "TestNode[" + this->get_path_segment() + "]";
    }

    using Node::build_full_path;
    using Node::combine_tasks;
};

std::shared_ptr<Task>
make_noop_task(const std::string &name) {
    return std::make_shared<qb::http::RouteLambdaTask<MockSession>>(
        [](std::shared_ptr<qb::http::Context<MockSession>> ctx) { ctx->complete(); }, name);
}

// build_full_path forwards to join_paths, so the node-level result must match the
// helper across multi-segment / parameterised / wildcard / empty shapes.
TEST(HandlerNodeExtraTest, BuildFullPathMultiSegmentAndParam) {
    TestNode users(":id");
    EXPECT_EQ(users.build_full_path("/api/v1"), "/api/v1/:id");
    EXPECT_EQ(users.build_full_path("/api/v1/"), "/api/v1/:id");

    TestNode wildcard("*rest");
    EXPECT_EQ(wildcard.build_full_path("/files"), "/files/*rest");

    // A segment that is itself empty just echoes the (normalized) parent.
    TestNode empty("");
    EXPECT_EQ(empty.build_full_path("/api/v1/"), "/api/v1");
    EXPECT_EQ(empty.build_full_path("///"), "/");
}

// The path segment is stored verbatim (inner slashes preserved); get_node_name
// reflects exactly that stored string.
TEST(HandlerNodeExtraTest, SegmentStoredVerbatim) {
    TestNode param(":userId");
    EXPECT_EQ(param.get_path_segment(), ":userId");
    EXPECT_EQ(param.get_node_name(), "TestNode[:userId]");

    TestNode nested("a/b");
    EXPECT_EQ(nested.get_path_segment(), "a/b"); // not normalized at construction
    EXPECT_EQ(nested.get_node_name(), "TestNode[a/b]");

    TestNode root("");
    EXPECT_EQ(root.get_path_segment(), "");
    EXPECT_EQ(root.get_node_name(), "TestNode[]");
}

// combine_tasks growth path: a long inherited chain forces the reserve+insert to
// actually extend, and the own middleware is appended after it in insertion order.
TEST(HandlerNodeExtraTest, CombineTasksGrowsAndPreservesOrderForLongChains) {
    TestNode node("/x");
    node.add_middleware(make_noop_task("own_1"));
    node.add_middleware(make_noop_task("own_2"));
    node.add_middleware(make_noop_task("own_3"));

    std::vector<std::shared_ptr<Task>> inherited;
    for (int i = 0; i < 8; ++i) {
        inherited.push_back(make_noop_task("p" + std::to_string(i)));
    }

    auto combined = node.combine_tasks(inherited);
    ASSERT_EQ(combined.size(), 11u);
    for (int i = 0; i < 8; ++i) {
        EXPECT_EQ(combined[static_cast<std::size_t>(i)]->name(), "p" + std::to_string(i));
    }
    EXPECT_EQ(combined[8]->name(), "own_1");
    EXPECT_EQ(combined[9]->name(), "own_2");
    EXPECT_EQ(combined[10]->name(), "own_3");

    // Source vector is untouched (a fresh vector is returned).
    EXPECT_EQ(inherited.size(), 8u);
}

// Own middleware with an EMPTY inherited list: the result is exactly this node's
// own chain, in order — the inverse of wave 1's "no own, echoes inherited" case.
TEST(HandlerNodeExtraTest, CombineTasksOwnOnlyWithEmptyInherited) {
    TestNode node("/x");
    node.add_middleware(make_noop_task("a"));
    node.add_middleware(make_noop_task("b"));

    auto combined = node.combine_tasks({});
    ASSERT_EQ(combined.size(), 2u);
    EXPECT_EQ(combined[0]->name(), "a");
    EXPECT_EQ(combined[1]->name(), "b");
}

} // namespace
