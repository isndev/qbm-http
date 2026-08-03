/**
 * @file qbm/http/tests/unit/routing/handler-node.cpp
 * @brief Unit tests for routing/handler_node.h — path-join helpers + IHandlerNode.
 *
 * Two layers are exercised here, both normally reached only transitively during
 * `Router::compile()` and therefore thinly covered:
 *
 *  1. The free helpers `qb::http::detail::normalize_path_segment` and
 *     `qb::http::detail::join_paths` — the slash-normalization primitives that
 *     turn a parent path + a node segment into a single canonical URL path. The
 *     documented example table in the header (empty/root/leading/trailing-slash
 *     permutations) is pinned row-for-row.
 *  2. `IHandlerNode<Session>` itself, via a minimal concrete subclass that surfaces
 *     the protected `build_full_path()` / `combine_tasks()`: parent wiring
 *     (`set_parent`/`get_parent` incl. the destroyed-parent → empty case),
 *     `get_path_segment`, null-middleware rejection in `add_middleware`, and the
 *     parent-then-self ordering `combine_tasks` must preserve.
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
// detail::normalize_path_segment — strips leading/trailing slashes.
// ===========================================================================
TEST(HandlerNodePathHelpers, NormalizeStripsSlashes) {
    using qb::http::detail::normalize_path_segment;
    EXPECT_EQ(normalize_path_segment("/users"), "users");
    EXPECT_EQ(normalize_path_segment("users/"), "users");
    EXPECT_EQ(normalize_path_segment("/users/"), "users");
    EXPECT_EQ(normalize_path_segment("/"), "");
    EXPECT_EQ(normalize_path_segment(""), "");
    // Inner slashes are preserved; only the outermost are stripped.
    EXPECT_EQ(normalize_path_segment("/a/b/"), "a/b");
    // Multiple leading/trailing slashes are all removed.
    EXPECT_EQ(normalize_path_segment("///x///"), "x");
}

// ===========================================================================
// detail::join_paths — the canonical example table from the header.
// ===========================================================================
TEST(HandlerNodePathHelpers, JoinPathsExampleTable) {
    using qb::http::detail::join_paths;
    EXPECT_EQ(join_paths("/api", "users"), "/api/users");
    EXPECT_EQ(join_paths("/api", "/users"), "/api/users");
    EXPECT_EQ(join_paths("/api/", "users"), "/api/users");
    EXPECT_EQ(join_paths("", "users"), "/users");
    EXPECT_EQ(join_paths("/", "users"), "/users");
    EXPECT_EQ(join_paths("", ""), "/");
}

TEST(HandlerNodePathHelpers, JoinPathsEmptySegmentKeepsParent) {
    using qb::http::detail::join_paths;
    EXPECT_EQ(join_paths("/api", ""), "/api");
    EXPECT_EQ(join_paths("/api/", "/"), "/api");
    EXPECT_EQ(join_paths("/", ""), "/");
    // A parameterised segment is opaque to the joiner (no special handling).
    EXPECT_EQ(join_paths("/users", ":id"), "/users/:id");
    EXPECT_EQ(join_paths("/files", "*rest"), "/files/*rest");
}

// ===========================================================================
// IHandlerNode via a minimal concrete subclass.
// ===========================================================================

/**
 * @brief Smallest concrete node: implements the two pure virtuals trivially and
 *        re-exposes the protected helpers so they can be asserted directly.
 */
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

    // Surface the protected helpers for testing.
    using Node::build_full_path;
    using Node::combine_tasks;
};

// A no-op middleware task used purely to assert combine_tasks ordering.
std::shared_ptr<Task>
make_noop_task(const std::string &name) {
    return std::make_shared<qb::http::RouteLambdaTask<MockSession>>(
        [](std::shared_ptr<qb::http::Context<MockSession>> ctx) { ctx->complete(); }, name);
}

TEST(HandlerNodeTest, PathSegmentAndNodeName) {
    auto node = std::make_shared<TestNode>("/products");
    EXPECT_EQ(node->get_path_segment(), "/products");
    EXPECT_EQ(node->get_node_name(), "TestNode[/products]");
}

TEST(HandlerNodeTest, BuildFullPathPrependsParent) {
    TestNode node("/users");
    EXPECT_EQ(node.build_full_path("/api"), "/api/users");
    EXPECT_EQ(node.build_full_path(""), "/users");
    EXPECT_EQ(node.build_full_path("/api/"), "/api/users");

    TestNode root("");
    EXPECT_EQ(root.build_full_path(""), "/");
    EXPECT_EQ(root.build_full_path("/api"), "/api");
}

TEST(HandlerNodeTest, ParentWiring) {
    auto parent = std::make_shared<TestNode>("/api");
    auto child  = std::make_shared<TestNode>("/users");

    // No parent set yet.
    EXPECT_EQ(child->get_parent(), nullptr);

    child->set_parent(parent);
    auto locked = child->get_parent();
    ASSERT_NE(locked, nullptr);
    EXPECT_EQ(locked.get(), parent.get());
    EXPECT_EQ(locked->get_path_segment(), "/api");
}

TEST(HandlerNodeTest, GetParentReturnsNullAfterParentDestroyed) {
    auto child = std::make_shared<TestNode>("/users");
    {
        auto parent = std::make_shared<TestNode>("/api");
        child->set_parent(parent);
        ASSERT_NE(child->get_parent(), nullptr);
    } // parent destroyed; weak_ptr now expired
    EXPECT_EQ(child->get_parent(), nullptr);
}

TEST(HandlerNodeTest, AddMiddlewareIgnoresNull) {
    TestNode node("/x");

    // A null middleware must be silently ignored, so combine_tasks emits nothing.
    node.add_middleware(nullptr);
    auto combined_after_null = node.combine_tasks({});
    EXPECT_TRUE(combined_after_null.empty());

    // A real task is retained.
    node.add_middleware(make_noop_task("own"));
    auto combined = node.combine_tasks({});
    ASSERT_EQ(combined.size(), 1u);
    EXPECT_EQ(combined.front()->name(), "own");
}

TEST(HandlerNodeTest, CombineTasksKeepsParentThenSelfOrder) {
    TestNode node("/x");
    node.add_middleware(make_noop_task("self_a"));
    node.add_middleware(make_noop_task("self_b"));

    std::vector<std::shared_ptr<Task>> inherited = {make_noop_task("parent_1"), make_noop_task("parent_2")};

    auto combined = node.combine_tasks(inherited);
    ASSERT_EQ(combined.size(), 4u);
    // Inherited (parent) tasks first, then this node's own middleware, both in order.
    EXPECT_EQ(combined[0]->name(), "parent_1");
    EXPECT_EQ(combined[1]->name(), "parent_2");
    EXPECT_EQ(combined[2]->name(), "self_a");
    EXPECT_EQ(combined[3]->name(), "self_b");

    // The inherited vector is not mutated (a fresh vector is returned).
    EXPECT_EQ(inherited.size(), 2u);
}

TEST(HandlerNodeTest, CombineTasksWithNoOwnMiddlewareEchoesInherited) {
    TestNode                           node("/x");
    std::vector<std::shared_ptr<Task>> inherited = {make_noop_task("only_parent")};
    auto                               combined  = node.combine_tasks(inherited);
    ASSERT_EQ(combined.size(), 1u);
    EXPECT_EQ(combined.front()->name(), "only_parent");
}

} // namespace
