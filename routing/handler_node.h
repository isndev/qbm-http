/**
 * @file qbm/http/routing/handler_node.h
 * @brief Defines the IHandlerNode interface, a base for elements in the HTTP routing tree.
 *
 * This file contains the `IHandlerNode` abstract base class, which serves as a common
 * interface for all nodes within the HTTP routing hierarchy, such as individual routes
 * (`Route`), groups of routes (`RouteGroup`), and controllers (`Controller`).
 * It establishes mechanisms for path segmentation, parent-child relationships, and
 * middleware aggregation during the route compilation process.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include "./async_task.h"
#include "./context.h"
// #include "../types.h" // For qb::http::method - Not directly used here but by derived classes like Route

#include <vector>   // For internal structures if any, or if children use it often
#include <string>   // For std::string
#include <memory>   // For std::weak_ptr, std::shared_ptr, std::enable_shared_from_this
#include <list>     // For std::list
#include <sstream>  // For std::ostringstream in build_full_path

namespace qb::http {
    // Forward declaration
    template<typename Session>
    class RouterCore;

    /**
     * @brief Abstract base class for nodes in the HTTP routing hierarchy.
     *
     * `IHandlerNode` defines the common interface and behavior for elements that form
     * the routing tree, such as `Route`, `RouteGroup`, and `Controller`.
     * Each node is associated with a path segment and can have its own chain of middleware.
     * The primary responsibility of a node is to participate in the compilation of the
     * routing table by contributing its path segment and tasks (middleware and its own handler,
     * if applicable) to the `RouterCore`.
     *
     * This class uses `std::enable_shared_from_this` to allow nodes to safely obtain
     * `std::shared_ptr` instances of themselves, typically for setting parent-child relationships.
     *
     * @tparam SessionType The session type used by the `Context` and `IAsyncTask`,
     *                     propagated throughout the routing system.
     */
    template<typename Session>
    class IHandlerNode : public std::enable_shared_from_this<IHandlerNode<Session> > {
        friend class RouterCore<Session>;

    protected:
        /** @brief Weak pointer to the parent node in the routing hierarchy. Used to avoid circular dependencies. */
        std::weak_ptr<IHandlerNode<Session> > _parent;
        /** @brief The specific path segment this node represents (e.g., "/users", ":id", ""). */
        std::string _path_segment;
        /** 
         * @brief List of middleware tasks specific to this node.
         * These tasks are executed after middleware from parent nodes and before any handler
         * specific to this node (for `Route` nodes) or before tasks from child nodes.
         * Middleware is executed in the order it is added to this list.
         */
        std::list<std::shared_ptr<IAsyncTask<Session> > > _middleware_tasks;

    public:
        /**
         * @brief Constructs an `IHandlerNode` with a given path segment.
         * @param path_segment The URL path segment this node will handle (e.g., "/products", ":userId").
         *                     For root-level groups or controllers mounted at the router root, this can be an empty string.
         */
        explicit IHandlerNode(std::string path_segment)
            : _path_segment(std::move(path_segment)) {
        }

        /** @brief Virtual destructor to ensure proper cleanup of derived node types. */
        virtual ~IHandlerNode() = default;

        // --- Hierarchy Management ---

        /**
         * @brief Sets the parent node for this handler node.
         * @param parent A `std::weak_ptr` to the parent `IHandlerNode`.
         */
        void set_parent(std::weak_ptr<IHandlerNode<Session> > parent) noexcept {
            _parent = parent;
        }

        /**
         * @brief Gets a shared pointer to the parent node.
         * @return A `std::shared_ptr<IHandlerNode<Session>>` to the parent. 
         *         Returns an empty `shared_ptr` if this node has no parent or the parent has been destroyed.
         */
        [[nodiscard]] std::shared_ptr<IHandlerNode<Session> > get_parent() const noexcept {
            return _parent.lock();
        }

        /**
         * @brief Gets the path segment associated with this node.
         * @return A constant reference to the node's path segment string.
         */
        [[nodiscard]] const std::string &get_path_segment() const noexcept {
            return _path_segment;
        }

        // --- Middleware Management ---

        /**
         * @brief Adds a middleware task to this node's specific processing chain.
         * Middleware tasks added via this method are typically executed after any middleware
         * inherited from parent nodes and before this node's own primary handler (if it's a `Route`)
         * or before propagating to child nodes (if it's a `RouteGroup` or `Controller`).
         * Middleware is processed in the order it is added.
         * @param middleware_task A `std::shared_ptr<IAsyncTask<Session>>` representing the middleware.
         */
        void add_middleware(std::shared_ptr<IAsyncTask<Session> > middleware_task) {
            if (middleware_task) {
                // Ensure not adding a null task
                _middleware_tasks.push_back(std::move(middleware_task));
            }
        }

        // --- Task Compilation (Pure Virtual) ---

        /**
         * @brief Recursively compiles the tasks for this node and its children, registering final route task chains with the `RouterCore`.
         *
         * This pure virtual method is the core of the route compilation process. Each derived node type
         * (`Route`, `RouteGroup`, `Controller`) must implement this to:
         * 1. Combine `inherited_tasks` (from its parent) with its own `_middleware_tasks`.
         * 2. If it's a terminal node (like `Route`), add its own handler task to this combined list and register
         *    the complete path and final task chain with the `router_core`.
         * 3. If it's an intermediate node (like `RouteGroup` or `Controller`), recursively call
         *    `compile_tasks_and_register` on its child nodes, passing down the augmented inherited task list.
         *
         * @param router_core Reference to the `RouterCore` where final, compiled routes are registered.
         * @param current_built_path The fully resolved URL path accumulated from the root down to this node's parent.
         *                           This node will append its `_path_segment` to this to form its own base path.
         * @param inherited_tasks A list of `IAsyncTask` shared pointers representing middleware tasks inherited from
         *                        all parent nodes in the hierarchy, already in execution order.
         */
        virtual void compile_tasks_and_register(
            RouterCore<Session> &router_core,
            const std::string &current_built_path,
            const std::list<std::shared_ptr<IAsyncTask<Session> > > &inherited_tasks) = 0;

        /**
         * @brief Gets a descriptive name for this handler node, primarily for debugging or logging purposes.
         * @return A `std::string` representing the node's name or type and path segment.
         */
        [[nodiscard]] virtual std::string get_node_name() const = 0;

    protected:
        /**
         * @brief (Protected) Helper method to construct the full URI path for this node.
         * It prepends the `parent_full_path` to this node's `_path_segment`,
         * correctly handling leading/trailing slashes to form a normalized path string.
         * For example, if `parent_full_path` is "/api" and `_path_segment` is "/users",
         * the result is "/api/users". If `_path_segment` is "users", result is "/api/users".
         * Ensures no trailing slash unless the path is just "/".
         * @param parent_full_path The full path accumulated from the root to this node's parent.
         * @return The fully resolved path string for this node.
         */
        [[nodiscard]] std::string build_full_path(const std::string &parent_full_path) const {
            std::string full_path = parent_full_path;

            // Ensure a single slash between parent_full_path and _path_segment if both are non-empty and don't already have one.
            if (!full_path.empty() && full_path.back() == '/' && !_path_segment.empty() && _path_segment.front() ==
                '/') {
                full_path.pop_back(); // Avoid double slashes like /api//users, use parent's slash
            } else if (!full_path.empty() && full_path.back() != '/' && !_path_segment.empty() && _path_segment.front()
                       != '/') {
                full_path += "/"; // Add a slash if missing between segments
            } else if (full_path == "/" && !_path_segment.empty() && _path_segment.front() == '/') {
                // Parent is root "/", current segment starts with "/" (e.g. /users), avoid //users
                // This case is tricky. If parent is "/" and child is "/foo", result should be "/foo".
                // If child is "foo", result should be "/foo".
                // The logic here might need to be path_segment = path_segment.substr(1) if it starts with / and full_path is /
                // Current logic: if full_path = "/", path_segment = "/users" -> "//users" which then gets fixed.
                // If full_path = "/", path_segment = "users" -> "/users". This is fine.
            }

            full_path += _path_segment;

            // Normalize: Remove trailing slash unless it's the root path "/" itself.
            if (full_path.length() > 1 && full_path.back() == '/') {
                full_path.pop_back();
            }
            // Ensure root path is "/", not empty, if it results from joining empty segments.
            if (full_path.empty() && parent_full_path.empty() && _path_segment.empty()) {
                return "/";
            }

            return full_path;
        }

        /**
         * @brief (Protected) Combines middleware tasks inherited from parent nodes with this node's own specific middleware.
         * The resulting list maintains execution order: parent middleware first, then this node's middleware.
         * @param inherited_tasks A list of middleware tasks passed down from the parent node.
         * @return A new `std::list` containing all combined middleware tasks.
         */
        [[nodiscard]] virtual std::list<std::shared_ptr<IAsyncTask<Session> > >
        combine_tasks(const std::list<std::shared_ptr<IAsyncTask<Session> > > &inherited_tasks) const {
            std::list<std::shared_ptr<IAsyncTask<Session> > > combined = inherited_tasks;
            combined.insert(combined.end(), _middleware_tasks.begin(), _middleware_tasks.end());
            return combined;
        }
    };
} // namespace qb::http 
