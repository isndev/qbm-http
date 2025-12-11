/**
 * @file qbm/http/routing/radix_tree.h
 * @brief Defines a Radix Tree for efficient HTTP route matching.
 *
 * This file contains the `RadixTree` class template, a specialized tree data structure
 * optimized for storing and matching URL paths. It supports static segments,
 * parameterized segments (e.g., `/users/:id`), and wildcard segments (e.g., `/files/ *filepath`).
 * Routes are associated with specific HTTP methods and compiled chains of tasks (middleware and handlers).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include <string>         // For std::string
#include <string_view>    // For std::string_view
#include <vector>         // For std::vector
#include <map>            // For std::map (handlers)
#include <unordered_map>  // For std::unordered_map (static_children - O(1) lookup)
#include <memory>         // For std::shared_ptr, std::make_shared, std::unique_ptr (used by Node)
#include <list>           // For std::list (task chains, _path_segment_storage)
#include <optional>       // For std::optional (match result)
#include <algorithm>      // For std::find_if, std::copy, std::back_inserter
#include <stdexcept>      // For std::runtime_error, std::invalid_argument
#include <utility>        // For std::move
#include <cassert>        // For assert (debug mode checks)

#include "../types.h"             // For qb::http::method enum
#include "./async_task.h"       // For IAsyncTask
#include "./path_parameters.h"  // For PathParameters
// #include <iostream> // Removed: For debug prints

// Forward declarations to avoid circular dependencies if RouteGroup is used in Node (not currently the case)
// template <typename SessionType> class RouteGroup;

namespace qb::http {
    /**
     * @brief (Internal) Holds information about a successfully matched route from the `RadixTree`.
     * @tparam SessionType The session type used by the `Context` and `IAsyncTask`.
     */
    template<typename SessionType>
    struct MatchedRouteInfo {
        /** @brief Extracted path parameters from the URI for this matched route. */
        PathParameters path_parameters;
        /**
         * @brief An optional shared pointer to the compiled list of asynchronous tasks for this route.
         *        The tasks include all applicable middleware and the final route handler.
         *        It's optional because a tree node might exist without a handler for a specific HTTP method.
         */
        std::optional<std::shared_ptr<const std::vector<std::shared_ptr<IAsyncTask<SessionType> > >> > route_tasks;

        /**
         * @brief Constructs `MatchedRouteInfo`.
         * @param params Extracted path parameters.
         * @param tasks Optional shared pointer to the task chain.
         */
        MatchedRouteInfo(PathParameters params,
                         std::optional<std::shared_ptr<const std::vector<std::shared_ptr<IAsyncTask<SessionType> > >> >
                         tasks)
            : path_parameters(std::move(params)), route_tasks(std::move(tasks)) {
        }

        /** @brief Default constructor. */
        MatchedRouteInfo() = default;
    };

    /**
     * @brief A Radix Tree implementation for storing and efficiently matching HTTP routes.
     *
     * This tree structure is optimized for path-based lookups. It supports:
     * - Static path segments (e.g., `/users`, `/products`).
     * - Parameterized path segments, denoted by a colon prefix (e.g., `/:id`, `/:category`).
     *   The value captured for the parameter is made available to handlers.
     * - Wildcard path segments, denoted by an asterisk prefix (e.g., `/ *filepath`).
     *   These match any remaining part of the path and must be the last segment in a route pattern.
     *
     * Each node in the tree can store handlers for different HTTP methods, where a handler
     * is a compiled list of tasks (`IAsyncTask`) including middleware and the final route logic.
     *
     * @tparam SessionType The session type used by `IAsyncTask` and potentially other context-dependent types.
     */
    template<typename SessionType>
    class RadixTree {
    public:
        /** @brief Type alias for a list of tasks (middleware + handler) associated with a route. */
        using TaskList = std::vector<std::shared_ptr<IAsyncTask<SessionType> > >;

    private:
        /** @brief Defines the type of a node in the Radix Tree, influencing matching logic. */
        enum class NodeType {
            ROOT, ///< The root of the tree.
            STATIC, ///< Represents a static path segment (e.g., "users").
            PARAMETER, ///< Represents a parameterized segment (e.g., ":id").
            WILDCARD ///< Represents a wildcard segment (e.g., "*filepath").
        };

        /**
         * @brief Represents a node within the Radix Tree.
         * Each node corresponds to a part of a URL path and can hold handlers for specific HTTP methods.
         */
        struct Node {
            NodeType type = NodeType::STATIC; ///< The type of this node.
            std::string_view segment_match;
            ///< For STATIC nodes: the exact segment string. For PARAMETER/WILDCARD nodes: the name of the parameter/wildcard (e.g., "id", "filepath").

            /** 
             * @brief Map of HTTP methods to their corresponding handler task lists.
             * The `TaskList` is a vector of `IAsyncTask` shared pointers, representing the compiled chain
             * of middleware and the final route handler to be executed for this specific path and method.
             */
            std::map<qb::http::method, std::shared_ptr<const TaskList> > handlers;

            /** @brief Children nodes representing static path segments. Keyed by the segment string.
             *  Uses std::unordered_map for O(1) average lookup time instead of O(log n) with std::map.
             *  Order is not important as we only perform lookups, never iterate in order.
             */
            qb::unordered_map<std::string_view, std::shared_ptr<Node> > static_children;
            /** @brief Child node for a parameterized segment, if one exists at this level. */
            std::shared_ptr<Node> param_child = nullptr;
            /** @brief The name of the parameter for `param_child` (e.g., "id" for a `:id` segment). */
            std::string_view param_name;
            /** @brief Child node for a wildcard segment, if one exists at this level. */
            std::shared_ptr<Node> wildcard_child = nullptr;

            /**
             * @brief Constructs a Node.
             * @param t The type of the node.
             * @param seg The segment string or parameter/wildcard name associated with this node.
             */
            Node(NodeType t = NodeType::STATIC, std::string_view seg = "") noexcept
                : type(t), segment_match(seg) {
            }
        };

        std::shared_ptr<Node> _root; ///< The root node of the Radix Tree.

        /**
         * @brief Internal storage for path segments to ensure `std::string_view` stability.
         * When a path is added, its segments (if they are new unique strings) are copied here,
         * and the `Node::segment_match` and `Node::param_name` `string_view`s point into this storage.
         */
        std::list<std::string> _path_segment_storage;

        /**
         * @brief (Private) Splits a URL path string_view into its constituent segments.
         * Leading and trailing slashes are handled, and empty segments (from consecutive slashes) are ignored.
         * Example: "/foo/bar/" results in a vector {"foo", "bar"}.
         * Example: "/" results in an empty vector (representing the root).
         * @param path_sv The `std::string_view` of the path to split.
         * @return A `std::vector<std::string_view>` of path segments.
         */
        [[nodiscard]] static std::vector<std::string_view> split_path_to_segments(std::string_view path_sv) noexcept {
            std::vector<std::string_view> segments;
            if (path_sv.empty()) {
                return segments;
            }

            size_t start = 0;
            size_t n = path_sv.length();

            // Skip leading slash
            if (n > 0 && path_sv[0] == '/') {
                start = 1;
            }

            for (size_t i = start; i < n; ++i) {
                if (path_sv[i] == '/') {
                    if (i > start) {
                        // Avoid empty segment from consecutive slashes or initial slash if start was 0
                        segments.push_back(path_sv.substr(start, i - start));
                    }
                    start = i + 1;
                }
            }

            // Add the last segment if it exists
            if (start < n) {
                segments.push_back(path_sv.substr(start, n - start));
            }
            // If path_sv was just "/", start becomes 1, n is 1. Loop doesn't run. start < n is false. segments is empty. Correct.
            // If path_sv was "/foo", start becomes 1. Loop finds no '/'. start (1) < n (4). segments gets {"foo"}. Correct.
            // If path_sv was "/foo/", start becomes 1. Loop finds '/' at i=4. segments gets {"foo"}. start becomes 5. start < n (5) is false. Correct.
            return segments;
        }

    public:
        /**
         * @brief Constructs an empty `RadixTree` with a root node.
         */
        RadixTree() : _root(std::make_shared<Node>(NodeType::ROOT)) {
        }

        /**
         * @brief Adds a compiled route to the Radix Tree.
         *
         * The path pattern is split into segments. The tree is traversed, and nodes are created as needed
         * for each segment. The type of node (STATIC, PARAMETER, WILDCARD) is determined by the segment's prefix.
         * The provided `task_chain_list` (middleware + handler) is associated with the terminal node of the path
         * for the specified HTTP method.
         *
         * @param path_pattern_str The full, normalized path pattern string for the route (e.g., "/users/:id").
         * @param method The HTTP method this route responds to.
         * @param task_chain_list A vector of `IAsyncTask` shared pointers representing the compiled execution chain for this route.
         * @throws std::invalid_argument if the path pattern is malformed (e.g., empty segment, misplaced wildcard, conflicting parameters).
         */
        void add_route(const std::string &path_pattern_str, qb::http::method method,
                       std::vector<std::shared_ptr<IAsyncTask<SessionType> > > task_chain_list) {
            TaskList task_chain_vec = std::move(task_chain_list); // RadixTree::Node stores a vector internally for handlers.

            std::shared_ptr<Node> current_node = _root;
            std::vector<std::string_view> segments = split_path_to_segments(path_pattern_str);

            for (size_t i = 0; i < segments.size(); ++i) {
                const auto &segment_sv = segments[i];

                // Path like "/" is represented by an empty segments vector. Handler is attached to _root.
                if (segment_sv.empty()) {
                    // This should only happen if path_pattern_str was something like "//" or "/foo//bar",
                    // which split_path_to_segments should ideally prevent by not creating empty segments for valid paths.
                    // If path_pattern_str is "/", segments is empty, loop doesn't run. Correct.
                    throw std::invalid_argument("Empty segment encountered in path pattern: " + path_pattern_str);
                }

                if (segment_sv[0] == '*') {
                    // Wildcard segment
                    if (segment_sv.length() < 2) {
                        throw std::invalid_argument(
                            "Wildcard segment must have a name (e.g., *filepath), got: '" + std::string(segment_sv) +
                            "' in path: " + path_pattern_str);
                    }
                    if (i != segments.size() - 1) {
                        // Wildcard must be the last segment
                        throw std::invalid_argument(
                            "Wildcard segment '" + std::string(segment_sv) +
                            "' must be the last segment in the path pattern: " + path_pattern_str);
                    }
                    if (current_node->type == NodeType::PARAMETER || current_node->type == NodeType::WILDCARD) {
                        throw std::invalid_argument(
                            "Cannot define a wildcard segment ('" + std::string(segment_sv) +
                            "') under a parent that is already a parameter or wildcard ('" + std::string(
                                current_node->segment_match) + "') in path: " + path_pattern_str);
                    }

                    _path_segment_storage.emplace_back(segment_sv.substr(1));
                    std::string_view wildcard_name_sv = _path_segment_storage.back();

                    if (!current_node->wildcard_child) {
                        current_node->wildcard_child = std::make_shared<Node>(NodeType::WILDCARD, wildcard_name_sv);
                    } else if (current_node->wildcard_child->segment_match != wildcard_name_sv) {
                        throw std::invalid_argument(
                            "Wildcard segment '" + std::string(segment_sv) + "' conflicts with existing wildcard '*" +
                            std::string(current_node->wildcard_child->segment_match) +
                            "' at the same level in path: " + path_pattern_str);
                    }
                    current_node = current_node->wildcard_child;
                    break; // Wildcard is always the last segment, so stop iterating path segments.
                } else if (segment_sv[0] == ':') {
                    // Parameter segment
                    if (segment_sv.length() < 2) {
                        throw std::invalid_argument(
                            "Parameter segment must have a name (e.g., :id), got: '" + std::string(segment_sv) +
                            "' in path: " + path_pattern_str);
                    }
                    if (current_node->type == NodeType::PARAMETER || current_node->type == NodeType::WILDCARD) {
                        throw std::invalid_argument(
                            "Cannot define a parameter segment ('" + std::string(segment_sv) +
                            "') under a parent that is already a parameter or wildcard ('" + std::string(
                                current_node->segment_match) + "') in path: " + path_pattern_str);
                    }

                    _path_segment_storage.emplace_back(segment_sv.substr(1));
                    std::string_view p_name_sv = _path_segment_storage.back();

                    if (!current_node->param_child) {
                        current_node->param_child = std::make_shared<Node>(NodeType::PARAMETER, p_name_sv);
                        current_node->param_name = p_name_sv;
                    } else if (current_node->param_name != p_name_sv) {
                        throw std::invalid_argument(
                            "Parameter segment '" + std::string(segment_sv) + "' conflicts with existing parameter ':" +
                            std::string(current_node->param_name) +
                            "' at the same level in path: " + path_pattern_str);
                    }
                    current_node = current_node->param_child;
                } else {
                    // Static segment
                    _path_segment_storage.emplace_back(segment_sv);
                    std::string_view static_segment_sv = _path_segment_storage.back();

                    auto it = current_node->static_children.find(static_segment_sv);
                    if (it == current_node->static_children.end()) {
                        auto new_node = std::make_shared<Node>(NodeType::STATIC, static_segment_sv);
                        current_node->static_children[static_segment_sv] = new_node;
                        current_node = new_node;
                    } else {
                        current_node = it->second;
                    }
                }
            }
            // After iterating all segments, current_node is the terminal node for this path.
            current_node->handlers[method] = std::make_shared<const TaskList>(std::move(task_chain_vec));
        }

        /**
         * @brief Matches a request path and HTTP method against the stored routes.
         *
         * Traverses the Radix Tree based on the segments of the input `path_str`.
         * It attempts to find a node that corresponds to the full path and has a handler
         * registered for the given `method`.
         * Parameter and wildcard values are extracted into `PathParameters`.
         * Matching priority (if multiple could match, e.g., static vs. param at same level):
         * 1. Static segments are preferred over parameterized segments.
         * 2. Parameterized segments are preferred over wildcard segments (though a wildcard can only be terminal).
         *
         * @param path_str The request URI path string (e.g., "/users/123/profile").
         * @param method The HTTP method of the request.
         * @return An `std::optional<MatchedRouteInfo<SessionType>>`. If a match is found, it contains the
         *         extracted path parameters and a shared pointer to the compiled task list for the route.
         *         If no match is found, `std::nullopt` is returned.
         */
        [[nodiscard]] std::optional<MatchedRouteInfo<SessionType> > match(
            const std::string &path_str, qb::http::method method) const {
            PathParameters params;
            std::vector<std::string_view> segments = split_path_to_segments(path_str);

            // Lazy allocation: path_segments_str_for_wildcard is only created if a wildcard is actually matched.
            // This avoids unnecessary allocations for the common case where no wildcard routes exist.
            std::optional<std::vector<std::string> > path_segments_str_for_wildcard;

            // Recursive lambda for matching
            std::function<std::optional<MatchedRouteInfo<SessionType> >(std::shared_ptr<Node>, size_t, PathParameters)>
                    find_match_recursive =
                            [&](std::shared_ptr<Node> current_node_ptr, size_t segment_idx,
                                PathParameters current_params)
                        -> std::optional<MatchedRouteInfo<SessionType> > {
                        if (!current_node_ptr) {
                            return std::nullopt;
                        }

#ifndef NDEBUG
                        // Debug assertions: Verify tree structure integrity
                        // These checks help detect corruption during development
                        if (current_node_ptr->param_child) {
                            assert(current_node_ptr->param_child->type == NodeType::PARAMETER &&
                                   "param_child must be of type PARAMETER");
                        }
                        if (current_node_ptr->wildcard_child) {
                            assert(current_node_ptr->wildcard_child->type == NodeType::WILDCARD &&
                                   "wildcard_child must be of type WILDCARD");
                        }
#endif

                        // Base case: All path segments have been consumed
                        if (segment_idx == segments.size()) {
                            auto handler_it = current_node_ptr->handlers.find(method);
                            if (handler_it != current_node_ptr->handlers.end()) {
                                return MatchedRouteInfo<SessionType>(current_params, handler_it->second);
                            }
                            // Special case for routes like /foo/* that can match /foo/ (wildcard captures empty)
                            if (current_node_ptr->wildcard_child) {
                                auto wc_handler_it = current_node_ptr->wildcard_child->handlers.find(method);
                                if (wc_handler_it != current_node_ptr->wildcard_child->handlers.end()) {
                                    PathParameters final_params_for_wc = current_params;
                                    final_params_for_wc.set(current_node_ptr->wildcard_child->segment_match, "");
                                    // Wildcard value is empty
                                    return MatchedRouteInfo<SessionType>(final_params_for_wc, wc_handler_it->second);
                                }
                            }
                            return std::nullopt;
                            // No handler for this method at this path, or no wildcard for empty remainder
                        }

                        const std::string_view &current_path_segment_view = segments[segment_idx];

                        // 1. Try static child match (highest priority)
                        auto static_child_it = current_node_ptr->static_children.find(current_path_segment_view);
                        if (static_child_it != current_node_ptr->static_children.end()) {
                            auto res = find_match_recursive(static_child_it->second, segment_idx + 1, current_params);
                            // Pass params by value for fork
                            if (res) return res;
                        }

                        // 2. Try parameter child match (second priority)
                        if (current_node_ptr->param_child) {
                            PathParameters params_for_param_branch = current_params;
                            params_for_param_branch.set(current_node_ptr->param_name, current_path_segment_view);
                            auto res = find_match_recursive(current_node_ptr->param_child, segment_idx + 1,
                                                            std::move(params_for_param_branch));
                            if (res) return res;
                        }

                        // 3. Try wildcard child match (lowest priority, and it consumes all remaining segments)
                        if (current_node_ptr->wildcard_child) {
                            // Lazy creation: only create path_segments_str_for_wildcard if we actually need it
                            if (!path_segments_str_for_wildcard.has_value()) {
                                path_segments_str_for_wildcard.emplace();
                                path_segments_str_for_wildcard->reserve(segments.size());
                                for (const auto &sv: segments) {
                                    path_segments_str_for_wildcard->emplace_back(sv);
                                }
                            }
                            
                            std::string wildcard_captured_value;
                            for (size_t i = segment_idx; i < segments.size(); ++i) {
                                if (i > segment_idx) wildcard_captured_value += "/";
                                wildcard_captured_value += (*path_segments_str_for_wildcard)[i];
                                // Use pre-converted strings for safety
                            }
                            PathParameters params_for_wildcard_branch = current_params;
                            params_for_wildcard_branch.set(current_node_ptr->wildcard_child->segment_match,
                                                           wildcard_captured_value);

                            // Wildcard consumes all remaining segments, so we must find the handler on the wildcard_child itself.
                            auto handler_it = current_node_ptr->wildcard_child->handlers.find(method);
                            if (handler_it != current_node_ptr->wildcard_child->handlers.end()) {
                                return MatchedRouteInfo<SessionType>(params_for_wildcard_branch, handler_it->second);
                            }
                        }

                        return std::nullopt; // No match found down any path from this node
                    };

            return find_match_recursive(_root, 0, params);
        }

        /**
         * @brief Clears all routes from the Radix Tree, resetting it to an empty state with only a root node.
         */
        void clear() noexcept {
            _root = std::make_shared<Node>(NodeType::ROOT); // Reset to a new root node
            _path_segment_storage.clear(); // Clear stored path segments as well
        }

        /**
         * @brief Placeholder for any finalization or optimization steps after all routes are added.
         * Currently, this is a no-op but can be extended for future tree validation or pre-compilation tasks.
         */
        void finalize_routes() noexcept {
            // No-op for now. Could be used for tree validation, optimization, etc.
        }
    };
} // namespace qb::http 
