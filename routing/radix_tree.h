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

#include <array>          // For std::array (method-indexed handler slots)
#include <string>         // For std::string
#include <string_view>    // For std::string_view
#include <vector>         // For std::vector
#include <qb/system/container/unordered_map.h>  // For qb::unordered_map (ska::flat_hash_map, cache-friendly O(1) lookup for static_children)
#include <memory>         // For std::shared_ptr, std::make_shared, std::unique_ptr (used by Node)
#include <list>           // For std::list (task chains, _path_segment_storage)
#include <optional>       // For std::optional (match result)
#include <algorithm>      // For std::find_if, std::copy, std::back_inserter
#include <stdexcept>      // For std::runtime_error, std::invalid_argument
#include <utility>        // For std::move
#include <cassert>        // For assert (debug mode checks)
#include <unordered_set>  // For duplicate capture name validation

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

    template<typename SessionType>
    struct PathAllowedMethodsInfo {
        PathParameters path_parameters;
        std::vector<qb::http::method> methods;

        PathAllowedMethodsInfo(PathParameters params, std::vector<qb::http::method> allowed_methods)
            : path_parameters(std::move(params)), methods(std::move(allowed_methods)) {
        }

        PathAllowedMethodsInfo() = default;
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
         * @brief Number of slots reserved for HTTP method-indexed handler lookup.
         * Covers the full range of `llhttp` method codes (0..46 for HTTP_QUERY).
         * Selected as a compile-time constant so that dispatch is an O(1) array index
         * rather than an O(log n) `std::map` lookup.
         */
        static constexpr std::size_t METHOD_SLOT_COUNT = 64;

        /**
         * @brief Maps a `qb::http::method` to its handler-array slot.
         * @return A valid index in `[0, METHOD_SLOT_COUNT)`, or a sentinel value
         *         greater than or equal to `METHOD_SLOT_COUNT` for uninitialised /
         *         out-of-range methods (which never receive a handler).
         */
        [[nodiscard]] static constexpr std::size_t method_slot(qb::http::method m) noexcept {
            const auto raw = std::to_underlying(static_cast<qb::http::method::Value>(m));
            if (raw < 0 || static_cast<std::size_t>(raw) >= METHOD_SLOT_COUNT) {
                return METHOD_SLOT_COUNT; // invalid / uninitialised
            }
            return static_cast<std::size_t>(raw);
        }

        [[nodiscard]] static constexpr qb::http::method slot_method(std::size_t slot) noexcept {
            return qb::http::method(static_cast<::http_method>(slot));
        }

        /**
         * @brief Represents a node within the Radix Tree.
         * Each node corresponds to a part of a URL path and can hold handlers for specific HTTP methods.
         */
        struct Node {
            NodeType type = NodeType::STATIC; ///< The type of this node.
            std::string_view segment_match;
            ///< For STATIC nodes: the exact segment string. For PARAMETER/WILDCARD nodes: the name of the parameter/wildcard (e.g., "id", "filepath").

            /**
             * @brief Flat, method-indexed table of handler task lists.
             *
             * The slot at index `method_slot(method)` contains the compiled chain
             * (middleware + final handler) registered for that method, or a null
             * pointer if no route is registered. Selected over `std::map` for
             * constant-time dispatch and cache-friendly layout; at fewer than 64
             * method slots per node, the extra 8*64 = 512 B per node is negligible
             * compared to the `std::map` node overhead that was previously paid
             * per registered method.
             */
            std::array<std::shared_ptr<const TaskList>, METHOD_SLOT_COUNT> handlers{};

            /** @brief Children nodes representing static path segments. Keyed by the segment string.
             *
             *  Backed by `qb::unordered_map` (an open-addressed `ska::flat_hash_map`) so
             *  both the buckets and the `string_view` keys live in a single contiguous
             *  buffer. This gives us O(1) average lookup with one cache line touch for
             *  small fanouts, which is the dominant case in real HTTP routers (a handful
             *  of children per node). Iteration order does not matter: we only perform
             *  `find()`, never range-scan, during matching.
             *
             *  Ownership is exclusive: routes are immutable after `compile()`, so a
             *  `std::unique_ptr` is sufficient and avoids the atomic refcount traffic a
             *  `std::shared_ptr` would incur on every traversal.
             */
            qb::unordered_map<std::string_view, std::unique_ptr<Node> > static_children;
            /** @brief Child node for a parameterized segment, if one exists at this level. */
            std::unique_ptr<Node> param_child;
            /** @brief The name of the parameter for `param_child` (e.g., "id" for a `:id` segment). */
            std::string_view param_name;
            /** @brief Child node for a wildcard segment, if one exists at this level. */
            std::unique_ptr<Node> wildcard_child;

            /**
             * @brief Constructs a Node.
             * @param t The type of the node.
             * @param seg The segment string or parameter/wildcard name associated with this node.
             */
            Node(NodeType t = NodeType::STATIC, std::string_view seg = "") noexcept
                : type(t), segment_match(seg) {
            }
        };

        [[nodiscard]] static bool has_any_handler(const Node &node) noexcept {
            for (const auto &handler: node.handlers) {
                if (handler) {
                    return true;
                }
            }
            return false;
        }

        [[nodiscard]] static std::vector<qb::http::method> collect_allowed_methods(const Node &node) {
            std::vector<qb::http::method> methods;
            methods.reserve(8);
            for (std::size_t slot = 0; slot < METHOD_SLOT_COUNT; ++slot) {
                if (node.handlers[slot]) {
                    methods.emplace_back(slot_method(slot));
                }
            }
            return methods;
        }

        static void merge_allowed_methods(std::vector<qb::http::method> &dst,
                                          const std::vector<qb::http::method> &src) {
            dst.insert(dst.end(), src.begin(), src.end());
            std::sort(dst.begin(), dst.end(), [](qb::http::method lhs, qb::http::method rhs) {
                return method_slot(lhs) < method_slot(rhs);
            });
            dst.erase(std::unique(dst.begin(), dst.end(), [](qb::http::method lhs, qb::http::method rhs) {
                return method_slot(lhs) == method_slot(rhs);
            }), dst.end());
        }

        std::unique_ptr<Node> _root; ///< The root node of the Radix Tree.

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
        RadixTree() : _root(std::make_unique<Node>(NodeType::ROOT)) {
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

            Node *current_node = _root.get();
            std::vector<std::string_view> segments = split_path_to_segments(path_pattern_str);
            std::unordered_set<std::string> seen_capture_names;

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
                    _path_segment_storage.emplace_back(segment_sv.substr(1));
                    std::string_view wildcard_name_sv = _path_segment_storage.back();
                    if (!seen_capture_names.emplace(std::string(wildcard_name_sv)).second) {
                        throw std::invalid_argument(
                            "Duplicate capture name '" + std::string(wildcard_name_sv) +
                            "' in path pattern: " + path_pattern_str);
                    }

                    if (!current_node->wildcard_child) {
                        current_node->wildcard_child = std::make_unique<Node>(NodeType::WILDCARD, wildcard_name_sv);
                    } else if (current_node->wildcard_child->segment_match != wildcard_name_sv) {
                        throw std::invalid_argument(
                            "Wildcard segment '" + std::string(segment_sv) + "' conflicts with existing wildcard '*" +
                            std::string(current_node->wildcard_child->segment_match) +
                            "' at the same level in path: " + path_pattern_str);
                    }
                    current_node = current_node->wildcard_child.get();
                    break; // Wildcard is always the last segment, so stop iterating path segments.
                } else if (segment_sv[0] == ':') {
                    // Parameter segment
                    if (segment_sv.length() < 2) {
                        throw std::invalid_argument(
                            "Parameter segment must have a name (e.g., :id), got: '" + std::string(segment_sv) +
                            "' in path: " + path_pattern_str);
                    }
                    _path_segment_storage.emplace_back(segment_sv.substr(1));
                    std::string_view p_name_sv = _path_segment_storage.back();
                    if (!seen_capture_names.emplace(std::string(p_name_sv)).second) {
                        throw std::invalid_argument(
                            "Duplicate capture name '" + std::string(p_name_sv) +
                            "' in path pattern: " + path_pattern_str);
                    }

                    if (!current_node->param_child) {
                        current_node->param_child = std::make_unique<Node>(NodeType::PARAMETER, p_name_sv);
                        current_node->param_name = p_name_sv;
                    } else if (current_node->param_name != p_name_sv) {
                        throw std::invalid_argument(
                            "Parameter segment '" + std::string(segment_sv) + "' conflicts with existing parameter ':" +
                            std::string(current_node->param_name) +
                            "' at the same level in path: " + path_pattern_str);
                    }
                    current_node = current_node->param_child.get();
                } else {
                    // Static segment
                    _path_segment_storage.emplace_back(segment_sv);
                    std::string_view static_segment_sv = _path_segment_storage.back();

                    auto it = current_node->static_children.find(static_segment_sv);
                    if (it == current_node->static_children.end()) {
                        auto new_node = std::make_unique<Node>(NodeType::STATIC, static_segment_sv);
                        Node *raw = new_node.get();
                        current_node->static_children.emplace(static_segment_sv, std::move(new_node));
                        current_node = raw;
                    } else {
                        current_node = it->second.get();
                    }
                }
            }
            // After iterating all segments, current_node is the terminal node for this path.
            const auto slot = method_slot(method);
            if (slot >= METHOD_SLOT_COUNT) {
                throw std::invalid_argument(
                    "Cannot register a handler for an uninitialised / out-of-range HTTP method on path: "
                    + path_pattern_str);
            }
            current_node->handlers[slot] = std::make_shared<const TaskList>(std::move(task_chain_vec));
        }

        /**
         * @brief Matches a request path and HTTP method against the stored routes.
         *
         * Traverses the Radix Tree based on the segments of the input `path_sv`.
         * It attempts to find a node that corresponds to the full path and has a handler
         * registered for the given `method`.
         * Parameter and wildcard values are extracted into `PathParameters`.
         * Matching priority (if multiple could match, e.g., static vs. param at same level):
         * 1. Static segments are preferred over parameterized segments.
         * 2. Parameterized segments are preferred over wildcard segments (though a wildcard can only be terminal).
         *
         * The caller owns the backing storage for `path_sv`; the returned
         * `MatchedRouteInfo` may contain `std::string_view`s that reference
         * slices of it, so it must remain valid for the lifetime of the match
         * result (typically: the current request processing chain).
         *
         * @param path_sv The request URI path (e.g., "/users/123/profile").
         * @param method The HTTP method of the request.
         * @return An `std::optional<MatchedRouteInfo<SessionType>>`. If a match is found, it contains the
         *         extracted path parameters and a shared pointer to the compiled task list for the route.
         *         If no match is found, `std::nullopt` is returned.
         */
        [[nodiscard]] std::optional<MatchedRouteInfo<SessionType> > match(
            std::string_view path_sv, qb::http::method method) const {
            PathParameters params;
            std::vector<std::string_view> segments = split_path_to_segments(path_sv);

            const std::size_t slot = method_slot(method);
            if (slot >= METHOD_SLOT_COUNT) {
                return std::nullopt; // unknown / uninitialised method -> cannot match anything
            }

            // For wildcard capture: reconstructing the slice joined by '/' is
            // a single substring of the original `path_sv`. This avoids the
            // per-request string copy / byte-wise concatenation the legacy
            // implementation performed.

            // Recursive lambda for matching. Nodes are borrowed via raw pointers:
            // the tree owns them through `std::unique_ptr`, so for the duration of
            // this call `const Node*` is guaranteed to outlive the recursion frame.
            std::function<std::optional<MatchedRouteInfo<SessionType> >(const Node *, size_t, PathParameters)>
                    find_match_recursive =
                            [&](const Node *current_node_ptr, size_t segment_idx,
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
                            const auto &handler_here = current_node_ptr->handlers[slot];
                            if (handler_here) {
                                return MatchedRouteInfo<SessionType>(current_params, handler_here);
                            }
                            // Special case for routes like /foo/* that can match /foo/ (wildcard captures empty)
                            if (current_node_ptr->wildcard_child) {
                                const auto &wc_handler = current_node_ptr->wildcard_child->handlers[slot];
                                if (wc_handler) {
                                    PathParameters final_params_for_wc = current_params;
                                    final_params_for_wc.set(current_node_ptr->wildcard_child->segment_match, "");
                                    // Wildcard value is empty
                                    return MatchedRouteInfo<SessionType>(final_params_for_wc, wc_handler);
                                }
                            }
                            return std::nullopt;
                            // No handler for this method at this path, or no wildcard for empty remainder
                        }

                        const std::string_view &current_path_segment_view = segments[segment_idx];

                        // 1. Try static child match (highest priority)
                        auto static_child_it = current_node_ptr->static_children.find(current_path_segment_view);
                        if (static_child_it != current_node_ptr->static_children.end()) {
                            auto res = find_match_recursive(static_child_it->second.get(), segment_idx + 1, current_params);
                            // Pass params by value for fork
                            if (res) return res;
                        }

                        // 2. Try parameter child match (second priority)
                        if (current_node_ptr->param_child) {
                            PathParameters params_for_param_branch = current_params;
                            params_for_param_branch.set(current_node_ptr->param_name, current_path_segment_view);
                            auto res = find_match_recursive(current_node_ptr->param_child.get(), segment_idx + 1,
                                                            std::move(params_for_param_branch));
                            if (res) return res;
                        }

                        // 3. Try wildcard child match (lowest priority, and it consumes all remaining segments)
                        if (current_node_ptr->wildcard_child) {
                            // Zero-copy wildcard slice: segments are views into `path_sv`, so
                            // the span "/segments[idx]/.../segments[last]" is a single
                            // contiguous substring. Compute it without allocations and let
                            // `PathParameters::set` do the sole owning copy.
                            const auto &first_seg = segments[segment_idx];
                            const auto &last_seg = segments.back();
                            const char *slice_begin = first_seg.data();
                            const char *slice_end = last_seg.data() + last_seg.size();
                            std::string_view wildcard_captured_view{
                                slice_begin, static_cast<std::size_t>(slice_end - slice_begin)};

                            PathParameters params_for_wildcard_branch = current_params;
                            params_for_wildcard_branch.set(current_node_ptr->wildcard_child->segment_match,
                                                           wildcard_captured_view);

                            // Wildcard consumes all remaining segments, so we must find the handler on the wildcard_child itself.
                            const auto &wc_handler = current_node_ptr->wildcard_child->handlers[slot];
                            if (wc_handler) {
                                return MatchedRouteInfo<SessionType>(params_for_wildcard_branch, wc_handler);
                            }
                        }

                        return std::nullopt; // No match found down any path from this node
                    };

            return find_match_recursive(_root.get(), 0, params);
        }

        /**
         * @brief Matches only the request path and returns methods registered
         *        at the resolved route node.
         *
         * This is used by RouterCore to distinguish a missing resource (404)
         * from an existing resource reached with an unsupported method (405).
         * It follows the same static > parameter > wildcard priority as
         * `match()` and returns no value when the path shape does not resolve
         * to a terminal route node with at least one handler.
         */
        [[nodiscard]] std::optional<PathAllowedMethodsInfo<SessionType> > allowed_methods(
            std::string_view path_sv) const {
            PathParameters params;
            std::vector<std::string_view> segments = split_path_to_segments(path_sv);

            std::function<std::optional<PathAllowedMethodsInfo<SessionType> >(const Node *, size_t, PathParameters)>
                    find_path_recursive =
                            [&](const Node *current_node_ptr, size_t segment_idx,
                                PathParameters current_params)
                        -> std::optional<PathAllowedMethodsInfo<SessionType> > {
                        if (!current_node_ptr) {
                            return std::nullopt;
                        }

                        std::optional<PathAllowedMethodsInfo<SessionType> > result;
                        const auto merge_result =
                                [&](std::optional<PathAllowedMethodsInfo<SessionType> > candidate) {
                            if (!candidate || candidate->methods.empty()) {
                                return;
                            }
                            if (!result) {
                                result = std::move(candidate);
                                std::sort(result->methods.begin(), result->methods.end(),
                                          [](qb::http::method lhs, qb::http::method rhs) {
                                              return method_slot(lhs) < method_slot(rhs);
                                          });
                                result->methods.erase(
                                    std::unique(result->methods.begin(), result->methods.end(),
                                                [](qb::http::method lhs, qb::http::method rhs) {
                                                    return method_slot(lhs) == method_slot(rhs);
                                                }),
                                    result->methods.end());
                            } else {
                                merge_allowed_methods(result->methods, candidate->methods);
                            }
                        };

                        if (segment_idx == segments.size()) {
                            if (has_any_handler(*current_node_ptr)) {
                                merge_result(PathAllowedMethodsInfo<SessionType>(
                                    current_params, collect_allowed_methods(*current_node_ptr)));
                            }
                            if (current_node_ptr->wildcard_child &&
                                has_any_handler(*current_node_ptr->wildcard_child)) {
                                PathParameters final_params_for_wc = current_params;
                                final_params_for_wc.set(current_node_ptr->wildcard_child->segment_match, "");
                                merge_result(PathAllowedMethodsInfo<SessionType>(
                                    std::move(final_params_for_wc),
                                    collect_allowed_methods(*current_node_ptr->wildcard_child)));
                            }
                            return result;
                        }

                        const std::string_view &current_path_segment_view = segments[segment_idx];

                        auto static_child_it = current_node_ptr->static_children.find(current_path_segment_view);
                        if (static_child_it != current_node_ptr->static_children.end()) {
                            merge_result(find_path_recursive(static_child_it->second.get(), segment_idx + 1,
                                                             current_params));
                        }

                        if (current_node_ptr->param_child) {
                            PathParameters params_for_param_branch = current_params;
                            params_for_param_branch.set(current_node_ptr->param_name, current_path_segment_view);
                            merge_result(find_path_recursive(current_node_ptr->param_child.get(), segment_idx + 1,
                                                             std::move(params_for_param_branch)));
                        }

                        if (current_node_ptr->wildcard_child &&
                            has_any_handler(*current_node_ptr->wildcard_child)) {
                            const auto &first_seg = segments[segment_idx];
                            const auto &last_seg = segments.back();
                            const char *slice_begin = first_seg.data();
                            const char *slice_end = last_seg.data() + last_seg.size();
                            std::string_view wildcard_captured_view{
                                slice_begin, static_cast<std::size_t>(slice_end - slice_begin)};

                            PathParameters params_for_wildcard_branch = current_params;
                            params_for_wildcard_branch.set(current_node_ptr->wildcard_child->segment_match,
                                                           wildcard_captured_view);
                            merge_result(PathAllowedMethodsInfo<SessionType>(
                                std::move(params_for_wildcard_branch),
                                collect_allowed_methods(*current_node_ptr->wildcard_child)));
                        }

                        return result;
                    };

            return find_path_recursive(_root.get(), 0, params);
        }

        /**
         * @brief Clears all routes from the Radix Tree, resetting it to an empty state with only a root node.
         */
        void clear() noexcept {
            _root = std::make_unique<Node>(NodeType::ROOT); // Reset to a new root node
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
