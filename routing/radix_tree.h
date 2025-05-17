#pragma once

#include "./async_task.h"
#include "../types.h" // For qb::http::method
#include "./path_parameters.h"

#include <string>
#include <string_view> // For string_view operations
#include <vector>
#include <map>
#include <memory>
#include <list>
#include <optional>
#include <algorithm> // For std::find_if
#include <stdexcept> // For std::runtime_error, std::invalid_argument
#include <iostream> // For debug prints

namespace qb::http {

/**
 * @brief Information stored for a matched route in the RadixTree.
 */
template <typename Session>
struct MatchedRouteInfo {
    PathParameters path_parameters;
    std::optional<std::shared_ptr<const std::vector<std::shared_ptr<IAsyncTask<Session>>>>> route_tasks; // The actual tasks to execute

    MatchedRouteInfo(PathParameters params, std::optional<std::shared_ptr<const std::vector<std::shared_ptr<IAsyncTask<Session>>>>> tasks)
        : path_parameters(std::move(params)), route_tasks(std::move(tasks)) {}
    
    MatchedRouteInfo() = default; 
};

/**
 * @brief A Radix Tree for storing and matching HTTP routes.
 *
 * This tree supports static segments, parameterized segments (e.g., /users/:id),
 * and wildcard segments (e.g., /files/ *filepath). It compiles route definitions
 * into task chains that are executed upon a successful match.
 */
template <typename Session>
class RadixTree {
public:
    using TaskList = std::vector<std::shared_ptr<IAsyncTask<Session>>>;

private:
    enum class NodeType {
        ROOT,
        STATIC,
        PARAMETER, // e.g., :id
        WILDCARD   // e.g., *filepath
    };

    struct Node {
        NodeType type = NodeType::STATIC;
        std::string_view segment_match; // For STATIC, the segment string. For PARAMETER/WILDCARD, the name.
        
        std::map<qb::http::method, std::shared_ptr<const TaskList>> handlers;
        
        std::map<std::string_view, std::shared_ptr<Node>> static_children;
        std::shared_ptr<Node> param_child = nullptr;
        std::string_view param_name; // Name of the parameter (e.g., "id" without ':')
        std::shared_ptr<Node> wildcard_child = nullptr;

        // New fields for middleware and group context, stored at the terminal node of a route
        std::map<qb::http::method, std::weak_ptr<RouteGroup<Session>>> group_context_for_route;
        std::map<qb::http::method, std::vector<std::shared_ptr<IMiddleware<Session>>>> route_specific_middleware_definitions;

        Node(NodeType t = NodeType::STATIC, std::string_view seg = "") : type(t), segment_match(seg) {}
    };

    std::shared_ptr<Node> _root;

    // Storage for path segments to ensure string_view stability
    std::list<std::string> _path_segment_storage;

    // Splits a path string_view into segments. Handles leading/trailing slashes.
    // Example: "/foo/bar/" -> {"foo", "bar"}
    // Example: "/" -> {}
    static std::vector<std::string_view> split_path_to_segments(std::string_view path_sv) {
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
                if (i > start) { // Avoid empty segment from consecutive slashes or leading slash
                    segments.push_back(path_sv.substr(start, i - start));
                }
                start = i + 1;
            }
        }

        // Last segment (or only segment if no slashes after start)
        if (start < n) {
            segments.push_back(path_sv.substr(start, n - start));
        }
        // If path was just "/", segments vector will be empty, which is the correct representation.
        // If path was "/foo/", the last segment "foo" is added, and the trailing slash does not create an empty segment.
        return segments;
    }

public:
    RadixTree() : _root(std::make_shared<Node>(NodeType::ROOT)) {}

    /**
     * @brief Adds a compiled route to the tree.
     * @param path The full path for the route.
     * @param method The HTTP method.
     * @param task_chain The pre-compiled list of tasks for this route.
     */
    void add_route(const std::string& path_pattern_str, qb::http::method method, std::list<std::shared_ptr<IAsyncTask<Session>>> task_chain_list) {
        TaskList task_chain_vec;
        std::copy(task_chain_list.begin(), task_chain_list.end(), std::back_inserter(task_chain_vec));

        std::shared_ptr<Node> current_node = _root;
        std::vector<std::string_view> segments = split_path_to_segments(path_pattern_str);

        for (size_t i = 0; i < segments.size(); ++i) {
            const auto& segment_sv = segments[i];
            
            std::string_view current_segment_for_node_construction;
            if (segment_sv.empty()) { 
                if (i == segments.size() -1 && segments.size() == 1 && path_pattern_str == "/") {
                    // Path is just "/", root node handles this. segment_match can be empty for root node type.
                    current_segment_for_node_construction = ""; // Or root specific marker if needed elsewhere
                } else {
                    throw std::invalid_argument("Empty segment encountered in path pattern: " + path_pattern_str);
                }
            } else {
                // Store the segment string and get a stable string_view
                // No specific check for path_pattern_str == "/" here because segment_sv won't be empty.
            }

            if (!segment_sv.empty() && segment_sv[0] == '*') { // Wildcard segment
                if (segment_sv.length() < 2) {
                    throw std::invalid_argument("Wildcard segment must have a name (e.g., *filepath), got: '" + std::string(segment_sv) + "' in path: " + path_pattern_str);
                }
                if (i != segments.size() - 1) { // Wildcard must be the last segment
                    throw std::invalid_argument("Wildcard segment '" + std::string(segment_sv) + "' must be the last segment in the path pattern: " + path_pattern_str);
                }
                if (current_node->type == NodeType::PARAMETER || current_node->type == NodeType::WILDCARD) {
                    throw std::invalid_argument("Cannot define a wildcard segment ('" + std::string(segment_sv) + "') under a parent that is already a parameter or wildcard ('" + std::string(current_node->segment_match) + "') in path: " + path_pattern_str);
                }

                _path_segment_storage.emplace_back(segment_sv.substr(1));
                std::string_view wildcard_name_sv = _path_segment_storage.back();

                if (!current_node->wildcard_child) {
                    current_node->wildcard_child = std::make_shared<Node>(NodeType::WILDCARD, wildcard_name_sv);
                } else if (current_node->wildcard_child->segment_match != wildcard_name_sv) {
                    throw std::invalid_argument("Wildcard segment '" + std::string(segment_sv) + "' conflicts with existing wildcard '*" +
                                             std::string(current_node->wildcard_child->segment_match) +
                                             "' at the same level in path: " + path_pattern_str);
                }
                current_node = current_node->wildcard_child;
                break; 
            } else if (!segment_sv.empty() && segment_sv[0] == ':') { // Parameter segment
                if (segment_sv.length() < 2) {
                    throw std::invalid_argument("Parameter segment must have a name (e.g., :id), got: '" + std::string(segment_sv) + "' in path: " + path_pattern_str);
                }
                if (current_node->type == NodeType::PARAMETER || current_node->type == NodeType::WILDCARD) {
                    throw std::invalid_argument("Cannot define a parameter segment ('" + std::string(segment_sv) + "') under a parent that is already a parameter or wildcard ('" + std::string(current_node->segment_match) + "') in path: " + path_pattern_str);
                }

                _path_segment_storage.emplace_back(segment_sv.substr(1));
                std::string_view p_name_sv = _path_segment_storage.back();

                if (!current_node->param_child) {
                    current_node->param_child = std::make_shared<Node>(NodeType::PARAMETER, p_name_sv);
                    current_node->param_name = p_name_sv; 
                } else if (current_node->param_name != p_name_sv) {
                    throw std::invalid_argument("Parameter segment '" + std::string(segment_sv) + "' conflicts with existing parameter ':" +
                                             std::string(current_node->param_name) +
                                             "' at the same level in path: " + path_pattern_str);
                }
                 current_node = current_node->param_child;
            } else { // Static segment
                // Store the segment_sv for static node construction if it's not empty
                // If path_pattern_str is "/", segments might be empty or contain one empty string based on split_path_to_segments logic for root
                // For root itself ("/"), segment_sv might be effectively empty for the purpose of node construction for root.
                // current_node (root) segment_match is already set by its constructor (default empty for ROOT type)
                if (path_pattern_str == "/" && segments.empty()) { // Handling the explicit "/" path where segments is empty
                    // This means the handler is for the root node itself. current_node is _root.
                    // No further node creation or segment processing needed for path structure.
                } else if (!segment_sv.empty()) { // Only proceed if segment_sv is not empty
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
                } else if (segment_sv.empty() && !(path_pattern_str == "/" && segments.empty())) {
                     // This case handles if split_path_to_segments could return an empty string_view for non-root
                     // e.g. path like "//foo" or "/foo//bar" - should be prevented by split or throw error
                     throw std::invalid_argument("Invalid empty segment from path split for non-root: " + path_pattern_str);
                }
                 // If segment_sv is empty and it's the root path case, we don't go into children, just attach handler to current_node (_root)
            }
        }
        current_node->handlers[method] = std::make_shared<const TaskList>(std::move(task_chain_vec));
    }

    /**
     * @brief Matches a request path and method to a compiled route.
     * @param path The request path to match.
     * @param method The HTTP method of the request.
     * @return An optional MatchedRouteInfo if a route is found, else std::nullopt.
     */
    std::optional<MatchedRouteInfo<Session>> match(const std::string& path_str, qb::http::method method) const {
        qb::http::PathParameters params;
        std::vector<std::string_view> segments = split_path_to_segments(path_str);
        
        // Store path segments as strings for wildcard matching to combine them
        std::vector<std::string> path_segments_str;
        for(const auto& sv : segments) {
            path_segments_str.push_back(std::string(sv));
        }

        std::function<std::optional<MatchedRouteInfo<Session>>(std::shared_ptr<Node>, size_t, qb::http::PathParameters)> 
        find_match = 
            [&](std::shared_ptr<Node> current_node, size_t segment_idx, qb::http::PathParameters current_params) 
            -> std::optional<MatchedRouteInfo<Session>> {
            
            if (!current_node) {
                return std::nullopt;
            }

            // If we've consumed all path segments
            if (segment_idx == segments.size()) {
                auto handler_it = current_node->handlers.find(method);
                if (handler_it != current_node->handlers.end()) {
                    return MatchedRouteInfo<Session>(current_params, handler_it->second);
                }
                // Check for wildcard match on empty remaining path (e.g. route /foo/* and path /foo/)
                if (current_node->wildcard_child) {
                    auto wc_handler_it = current_node->wildcard_child->handlers.find(method);
                    if (wc_handler_it != current_node->wildcard_child->handlers.end()) {
                        qb::http::PathParameters final_params = current_params; 
                        final_params.set(current_node->wildcard_child->segment_match, ""); // Wildcard captures empty string
                        return MatchedRouteInfo<Session>(final_params, wc_handler_it->second);
                    }
                }
                return std::nullopt; // No direct handler, no wildcard match on empty path remainder.
            }

            const std::string_view& current_path_segment_sv = segments[segment_idx];
            const std::string& current_path_segment_str = path_segments_str[segment_idx];

            // Try static child match first (highest priority)
            auto static_it = current_node->static_children.find(current_path_segment_sv); 
            if (static_it != current_node->static_children.end()) {
                auto res = find_match(static_it->second, segment_idx + 1, current_params); // Pass copy of params
                if (res) return res;
            }

            // Try parameter child match (second priority)
            if (current_node->param_child) {
                qb::http::PathParameters next_params = current_params; 
                next_params.set(current_node->param_name, current_path_segment_sv);
                auto res = find_match(current_node->param_child, segment_idx + 1, std::move(next_params));
                if (res) return res;
            }
            
            // Try wildcard child match (lowest priority for this segment)
            if (current_node->wildcard_child) {
                std::string wildcard_value;
                for (size_t i = segment_idx; i < segments.size(); ++i) {
                    if (i > segment_idx) wildcard_value += "/";
                    wildcard_value += path_segments_str[i];
                }
                current_params.set(current_node->wildcard_child->segment_match, wildcard_value); // segment_match holds wildcard name
                
                // After wildcard, we expect to find the handler directly on the wildcard node
                auto handler_it = current_node->wildcard_child->handlers.find(method);
                if (handler_it != current_node->wildcard_child->handlers.end()) {
                    return MatchedRouteInfo<Session>(current_params, handler_it->second);
                }
            }
            
            return std::nullopt;
        };

        return find_match(_root, 0, params);
    }

    void clear() {
        _root = std::make_shared<Node>(NodeType::ROOT); // Reset to a new root node, effectively clearing the tree.
    }

    void finalize_routes() {
        // std::cerr << "RadixTree: Finalize routes called. (No-op for now)" << std::endl;
        // Placeholder for any tree optimization or validation after all routes are added.
        // For example, could pre-compile certain structures or validate constraints.
    }
};

} // namespace qb::http 