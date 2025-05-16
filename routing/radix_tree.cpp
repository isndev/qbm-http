#include "radix_tree.h"
#include "logging_helpers.h"
#include <algorithm>
#include <iostream>
#include <optional>

namespace qb::http {

void
RadixNode::insert(const std::string &path, void *entity_ptr, int entity_priority, RadixMatchResult::TargetType type_of_entity) {
    if (path.empty() || path == "/") {
        this->is_endpoint = true;
        this->entity_ptr = entity_ptr;
        this->priority = entity_priority;
        this->entity_type = type_of_entity;
        return;
    }
    std::string p = path;
    if (p[0] == '/') { p = p.substr(1); }
    if (p.empty()) { // Original path was just "/"
        this->is_endpoint = true;
        this->entity_ptr = entity_ptr;
        this->priority = entity_priority;
        this->entity_type = type_of_entity;
        return;
    }
    size_t next_slash = p.find('/');
    std::string segment_value = (next_slash == std::string::npos) ? p : p.substr(0, next_slash);
    std::string rest_of_path = (next_slash == std::string::npos) ? "" : p.substr(next_slash);
    bool is_param_node_segment = false;
    std::string param_name_val;
    std::string static_prefix_for_child = segment_value;
    size_t colon_pos = segment_value.find(':');
    if (colon_pos != std::string::npos) {
        is_param_node_segment = true;
        static_prefix_for_child = segment_value.substr(0, colon_pos);
        param_name_val = segment_value.substr(colon_pos + 1);
    }
    for (auto &child : children) {
        if (child.segment == static_prefix_for_child && child.is_param == is_param_node_segment) {
            if (is_param_node_segment && child.param_name != param_name_val) continue;
            child.node->insert(rest_of_path, entity_ptr, entity_priority, type_of_entity);
            return;
        }
    }
    auto new_node = std::make_shared<RadixNode>();
    children.push_back({static_prefix_for_child, new_node, is_param_node_segment, param_name_val});
    new_node->insert(rest_of_path, entity_ptr, entity_priority, type_of_entity);
}

void
RadixTree::insert(const std::string &path, void *entity_ptr, int priority, RadixMatchResult::TargetType type_of_entity) {
    std::string normalized_path = path;
    if (normalized_path.empty() || (normalized_path == "/" && path.length() == 1)) { 
        _root->is_endpoint = true; 
        _root->entity_ptr = entity_ptr;
        _root->priority = priority;
        _root->entity_type = type_of_entity;
        return;
    }
    if (normalized_path[0] != '/') {
        normalized_path = "/" + normalized_path;
    }
    _root->insert(normalized_path, entity_ptr, priority, type_of_entity);
}

std::optional<RadixMatchResult>
RadixNode::match(const std::string &path_to_match, PathParameters& accumulated_params, const std::string& current_path_build) const {
    // path_to_match is the *remaining* path from the parent call.
    // current_path_build is the path matched so far to reach THIS node.
    // accumulated_params are the parameters gathered along current_path_build.

    // Base Case: path_to_match is empty or just "/", meaning we are at the potential end of a match.
    if (path_to_match.empty() || path_to_match == "/") {
        if (this->is_endpoint) { // This node itself is registered as an endpoint for an entity.
            RadixMatchResult res;
            res.target_ptr = this->entity_ptr;
            res.type = this->entity_type;
            res.params = accumulated_params; // Params gathered to reach this node.
            res.matched_path_prefix = current_path_build.empty() ? "/" : current_path_build;
            res.full_debug_matched_path = res.matched_path_prefix;
            res.remaining_path = path_to_match; // Should be empty or "/" if this endpoint is the exact match.
            res.priority = this->priority;
            return res;
        }
        // Path is exhausted, but this node isn't an endpoint itself. No match here.
        return std::nullopt;
    }

    // Process the next segment from path_to_match
    std::string path_remainder = path_to_match;
    if (path_remainder[0] == '/') path_remainder = path_remainder.substr(1);
    if (path_remainder.empty()) return std::nullopt; // Should have been caught by base case if path_to_match was just "/"

    size_t next_slash_pos = path_remainder.find('/');
    std::string current_segment_from_path = (next_slash_pos == std::string::npos) ? path_remainder : path_remainder.substr(0, next_slash_pos);
    std::string next_remaining_path = (next_slash_pos == std::string::npos) ? "" : path_remainder.substr(next_slash_pos);

    // Try static children first
    for (const auto &child : children) {
        if (!child.is_param && child.segment == current_segment_from_path) {
            std::string next_build = current_path_build + (current_path_build.back() == '/' ? "" : "/") + child.segment;
            if (current_path_build.empty() && child.segment.empty()) next_build = "/"; 
            else if (current_path_build.empty()) next_build = "/" + child.segment; 
            
            auto result = child.node->match(next_remaining_path, accumulated_params, next_build);
            if (result) return result;
        }
    }

    // Try parameter children
    for (const auto &child : children) {
        if (child.is_param) {
            // child.segment is the static prefix (e.g. "file-" in "file-:name"). Can be empty for pure ":name".
            if (current_segment_from_path.rfind(child.segment, 0) == 0) { 
                std::string param_value = current_segment_from_path.substr(child.segment.length());
                if (!param_value.empty() || child.segment.empty()) { // Param value must exist, or it's a pure /:id type param
                    PathParameters params_for_branch = accumulated_params; // Copy params for this recursive path
                    params_for_branch[child.param_name] = param_value;
                    
                    std::string next_build = current_path_build + (current_path_build.back() == '/' ? "" : "/") + current_segment_from_path;
                    if (current_path_build.empty() && current_segment_from_path.empty()) next_build = "/";
                    else if (current_path_build.empty()) next_build = "/" + current_segment_from_path;

                    auto result = child.node->match(next_remaining_path, params_for_branch, next_build);
                    if (result) {
                        // The result->params will have params from deeper levels + params_for_this_branch
                        // No, the result->params will be the one from the deepest successful match.
                        // We need to ensure the param extracted at *this* level is included.
                        // The `params_for_this_branch` passed to recursion now includes it.
                        // The returned `result->params` should be correct.
                        // Let's assume `result->params` is already correctly populated by the recursion that used `params_for_this_branch`.
                        return result; 
                    }
                }
            }
        }
    }
    
    // If no child matches, but this node is a controller mount, then the *entire current path_to_match*
    // is the remaining path for this controller. accumulated_params are those that led to this controller node.
    if (this->is_endpoint && this->entity_type == RadixMatchResult::TargetType::CONTROLLER) {
        RadixMatchResult res;
        res.target_ptr = this->entity_ptr;
        res.type = RadixMatchResult::TargetType::CONTROLLER;
        res.params = accumulated_params; // Params used to reach this controller mount point
        res.matched_path_prefix = current_path_build.empty() ? "/" : current_path_build;
        res.full_debug_matched_path = res.matched_path_prefix;
        res.remaining_path = path_to_match; // The original full remaining path for the controller
        res.priority = this->priority;
        return res;
    }

    return std::nullopt;
}

std::optional<RadixMatchResult>
RadixTree::match(const std::string &path) const {
    std::string normalized_path = path;
    if (normalized_path.empty()) normalized_path = "/";
    else if (normalized_path[0] != '/') {
        normalized_path = "/" + normalized_path;
    }
    PathParameters accumulated_params; 
    // For root call, current_path_build starts empty. If normalized_path is just "/", 
    // the root node match logic will handle it. If path is "/foo", then root match gets "/foo", and current_path_build "".
    return _root->match(normalized_path, accumulated_params, ""); 
}

} // namespace qb::http
