#pragma clang diagnostic push
#pragma ide diagnostic ignored "misc-no-recursion"
#include "radix_tree.h"

namespace qb::http {

void
RadixNode::insert(const std::string &path, void *handler_ptr, int route_priority) {
    is_endpoint = path.empty();
    if (is_endpoint) {
        handler  = handler_ptr;
        priority = route_priority;
        return;
    }

    // Extract the segment up to the next slash
    size_t param_start = path.find(':');
    size_t slash_pos   = path.find('/', 1);
    bool   has_param   = param_start != std::string::npos &&
                     (slash_pos == std::string::npos || param_start < slash_pos);

    std::string segment;
    std::string rest_path;
    std::string param_name;
    bool        is_param_segment = false;

    if (has_param) {
        // This segment contains a parameter
        segment = path.substr(0, param_start);

        // Extract the parameter name
        size_t param_end = (slash_pos != std::string::npos) ? slash_pos : path.length();
        param_name       = path.substr(param_start + 1, param_end - param_start - 1);

        // Rest of the path
        rest_path = (slash_pos != std::string::npos) ? path.substr(slash_pos) : "";
        is_param_segment = true;
    } else {
        // Regular path segment
        segment   = (slash_pos != std::string::npos) ? path.substr(0, slash_pos) : path;
        rest_path = (slash_pos != std::string::npos) ? path.substr(slash_pos) : "";
        is_param_segment = false;
    }

    // Look for an existing child with the same segment
    for (auto &child : children) {
        if (child.segment == segment && child.is_param == is_param_segment) {
            child.node->insert(rest_path, handler_ptr, route_priority);
            return;
        }
    }

    // No matching child found, create a new one
    auto new_node = std::make_shared<RadixNode>();
    children.push_back({segment, new_node, is_param_segment, param_name});
    new_node->insert(rest_path, handler_ptr, route_priority);
}

void *
RadixNode::match(const std::string &path, PathParameters &params) const {
    if (path.empty() || path == "/") {
        return is_endpoint ? handler : nullptr;
    }

    size_t      slash_pos = path.find('/', 1);
    std::string segment =
        (slash_pos != std::string::npos) ? path.substr(0, slash_pos) : path;
    std::string rest_path =
        (slash_pos != std::string::npos) ? path.substr(slash_pos) : "";

    // First try exact matches
    for (const auto &child : children) {
        if (!child.is_param && segment == child.segment) {
            void *result = child.node->match(rest_path, params);
            if (result)
                return result;
        }
    }

    // Then try parameter matches
    for (const auto &child : children) {
        if (child.is_param) {
            // Extract parameter value - if segment starts with the static part
            if (segment.find(child.segment) == 0) {
                std::string param_value = segment.substr(child.segment.length());

                // Save the parameter
                params[child.param_name] = param_value;

                // Continue matching
                void *result = child.node->match(rest_path, params);
                if (result)
                    return result;

                // If no match, remove the parameter
                params.erase(child.param_name);
            }
        }
    }

    return nullptr;
}

void
RadixTree::insert(const std::string &path, void *handler_ptr, int priority) {
    // Normalize the path to always start with /
    std::string normalized_path = path;
    if (normalized_path.empty() || normalized_path[0] != '/') {
        normalized_path = "/" + normalized_path;
    }

    _root->insert(normalized_path, handler_ptr, priority);
}

void *
RadixTree::match(const std::string &path, PathParameters &params) const {
    // Normalize the path to always start with /
    std::string normalized_path = path;
    if (normalized_path.empty() || normalized_path[0] != '/') {
        normalized_path = "/" + normalized_path;
    }

    return _root->match(normalized_path, params);
}

} // namespace qb::http
#pragma clang diagnostic pop