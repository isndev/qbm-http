#pragma once

#include <memory>
#include <string>
#include <vector>
#include "./path_parameters.h"

namespace qb::http {

/**
 * @brief Radix tree node for efficient route matching
 *
 * This class implements a radix tree (also known as a patricia trie) for
 * efficiently matching URL paths. It provides significantly faster matching
 * than regex-based approaches, especially for large numbers of routes.
 */
class RadixNode {
public:
    /**
     * @struct Child
     * @brief Represents a child node in the radix tree.
     * Stores the path segment leading to this child, a pointer to the child RadixNode,
     * a flag indicating if this segment is a parameter, and the parameter name if applicable.
     */
    struct Child {
        std::string                segment;    ///< The path segment (e.g., "users", ":id").
        std::shared_ptr<RadixNode> node;       ///< Pointer to the child RadixNode.
        bool                       is_param;   ///< True if this segment represents a path parameter.
        std::string                param_name; ///< The name of the parameter (e.g., "id"), if is_param is true.
    };

    std::vector<Child> children;    ///< List of child nodes.
    void              *handler     = nullptr; ///< Pointer to the route handler if this node is an endpoint.
    int                priority    = 0;       ///< Priority of the route, used for conflict resolution.
    bool               is_endpoint = false;   ///< True if this node represents the end of a route.

    /**
     * @brief Inserts a path pattern into the radix tree node and its descendants.
     *
     * Recursively adds nodes to the tree based on the segments of the path.
     * If a segment corresponds to a parameter (e.g., ":id"), it's marked accordingly.
     *
     * @param path The path pattern to insert (e.g., "/users/:id/profile").
     * @param handler_ptr Pointer to the handler function or object for this route.
     * @param route_priority Priority of this route (higher value means higher priority).
     */
    void insert(const std::string &path, void *handler_ptr, int route_priority);

    /**
     * @brief Matches a URL path against this radix tree node and its descendants.
     *
     * Traverses the tree based on path segments. If a match is found,
     * it populates the `params` map with any extracted path parameters.
     *
     * @param path The URL path to match.
     * @param params Output parameter (PathParameters map) to store extracted path parameters.
     * @return Pointer to the handler if a match is found; nullptr otherwise.
     */
    void *match(const std::string &path, PathParameters &params) const;
};

/**
 * @brief Radix tree for efficient route matching.
 *
 * This class provides a high-level interface for a radix tree (Patricia trie)
 * specialized for HTTP route matching. It wraps a root RadixNode and offers
 * methods to insert routes and match incoming URL paths against the stored routes.
 * It handles path normalization (ensuring paths start with '/') internally.
 */
class RadixTree {
private:
    std::shared_ptr<RadixNode> _root; ///< The root node of the radix tree.

public:
    /**
     * @brief Default constructor. Initializes an empty RadixTree with a root node.
     */
    RadixTree()
        : _root(std::make_shared<RadixNode>()) {}

    /**
     * @brief Inserts a route into the tree.
     *
     * The path is normalized (prefixed with '/' if not already) before insertion.
     *
     * @param path The route path pattern (e.g., "/users/:id").
     * @param handler_ptr Pointer to the handler for this route.
     * @param priority Priority of the route (higher value means higher priority).
     */
    void insert(const std::string &path, void *handler_ptr, int priority);

    /**
     * @brief Matches an incoming URL path against the routes stored in the tree.
     *
     * The input path is normalized (prefixed with '/' if not already) before matching.
     * Extracted path parameters are stored in the `params` map.
     *
     * @param path The URL path to match.
     * @param params Output parameter (PathParameters map) to store extracted path parameters.
     * @return Pointer to the handler if a match is found; nullptr otherwise.
     */
    void *match(const std::string &path, PathParameters &params) const;
};

} // namespace qb::http