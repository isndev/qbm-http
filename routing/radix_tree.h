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
    struct Child {
        std::string                segment;
        std::shared_ptr<RadixNode> node;
        bool                       is_param;
        std::string                param_name;
    };

    std::vector<Child> children;
    void              *handler     = nullptr;
    int                priority    = 0;
    bool               is_endpoint = false;

    /**
     * @brief Insert a path pattern into the radix tree
     *
     * @param path Path pattern to insert (e.g., "/users/:id/profile")
     * @param handler_ptr Pointer to the handler for this route
     * @param route_priority Priority of this route
     */
    void insert(const std::string &path, void *handler_ptr, int route_priority);

    /**
     * @brief Match a URL path against the radix tree
     *
     * @param path Path to match
     * @param params Output parameter to store extracted path parameters
     * @return Pointer to the handler if a match is found, nullptr otherwise
     */
    void *match(const std::string &path, PathParameters &params) const;
};

/**
 * @brief Radix tree for efficient route matching
 *
 * This class provides a wrapper around the RadixNode implementation
 * with a simplified interface for inserting and matching routes.
 */
class RadixTree {
private:
    std::shared_ptr<RadixNode> _root;

public:
    RadixTree()
        : _root(std::make_shared<RadixNode>()) {}

    /**
     * @brief Insert a route into the tree
     *
     * @param path Route path pattern
     * @param handler_ptr Pointer to the handler for this route
     * @param priority Priority of the route
     */
    void insert(const std::string &path, void *handler_ptr, int priority);

    /**
     * @brief Match a path against the tree
     *
     * @param path Path to match
     * @param params Output parameter to store path parameters
     * @return Pointer to the handler if a match is found, nullptr otherwise
     */
    void *match(const std::string &path, PathParameters &params) const;
};

} // namespace qb::http