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
template <typename Session>
class RouterCore;

/**
 * @brief Represents a node in the routing hierarchy (Route, RouteGroup, Controller).
 *
 * Each node can have a parent, a path segment, and middleware.
 * It's responsible for contributing its tasks (middleware, own handler) to the
 * overall task chain for a matched route.
 */
template <typename Session>
class IHandlerNode : public std::enable_shared_from_this<IHandlerNode<Session>> {
protected:
    std::weak_ptr<IHandlerNode<Session>> _parent;
    std::string _path_segment; // The path segment this node is responsible for (e.g., "/users", ":id")
    // Middleware tasks specific to this node, to be executed after parent's tasks
    // and before this node's specific handler (if any) or children's tasks.
    std::list<std::shared_ptr<IAsyncTask<Session>>> _middleware_tasks;

public:
    IHandlerNode(std::string path_segment)
        : _path_segment(std::move(path_segment)) {}

    virtual ~IHandlerNode() = default;

    // --- Hierarchy Management --- 
    void set_parent(std::weak_ptr<IHandlerNode<Session>> parent) {
        _parent = parent;
    }

    std::shared_ptr<IHandlerNode<Session>> get_parent() const {
        return _parent.lock();
    }

    const std::string& get_path_segment() const {
        return _path_segment;
    }

    // --- Middleware Management --- 

    /**
     * @brief Adds a middleware task to this node's chain.
     *        Middleware added this way will be executed in the order they are added (pipeline).
     */
    void add_middleware(std::shared_ptr<IAsyncTask<Session>> middleware_task) {
        _middleware_tasks.push_back(std::move(middleware_task));
    }

    /**
     * @brief Adds a middleware task to this node's chain (appended).
     */
    // void add_middleware_back(std::shared_ptr<IAsyncTask<Session>> middleware_task) {
    //     _middleware_tasks.push_back(std::move(middleware_task));
    // }

    // --- Task Compilation --- 

    /**
     * @brief Gathers all asynchronous tasks for this node, including parent middleware,
     *        this node's middleware, and the node's specific handler task (for Routes).
     *
     * @param base_path The accumulated base path from parent nodes.
     * @param router_core A reference to the router core for registering final route details.
     * @param tasks A list to which compiled tasks for any terminal Route nodes will be added.
     *              This is the "output" of the compilation for a specific route.
     */
    virtual void compile_tasks_and_register( 
        RouterCore<Session>& router_core,
        const std::string& current_built_path,
        const std::list<std::shared_ptr<IAsyncTask<Session>>>& inherited_tasks) = 0;

    /**
     * @brief Returns the name of the handler node, for debugging or logging.
     */
    virtual std::string get_node_name() const = 0;

protected:
    /**
     * @brief Helper to build the full path for this node.
     */
    std::string build_full_path(const std::string& parent_full_path) const {
        std::string full_path = parent_full_path;
        if (!full_path.empty() && full_path.back() == '/' && !_path_segment.empty() && _path_segment.front() == '/') {
            full_path.pop_back(); // Avoid double slashes like /api//users
        }
        if (full_path.empty() || full_path.back() != '/') {
            if (!_path_segment.empty() && _path_segment.front() != '/') {
                full_path += "/";
            }
        }
        full_path += _path_segment;
        // Ensure no trailing slash unless it's the root path itself
        if (full_path.length() > 1 && full_path.back() == '/') {
            full_path.pop_back();
        }
        return full_path;
    }

    /**
     * @brief Combines inherited tasks with this node's own middleware tasks.
     */
    virtual std::list<std::shared_ptr<IAsyncTask<Session>>> 
    combine_tasks(const std::list<std::shared_ptr<IAsyncTask<Session>>>& inherited_tasks) const {
        std::list<std::shared_ptr<IAsyncTask<Session>>> combined = inherited_tasks;
        combined.insert(combined.end(), _middleware_tasks.begin(), _middleware_tasks.end());
        return combined;
    }
};

} // namespace qb::http 