/**
 * @file request_path_view.h
 * @brief Provides a lightweight view for modifying request paths
 */

#pragma once

#include <string>
#include <qb/io/uri.h>

namespace qb::http {

/**
 * @brief Lightweight view of a request path
 *
 * Provides a lightweight, non-owning view of a request path,
 * allowing temporary modification of paths without copying or
 * modifying the original request. Used by controllers for
 * efficient routing without copying the request.
 */
class RequestPathView {
private:
    qb::io::uri& _uri;        // Reference to the original URI
    std::string _saved_path;  // Saved original path for restoration
    bool _modified = false;   // Flag to indicate if path was modified

public:
    /**
     * @brief Create a view of a request path
     * @param request_uri Reference to the original request URI
     */
    explicit RequestPathView(qb::io::uri& request_uri)
        : _uri(request_uri), _saved_path(request_uri.path()) {}

    /**
     * @brief Destructor that restores the original path if needed
     */
    ~RequestPathView() {
        if (_modified) {
            _uri = qb::io::uri(_saved_path);
        }
    }

    /**
     * @brief Get the current path
     * @return Current path string
     */
    [[nodiscard]] std::string path() const {
        return std::string{_uri.path()};
    }

    /**
     * @brief Temporarily modify the path
     * @param new_path New path to set
     */
    void set_path(const std::string& new_path) {
        _modified = true;
        _uri = qb::io::uri(new_path);
    }

    /**
     * @brief Set path to a new relative path based on a prefix
     * @param base_path Base path to strip
     * @return Remaining path after the base
     */
    std::string set_relative_path(const std::string& base_path) {
        std::string current = path();
        std::string remaining;
        
        if (current.compare(0, base_path.length(), base_path) == 0) {
            remaining = current.substr(base_path.length());
            if (remaining.empty()) {
                remaining = "/";
            }
        } else {
            remaining = "/";
        }
        
        _modified = true;
        _uri = qb::io::uri(remaining);
        return remaining;
    }

    /**
     * @brief Restore the original path
     */
    void restore() {
        if (_modified) {
            _uri = qb::io::uri(_saved_path);
            _modified = false;
        }
    }
};

} // namespace qb::http 