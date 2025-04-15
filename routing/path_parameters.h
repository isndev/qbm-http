#pragma once

#include <qb/system/container/unordered_map.h>
#include <string>

namespace qb::http {

/**
 * @brief Container for URL path parameters
 *
 * Stores parameters extracted from URL path patterns in HTTP routes.
 * For example, in a route like "/users/:id/profile", the value of "id"
 * will be stored in this container when matching a request to "/users/123/profile".
 *
 * Provides convenient access to parameter values with a fallback for missing parameters.
 * Inherits from qb::unordered_map to provide all standard map operations.
 */
class PathParameters : public qb::unordered_map<std::string, std::string> {
public:
    PathParameters()                                      = default;
    PathParameters(PathParameters const &)                = default;
    PathParameters(PathParameters &&) noexcept            = default;
    PathParameters &operator=(PathParameters const &)     = default;
    PathParameters &operator=(PathParameters &&) noexcept = default;

    /**
     * @brief Get a path parameter value
     *
     * Retrieves the value of a path parameter by name, with an optional
     * default value to return if the parameter is not found. This provides
     * a convenient way to access path parameters with fallbacks.
     *
     * @param name Parameter name to look up
     * @param not_found Default value to return if parameter not found
     * @return Parameter value or default value if not found
     */
    [[nodiscard]] std::string const &
    param(std::string const &name, std::string const &not_found = "") const {
        const auto &it = find(name);
        return it != cend() ? it->second : not_found;
    }
};

using path_parameters = PathParameters;

} // namespace qb::http