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
 * This class inherits from `qb::unordered_map<std::string, std::string>` to provide
 * standard map operations and adds a convenient `param()` method for safe access
 * with a default fallback value.
 */
class PathParameters : public qb::unordered_map<std::string, std::string> {
public:
    PathParameters()                                      = default;
    PathParameters(PathParameters const &)                = default;
    PathParameters(PathParameters &&) noexcept            = default;
    PathParameters &operator=(PathParameters const &)     = default;
    PathParameters &operator=(PathParameters &&) noexcept = default;

    /**
     * @brief Get a path parameter value by name.
     *
     * Retrieves the value of a path parameter. If the parameter is not found,
     * an empty string or the specified `not_found` value is returned.
     *
     * @param name The name of the parameter to look up.
     * @param not_found The default value to return if the parameter is not found. Defaults to an empty string.
     * @return The parameter's value as a constant string reference, or the `not_found` value.
     */
    [[nodiscard]] std::string const &
    param(std::string const &name, std::string const &not_found = "") const {
        const auto &it = find(name);
        return it != cend() ? it->second : not_found;
    }
};

using path_parameters = PathParameters;

} // namespace qb::http