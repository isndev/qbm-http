/**
 * @file qbm/http/routing/path_parameters.h
 * @brief Defines the PathParameters class for storing extracted URL path parameters.
 *
 * This file contains the `PathParameters` class, which is used by the HTTP routing
 * system to store and provide access to named parameters extracted from the request URI path
 * during route matching (e.g., the value of `:id` in a route like `/users/:id`).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include <optional>    // For std::optional
#include <string>      // For std::string
#include <string_view> // For std::string_view
#include <utility>     // For std::swap (though qb::unordered_map likely has its own swap)

#include <qb/system/container/unordered_map.h> // For qb::unordered_map

namespace qb::http {

/**
 * @brief Represents a collection of extracted path parameters from a matched HTTP route.
 *
 * This class encapsulates key-value pairs where keys are parameter names (as `std::string_view`,
 * typically viewing segments of the route pattern string stored in the router) and values are
 * the actual extracted segments from the request path (as `std::string`, owned by this object).
 * It provides a map-like interface for accessing these parameters.
 */
class PathParameters {
public:
    /**
     * @brief The underlying storage type for path parameters.
     * It's a case-sensitive unordered map where:
     * - Key (`std::string_view`): The name of the path parameter (e.g., "id" from a route like "/users/:id").
     *   This view typically points to a segment of the original route pattern string, which has a long lifetime.
     * - Value (`std::string`): The actual value extracted from the request URI path for that parameter.
     *   This is an owned string, as it's a copy of a part of the (potentially transient) request URI.
     */
    using Storage = qb::unordered_map<std::string_view, std::string>;

private:
    Storage _params; ///< Internal map holding the parameter key-value pairs.

public:
    /** @brief Default constructor. Creates an empty set of path parameters. */
    PathParameters() = default;

    // Default copy/move constructors and assignment operators are sufficient
    PathParameters(const PathParameters&) = default;
    PathParameters(PathParameters&&) noexcept = default; // Assuming Storage move is noexcept
    PathParameters& operator=(const PathParameters&) = default;
    PathParameters& operator=(PathParameters&&) noexcept = default; // Assuming Storage move assign is noexcept

    /**
     * @brief Sets or updates a path parameter.
     * If the key already exists, its value is updated. Otherwise, a new parameter is inserted.
     * @param key The name of the path parameter (a `std::string_view`).
     * @param value_sv The value of the path parameter (a `std::string_view`), which will be copied into a `std::string`.
     */
    void set(std::string_view key, std::string_view value_sv) {
        // emplace constructs std::string from value_sv in place if key is new,
        // or assigns if key exists (operator[] behavior for unordered_map).
        _params.insert_or_assign(key, std::string(value_sv));
    }

    /**
     * @brief Retrieves the value of a path parameter by its name.
     * @param key The name of the path parameter to retrieve.
     * @return An `std::optional<std::string_view>` containing a view of the parameter's value
     *         if found. The view is to the `std::string` stored internally. Returns `std::nullopt` if the key is not found.
     */
    [[nodiscard]] std::optional<std::string_view> get(std::string_view key) const noexcept {
        auto it = _params.find(key);
        if (it != _params.end()) {
            return it->second; // it->second is std::string, implicitly convertible to std::string_view
        }
        return std::nullopt;
    }

    /**
     * @brief Checks if a path parameter with the given name exists.
     * @param key The name of the path parameter.
     * @return `true` if the parameter exists, `false` otherwise.
     */
    [[nodiscard]] bool has(std::string_view key) const noexcept {
        return _params.count(key) > 0;
    }

    /**
     * @brief Gets a constant reference to the underlying storage map of all parameters.
     * @return `const Storage&` (i.e., `const qb::unordered_map<std::string_view, std::string>&`).
     */
    [[nodiscard]] const Storage& get_all() const noexcept {
        return _params;
    }

    /** @brief Removes all path parameters. */
    void clear() noexcept {
        _params.clear();
    }

    /** @brief Returns the number of path parameters stored. */
    [[nodiscard]] auto size() const noexcept {
        return _params.size();
    }

    /** @brief Checks if there are no path parameters stored. */
    [[nodiscard]] bool empty() const noexcept {
        return _params.empty();
    }

    /**
     * @brief Swaps the contents of this `PathParameters` object with another.
     * @param other The `PathParameters` object to swap contents with.
     */
    void swap(PathParameters& other) noexcept(noexcept(_params.swap(other._params))) {
        _params.swap(other._params);
    }

    // --- Standard map-like interface methods (iterators, find, at, erase) ---

    /** @brief Returns an iterator to the beginning of the parameters. */
    [[nodiscard]] auto begin() noexcept { return _params.begin(); }
    /** @brief Returns a constant iterator to the beginning of the parameters. */
    [[nodiscard]] auto begin() const noexcept { return _params.begin(); }
    /** @brief Returns an iterator to the end of the parameters. */
    [[nodiscard]] auto end() noexcept { return _params.end(); }
    /** @brief Returns a constant iterator to the end of the parameters. */
    [[nodiscard]] auto end() const noexcept { return _params.end(); }
    /** @brief Returns a constant iterator to the beginning of the parameters. */
    [[nodiscard]] auto cbegin() const noexcept { return _params.cbegin(); }
    /** @brief Returns a constant iterator to the end of the parameters. */
    [[nodiscard]] auto cend() const noexcept { return _params.cend(); }

    /**
     * @brief Finds a parameter by key.
     * @param key The key of the parameter to find.
     * @return An iterator to the element if found, otherwise an iterator to `end()`.
     */
    [[nodiscard]] auto find(std::string_view key) noexcept { return _params.find(key); }
    /** @copydoc find(std::string_view) */
    [[nodiscard]] auto find(std::string_view key) const noexcept { return _params.find(key); }

    /**
     * @brief Accesses a parameter's value by key, with bounds checking.
     * @param key The key of the parameter to access.
     * @return A reference to the parameter's value (`std::string&`).
     * @throws std::out_of_range if the key is not found.
     */
    [[nodiscard]] auto at(std::string_view key) { return _params.at(key); }
    /** @copydoc at(std::string_view) */
    [[nodiscard]] auto at(std::string_view key) const { return _params.at(key); }

    /**
     * @brief Erases a parameter by iterator position.
     * @param pos Iterator to the parameter to erase.
     * @return An iterator to the element following the erased one, or `end()`.
     */
    auto erase(typename Storage::iterator pos) noexcept { return _params.erase(pos); }
    /**
     * @brief Erases a range of parameters.
     * @param first Iterator to the beginning of the range to erase.
     * @param last Iterator to the end of the range to erase.
     * @return An iterator to the element following the last erased one, or `end()`.
     */
    auto erase(typename Storage::const_iterator first, typename Storage::const_iterator last) noexcept {
         return _params.erase(first, last); 
    }
    /**
     * @brief Erases a parameter by key.
     * @param key The key of the parameter to erase.
     * @return The number of elements erased (0 or 1).
     */
    auto erase(std::string_view key) noexcept { return _params.erase(key); }

    /**
     * @brief Reserves space in the underlying map for at least `n` elements.
     * @param n The minimum number of elements to reserve space for.
     */
    void reserve(size_t n) { _params.reserve(n); } // Can throw std::bad_alloc
};

} // namespace qb::http