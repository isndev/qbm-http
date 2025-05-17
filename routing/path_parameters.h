#pragma once

#include <optional>
#include <qb/system/container/unordered_map.h>
#include <string>
#include <vector>

namespace qb::http {

/**
 * @brief Represents extracted path parameters from a route match.
 *
 * Stores parameters as key-value (std::string_view key, std::string value).
 * This is part of the qb::http namespace directly.
 */
class PathParameters {
public:
    // Key is a view into the route pattern string (long-lived in RadixTree)
    // Value is an owned string, copied from the request path segment.
    using Storage = qb::unordered_map<std::string_view, std::string>;

private:
    Storage _params;

public:
    PathParameters() = default;

    void set(std::string_view key, std::string_view value_sv) {
        _params.emplace(key, std::string(value_sv));
    }

    std::optional<std::string_view> get(std::string_view key) const {
        auto it = _params.find(key);
        if (it != _params.end()) {
            return it->second; // it->second is std::string, implicitly converts to std::string_view
        }
        return std::nullopt;
    }

    bool has(std::string_view key) const {
        return _params.count(key) > 0;
    }

    const Storage& get_all() const {
        return _params;
    }

    void clear() {
        _params.clear();
    }

    auto size() const {
        return _params.size();
    }

    auto empty() const {
        return _params.empty();
    }

    auto swap(PathParameters& other) {
        _params.swap(other._params);
    }

    auto begin() {
        return _params.begin();
    }

    auto begin() const {
        return _params.begin();
    }

    auto end() {
        return _params.end();
    }

    auto end() const {
        return _params.end();
    }

    auto cbegin() const {
        return _params.cbegin();
    }

    auto cend() const {
        return _params.cend();
    }

    auto find(std::string_view key) const {
        return _params.find(key);
    }

    auto find(std::string_view key) {
        return _params.find(key);
    }

    auto at(std::string_view key) const {
        return _params.at(key);
    }

    auto at(std::string_view key) {
        return _params.at(key);
    }

    auto erase(Storage::iterator pos) {
        return _params.erase(pos);
    }

    auto erase(Storage::iterator first, Storage::iterator last) {
        return _params.erase(first, last);
    }

    auto erase(std::string_view key) {
        return _params.erase(key);
    }

    void reserve(size_t n) {
        _params.reserve(n);
    }
};
} // namespace qb::http