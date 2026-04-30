/**
 * @file qbm/http/multipart.cpp
 * @brief Multipart form-data parser implementation
 *
 * This file implements the parser for multipart/form-data content according to RFC 7578.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./multipart.h"

#include <algorithm>

namespace qb::http {
    namespace {
        [[nodiscard]] bool
        is_multipart_boundary_char(char c) noexcept {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '\'' || c == '(' ||
                   c == ')' || c == '+' || c == '_' || c == ',' ||
                   c == '-' || c == '.' || c == '/' || c == ':' ||
                   c == '=' || c == '?' || c == ' ';
        }

        [[nodiscard]] bool
        is_valid_multipart_boundary(const std::string &boundary) noexcept {
            return !boundary.empty() &&
                   boundary.size() <= multipart_limits::MAX_BOUNDARY_LENGTH &&
                   boundary.back() != ' ' &&
                   std::all_of(boundary.begin(), boundary.end(), is_multipart_boundary_char);
        }
    } // namespace

    /**
     * @brief Find the boundary in multipart content
     * @param str Content to search
     * @param boundary Boundary string to find
     * @return Iterator to the start of the boundary, or str.end() if not found
     *
     * Searches for a multipart boundary string in HTTP content.
     * This is used for parsing multipart/form-data content where
     * parts are separated by boundary markers.
     */
    std::string::const_iterator
    find_boundary(std::string const &str, std::string const &boundary) {
        auto begin = str.begin();
        while (begin != str.end()) {
            auto p = std::mismatch(begin, str.end(), boundary.begin(), boundary.end());
            if (p.second == boundary.end())
                return begin;
            begin = std::next(p.first);
        }
        return str.end();
    }

    /**
     * @brief Extract boundary string from Content-Type header
     * @param content_type Content-Type header value
     * @return Boundary string or empty string if not found
     *
     * Parses a multipart/form-data Content-Type header to extract the boundary parameter.
     * The boundary is used to identify the start and end of each part in a multipart
     * message.
     *
     * Example: From "multipart/form-data; boundary=abc123", extracts "abc123".
     */
    [[nodiscard]] std::string
    parse_boundary(std::string const &content_type) {
        const auto semicolon_pos = content_type.find(';');
        const auto media_type = utility::trim_http_whitespace(
            semicolon_pos == std::string::npos
                ? std::string_view(content_type)
                : std::string_view(content_type.data(), semicolon_pos));
        if (!utility::iequals(media_type, "multipart/form-data")) {
            return "";
        }

        auto attrs = parse_header_attributes(content_type);
        auto it = attrs.find("boundary");
        if (it == attrs.end() || it->second.empty()) {
            return "";
        }

        if (!is_valid_multipart_boundary(it->second)) {
            throw std::runtime_error("Invalid multipart boundary");
        }
        return it->second;
    }

} // namespace qb::http

namespace qb::allocator {
    namespace {
        [[nodiscard]] bool
        is_multipart_header_name_char(char c) noexcept {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '!' || c == '#' ||
                   c == '$' || c == '%' || c == '&' || c == '\'' ||
                   c == '*' || c == '+' || c == '-' || c == '.' ||
                   c == '^' || c == '_' || c == '`' || c == '|' ||
                   c == '~';
        }

        [[nodiscard]] bool
        is_valid_multipart_header_name(const std::string &name) noexcept {
            return !name.empty() &&
                   name.size() <= qb::http::multipart_limits::MAX_HEADER_NAME_LENGTH &&
                   std::all_of(name.begin(), name.end(), is_multipart_header_name_char);
        }

        [[nodiscard]] bool
        is_valid_multipart_header_value(const std::string &value) noexcept {
            if (value.size() > qb::http::multipart_limits::MAX_HEADER_VALUE_LENGTH) {
                return false;
            }

            return std::all_of(value.begin(), value.end(), [](char c) {
                const auto uc = static_cast<unsigned char>(c);
                return c == '\t' || (uc >= 0x20 && uc != 0x7f);
            });
        }

        void
        validate_multipart_for_serialization(const qb::http::Multipart &mp) {
            if (!qb::http::is_valid_multipart_boundary(mp.boundary())) {
                throw std::length_error(
                    "qb::http::Multipart serialization: invalid multipart boundary.");
            }

            for (const auto &part : mp.parts()) {
                for (const auto &[key, values] : part.headers()) {
                    if (!is_valid_multipart_header_name(key)) {
                        throw std::length_error(
                            "qb::http::Multipart serialization: invalid part header name.");
                    }
                    for (const auto &value : values) {
                        if (!is_valid_multipart_header_value(value)) {
                            throw std::length_error(
                                "qb::http::Multipart serialization: invalid part header value.");
                        }
                    }
                }
            }
        }
    } // namespace

    /**
     * @brief Serialize a Multipart form-data content into a byte stream
     * @param mp Multipart object to serialize
     * @return Reference to this pipe
     *
     * Formats a multipart/form-data content according to RFC 7578.
     * Each part is formatted with its headers and body, separated
     * by the multipart boundary.
     *
     * The format is:
     * - For each part:
     *   - Boundary line (--boundary)
     *   - Part headers
     *   - Empty line
     *   - Part body
     *   - CRLF
     * - Final boundary (--boundary--)
     */
    template<>
    pipe<char> &
    pipe<char>::put<qb::http::Multipart>(const qb::http::Multipart &mp) {
        validate_multipart_for_serialization(mp);
        this->reserve(mp.content_length());
        for (const auto &part : mp.parts()) {
            *this << "--" << mp.boundary() << qb::http::endl;
            for (const auto &[key, values] : part.headers()) {
                for (const auto &header : values)
                    *this << key << ": " << header << qb::http::endl;
            }
            *this << qb::http::endl << part.body << qb::http::endl;
        }
        *this << "--" << mp.boundary() << "--";
        return *this;
    }
} // namespace qb::allocator
