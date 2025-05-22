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

namespace qb::http {
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
        static const std::regex boundary_regex("^multipart/form-data;\\s{0,}boundary=(.+)$");
        std::smatch what;
        std::string to_find(content_type.data(), content_type.size());
        return std::regex_match(to_find, what, boundary_regex) ? what[1].str() : "";
    }

    template class TMultiPart<std::string>;
    template class TMultiPart<std::string_view>;
} // namespace qb::http

namespace qb::allocator {
    template<typename MultiPartType>
    pipe<char> &
    put_impl(pipe<char> &pipe, const MultiPartType &mp) {
        pipe.reserve(mp.content_length());
        for (const auto &part: mp.parts()) {
            pipe << "--" << mp.boundary() << qb::http::endl;
            for (const auto &[key, headers]: part.headers()) {
                for (const auto &header: headers)
                    pipe << key << ": " << header << qb::http::endl;
            }
            pipe << qb::http::endl << part.body << qb::http::endl;
        }
        pipe << "--" << mp.boundary() << "--";
        return pipe;
    }

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
        return put_impl(*this, mp);
    }

    /**
     * @brief Serialize a MultipartView form-data content into a byte stream
     * @param mp MultipartView object to serialize
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
    pipe<char>::put<qb::http::MultipartView>(const qb::http::MultipartView &mp) {
        return put_impl(*this, mp);
    }
} // namespace qb::allocator
