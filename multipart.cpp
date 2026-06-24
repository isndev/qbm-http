/**
 * @file qbm/http/multipart.cpp
 * @brief Multipart form-data parser implementation
 *
 * This file implements the parser for multipart/form-data content according to RFC 7578.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./multipart.h"

#include <algorithm>

namespace qb::http {
namespace {
[[nodiscard]] bool
is_multipart_boundary_char(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '\'' || c == '(' || c == ')' || c == '+'
           || c == '_' || c == ',' || c == '-' || c == '.' || c == '/' || c == ':' || c == '=' || c == '?' || c == ' ';
}

[[nodiscard]] bool
is_valid_multipart_boundary(const std::string &boundary) noexcept {
    return !boundary.empty() && boundary.size() <= multipart_limits::MAX_BOUNDARY_LENGTH && boundary.back() != ' '
           && std::all_of(boundary.begin(), boundary.end(), is_multipart_boundary_char);
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
    const auto media_type    = utility::trim_http_whitespace(
        semicolon_pos == std::string::npos ? std::string_view(content_type) : std::string_view(content_type.data(), semicolon_pos));
    if (!utility::iequals(media_type, "multipart/form-data")) {
        return "";
    }

    auto attrs = parse_header_attributes(content_type);
    auto it    = attrs.find("boundary");
    if (it == attrs.end() || it->second.empty()) {
        return "";
    }

    if (!is_valid_multipart_boundary(it->second)) {
        throw std::runtime_error("Invalid multipart boundary");
    }
    return it->second;
}

void
MultipartParser::indexBoundary() {
    const char *current;
    const char *end = boundaryData + boundarySize;

    std::memset(boundaryIndex, 0, sizeof(boundaryIndex));

    for (current = boundaryData; current < end; current++) {
        boundaryIndex[(unsigned char) *current] = true;
    }
}

void
MultipartParser::callback(Callback cb, const char *buffer, size_t start, size_t end, bool allowEmpty) {
    if (start != UNMARKED && start == end && !allowEmpty) {
        return;
    }
    if (cb != NULL) {
        cb(buffer, start, end, userData);
    }
}

void
MultipartParser::dataCallback(Callback cb, size_t &mark, const char *buffer, size_t i, size_t bufferLen, bool clear, bool allowEmpty) {
    if (mark == UNMARKED) {
        return;
    }

    if (!clear) {
        callback(cb, buffer, mark, bufferLen, allowEmpty);
        mark = 0;
    } else {
        callback(cb, buffer, mark, i, allowEmpty);
        mark = UNMARKED;
    }
}

void
MultipartParser::processPartData(size_t &prevIndex, size_t &l_index, const char *buffer, size_t len, size_t boundaryEnd, size_t &i, char c,
                                 State &l_state, int &l_flags) {
    prevIndex = l_index;

    if (l_index == 0) {
        // boyer-moore derived algorithm to safely skip non-boundary data
        while (i + boundarySize <= len) {
            if (isBoundaryChar(buffer[i + boundaryEnd])) {
                break;
            }

            i += boundarySize;
        }
        if (i == len) {
            return;
        }
        c = buffer[i];
    }

    if (l_index < boundarySize) {
        if (boundary[l_index] == c) {
            if (l_index == 0) {
                dataCallback(onPartData, partDataMark, buffer, i, len, true);
            }
            l_index++;
        } else {
            l_index = 0;
        }
    } else if (l_index == boundarySize) {
        l_index++;
        if (c == CR) {
            // CR = part boundary
            l_flags |= PART_BOUNDARY;
        } else if (c == HYPHEN) {
            // HYPHEN = end boundary
            l_flags |= LAST_BOUNDARY;
        } else {
            l_index = 0;
        }
    } else if (l_index - 1 == boundarySize) {
        if (l_flags & PART_BOUNDARY) {
            l_index = 0;
            if (c == LF) {
                // unset the PART_BOUNDARY flag
                l_flags &= ~PART_BOUNDARY;
                callback(onPartEnd);
                callback(onPartBegin);
                l_state = HEADER_FIELD_START;
                return;
            }
        } else if (l_flags & LAST_BOUNDARY) {
            if (c == HYPHEN) {
                callback(onPartEnd);
                callback(onEnd);
                l_state = END;
            } else {
                l_index = 0;
            }
        } else {
            l_index = 0;
        }
    } else if (l_index - 2 == boundarySize) {
        if (c == CR) {
            l_index++;
        } else {
            l_index = 0;
        }
    } else if (l_index - boundarySize == 3) {
        l_index = 0;
        if (c == LF) {
            callback(onPartEnd);
            callback(onEnd);
            l_state = END;
            return;
        }
    }

    if (l_index > 0) {
        // when matching a possible boundary, keep a lookbehind reference
        // in case it turns out to be a false lead
        if (l_index - 1 >= lookbehindSize) {
            setError("Parser bug: index overflows lookbehind buffer. "
                     "Please send bug report with input file attached.");
            throw std::out_of_range("index overflows lookbehind buffer");
        } else if (static_cast<int64_t>(l_index) - 1 < 0) {
            setError("Parser bug: index underflows lookbehind buffer. "
                     "Please send bug report with input file attached.");
            throw std::out_of_range("index underflows lookbehind buffer");
        }
        lookbehind[l_index - 1] = c;
    } else if (prevIndex > 0) {
        // if our boundary turned out to be rubbish, the captured lookbehind
        // belongs to partData
        callback(onPartData, lookbehind.data(), 0, prevIndex);
        prevIndex    = 0;
        partDataMark = i;

        // reconsider the current character even so it interrupted the sequence
        // it could be the beginning of a new sequence
        i--;
    }
}

void
MultipartParser::reset() {
    state = ERROR;
    boundary.clear();
    boundaryData = boundary.c_str();
    boundarySize = 0;
    lookbehind.clear();
    lookbehindSize  = 0;
    flags           = 0;
    index           = 0;
    headerFieldMark = UNMARKED;
    headerValueMark = UNMARKED;
    partDataMark    = UNMARKED;
    errorReason     = "Parser uninitialized.";
}

void
MultipartParser::setBoundary(std::string l_boundary) {
    reset();
    if (l_boundary.empty() || l_boundary.size() > multipart_limits::MAX_BOUNDARY_LENGTH) {
        errorReason = "Boundary exceeds maximum allowed length";
        state       = ERROR;
        return;
    }
    for (const auto c : l_boundary) {
        const auto uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7f) {
            errorReason = "Boundary contains invalid control character";
            state       = ERROR;
            return;
        }
    }
    this->boundary = "\r\n--" + std::move(l_boundary);
    boundaryData   = this->boundary.c_str();
    boundarySize   = this->boundary.size();

    indexBoundary();
    lookbehindSize = boundarySize + 8;
    lookbehind.resize(lookbehindSize);
    state       = START;
    errorReason = "No error.";
}

DISABLE_WARNING_PUSH
DISABLE_WARNING_IMPLICIT_FALLTHROUGH
size_t
MultipartParser::feed(const char *buffer, size_t len) {
    if (state == ERROR || len == 0) {
        return 0;
    }

    State  l_state     = this->state;
    int    l_flags     = this->flags;
    size_t prevIndex   = this->index;
    size_t l_index     = this->index;
    size_t boundaryEnd = boundarySize - 1;
    size_t i;
    char   c;

    for (i = 0; i < len; i++) {
        c = buffer[i];

        switch (l_state) {
            case ERROR:
                return i;
            case START:
                l_index = 0;
                l_state = START_BOUNDARY;
            case START_BOUNDARY:
                if (l_index == boundarySize - 2) {
                    if (c != CR) {
                        setError("Malformed. Expected CR after boundary.");
                        return i;
                    }
                    l_index++;
                    break;
                } else if (l_index - 1 == boundarySize - 2) {
                    if (c != LF) {
                        setError("Malformed. Expected LF after boundary CR.");
                        return i;
                    }
                    l_index = 0;
                    callback(onPartBegin);
                    l_state = HEADER_FIELD_START;
                    break;
                }
                if (c != boundary[l_index + 2]) {
                    setError("Malformed. Found different boundary data than the "
                             "given one.");
                    return i;
                }
                l_index++;
                break;
            case HEADER_FIELD_START:
                l_state         = HEADER_FIELD;
                headerFieldMark = i;
                l_index         = 0;
            case HEADER_FIELD:
                if (c == CR) {
                    headerFieldMark = UNMARKED;
                    l_state         = HEADERS_ALMOST_DONE;
                    break;
                }

                l_index++;
                if (c == COLON) {
                    if (l_index == 1) {
                        // empty header field
                        setError("Malformed first header name character.");
                        return i;
                    }
                    dataCallback(onHeaderField, headerFieldMark, buffer, i, len, true);
                    l_state = HEADER_VALUE_START;
                    break;
                }

                if (!isHeaderFieldCharacter(c)) {
                    setError("Malformed header name.");
                    return i;
                }
                break;
            case HEADER_VALUE_START:
                if (c == SPACE) {
                    break;
                }

                headerValueMark = i;
                l_state         = HEADER_VALUE;
            case HEADER_VALUE:
                if (c == CR) {
                    dataCallback(onHeaderValue, headerValueMark, buffer, i, len, true, true);
                    callback(onHeaderEnd);
                    l_state = HEADER_VALUE_ALMOST_DONE;
                }
                break;
            case HEADER_VALUE_ALMOST_DONE:
                if (c != LF) {
                    setError("Malformed header value: LF expected after CR");
                    return i;
                }

                l_state = HEADER_FIELD_START;
                break;
            case HEADERS_ALMOST_DONE:
                if (c != LF) {
                    setError("Malformed header ending: LF expected after CR");
                    return i;
                }

                callback(onHeadersEnd);
                l_state = PART_DATA_START;
                break;
            case PART_DATA_START:
                l_state      = PART_DATA;
                partDataMark = i;
            case PART_DATA:
                processPartData(prevIndex, l_index, buffer, len, boundaryEnd, i, c, l_state, l_flags);
                break;
            default:
                return i;
        }
    }

    dataCallback(onHeaderField, headerFieldMark, buffer, i, len, false);
    dataCallback(onHeaderValue, headerValueMark, buffer, i, len, false);
    dataCallback(onPartData, partDataMark, buffer, i, len, false);

    this->index = l_index;
    this->state = l_state;
    this->flags = l_flags;

    return len;
}
DISABLE_WARNING_POP

std::string
Multipart::generate_boundary() {
    constexpr size_t BOUNDARY_RANDOM_LENGTH = 32;
    constexpr size_t BOUNDARY_PREFIX_LENGTH = 28; // "----------------------------qb"
    constexpr size_t TOTAL_BOUNDARY_LENGTH  = BOUNDARY_PREFIX_LENGTH + BOUNDARY_RANDOM_LENGTH;

    static_assert(TOTAL_BOUNDARY_LENGTH <= multipart_limits::MAX_BOUNDARY_LENGTH, "Generated boundary exceeds RFC 2046 recommended maximum");

    std::string result = "----------------------------qb";
    result.reserve(TOTAL_BOUNDARY_LENGTH);
#ifdef QB_HAS_SSL
    result += qb::crypto::generate_secure_random_string(BOUNDARY_RANDOM_LENGTH, qb::crypto::range_alpha_numeric);
#else
    auto uuid = uuids::to_string(qb::generate_random_uuid());
    uuid.erase(std::remove(uuid.begin(), uuid.end(), '-'), uuid.end());
    result += uuid.substr(0, BOUNDARY_RANDOM_LENGTH);
#endif
    return result;
}

} // namespace qb::http

namespace qb::allocator {
namespace {
[[nodiscard]] bool
is_multipart_header_name_char(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '!' || c == '#' || c == '$' || c == '%'
           || c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

[[nodiscard]] bool
is_valid_multipart_header_name(const std::string &name) noexcept {
    return !name.empty() && name.size() <= qb::http::multipart_limits::MAX_HEADER_NAME_LENGTH
           && std::all_of(name.begin(), name.end(), is_multipart_header_name_char);
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
        throw std::length_error("qb::http::Multipart serialization: invalid multipart boundary.");
    }

    for (const auto &part : mp.parts()) {
        for (const auto &[key, values] : part.headers()) {
            if (!is_valid_multipart_header_name(key)) {
                throw std::length_error("qb::http::Multipart serialization: invalid part header name.");
            }
            for (const auto &value : values) {
                if (!is_valid_multipart_header_value(value)) {
                    throw std::length_error("qb::http::Multipart serialization: invalid part header value.");
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
template <>
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
