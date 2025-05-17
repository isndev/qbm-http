/**
 * @file multipart.h
 * @brief Multipart form-data parser for the QB Actor Framework
 *
 * This file implements a parser for multipart/form-data content according to RFC 7578.
 * Multipart form data is commonly used in HTTP for file uploads and complex form
 * submissions. The implementation provides a state machine based parser with callback
 * functionality for efficient processing of multipart content.
 *
 * Key features:
 * - Streaming parser that processes data incrementally
 * - Callback-based event system for efficient memory management
 * - Robust error handling with detailed error messages
 * - Boundary detection and validation
 * - Header parsing and normalization
 * - Support for both string and binary content
 *
 * The MultipartParser is primarily used internally by the HTTP module to process
 * multipart form data in incoming requests, but can also be used directly for
 * custom multipart content processing needs.
 *
 * @see qb::http::Multipart
 * @see qb::http::internal::MultipartReader
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2021 isndev (www.qbaf.io)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cassert>
#include <cstring>
#include <iostream>
#include <random>
#include <regex>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <vector>

#include <qb/system/allocator/pipe.h>
#include <qb/utility/build_macros.h>

#include "./headers.h"

DISABLE_WARNING_PUSH
DISABLE_WARNING_IMPLICIT_FALLTHROUGH

#undef ERROR
namespace qb::http {

/**
 * @brief Parser for multipart/form-data content
 *
 * The MultipartParser processes multipart form data streams according to
 * RFC 7578. It uses a state machine to track the parsing process and calls
 * appropriate callbacks for different events during parsing.
 */
class MultipartParser {
public:
    /**
     * @brief Callback function type for parser events
     * @param buffer The data buffer being parsed
     * @param start Start offset of the current segment
     * @param end End offset of the current segment
     * @param userData User data passed to the callback
     */
    typedef void (*Callback)(const char *buffer, size_t start, size_t end,
                             void *userData);

private:
    /**
     * @brief Carriage Return character (ASCII 13)
     *
     * Used in HTTP line endings (CR+LF) and multipart boundaries.
     */
    static const char CR = 13;

    /**
     * @brief Line Feed character (ASCII 10)
     *
     * Used in HTTP line endings (CR+LF) and multipart boundaries.
     */
    static const char LF = 10;

    /**
     * @brief Space character (ASCII 32)
     *
     * Used in header parsing for whitespace detection.
     */
    static const char SPACE = 32;

    /**
     * @brief Hyphen character (ASCII 45)
     *
     * Used in multipart boundaries which begin with two hyphens.
     */
    static const char HYPHEN = 45;

    /**
     * @brief Colon character (ASCII 58)
     *
     * Used to separate header field names from values.
     */
    static const char COLON = 58;

    /**
     * @brief Special value indicating an unmarked position
     *
     * Used to indicate that no mark has been set for a segment.
     */
    static const size_t UNMARKED = (size_t) -1;

    /**
     * @brief Parser state machine states
     *
     * These states track the current position in the parsing process,
     * from initial state to end of parsing, including various stages
     * of header and data processing.
     */
    enum State {
        ERROR,                    ///< Error occurred during parsing
        START,                    ///< Initial state before any data is processed
        START_BOUNDARY,           ///< Processing the first boundary
        HEADER_FIELD_START,       ///< Start of a header field name
        HEADER_FIELD,             ///< Processing a header field name
        HEADER_VALUE_START,       ///< Start of a header field value
        HEADER_VALUE,             ///< Processing a header field value
        HEADER_VALUE_ALMOST_DONE, ///< Found CR at end of header value
        HEADERS_ALMOST_DONE,      ///< Found CR at end of header section
        PART_DATA_START,          ///< Start of a part's data section
        PART_DATA,                ///< Processing a part's data
        PART_END,                 ///< End of a part
        END                       ///< End of the multipart data
    };

    /**
     * @brief Parser flags to track boundary types
     *
     * Used to distinguish between part boundaries and the final boundary
     * that ends the entire multipart content.
     */
    enum Flags {
        PART_BOUNDARY = 1, ///< Found a boundary between parts
        LAST_BOUNDARY = 2  ///< Found the final boundary
    };

    std::string boundary;     ///< Complete boundary string (including CR+LF and dashes)
    const char *boundaryData; ///< Pointer to boundary string data
    size_t      boundarySize; ///< Length of the boundary string
    bool        boundaryIndex[256]; ///< Lookup table for quick boundary character checks
    char       *lookbehind;         ///< Buffer for boundary detection lookahead
    size_t      lookbehindSize;     ///< Size of the lookbehind buffer
    State       state;              ///< Current parser state
    int         flags;              ///< Current parser flags
    size_t      index;              ///< Current index in the boundary string
    size_t      headerFieldMark;    ///< Mark for start of header field
    size_t      headerValueMark;    ///< Mark for start of header value
    size_t      partDataMark;       ///< Mark for start of part data
    const char *errorReason;        ///< Error message if state is ERROR

    /**
     * @brief Reset all callback pointers to NULL
     */
    void
    resetCallbacks() {
        onPartBegin   = NULL;
        onHeaderField = NULL;
        onHeaderValue = NULL;
        onHeaderEnd   = NULL;
        onHeadersEnd  = NULL;
        onPartData    = NULL;
        onPartEnd     = NULL;
        onEnd         = NULL;
        userData      = NULL;
    }

    /**
     * @brief Build boundary character lookup table
     *
     * Creates a lookup table for quick checking if a character
     * is part of the boundary string.
     */
    void
    indexBoundary() {
        const char *current;
        const char *end = boundaryData + boundarySize;

        std::memset(boundaryIndex, 0, sizeof(boundaryIndex));

        for (current = boundaryData; current < end; current++) {
            boundaryIndex[(unsigned char) *current] = true;
        }
    }

    /**
     * @brief Execute a callback function
     * @param cb The callback function to call
     * @param buffer The data buffer
     * @param start Start offset
     * @param end End offset
     * @param allowEmpty Whether to allow empty segments
     */
    void
    callback(Callback cb, const char *buffer = NULL, size_t start = UNMARKED,
             size_t end = UNMARKED, bool allowEmpty = false) {
        if (start != UNMARKED && start == end && !allowEmpty) {
            return;
        }
        if (cb != NULL) {
            cb(buffer, start, end, userData);
        }
    }

    /**
     * @brief Execute a data callback
     * @param cb The callback function
     * @param mark Reference to mark position
     * @param buffer Data buffer
     * @param i Current position
     * @param bufferLen Buffer length
     * @param clear Whether to clear the mark
     * @param allowEmpty Whether to allow empty segments
     */
    void
    dataCallback(Callback cb, size_t &mark, const char *buffer, size_t i,
                 size_t bufferLen, bool clear, bool allowEmpty = false) {
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

    /**
     * @brief Convert a character to lowercase
     * @param c Character to convert
     * @return Lowercase version of the character
     */
    char
    lower(char c) const {
        return c | 0x20;
    }

    /**
     * @brief Check if a character is part of the boundary
     * @param c Character to check
     * @return true if the character is part of the boundary
     */
    inline bool
    isBoundaryChar(char c) const {
        return boundaryIndex[(unsigned char) c];
    }

    /**
     * @brief Check if a character is valid in a header field name (RFC 7230 tchar)
     * @param c Character to check
     * @return true if the character is valid for header field
     */
    bool
    isHeaderFieldCharacter(char c) const {
        return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
                c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
                c == '^' || c == '_' || c == '`' || c == '|' || c == '~');
    }

    /**
     * @brief Set parser error state with message
     * @param message Error message
     */
    void
    setError(const char *message) {
        state       = ERROR;
        errorReason = message;
    }

    /**
     * @brief Process part data
     *
     * Core processing function for part data that detects boundaries
     * and transitions between states.
     *
     * @param prevIndex Previous index value
     * @param l_index Current index value
     * @param buffer Data buffer
     * @param len Buffer length
     * @param boundaryEnd Boundary end position
     * @param i Current position
     * @param c Current character
     * @param l_state Current state
     * @param l_flags Current flags
     */
    void
    processPartData(size_t &prevIndex, size_t &l_index, const char *buffer, size_t len,
                    size_t boundaryEnd, size_t &i, char c, State &l_state,
                    int &l_flags) {
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
            callback(onPartData, lookbehind, 0, prevIndex);
            prevIndex    = 0;
            partDataMark = i;

            // reconsider the current character even so it interrupted the sequence
            // it could be the beginning of a new sequence
            i--;
        }
    }

public:
    /**
     * @brief Callback for when a new part begins
     *
     * Called after the boundary is detected but before any headers are processed.
     * Note that the first part has this callback called after the initial boundary,
     * and subsequent parts have it called after the previous part's end.
     */
    Callback onPartBegin;

    /**
     * @brief Callback for header field name
     *
     * Called with the name of a header field (e.g., "Content-Type").
     * May be called multiple times if the header name comes in multiple chunks.
     */
    Callback onHeaderField;

    /**
     * @brief Callback for header field value
     *
     * Called with the value of a header field (e.g., "text/plain").
     * May be called multiple times if the header value comes in multiple chunks.
     */
    Callback onHeaderValue;

    /**
     * @brief Callback for when a header is complete
     *
     * Called after a complete header (field + value) has been processed.
     */
    Callback onHeaderEnd;

    /**
     * @brief Callback for when all headers for a part are complete
     *
     * Called after all headers for a part have been processed,
     * just before the part data begins.
     */
    Callback onHeadersEnd;

    /**
     * @brief Callback for part data
     *
     * Called with chunks of part data. For large parts, this
     * may be called multiple times as data becomes available.
     */
    Callback onPartData;

    /**
     * @brief Callback for when a part is complete
     *
     * Called after all data for a part has been processed,
     * when a new boundary is detected.
     */
    Callback onPartEnd;

    /**
     * @brief Callback for when the entire multipart message is complete
     *
     * Called after the final boundary is detected, indicating
     * the end of the multipart content.
     */
    Callback onEnd;

    /**
     * @brief User data pointer passed to callbacks
     *
     * This pointer is passed unchanged to all callbacks, allowing
     * context to be maintained across callback invocations.
     */
    void *userData;

    /**
     * @brief Default constructor
     *
     * Creates an uninitialized parser. SetBoundary must be called
     * before using the parser.
     */
    MultipartParser() {
        lookbehind = NULL;
        resetCallbacks();
        reset();
    }

    /**
     * @brief Constructor with boundary
     * @param boundary The multipart boundary string
     *
     * Creates a parser initialized with the specified boundary.
     */
    MultipartParser(std::string boundary) {
        lookbehind = NULL;
        resetCallbacks();
        setBoundary(std::move(boundary));
    }

    /**
     * @brief Destructor
     *
     * Frees any allocated resources.
     */
    ~MultipartParser() {
        delete[] lookbehind;
    }

    /**
     * @brief Reset the parser to initial state
     *
     * Clears all state and frees resources. SetBoundary must
     * be called again before using the parser.
     */
    void
    reset() {
        delete[] lookbehind;
        state = ERROR;
        boundary.clear();
        boundaryData    = boundary.c_str();
        boundarySize    = 0;
        lookbehind      = NULL;
        lookbehindSize  = 0;
        flags           = 0;
        index           = 0;
        headerFieldMark = UNMARKED;
        headerValueMark = UNMARKED;
        partDataMark    = UNMARKED;
        errorReason     = "Parser uninitialized.";
    }

    /**
     * @brief Set the boundary for parsing
     * @param l_boundary The boundary string
     *
     * Initializes the parser with the specified boundary string.
     * Must be called before feeding data to the parser.
     */
    void
    setBoundary(std::string l_boundary) {
        reset();
        this->boundary = "\r\n--" + std::move(l_boundary);
        boundaryData   = this->boundary.c_str();
        boundarySize   = this->boundary.size();
        indexBoundary();
        lookbehind     = new char[boundarySize + 8];
        lookbehindSize = boundarySize + 8;
        state          = START;
        errorReason    = "No error.";
    }

    /**
     * @brief Feed data to the parser
     * @param buffer Data buffer to parse
     * @param len Length of the data
     * @return Number of bytes processed
     *
     * Processes the provided data and advances the parser state.
     * Returns the number of bytes successfully processed.
     */
    size_t
    feed(const char *buffer, size_t len) {
        if (state == ERROR || len == 0) {
            return 0;
        }

        State  l_state     = this->state;
        int    l_flags     = this->flags;
        size_t prevIndex   = this->index;
        size_t l_index     = this->index;
        size_t boundaryEnd = boundarySize - 1;
        size_t i;
        char   c, cl;

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
                        dataCallback(onHeaderField, headerFieldMark, buffer, i, len,
                                     true);
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
                        dataCallback(onHeaderValue, headerValueMark, buffer, i, len,
                                     true, true);
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
                    processPartData(prevIndex, l_index, buffer, len, boundaryEnd, i, c,
                                    l_state, l_flags);
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

    /**
     * @brief Check if parsing completed successfully
     * @return true if parsing is complete and successful
     */
    bool
    succeeded() const {
        return state == END;
    }

    /**
     * @brief Check if parser encountered an error
     * @return true if an error occurred during parsing
     */
    bool
    hasError() const {
        return state == ERROR;
    }

    /**
     * @brief Check if parser is stopped
     * @return true if parser is in ERROR or END state
     */
    bool
    stopped() const {
        return state == ERROR || state == END;
    }

    /**
     * @brief Get error message if an error occurred
     * @return Error message string
     */
    const char *
    getErrorMessage() const {
        return errorReason;
    }
};

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
[[nodiscard]] std::string::const_iterator find_boundary(std::string const &str,
                                                        std::string const &boundary);

/**
 * @brief Parse boundary from Content-Type header
 * @param content_type Content-Type header value
 * @return Boundary string
 *
 * Extracts the boundary string from a multipart/form-data Content-Type header.
 * The boundary is used to separate different parts in the multipart body.
 * Returns an empty string if the Content-Type is not multipart/form-data
 * or if the boundary is not found.
 *
 * Example: from "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"
 * extracts "----WebKitFormBoundary7MA4YWxkTrZu0gW"
 */
[[nodiscard]] std::string parse_boundary(std::string const &content_type);

/**
 * @brief Template class for multipart form data handling
 * @tparam String String type (std::string or std::string_view)
 *
 * Provides functionality for creating and managing multipart/form-data content
 * as defined in RFC 7578. This class supports:
 *
 * - Creating and parsing multipart form data with proper boundary handling
 * - Managing individual parts with their headers and body content
 * - Automatic boundary generation for new multipart content
 * - Content-Length calculation for efficient transmission
 * - Support for file uploads and form field data
 * - Proper MIME type handling for each part
 *
 * The implementation follows standards for multipart MIME types and supports
 * both client-side content creation and server-side content parsing.
 */
template <typename String>
class TMultiPart {
    friend class Body;

public:
    /**
     * @brief A single part in a multipart message
     *
     * Contains headers and body for one part of a multipart message.
     */
    struct Part : public THeaders<String> {
        String body;

        /**
         * @brief Get the total size of this part
         * @return Size in bytes
         */
        [[nodiscard]] std::size_t
        size() const {
            std::size_t length = body.size() + sizeof(http::endl) + 1;
            for (const auto &[key, values] : this->_headers) {
                for (const auto &value : values)
                    length += key.size() + value.size() + sizeof(http::endl) + 1; // ': '
            }
            return length;
        }
    };

private:
    std::string       _boundary;
    std::vector<Part> _parts;

    /**
     * @brief Generate a random boundary string
     * @return Generated boundary string
     */
    [[nodiscard]] static std::string
    generate_boundary() {
        std::mt19937                       generator{std::random_device{}()};
        std::uniform_int_distribution<int> distribution{'0', '9'};

        std::string result =
            "----------------------------qb00000000000000000000000000000000";
        for (auto i = result.begin() + 30; i != result.end(); ++i)
            *i = static_cast<char>(distribution(generator));

        return result;
    }

public:
    /**
     * @brief Default constructor
     *
     * Creates a multipart object with a random boundary.
     */
    TMultiPart()
        : _boundary(generate_boundary()) {}

    /**
     * @brief Constructor with custom boundary
     * @param boundary Boundary string to use
     */
    explicit TMultiPart(std::string boundary)
        : _boundary(std::move(boundary)) {}

    /**
     * @brief Create a new part
     * @return Reference to the newly created part
     */
    [[nodiscard]] Part &
    create_part() {
        return _parts.emplace_back();
    }

    /**
     * @brief Calculate the total content length
     * @return Total content length in bytes
     */
    [[nodiscard]] std::size_t
    content_length() const {
        std::size_t ret = 0;

        for (const auto &part : _parts)
            ret += _boundary.size() + part.size() + 4;
        ret += _boundary.size() + 4; // end

        return ret;
    }

    /**
     * @brief Get the boundary string
     * @return Boundary string
     */
    [[nodiscard]] std::string const &
    boundary() const {
        return _boundary;
    }

    /**
     * @brief Get the parts collection
     * @return Vector of parts
     */
    [[nodiscard]] std::vector<Part> const &
    parts() const {
        return _parts;
    }

    /**
     * @brief Get the parts collection (non-const)
     * @return Vector of parts
     */
    [[nodiscard]] std::vector<Part> &
    parts() {
        return _parts;
    }
};
using Multipart      = TMultiPart<std::string>;
using multipart      = Multipart;
using MultipartView  = TMultiPart<std::string_view>;
using multipart_view = MultipartView;

} // namespace qb::http
DISABLE_WARNING_POP

namespace qb::allocator {
/**
 * @brief HTTP Multipart content serialization specialization
 *
 * Specialization of the pipe<char>::put template for HTTP multipart content.
 * This function formats multipart/form-data content according to RFC 7578.
 *
 * The formatted multipart content includes:
 * - Boundary markers between parts
 * - Headers for each part (Content-Type, Content-Disposition, etc.)
 * - Content for each part
 * - Final boundary marker to indicate the end of the multipart content
 *
 * @param f Multipart form data to serialize
 * @return Reference to the pipe for method chaining
 */
template <>
pipe<char> &pipe<char>::put<qb::http::Multipart>(const qb::http::Multipart &f);

/**
 * @brief HTTP Multipart content serialization specialization
 *
 * Specialization of the pipe<char>::put template for HTTP multipart content.
 * This function formats multipart/form-data content according to RFC 7578.
 *
 * The formatted multipart content includes:
 * - Boundary markers between parts
 * - Headers for each part (Content-Type, Content-Disposition, etc.)
 * - Content for each part
 * - Final boundary marker to indicate the end of the multipart content
 *
 * @param f MultipartView form data to serialize
 * @return Reference to the pipe for method chaining
 */
template <>
pipe<char> &pipe<char>::put<qb::http::MultipartView>(const qb::http::MultipartView &f);

} // namespace qb::allocator
