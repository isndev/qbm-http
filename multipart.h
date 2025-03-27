#ifndef _MULTIPART_PARSER_H_
#define _MULTIPART_PARSER_H_

#include <sys/types.h>
#include <string>
#include <stdexcept>
#include <cstring>
#include <qb/utility/build_macros.h>
DISABLE_WARNING_PUSH
DISABLE_WARNING_IMPLICIT_FALLTHROUGH
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
    typedef void (*Callback)(const char *buffer, size_t start, size_t end, void *userData);

private:
    // Character constants used in parsing
    static const char CR = 13;
    static const char LF = 10;
    static const char SPACE = 32;
    static const char HYPHEN = 45;
    static const char COLON = 58;
    static const size_t UNMARKED = (size_t)-1;

    // Parser states
    enum State {
        ERROR,
        START,
        START_BOUNDARY,
        HEADER_FIELD_START,
        HEADER_FIELD,
        HEADER_VALUE_START,
        HEADER_VALUE,
        HEADER_VALUE_ALMOST_DONE,
        HEADERS_ALMOST_DONE,
        PART_DATA_START,
        PART_DATA,
        PART_END,
        END
    };

    enum Flags { PART_BOUNDARY = 1, LAST_BOUNDARY = 2 };

    std::string boundary;
    const char *boundaryData;
    size_t boundarySize;
    bool boundaryIndex[256];
    char *lookbehind;
    size_t lookbehindSize;
    State state;
    int flags;
    size_t index;
    size_t headerFieldMark;
    size_t headerValueMark;
    size_t partDataMark;
    const char *errorReason;

    /**
     * @brief Reset all callback pointers to NULL
     */
    void
    resetCallbacks() {
        onPartBegin = NULL;
        onHeaderField = NULL;
        onHeaderValue = NULL;
        onHeaderEnd = NULL;
        onHeadersEnd = NULL;
        onPartData = NULL;
        onPartEnd = NULL;
        onEnd = NULL;
        userData = NULL;
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
            boundaryIndex[(unsigned char)*current] = true;
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
    callback(
        Callback cb, const char *buffer = NULL, size_t start = UNMARKED, size_t end = UNMARKED,
        bool allowEmpty = false) {
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
    dataCallback(
        Callback cb, size_t &mark, const char *buffer, size_t i, size_t bufferLen, bool clear,
        bool allowEmpty = false) {
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
        return boundaryIndex[(unsigned char)c];
    }

    /**
     * @brief Check if a character is valid in a header field name
     * @param c Character to check
     * @return true if the character is valid for header field
     */
    bool
    isHeaderFieldCharacter(char c) const {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == HYPHEN;
    }

    /**
     * @brief Set parser error state with message
     * @param message Error message
     */
    void
    setError(const char *message) {
        state = ERROR;
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
    processPartData(
        size_t &prevIndex, size_t &l_index, const char *buffer, size_t len, size_t boundaryEnd, size_t &i, char c,
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
            callback(onPartData, lookbehind, 0, prevIndex);
            prevIndex = 0;
            partDataMark = i;

            // reconsider the current character even so it interrupted the sequence
            // it could be the beginning of a new sequence
            i--;
        }
    }

public:
    // Callback functions for parser events
    Callback onPartBegin;
    Callback onHeaderField;
    Callback onHeaderValue;
    Callback onHeaderEnd;
    Callback onHeadersEnd;
    Callback onPartData;
    Callback onPartEnd;
    Callback onEnd;
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
    MultipartParser(const std::string &boundary) {
        lookbehind = NULL;
        resetCallbacks();
        setBoundary(boundary);
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
        boundaryData = boundary.c_str();
        boundarySize = 0;
        lookbehind = NULL;
        lookbehindSize = 0;
        flags = 0;
        index = 0;
        headerFieldMark = UNMARKED;
        headerValueMark = UNMARKED;
        partDataMark = UNMARKED;
        errorReason = "Parser uninitialized.";
    }

    /**
     * @brief Set the boundary for parsing
     * @param l_boundary The boundary string
     * 
     * Initializes the parser with the specified boundary string.
     * Must be called before feeding data to the parser.
     */
    void
    setBoundary(const std::string &l_boundary) {
        reset();
        this->boundary = "\r\n--" + l_boundary;
        boundaryData = this->boundary.c_str();
        boundarySize = this->boundary.size();
        indexBoundary();
        lookbehind = new char[boundarySize + 8];
        lookbehindSize = boundarySize + 8;
        state = START;
        errorReason = "No error.";
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

        State l_state = this->state;
        int l_flags = this->flags;
        size_t prevIndex = this->index;
        size_t l_index = this->index;
        size_t boundaryEnd = boundarySize - 1;
        size_t i;
        char c, cl;

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
                    setError("Malformed. Found different boundary data than the given one.");
                    return i;
                }
                l_index++;
                break;
            case HEADER_FIELD_START:
                l_state = HEADER_FIELD;
                headerFieldMark = i;
                l_index = 0;
            case HEADER_FIELD:
                if (c == CR) {
                    headerFieldMark = UNMARKED;
                    l_state = HEADERS_ALMOST_DONE;
                    break;
                }

                l_index++;
                if (c == HYPHEN) {
                    break;
                }

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

                cl = lower(c);
                if (cl < 'a' || cl > 'z') {
                    setError("Malformed header name.");
                    return i;
                }
                break;
            case HEADER_VALUE_START:
                if (c == SPACE) {
                    break;
                }

                headerValueMark = i;
                l_state = HEADER_VALUE;
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
                l_state = PART_DATA;
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

} // namespace qb::http
DISABLE_WARNING_POP
#endif /* _MULTIPART_PARSER_H_ */