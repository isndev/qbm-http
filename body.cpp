
#include "./body.h"
#include "./types.h"
namespace qb::http {

namespace internal {

/**
 * @brief Multipart form data parser for HTTP
 * @tparam String String type used for storage (std::string or std::string_view)
 * 
 * Parses multipart/form-data content according to RFC 7578.
 * Provides a callback-based interface for processing multipart body parts.
 * The reader processes each part of a multipart message sequentially, 
 * calling appropriate callbacks at different stages of parsing.
 */
template <typename String>
class MultipartReader {
public:
    /**
     * @brief Callback type for when a new part begins
     * 
     * Called after all headers for a part have been parsed, 
     * but before any part data is processed.
     */
    typedef void (*PartBeginCallback)(THeaders<String> &headers, void *userData);
    
    /**
     * @brief Callback type for part data chunks
     * 
     * Called when part data is available for processing.
     * May be called multiple times for a single part if data is large.
     */
    typedef void (*PartDataCallback)(const char *buffer, size_t size, void *userData);
    
    /**
     * @brief Generic callback type
     * 
     * Used for part end and parser end events.
     */
    typedef void (*Callback)(void *userData);

private:
    MultipartParser parser;
    bool headersProcessed;
    THeaders<String> currentHeaders;
    String currentHeaderName, currentHeaderValue;

    /**
     * @brief Reset all reader callbacks to NULL
     * 
     * Clears all callback function pointers without affecting the parser state.
     */
    void
    resetReaderCallbacks() {
        onPartBegin = NULL;
        onPartData = NULL;
        onPartEnd = NULL;
        onEnd = NULL;
        userData = NULL;
    }

    /**
     * @brief Configure internal parser callbacks
     * 
     * Sets up the internal MultipartParser callbacks to call into
     * the MultipartReader's static callback methods.
     */
    void
    setParserCallbacks() {
        parser.onPartBegin = cbPartBegin;
        parser.onHeaderField = cbHeaderField;
        parser.onHeaderValue = cbHeaderValue;
        parser.onHeaderEnd = cbHeaderEnd;
        parser.onHeadersEnd = cbHeadersEnd;
        parser.onPartData = cbPartData;
        parser.onPartEnd = cbPartEnd;
        parser.onEnd = cbEnd;
        parser.userData = this;
    }

    /**
     * @brief Static callback for when a new part begins
     * 
     * Resets the current headers and prepares to parse the new part.
     */
    static void
    cbPartBegin(const char *, size_t, size_t, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        self->headersProcessed = false;
        self->currentHeaders.headers().clear();
        self->currentHeaderName = {};
        self->currentHeaderValue = {};
    }

    /**
     * @brief Static callback for header field name
     * 
     * Stores the current header field name for later use.
     */
    static void
    cbHeaderField(const char *buffer, size_t start, size_t end, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        self->currentHeaderName = String(buffer + start, end - start);
    }

    /**
     * @brief Static callback for header field value
     * 
     * Stores the current header field value for later use.
     */
    static void
    cbHeaderValue(const char *buffer, size_t start, size_t end, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        self->currentHeaderValue = String(buffer + start, end - start);
    }

    /**
     * @brief Static callback for header completion
     * 
     * Called when a complete header has been parsed.
     * Adds the current header name/value pair to the headers map.
     */
    static void
    cbHeaderEnd(const char *, size_t, size_t, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        self->currentHeaders.headers()[self->currentHeaderName].push_back(self->currentHeaderValue);
        self->currentHeaderName = {};
        self->currentHeaderValue = {};
    }

    /**
     * @brief Static callback for all headers completion
     * 
     * Called when all headers for a part have been parsed.
     * Triggers the user-provided onPartBegin callback.
     */
    static void
    cbHeadersEnd(const char *, size_t, size_t, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        if (self->onPartBegin != NULL) {
            self->onPartBegin(self->currentHeaders, self->userData);
        }
        self->currentHeaders.headers().clear();
        self->currentHeaderName = {};
        self->currentHeaderValue = {};
    }

    /**
     * @brief Static callback for part data
     * 
     * Called when part data is available.
     * Triggers the user-provided onPartData callback.
     */
    static void
    cbPartData(const char *buffer, size_t start, size_t end, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        if (self->onPartData != NULL) {
            self->onPartData(buffer + start, end - start, self->userData);
        }
    }

    /**
     * @brief Static callback for part completion
     * 
     * Called when a part has been completely parsed.
     * Triggers the user-provided onPartEnd callback.
     */
    static void
    cbPartEnd(const char *, size_t, size_t, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        if (self->onPartEnd != NULL) {
            self->onPartEnd(self->userData);
        }
    }

    /**
     * @brief Static callback for parser completion
     * 
     * Called when the entire multipart content has been parsed.
     * Triggers the user-provided onEnd callback.
     */
    static void
    cbEnd(const char *, size_t, size_t, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        if (self->onEnd != NULL) {
            self->onEnd(self->userData);
        }
    }

public:
    PartBeginCallback onPartBegin;  ///< User callback for part begin
    PartDataCallback onPartData;    ///< User callback for part data
    Callback onPartEnd;             ///< User callback for part end
    Callback onEnd;                 ///< User callback for parser end
    void *userData;                 ///< User data passed to callbacks

    /**
     * @brief Default constructor
     * 
     * Creates a MultipartReader with no boundary.
     * A boundary must be set before parsing using setBoundary().
     */
    MultipartReader() {
        resetReaderCallbacks();
        setParserCallbacks();
    }

    /**
     * @brief Constructor with boundary
     * @param boundary Multipart boundary string
     * 
     * Creates a MultipartReader with the specified boundary.
     */
    MultipartReader(std::string boundary)
        : parser(std::move(boundary)) {
        resetReaderCallbacks();
        setParserCallbacks();
    }

    /**
     * @brief Reset the parser state
     * 
     * Resets the internal parser state to start parsing a new message.
     * Does not affect callbacks or userData.
     */
    void
    reset() {
        parser.reset();
    }

    /**
     * @brief Set the multipart boundary
     * @param boundary Multipart boundary string
     * 
     * Sets or changes the multipart boundary for parsing.
     */
    void
    setBoundary(std::string boundary) {
        parser.setBoundary(std::move(boundary));
    }

    /**
     * @brief Process a chunk of multipart data
     * @param buffer Pointer to the data buffer
     * @param len Length of the buffer in bytes
     * @return Number of bytes processed
     * 
     * Feeds a chunk of multipart data to the parser.
     * Callbacks will be triggered during parsing as appropriate.
     */
    size_t
    feed(const char *buffer, size_t len) {
        return parser.feed(buffer, len);
    }

    /**
     * @brief Check if parsing completed successfully
     * @return true if parsing completed successfully
     * 
     * Returns true if the parser reached the end of the multipart
     * content and successfully parsed all parts.
     */
    bool
    succeeded() const {
        return parser.succeeded();
    }

    /**
     * @brief Check if parsing encountered an error
     * @return true if an error occurred during parsing
     * 
     * Returns true if an error occurred during parsing.
     * The error message can be retrieved with getErrorMessage().
     */
    bool
    hasError() const {
        return parser.hasError();
    }

    /**
     * @brief Check if parsing was stopped
     * @return true if parsing was stopped
     * 
     * Returns true if parsing was stopped, either due to 
     * an error or by request.
     */
    bool
    stopped() const {
        return parser.stopped();
    }

    /**
     * @brief Get the error message if an error occurred
     * @return Error message string or empty if no error
     * 
     * Returns a descriptive error message if hasError() returns true.
     */
    const char *
    getErrorMessage() const {
        return parser.getErrorMessage();
    }
};

} // namespace qb::http::internal


#ifdef QB_IO_WITH_ZLIB
/**
 * @brief Get a compressor provider based on encoding header
 * @param encoding Content-Encoding or Accept-Encoding header value
 * @return Unique pointer to appropriate compressor or nullptr if none needed
 * 
 * Creates a compression provider based on the specified encoding.
 * Supports multiple encodings separated by commas, choosing the first
 * supported one. Special values "identity" and "chunked" return nullptr.
 * 
 * @throws std::runtime_error If no supported encoding is found
 */
std::unique_ptr<qb::compression::compress_provider>
Body::get_compressor_from_header(const std::string &encoding) {
    auto tokens = utility::split_string<std::string>(encoding, ",; \t");

    for (const auto &token : tokens) {
        auto c = qb::compression::builtin::make_compressor(token);
        if (c || utility::iequals(token, "identity") || utility::iequals(token, "chunked"))
            return c;
    }

    throw std::runtime_error("Unsupported encoding type");
}

/**
 * @brief Compress the body content using specified encoding
 * @param encoding Content-Encoding value to use
 * @return Size of the compressed data or original size if no compression performed
 * 
 * Compresses the body content using the compression algorithm specified
 * in the encoding parameter. If the body is empty or encoding is empty,
 * no compression is performed.
 * 
 * The function handles creating temporary buffers and replacing the
 * body content with the compressed version when done.
 */
std::size_t
Body::compress(std::string const &encoding) {
    if (!size() || encoding.empty())
        return size();
    auto compressor = get_compressor_from_header(encoding);
    if (!compressor)
        return size();
    auto &body = raw();
    qb::allocator::pipe<char> out;
    std::size_t i_processed{}, o_processed{};
    bool done{};

    while (!done && i_processed != body.size()) {
        std::size_t alloc = (body.size() + 32);
        out.allocate_back(alloc);
        std::size_t i_tmp;
        o_processed += compressor->compress(
            reinterpret_cast<uint8_t const *>(body.begin()) + i_processed,
            body.size() - i_processed,
            reinterpret_cast<uint8_t *>(out.begin()) + o_processed,
            out.size() - o_processed,
            qb::compression::is_last,
            i_tmp,
            done);
        i_processed += i_tmp;
    }
    out.free_back(out.size() - o_processed);
    _data = std::move(out);
    return o_processed;
}

/**
 * @brief Get a decompressor provider based on encoding header
 * @param encoding Content-Encoding header value
 * @return Unique pointer to appropriate decompressor
 * 
 * Creates a decompression provider based on the specified encoding.
 * Validates that only one compression algorithm is used (multiple
 * compression algorithms in sequence are not supported). Also verifies
 * that "chunked" encoding is the last one if present.
 * 
 * @throws std::runtime_error If encoding is invalid or unsupported
 */
std::unique_ptr<qb::compression::decompress_provider>
Body::get_decompressor_from_header(const std::string &encoding) {
    std::unique_ptr<qb::compression::decompress_provider> decompressor;

    auto tokens = utility::split_string<std::string>(encoding, ", \t");
    auto i = 1u;
    for (const auto &token : tokens) {
        auto d = qb::compression::builtin::make_decompressor(token);
        if (d) {
            if (decompressor) {
                throw std::runtime_error("Multiple compression algorithms not "
                                         "supported for a single request");
            }

            // We found our decompressor; store it off while we process the rest of the
            // header
            decompressor = std::move(d);
        } else {
            if (utility::iequals("chunked", token) && i != tokens.size())
                throw std::runtime_error("Chunked must come last in the Transfer-Encoding header");
        }
        ++i;
    }

    if (!decompressor)
        throw std::runtime_error("Unsupported encoding type");

    return decompressor;
}

/**
 * @brief Decompress the body content using specified encoding
 * @param encoding Content-Encoding value to use
 * @return Size of the decompressed data or original size if no decompression performed
 * 
 * Decompresses the body content using the decompression algorithm specified
 * in the encoding parameter. If the body is empty or encoding is empty,
 * no decompression is performed.
 * 
 * The function handles creating temporary buffers and replacing the
 * body content with the decompressed version when done.
 */
std::size_t
Body::uncompress(const std::string &encoding) {
    if (!size() || encoding.empty())
        return size();
    auto decompressor = get_decompressor_from_header(encoding);
    auto &body = raw();
    qb::allocator::pipe<char> out;
    std::size_t i_processed{}, o_processed{};
    bool done{};

    while (!done && i_processed != body.size()) {
        std::size_t alloc = (body.size() * 2);
        out.allocate_back(alloc);
        std::size_t i_tmp;
        o_processed += decompressor->decompress(
            reinterpret_cast<uint8_t const *>(body.begin()) + i_processed,
            body.size() - i_processed,
            reinterpret_cast<uint8_t *>(out.begin()) + o_processed,
            out.size() - o_processed,
            qb::compression::is_last,
            i_tmp,
            done);
        i_processed += i_tmp;
    }
    out.free_back(out.size() - o_processed);
    _data = std::move(out);
    return o_processed;
}
#endif

/**
 * @brief Assign a string to the body by moving
 * @param str String to move into the body
 * @return Reference to this body
 * 
 * Move assignment operator for std::string.
 * This specialization is optimized to clear the source string after moving.
 */
template <>
Body &
Body::operator=<std::string>(std::string &&str) noexcept {
    _data.clear();
    _data << str;
    str.clear();
    return *this;
}

/**
 * @brief Assign a string_view to the body by moving
 * @param str String_view to move into the body
 * @return Reference to this body
 * 
 * Move assignment operator for std::string_view.
 */
template <>
Body &
Body::operator=<std::string_view>(std::string_view &&str) noexcept {
    _data.clear();
    _data << str;
    return *this;
}

/**
 * @brief Assign a string to the body by copying
 * @param str String to copy into the body
 * @return Reference to this body
 * 
 * Copy assignment operator for std::string.
 */
template <>
Body &
Body::operator=<std::string>(std::string const &str) {
    _data.clear();
    _data << str;
    return *this;
}

/**
 * @brief Assign a char vector to the body by copying
 * @param rhs Vector to copy into the body
 * @return Reference to this body
 * 
 * Copy assignment operator for std::vector<char>.
 */
template <>
Body &
Body::operator=<std::vector<char>>(std::vector<char> const &rhs) {
    _data.clear();
    _data << rhs;
    return *this;
}

/**
 * @brief Assign a char vector to the body by moving
 * @param rhs Vector to move into the body
 * @return Reference to this body
 * 
 * Move assignment operator for std::vector<char>.
 * This specialization is optimized to clear the source vector after moving.
 */
template <>
Body &
Body::operator=<std::vector<char>>(std::vector<char> &&rhs) noexcept {
    _data.clear();
    _data << rhs;
    rhs.clear();
    return *this;
}

/**
 * @brief Assign a Multipart object to the body by copying
 * @param mp Multipart object to copy into the body
 * @return Reference to this body
 * 
 * Copy assignment operator for Multipart.
 * Serializes the multipart content into the body.
 */
template <>
Body &
Body::operator=<Multipart>(Multipart const &mp) {
    _data.clear();
    _data << mp;
    return *this;
}


/**
 * @brief Assign a json object to the body by copying
 * @param json Json object to copy into the body
 * @return Reference to this body
 * 
 * Copy assignment operator for qb::json.
 */
template <>
Body &
Body::operator=<qb::json>(qb::json const &json) {
    _data.clear();
    _data << json;
    return *this;
}

/**
 * @brief Convert the body to a string_view
 * @return String view of the body content
 * 
 * This specialization provides a zero-copy view of the body content.
 * The returned view is valid only as long as the body object is not modified.
 */
template <>
std::string_view
Body::as<std::string_view>() const {
    return _data.view();
}

/**
 * @brief Convert the body to a string
 * @return String copy of the body content
 * 
 * This specialization creates a new string with the body content.
 */
template <>
std::string
Body::as<std::string>() const {
    return _data.str();
}

/**
 * @brief Convert the body to a json object
 * @return Json object of the body content
 * 
 * This specialization creates a json object from the body content.
 */
template <>
qb::json
Body::as<qb::json>() const {
    return qb::json::parse(_data.view());
}


/**
 * @brief Parse the body as a multipart form-data content
 * @return Multipart object containing the parsed parts
 * 
 * Parses the body content as multipart/form-data format and returns
 * a Multipart object containing the individual parts.
 * 
 * The function extracts the boundary from the body's first line,
 * then uses a MultipartReader to parse each part.
 * 
 * @throws std::runtime_error If the body doesn't contain a valid boundary
 *                            or if parsing fails
 */
template <>
Multipart
Body::as<Multipart>() const {
    auto view = _data.view();
    auto pos = view.find_first_of(qb::http::endl);
    if (pos == std::string::npos || pos < 2)
        throw std::runtime_error("boundary not found");
    auto boundary = std::string(_data.begin() + 2, pos - 2);

    internal::MultipartReader<std::string> reader(boundary);
    Multipart mp(boundary);
    reader.userData = &mp;
    reader.onPartBegin = [](THeaders<std::string> &headers, void *userData) {
        auto &part = reinterpret_cast<Multipart *>(userData)->create_part();
        part.headers() = std::move(headers.headers());
        if (part.has_header("Content-Type"))
            part.set_content_type(part.header("Content-Type"));
    };
    reader.onPartData = [](const char *buffer, size_t size, void *userData) {
        auto &part = reinterpret_cast<Multipart *>(userData)->parts().back();
        part.body = std::string(buffer, size);
    };
    reader.onPartEnd = [](void *) {};
    reader.onEnd = [](void *) {};

    reader.feed(_data.begin(), _data.size());
    if (reader.hasError())
        throw std::runtime_error("failed to parse multipart: " + std::string(reader.getErrorMessage()));

    return mp;
}

/**
 * @brief Parse the body as a multipart form-data content
 * @return Multipart object containing the parsed parts
 * 
 * Parses the body content as multipart/form-data format and returns
 * a Multipart object containing the individual parts.
 * 
 * The function extracts the boundary from the body's first line,
 * then uses a MultipartReader to parse each part.
 * 
 * @throws std::runtime_error If the body doesn't contain a valid boundary
 *                            or if parsing fails
 */
template <>
MultipartView
Body::as<MultipartView>() const {
    auto view = _data.view();
    auto pos = view.find_first_of(qb::http::endl);
    if (pos == std::string::npos || pos < 2)
        throw std::runtime_error("boundary not found");
    auto boundary = std::string(_data.begin() + 2, pos - 2);

    internal::MultipartReader<std::string_view> reader(boundary);
    MultipartView mp(boundary);
    reader.userData = &mp;
    reader.onPartBegin = [](THeaders<std::string_view> &headers, void *userData) {
        auto &part = reinterpret_cast<MultipartView *>(userData)->create_part();
        part.headers() = std::move(headers.headers());
        if (part.has_header("Content-Type"))
            part.set_content_type(part.header("Content-Type"));
    };
    reader.onPartData = [](const char *buffer, size_t size, void *userData) {
        auto &part = reinterpret_cast<MultipartView *>(userData)->parts().back();
        part.body = std::string_view(buffer, size);
    };
    reader.onPartEnd = [](void *) {};
    reader.onEnd = [](void *) {};

    reader.feed(_data.begin(), _data.size());
    if (reader.hasError())
        throw std::runtime_error("failed to parse multipart: " + std::string(reader.getErrorMessage()));

    return mp;
}

}
