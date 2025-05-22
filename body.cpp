/**
 * @file qbm/http/body.cpp
 * @brief HTTP message body class
 *
 * This file contains the definition of the `Body` class, which represents
 * the body of an HTTP message. It provides methods for manipulating and
 * accessing the body data.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <qb/io/uri.h>
#include "./body.h"

namespace qb::http {
    // Placed explicit copy constructor and assignment operator definitions here
    Body::Body(Body const &rhs)
        : _data(rhs._data) {
        // Explicitly use pipe's copy constructor
    }

    Body &Body::operator=(Body const &rhs) {
        if (this != &rhs) {
            _data = rhs._data; // Explicitly use pipe's copy assignment
        }
        return *this;
    }

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
        template<typename String>
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
                onPartBegin = nullptr;
                onPartData = nullptr;
                onPartEnd = nullptr;
                onEnd = nullptr;
                userData = nullptr;
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
                MultipartReader<String> *self = static_cast<MultipartReader<String> *>(userData);
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
                MultipartReader<String> *self = static_cast<MultipartReader<String> *>(userData);
                self->currentHeaderName = String(buffer + start, end - start);
            }

            /**
             * @brief Static callback for header field value
             *
             * Stores the current header field value for later use.
             */
            static void
            cbHeaderValue(const char *buffer, size_t start, size_t end, void *userData) {
                MultipartReader<String> *self = static_cast<MultipartReader<String> *>(userData);
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
                MultipartReader<String> *self = static_cast<MultipartReader<String> *>(userData);
                self->currentHeaders.headers()[self->currentHeaderName].push_back(
                    self->currentHeaderValue);
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
                MultipartReader<String> *self = static_cast<MultipartReader<String> *>(userData);
                if (self->onPartBegin != nullptr) {
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
                MultipartReader<String> *self = static_cast<MultipartReader<String> *>(userData);
                if (self->onPartData != nullptr) {
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
                MultipartReader<String> *self = static_cast<MultipartReader<String> *>(userData);
                if (self->onPartEnd != nullptr) {
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
                MultipartReader<String> *self = static_cast<MultipartReader<String> *>(userData);
                if (self->onEnd != nullptr) {
                    self->onEnd(self->userData);
                }
            }

        public:
            PartBeginCallback onPartBegin; ///< User callback for part begin
            PartDataCallback onPartData; ///< User callback for part data
            Callback onPartEnd; ///< User callback for part end
            Callback onEnd; ///< User callback for parser end
            void *userData; ///< User data passed to callbacks

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
            explicit MultipartReader(std::string boundary)
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
            [[nodiscard]] bool
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
            [[nodiscard]] bool
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
            [[nodiscard]] bool
            stopped() const {
                return parser.stopped();
            }

            /**
             * @brief Get the error message if an error occurred
             * @return Error message string or empty if no error
             *
             * Returns a descriptive error message if hasError() returns true.
             */
            [[nodiscard]] const char *
            getErrorMessage() const {
                return parser.getErrorMessage();
            }
        };
    } // namespace internal

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
        std::unique_ptr<qb::compression::compress_provider> actual_compressor;

        for (const auto &token: tokens) {
            if (utility::iequals(token, "chunked") || utility::iequals(token, "identity")) {
                continue; // Skip these tokens for compressor selection
            }
            actual_compressor = qb::compression::builtin::make_compressor(token);
            if (actual_compressor) {
                return actual_compressor; // Found the first real compressor
            }
        }
        // If loop finishes, no actual compressor was found.
        // Check if "identity" was a relevant token, or if encoding implies no compression by being empty or only "chunked".
        bool only_chunked_or_empty = true;
        bool has_identity = false;
        for (const auto &token: tokens) {
            if (utility::iequals(token, "identity")) {
                has_identity = true;
            }
            if (!token.empty() && !utility::iequals(token, "chunked") && !utility::iequals(token, "identity")) {
                only_chunked_or_empty = false; // Found a token that is not chunked or identity
            }
        }

        if (has_identity) return nullptr; // Explicit identity means no compression
        if (only_chunked_or_empty && tokens.empty()) return nullptr; // Empty encoding means no compression
        if (only_chunked_or_empty && !tokens.empty()) return nullptr;
        // Only chunked also means no actual compressor selected here

        // If we are here, it means there was a token that was not chunked, not identity, and not a known compressor.
        throw std::runtime_error("Unsupported encoding type: " + encoding);
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
                out.size() - o_processed, qb::compression::is_last, i_tmp, done);
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
        for (const auto &token: tokens) {
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
                    throw std::runtime_error(
                        "Chunked must come last in the Transfer-Encoding header");
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
                out.size() - o_processed, qb::compression::is_last, i_tmp, done);
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
    template<>
    Body &Body::operator=<std::string>(std::string &&str) noexcept {
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
    template<>
    Body &Body::operator=<std::string_view>(std::string_view &&str) noexcept {
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
    template<>
    Body &Body::operator=<std::string>(std::string const &str) {
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
    template<>
    Body &Body::operator=<std::vector<char> >(std::vector<char> const &rhs) {
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
    template<>
    Body &Body::operator=<std::vector<char> >(std::vector<char> &&rhs) noexcept {
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
    template<>
    Body &Body::operator=<Multipart>(Multipart const &mp) {
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
    template<>
    Body &Body::operator=<qb::json>(qb::json const &json) {
        _data.clear();
        _data << json;
        return *this;
    }

    /**
     * @brief Assign a json object to the body by copying
     * @param json Json object to copy into the body
     * @return Reference to this body
     *
     * Copy assignment operator for qb::json.
     */
    template<>
    Body &Body::operator=<qb::json>(qb::json &&json) noexcept {
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
    template<>
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
    template<>
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
    template<>
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
    template<>
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
        reader.onPartEnd = [](void *) {
        };
        reader.onEnd = [](void *) {
        };

        reader.feed(_data.begin(), _data.size());
        if (reader.hasError())
            throw std::runtime_error("failed to parse multipart: " +
                                     std::string(reader.getErrorMessage()));

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
    template<>
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
        reader.onPartEnd = [](void *) {
        };
        reader.onEnd = [](void *) {
        };

        reader.feed(_data.begin(), _data.size());
        if (reader.hasError())
            throw std::runtime_error("failed to parse multipart: " +
                                     std::string(reader.getErrorMessage()));

        return mp;
    }

    /**
     * @brief Assign a Form object to the body by copying
     * @param form Form object to copy into the body
     * @return Reference to this body
     *
     * Copy assignment operator for Form.
     * Serializes the form content into the body as x-www-form-urlencoded.
     */
    template<>
    Body &Body::operator=<Form>(Form const &form) {
        _data.clear();
        bool first_pair = true;
        for (const auto &field_pair: form.fields()) {
            for (const auto &value: field_pair.second) {
                if (!first_pair) {
                    _data << '&';
                }
                _data << qb::io::uri::encode(field_pair.first);
                _data << '=';
                _data << qb::io::uri::encode(value);
                first_pair = false;
            }
        }
        return *this;
    }

    /**
     * @brief Assign a Form object to the body by moving
     * @param form Form object to move into the body
     * @return Reference to this body
     *
     * Move assignment operator for Form.
     * Serializes the form content into the body as x-www-form-urlencoded.
     */
    template<>
    Body &Body::operator=<Form>(Form &&form) noexcept {
        _data.clear();
        bool first_pair = true;
        for (const auto &field_pair: form.fields()) {
            for (const auto &value: field_pair.second) {
                if (!first_pair) {
                    _data << '&';
                }
                _data << qb::io::uri::encode(field_pair.first);
                _data << '=';
                _data << qb::io::uri::encode(value);
                first_pair = false;
            }
        }
        form.clear(); // Clear the source form after moving its content
        return *this;
    }

    /**
     * @brief Parse the body as x-www-form-urlencoded content
     * @return Form object containing the parsed key-value pairs
     *
     * Parses the body content as x-www-form-urlencoded format and returns
     * a Form object.
     *
     * @throws std::runtime_error If parsing fails (e.g., malformed data)
     */
    template<>
    Form Body::as<Form>() const {
        Form form_data;
        auto body_view = _data.view();

        if (body_view.empty()) {
            return form_data;
        }

        size_t start = 0;
        while (start < body_view.length()) {
            size_t end_pair = body_view.find('&', start);
            if (end_pair == std::string_view::npos) {
                end_pair = body_view.length();
            }

            std::string_view pair_str = body_view.substr(start, end_pair - start);
            size_t eq_pos = pair_str.find('=');

            if (eq_pos != std::string_view::npos) {
                std::string key = qb::io::uri::decode(pair_str.substr(0, eq_pos));
                std::string value = qb::io::uri::decode(pair_str.substr(eq_pos + 1));
                if (!key.empty()) {
                    // Ensure key is not empty after decoding
                    form_data.add(key, value);
                }
            } else {
                // Handle cases where there is no '=' (e.g., 'key' or empty string if pair_str is empty)
                std::string key = qb::io::uri::decode(pair_str);
                if (!key.empty()) {
                    // Ensure key is not empty after decoding
                    form_data.add(key, ""); // Add with empty value
                }
            }
            start = end_pair + 1;
        }

        return form_data;
    }

    // Specialization for const std::string_view&
    template<>
    Body &Body::operator=<std::string_view>(std::string_view const &str) {
        _data.clear();
        _data << str;
        return *this;
    }

    // Specialization for const char* const&
    template<>
    Body &Body::operator=<const char *>(char const *const &str) {
        _data.clear();
        if (str) {
            // Check for nullptr before attempting to stream
            _data << str;
        }
        return *this;
    }

    /**
     * @brief Assign a MultipartView object to the body by copying its structure.
     * @param mpv MultipartView object to serialize into the body.
     * @return Reference to this body.
     *
     * Note: This serializes the content referenced by MultipartView. The string_views
     * in MultipartView must be valid when this operator is called.
     */
    template<>
    Body &Body::operator=<MultipartView>(MultipartView const &mpv) {
        _data.clear();
        // The actual serialization logic uses qb::allocator::pipe<char>::put<MultipartView>
        // which is already defined in multipart.cpp using a common put_impl.
        // So, we can directly use the stream operator here.
        _data << mpv;
        return *this;
    }

    /**
     * @brief Assign a MultipartView object to the body by moving its structure.
     * @param mpv MultipartView object to serialize and then clear.
     * @return Reference to this body.
     *
     * Note: This serializes the content referenced by MultipartView. The string_views
     * in MultipartView must be valid. After serialization, the source mpv is cleared.
     */
    template<>
    Body &Body::operator=<MultipartView>(MultipartView &&mpv) noexcept {
        _data.clear();
        _data << mpv; // Serialize the content
        // Clearing a MultipartView typically means clearing its internal parts vector.
        // The actual data pointed to by string_views is not owned by MultipartView.
        mpv.parts().clear(); // Example: clear the parts. Actual clear might differ based on TMultiPart impl.
        // If TMultiPart for string_view doesn't have a clear() or if clearing parts isn't enough,
        // this might need adjustment based on MultipartView's specific clear semantics.
        // For now, clearing parts is a reasonable assumption for "moved-from" state.
        return *this;
    }
} // namespace qb::http
