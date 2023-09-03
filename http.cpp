/*
 * qb - C++ Actor Framework
 * Copyright (C) 2011-2021 isndev (www.qbaf.io). All rights reserved.
 *
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
 *         limitations under the License.
 */

#include "http.h"
#include "multipart.h"
#if defined(_WIN32)
#    undef DELETE // Windows :/
#endif
#define _XPLATSTR(x) x

#define REGISTER_HTTP_SYNC_FUNCTION(num, name, description) \
    Response name(Request request, double timeout) {        \
        Response response;                                  \
        bool wait = true;                                   \
        name(                                               \
            request,                                        \
            [&response, &wait](async::Reply &&reply) {      \
                response = std::move(reply.response);       \
                wait = false;                               \
            },                                              \
            timeout);                                       \
        qb::io::async::run_until(wait);                     \
        return response;                                    \
    }

namespace qb::http::internal {

template <typename String>
class MultipartReader {
public:
    typedef void (*PartBeginCallback)(THeaders<String> &headers, void *userData);
    typedef void (*PartDataCallback)(const char *buffer, size_t size, void *userData);
    typedef void (*Callback)(void *userData);

private:
    MultipartParser parser;
    bool headersProcessed;
    THeaders<String> currentHeaders;
    String currentHeaderName, currentHeaderValue;

    void
    resetReaderCallbacks() {
        onPartBegin = NULL;
        onPartData = NULL;
        onPartEnd = NULL;
        onEnd = NULL;
        userData = NULL;
    }

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

    static void
    cbPartBegin(const char *buffer, size_t start, size_t end, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        self->headersProcessed = false;
        self->currentHeaders.headers().clear();
        self->currentHeaderName.clear();
        self->currentHeaderValue.clear();
    }

    static void
    cbHeaderField(const char *buffer, size_t start, size_t end, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        self->currentHeaderName = String(buffer + start, end - start);
    }

    static void
    cbHeaderValue(const char *buffer, size_t start, size_t end, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        self->currentHeaderValue = String(buffer + start, end - start);
    }

    static void
    cbHeaderEnd(const char *buffer, size_t start, size_t end, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        self->currentHeaders.headers()[self->currentHeaderName].push_back(self->currentHeaderValue);
        self->currentHeaderName.clear();
        self->currentHeaderValue.clear();
    }

    static void
    cbHeadersEnd(const char *buffer, size_t start, size_t end, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        if (self->onPartBegin != NULL) {
            self->onPartBegin(self->currentHeaders, self->userData);
        }
        self->currentHeaders.headers().clear();
        self->currentHeaderName.clear();
        self->currentHeaderValue.clear();
    }

    static void
    cbPartData(const char *buffer, size_t start, size_t end, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        if (self->onPartData != NULL) {
            self->onPartData(buffer + start, end - start, self->userData);
        }
    }

    static void
    cbPartEnd(const char *buffer, size_t start, size_t end, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        if (self->onPartEnd != NULL) {
            self->onPartEnd(self->userData);
        }
    }

    static void
    cbEnd(const char *buffer, size_t start, size_t end, void *userData) {
        MultipartReader *self = (MultipartReader *)userData;
        if (self->onEnd != NULL) {
            self->onEnd(self->userData);
        }
    }

public:
    PartBeginCallback onPartBegin;
    PartDataCallback onPartData;
    Callback onPartEnd;
    Callback onEnd;
    void *userData;

    MultipartReader() {
        resetReaderCallbacks();
        setParserCallbacks();
    }

    MultipartReader(const std::string &boundary)
        : parser(boundary) {
        resetReaderCallbacks();
        setParserCallbacks();
    }

    void
    reset() {
        parser.reset();
    }

    void
    setBoundary(const std::string &boundary) {
        parser.setBoundary(boundary);
    }

    size_t
    feed(const char *buffer, size_t len) {
        return parser.feed(buffer, len);
    }

    bool
    succeeded() const {
        return parser.succeeded();
    }

    bool
    hasError() const {
        return parser.hasError();
    }

    bool
    stopped() const {
        return parser.stopped();
    }

    const char *
    getErrorMessage() const {
        return parser.getErrorMessage();
    }
};

} // namespace qb::http::internal

namespace qb::http {

[[nodiscard]] std::string
parse_boundary(std::string const &content_type) {
    static const std::regex boundary_regex("^multipart/form-data;\\s{0,}boundary=(.+)$");
    std::smatch what;
    std::string to_find(content_type.data(), content_type.size());
    return std::regex_match(to_find, what, boundary_regex) ? what[1].str() : "";
}

inline bool is_cookie_attribute(const std::string& name, bool set_cookie_header)
{
    return (name.empty() || name[0] == '$' || (set_cookie_header &&
                                               (
                                                   // This is needed because of a very lenient determination in parse_cookie_header() of what
                                                   // qualifies as a cookie-pair in a Set-Cookie header.
                                                   // According to RFC 6265, everything after the first semicolon is a cookie attribute, but RFC 2109,
                                                   // which is obsolete, allowed multiple comma separated cookies.
                                                   // parse_cookie_header() is very conservatively assuming that any <name>=<value> pair in a
                                                   // Set-Cookie header is a cookie-pair unless <name> is a known cookie attribute.
                                                   utility::iequals(name, "Comment")
                                                   || utility::iequals(name, "Domain")
                                                   || utility::iequals(name, "Max-Age")
                                                   || utility::iequals(name, "Path")
                                                   || utility::iequals(name, "Secure")
                                                   || utility::iequals(name, "Version")
                                                   || utility::iequals(name, "Expires")
                                                   || utility::iequals(name, "HttpOnly")
                                                       )
                                                   ));
}

qb::icase_unordered_map<std::string>
parse_cookies(const char *ptr, const size_t len,
              bool set_cookie_header) {
    qb::icase_unordered_map<std::string> dict;
    // BASED ON RFC 2109
    // http://www.ietf.org/rfc/rfc2109.txt
    //
    // The current implementation ignores cookie attributes which begin with '$'
    // (i.e. $Path=/, $Domain=, etc.)

    // used to track what we are parsing
    enum CookieParseState {
        COOKIE_PARSE_NAME, COOKIE_PARSE_VALUE, COOKIE_PARSE_IGNORE
    } parse_state = COOKIE_PARSE_NAME;

    // misc other variables used for parsing
    const char * const end = ptr + len;
    std::string cookie_name;
    std::string cookie_value;
    char value_quote_character = '\0';

    // iterate through each character
    while (ptr < end) {
        switch (parse_state) {

        case COOKIE_PARSE_NAME:
            // parsing cookie name
            if (*ptr == '=') {
                // end of name found (OK if empty)
                value_quote_character = '\0';
                parse_state = COOKIE_PARSE_VALUE;
            } else if (*ptr == ';' || *ptr == ',') {
                // ignore empty cookie names since this may occur naturally
                // when quoted values are encountered
                if (! cookie_name.empty()) {
                    // value is empty (OK)
                    if (! is_cookie_attribute(cookie_name, set_cookie_header))
                        dict.emplace(cookie_name, cookie_value);
                    cookie_name.erase();
                }
            } else if (*ptr != ' ') {   // ignore whitespace
                // check if control character detected, or max sized exceeded
                if (utility::is_control(*ptr) || cookie_name.size() >= COOKIE_NAME_MAX)
                    throw std::runtime_error("ctrl in name found or max cookie name length");
                // character is part of the name
                cookie_name.push_back(*ptr);
            }
            break;

        case COOKIE_PARSE_VALUE:
            // parsing cookie value
            if (value_quote_character == '\0') {
                // value is not (yet) quoted
                if (*ptr == ';' || *ptr == ',') {
                    // end of value found (OK if empty)
                    if (! is_cookie_attribute(cookie_name, set_cookie_header))
                        dict.emplace(cookie_name, cookie_value);
                    cookie_name.erase();
                    cookie_value.erase();
                    parse_state = COOKIE_PARSE_NAME;
                } else if (*ptr == '\'' || *ptr == '"') {
                    if (cookie_value.empty()) {
                        // begin quoted value
                        value_quote_character = *ptr;
                    } else if (cookie_value.size() >= COOKIE_VALUE_MAX) {
                        // max size exceeded
                        throw std::runtime_error("cookie ");
                    } else {
                        // assume character is part of the (unquoted) value
                        cookie_value.push_back(*ptr);
                    }
                } else if (*ptr != ' ' || !cookie_value.empty()) {  // ignore leading unquoted whitespace
                    // check if control character detected, or max sized exceeded
                    if (utility::is_control(*ptr) || cookie_value.size() >= COOKIE_VALUE_MAX)
                        throw std::runtime_error("ctrl in value found or max cookie value length");
                    // character is part of the (unquoted) value
                    cookie_value.push_back(*ptr);
                }
            } else {
                // value is quoted
                if (*ptr == value_quote_character) {
                    // end of value found (OK if empty)
                    if (! is_cookie_attribute(cookie_name, set_cookie_header))
                        dict.emplace(cookie_name, cookie_value);
                    cookie_name.erase();
                    cookie_value.erase();
                    parse_state = COOKIE_PARSE_IGNORE;
                } else if (cookie_value.size() >= COOKIE_VALUE_MAX) {
                    // max size exceeded
                    throw std::runtime_error("max cookie value length");
                } else {
                    // character is part of the (quoted) value
                    cookie_value.push_back(*ptr);
                }
            }
            break;

        case COOKIE_PARSE_IGNORE:
            // ignore everything until we reach a comma "," or semicolon ";"
            if (*ptr == ';' || *ptr == ',')
                parse_state = COOKIE_PARSE_NAME;
            break;
        }

        ++ptr;
    }

    // handle last cookie in string
    if (! is_cookie_attribute(cookie_name, set_cookie_header))
        dict.emplace(cookie_name, cookie_value);

    return dict;
}
qb::icase_unordered_map<std::string>
parse_cookies(std::string const &header, bool set_cookie_header) {
    return parse_cookies(header.c_str(), header.size(), set_cookie_header);
}
qb::icase_unordered_map<std::string>
parse_cookies(std::string_view const &header, bool set_cookie_header) {
    return parse_cookies(header.data(), header.size(), set_cookie_header);
}


qb::icase_unordered_map<std::string>
parse_header_attributes(const char *ptr, const size_t len) {
    qb::icase_unordered_map<std::string> dict;

    enum AttributeParseState {
        ATTRIBUTE_PARSE_NAME, ATTRIBUTE_PARSE_VALUE, ATTRIBUTE_PARSE_IGNORE
    } parse_state = ATTRIBUTE_PARSE_NAME;

    // misc other variables used for parsing
    const char * const end = ptr + len;
    std::string attribute_name;
    std::string attribute_value;
    char value_quote_character = '\0';

    // iterate through each character
    while (ptr < end) {
        switch (parse_state) {

        case ATTRIBUTE_PARSE_NAME:
            // parsing attribute name
            if (*ptr == '=') {
                // end of name found (OK if empty)
                value_quote_character = '\0';
                parse_state = ATTRIBUTE_PARSE_VALUE;
            } else if (*ptr == ';' || *ptr == ',') {
                // ignore empty attribute names since this may occur naturally
                // when quoted values are encountered
                if (! attribute_name.empty()) {
                    // value is empty (OK)
                    dict.emplace(attribute_name, attribute_value);
                    attribute_name.erase();
                }
            } else if (*ptr != ' ') {   // ignore whitespace
                // check if control character detected, or max sized exceeded
                if (utility::is_control(*ptr) || attribute_name.size() >= ATTRIBUTE_NAME_MAX)
                    throw std::runtime_error("ctrl in name found or max attribute name length");
                // character is part of the name
                attribute_name.push_back(*ptr);
            }
            break;

        case ATTRIBUTE_PARSE_VALUE:
            // parsing attribute value
            if (value_quote_character == '\0') {
                // value is not (yet) quoted
                if (*ptr == ';' || *ptr == ',') {
                    // end of value found (OK if empty)
                    dict.emplace(attribute_name, attribute_value);
                    attribute_name.erase();
                    attribute_value.erase();
                    parse_state = ATTRIBUTE_PARSE_NAME;
                } else if (*ptr == '\'' || *ptr == '"') {
                    if (attribute_value.empty()) {
                        // begin quoted value
                        value_quote_character = *ptr;
                    } else if (attribute_value.size() >= ATTRIBUTE_VALUE_MAX) {
                        // max size exceeded
                        throw std::runtime_error("max attribute size");
                    } else {
                        // assume character is part of the (unquoted) value
                        attribute_value.push_back(*ptr);
                    }
                } else if (*ptr != ' ' || !attribute_value.empty()) {  // ignore leading unquoted whitespace
                    // check if control character detected, or max sized exceeded
                    if (utility::is_control(*ptr) || attribute_value.size() >= ATTRIBUTE_VALUE_MAX)
                        throw std::runtime_error("ctrl in value found or max attribute value length");
                    // character is part of the (unquoted) value
                    attribute_value.push_back(*ptr);
                }
            } else {
                // value is quoted
                if (*ptr == value_quote_character) {
                    // end of value found (OK if empty)
                    dict.emplace(attribute_name, attribute_value);
                    attribute_name.erase();
                    attribute_value.erase();
                    parse_state = ATTRIBUTE_PARSE_IGNORE;
                } else if (attribute_value.size() >= ATTRIBUTE_VALUE_MAX) {
                    // max size exceeded
                    throw std::runtime_error("max attribute value length");
                } else {
                    // character is part of the (quoted) value
                    attribute_value.push_back(*ptr);
                }
            }
            break;

        case ATTRIBUTE_PARSE_IGNORE:
            // ignore everything until we reach a comma "," or semicolon ";"
            if (*ptr == ';' || *ptr == ',')
                parse_state = ATTRIBUTE_PARSE_NAME;
            break;
        }

        ++ptr;
    }

    // handle last attribute in string
    dict.emplace(attribute_name, attribute_value);

    return dict;
}
qb::icase_unordered_map<std::string>
parse_header_attributes(std::string const &header) {
    return parse_header_attributes(header.c_str(), header.size());
}
qb::icase_unordered_map<std::string>
parse_header_attributes(std::string_view const &header) {
    return parse_header_attributes(header.data(), header.size());
}

[[nodiscard]] std::string
accept_encoding() {
    std::string algorithms;
#ifdef QB_IO_WITH_ZLIB
    algorithms.reserve(64);
    for (auto factory : qb::compression::builtin::get_decompress_factories()) {
        auto weight = factory->weight();
        algorithms += factory->algorithm();
        if (weight <= 1000) {
            algorithms += ";q=";
            algorithms += std::to_string(weight / 1000);
            algorithms += '.';
            algorithms += std::to_string(weight % 1000);
        }
        algorithms += ", ";
    }
#endif
    algorithms += "chunked";
    return algorithms;
}

[[nodiscard]] std::string
content_encoding(std::string_view const &accept_encoding) {
    auto tokens = utility::split_string(accept_encoding, ",; \t");
    auto factories = qb::compression::builtin::get_compress_factories();
    for (const auto &token : tokens) {
        for (const auto &factory : factories) {
            if (utility::iequals(factory->algorithm(), std::string(token)))
                return factory->algorithm();
        }
    }

    return "";
}

#ifdef QB_IO_WITH_ZLIB
std::unique_ptr<qb::compression::compress_provider>
Body::get_compressor_from_header(const std::string &encoding) {
    auto tokens = utility::split_string(encoding, ",; \t");

    for (const auto &token : tokens) {
        auto c = qb::compression::builtin::make_compressor(token);
        if (c || utility::iequals(token, "identity") || utility::iequals(token, "chunked"))
            return c;
    }

    throw std::runtime_error("Unsupported encoding type");
}

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

    while (!done) {
        std::size_t alloc = (body.size() + 32);
        out.allocate_back(alloc);
        o_processed += compressor->compress(
            reinterpret_cast<uint8_t const *>(body.begin()) + i_processed,
            body.size() - i_processed,
            reinterpret_cast<uint8_t *>(out.begin()) + o_processed,
            out.size() - o_processed,
            qb::compression::is_last,
            i_processed,
            done);
    }
    out.free_back(out.size() - o_processed);
    _data = std::move(out);
    return o_processed;
}

std::unique_ptr<qb::compression::decompress_provider>
Body::get_decompressor_from_header(const std::string &encoding) {
    std::unique_ptr<qb::compression::decompress_provider> decompressor;

    auto tokens = utility::split_string(encoding, ", \t");
    auto i = 1;
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

std::size_t
Body::uncompress(const std::string &encoding) {
    if (!size() || encoding.empty())
        return size();
    auto decompressor = get_decompressor_from_header(encoding);
    auto &body = raw();
    qb::allocator::pipe<char> out;
    std::size_t i_processed{}, o_processed{};
    bool done{};

    while (!done) {
        std::size_t alloc = (body.size() * 2);
        out.allocate_back(alloc);
        o_processed += decompressor->decompress(
            reinterpret_cast<uint8_t const *>(body.begin()) + i_processed,
            body.size() - i_processed,
            reinterpret_cast<uint8_t *>(out.begin()) + o_processed,
            out.size() - o_processed,
            qb::compression::is_last,
            i_processed,
            done);
    }
    out.free_back(out.size() - o_processed);
    _data = std::move(out);
    return o_processed;
}
#endif

template <>
Body &
Body::operator=<std::string>(std::string &&str) noexcept {
    _data.clear();
    _data << str;
    str.clear();
    return *this;
}
template <>
Body &
Body::operator=<std::string_view>(std::string_view &&str) noexcept {
    _data.clear();
    _data << str;
    return *this;
}
template <>
Body &
Body::operator=<std::string>(std::string const &str) {
    _data.clear();
    _data << str;
    return *this;
}
template <>
Body &
Body::operator=<std::vector<char>>(std::vector<char> const &rhs) {
    _data.clear();
    _data << rhs;
    return *this;
}
template <>
Body &
Body::operator=<std::vector<char>>(std::vector<char> &&rhs) noexcept {
    _data.clear();
    _data << rhs;
    rhs.clear();
    return *this;
}

template <>
Body &
Body::operator=<Multipart>(Multipart const &mp) {
    _data.clear();
    _data << mp;
    return *this;
}

template <>
std::string_view
Body::as<std::string_view>() const {
    return _data.view();
}
template <>
std::string
Body::as<std::string>() const {
    return _data.str();
}


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
    reader.onPartEnd = [](void *userData) {};
    reader.onEnd = [](void *userData) {};

    reader.feed(_data.begin(), _data.size());
    if (reader.hasError())
        throw std::runtime_error("failed to parse multipart: " + std::string(reader.getErrorMessage()));

    return mp;
}

HTTP_METHOD_MAP(REGISTER_HTTP_SYNC_FUNCTION)

} // namespace qb::http

namespace qb::allocator {
template <>
pipe<char> &
pipe<char>::put<qb::http::Request>(const qb::http::Request &r) {
    // HTTP Status Line
    *this << ::http_method_name(static_cast<http_method_t>(r.method)) << qb::http::sep << r.uri().full_path() << qb::http::sep
          << "HTTP/" << r.major_version << "." << r.minor_version << qb::http::endl;
    // HTTP Headers
    for (const auto &it : r.headers()) {
        for (const auto &value : it.second)
            *this << it.first << ": " << value << qb::http::endl;
    }
    // Body
    const auto length = r.body().size();
    if (length) {
        *this << "content-length: " << length << qb::http::endl << qb::http::endl;
        *this << r.body().raw();
    } else
        *this << qb::http::endl;
    return *this;
}

template <>
pipe<char> &
pipe<char>::put<qb::http::Response>(const qb::http::Response &r) {
    // HTTP Status Line
    *this << "HTTP/" << r.major_version << "." << r.minor_version << qb::http::sep << r.status_code << qb::http::sep
          << (r.status.empty() ? ::http_status_str(static_cast<http_status>(r.status_code)) : r.status.c_str())
          << qb::http::endl;
    // HTTP Headers
    for (const auto &it : r.headers()) {
        for (const auto &value : it.second)
            *this << it.first << ": " << value << qb::http::endl;
    }
    // Body
    auto length = r.body().size();
    if (length) {
        if (r.has_header("Content-Encoding"))
            length = const_cast<qb::http::Response &>(r).body().compress(r.header("Content-Encoding"));

        *this << "content-length: " << length << qb::http::endl << qb::http::endl << r.body().raw();
    } else
        *this << qb::http::endl;
    return *this;
}

template <>
pipe<char> &
pipe<char>::put<qb::http::Chunk>(const qb::http::Chunk &c) {
    constexpr static const std::size_t hex_len = sizeof(std::size_t) << 1u;
    static const char digits[] = "0123456789ABCDEF";
    if (c.size()) {
        std::string rc(hex_len, '0');
        auto f_pos = 0u;
        for (size_t i = 0u, j = (hex_len - 1u) * 4u; i < hex_len; ++i, j -= 4u) {
            const auto offset = (c.size() >> j) & 0x0fu;
            rc[i] = digits[offset];
            if (!offset)
                ++f_pos;
        }
        std::string_view hex_view(rc.c_str() + f_pos, rc.size() - f_pos);
        *this << hex_view << qb::http::endl;
        put(c.data(), c.size());
    } else {
        *this << '0' << qb::http::endl;
    }

    *this << qb::http::endl;
    return *this;
}

template <>
pipe<char> &
pipe<char>::put<qb::http::Multipart>(const qb::http::Multipart &mp) {
    reserve(mp.content_length());
    for (const auto &part : mp.parts()) {
        *this << "--" << mp.boundary() << qb::http::endl;
        for (const auto &[key, headers] : part.headers()) {
            for (const auto &header : headers)
                *this << key << ": " << header << qb::http::endl;
        }
        *this << qb::http::endl << part.body << qb::http::endl;
    }
    *this << "--" << mp.boundary() << "--";
    return *this;
}

} // namespace qb::allocator

// templates instantiation
// objects
template struct qb::http::TRequest<std::string>;
template struct qb::http::TRequest<std::string_view>;
template struct qb::http::TResponse<std::string>;
template struct qb::http::TResponse<std::string_view>;
template class qb::http::TMultiPart<std::string>;
template class qb::http::TMultiPart<std::string_view>;