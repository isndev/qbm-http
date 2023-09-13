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

#ifndef QB_MODULE_HTTP_H_
#define QB_MODULE_HTTP_H_
#include <qb/io/async.h>
#include <qb/io/async/listener.h>
#include <qb/io/async/tcp/connector.h>
#include <qb/io/transport/file.h>
#include <qb/system/allocator/pipe.h>
#include <qb/system/container/unordered_map.h>
#include <qb/system/timestamp.h>
#ifdef QB_IO_WITH_ZLIB
#    include <qb/io/compression.h>
#endif
#include <regex>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include "not-qb/llhttp/include/llhttp.h"

#if defined(_WIN32)
#    undef DELETE // Windows :/
#endif

namespace qb::http {
using method = http_method;
using status = http_status;
using headers_map = qb::icase_unordered_map<std::vector<std::string>>;
constexpr const char endl[] = "\r\n";
constexpr const char sep = ' ';
constexpr const uint32_t COOKIE_NAME_MAX = 1024;            // 1 KB
constexpr const uint32_t COOKIE_VALUE_MAX = 1024 * 1024;    // 1 MB
constexpr const uint32_t ATTRIBUTE_NAME_MAX = 1024;         // 1 KB
constexpr const uint32_t ATTRIBUTE_VALUE_MAX = 1024 * 1024; // 1 MB

namespace utility {
inline bool
is_char(int c) {
    return (c >= 0 && c <= 127);
}
inline bool
is_control(int c) {
    return ((c >= 0 && c <= 31) || c == 127);
}
inline bool
is_special(int c) {
    switch (c) {
    case '(':
    case ')':
    case '<':
    case '>':
    case '@':
    case ',':
    case ';':
    case ':':
    case '\\':
    case '"':
    case '/':
    case '[':
    case ']':
    case '?':
    case '=':
    case '{':
    case '}':
    case ' ':
    case '\t':
        return true;
    default:
        return false;
    }
}
inline bool
is_digit(int c) {
    return (c >= '0' && c <= '9');
}
inline bool
is_hex_digit(int c) {
    return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
}
inline bool
iequals(const std::string &a, const std::string &b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end(), [](char a, char b) {
        return tolower(a) == tolower(b);
    });
}
inline bool
is_http_whitespace(const char ch) {
    return ch == ' ' || ch == '\t';
}
template <typename String>
std::vector<String>
split_string(String const &str, std::string const &delimiters, std::size_t reserve = 5) {
    std::vector<String> ret;
    std::size_t begin = 0;
    std::size_t end = 0;
    bool flag_delim = true;

    ret.reserve(reserve);
    while (begin != str.size()) {
        if (flag_delim) {
            begin = str.find_first_not_of(delimiters, begin);
            begin = begin == std::string::npos ? str.size() : begin;
            flag_delim = false;
        } else {
            end = str.find_first_of(delimiters, begin);
            end = end == std::string::npos ? str.size() : end;
            ret.push_back({str.data() + begin, end - begin});
            begin = end;
            flag_delim = true;
        }
    }

    return ret;
}
template <typename String>
std::vector<String>
split_string_by(String const &str, std::string const &boundary, std::size_t reserve = 5) {
    std::vector<String> ret;
    auto begin = str.begin();
    auto end = str.end();
    bool flag_delim = true;

    ret.reserve(reserve);
    while (begin != str.end()) {
        if (flag_delim) {
            auto p = std::mismatch(begin, str.end(), boundary.begin(), boundary.end());
            if (static_cast<std::size_t>(p.first - begin) == boundary.size())
                begin = p.first;
            flag_delim = false;
        } else {
            const auto pos = str.find(boundary, begin - str.begin());
            if (pos != std::string::npos)
                end = str.begin() + pos;
            else
                end = str.end();
            ret.push_back({&(*begin), static_cast<std::size_t>(end - begin)});
            begin = end;
            flag_delim = true;
        }
    }

    return ret;
}
} // namespace utility

[[nodiscard]] std::string parse_boundary(std::string const &content_type);
[[nodiscard]] qb::icase_unordered_map<std::string> parse_cookies(const char *ptr, size_t len, bool set_cookie_header);
[[nodiscard]] qb::icase_unordered_map<std::string> parse_cookies(std::string const &header, bool set_cookie_header);
[[nodiscard]] qb::icase_unordered_map<std::string>
parse_cookies(std::string_view const &header, bool set_cookie_header);
[[nodiscard]] qb::icase_unordered_map<std::string> parse_header_attributes(const char *ptr, size_t len);
[[nodiscard]] qb::icase_unordered_map<std::string> parse_header_attributes(std::string const &header);
[[nodiscard]] qb::icase_unordered_map<std::string> parse_header_attributes(std::string_view const &header);
[[nodiscard]] std::string accept_encoding();
[[nodiscard]] std::string content_encoding(std::string_view const &accept_encoding);

template <typename String>
class THeaders {
public:
    constexpr static const char default_content_type[] = "application/octet-stream";
    constexpr static const char default_charset[] = "utf8";
    using headers_map_type = qb::icase_unordered_map<std::vector<String>>;

    class ContentType {
    public:
        static std::pair<String, String>
        parse(String const &content_type) {
            std::pair<String, String> ret{default_content_type, default_charset};

            auto words = utility::split_string<String>(content_type, " \t;=");
            if (!words.size())
                return ret;
            ret.first = std::move(words.front());
            if (words.size() == 3 && words[1] == "charset") {
                auto &charset = words[2];
                ret.second = charset.substr(
                    charset.front() == '"' ? 1 : 0,
                    charset.back() == '"' ? charset.size() - 2 : std::string::npos);
            }
            return ret;
        }

    private:
        std::pair<String, String> type_charset;

    public:
        explicit ContentType(String const &content_type = "")
            : type_charset{parse(content_type)} {}

        ContentType(ContentType const &rhs) = default;
        ContentType(ContentType &&rhs) noexcept = default;

        ContentType &operator=(ContentType const &rhs) = default;
        ContentType &operator=(ContentType &&rhs) noexcept = default;

        [[nodiscard]] String const &
        type() const {
            return type_charset.first;
        }

        [[nodiscard]] String const &
        charset() const {
            return type_charset.second;
        }
    };

protected:
    headers_map_type _headers;
    ContentType _content_type;

public:
    THeaders() = default;
    THeaders(qb::icase_unordered_map<std::vector<String>> headers)
        : _headers(std::move(headers))
        , _content_type(header("Content-Type", 0, default_content_type)) {}
    THeaders(THeaders const &) = default;
    THeaders(THeaders &&) noexcept = default;
    THeaders &operator=(THeaders const &) = default;
    THeaders &operator=(THeaders &&) noexcept = default;

    [[nodiscard]] headers_map_type &
    headers() noexcept {
        return _headers;
    }

    [[nodiscard]] headers_map_type const &
    headers() const noexcept {
        return _headers;
    }

    template <typename T>
    [[nodiscard]] const auto &
    header(T &&name, std::size_t const index = 0, String const &not_found = "") const {
        const auto &it = this->_headers.find(std::forward<T>(name));
        if (it != this->_headers.cend() && index < it->second.size())
            return it->second[index];
        return not_found;
    }

    template <typename T>
    [[nodiscard]] auto
    attributes(T &&name, std::size_t const index = 0, String const &not_found = "") const {
        return parse_header_attributes(header(std::forward<T>(name), index, not_found));
    }

    template <typename T>
    [[nodiscard]] inline bool
    has_header(T &&key) const noexcept {
        return this->_headers.has(std::forward<T>(key));
    }

    void
    set_content_type(String const &value) {
        _content_type = ContentType{value};
    }

    [[nodiscard]] ContentType const &
    content_type() const noexcept {
        return _content_type;
    }
};

using Headers = THeaders<std::string>;
using HeadersView = THeaders<std::string_view>;
using headers = THeaders<std::string>;
using headers_view = THeaders<std::string_view>;

class Body {
    qb::allocator::pipe<char> _data;

public:
    Body() = default;
    Body(Body const &) = default;
    Body(Body &&) noexcept = default;
    Body &operator=(Body &&rhs) noexcept = default;

    template <typename... Args>
    Body(Args &&...args) {
        (_data << ... << std::forward<Args>(args));
    }

    template <typename... Args>
    Body &
    operator<<(Args &&...args) {
        (_data << ... << std::forward<Args>(args));
        return *this;
    }

    template <typename T>
    inline Body &
    operator=(T &rhs) {
        return operator=(static_cast<T const &>(rhs));
    }
    template <typename T>
    Body &operator=(T const &);
    template <typename T>
    Body &operator=(T &&) noexcept;
    template <std::size_t N>
    Body &
    operator=(const char (&str)[N]) noexcept {
        _data.clear();
        _data << str;
        return *this;
    }

#ifdef QB_IO_WITH_ZLIB
    static std::unique_ptr<qb::compression::compress_provider> get_compressor_from_header(const std::string &encoding);
    std::size_t compress(std::string const &encoding);

    static std::unique_ptr<qb::compression::decompress_provider>
    get_decompressor_from_header(const std::string &encoding);
    std::size_t uncompress(const std::string &encoding);
#endif

    [[nodiscard]] inline qb::allocator::pipe<char> const &
    raw() const noexcept {
        return _data;
    }

    [[nodiscard]] inline qb::allocator::pipe<char> &
    raw() noexcept {
        return _data;
    }

    [[nodiscard]] inline auto
    begin() const {
        return _data.begin();
    }

    [[nodiscard]] inline auto
    end() const {
        return _data.end();
    }

    [[nodiscard]] inline std::size_t
    size() const {
        return _data.size();
    }

    [[nodiscard]] inline bool
    empty() const {
        return _data.empty();
    }

    template <typename T>
    [[nodiscard]] T
    as() const {
        static_assert("cannot convert http body to a not implemented type");
        return {};
    }
};
using body = Body;

template <>
Body &Body::operator=<std::string>(std::string &&str) noexcept;
template <>
Body &Body::operator=<std::string_view>(std::string_view &&str) noexcept;
template <>
Body &Body::operator=<std::string>(std::string const &str);
template <>
Body &Body::operator=<std::vector<char>>(std::vector<char> const &str);
template <>
Body &Body::operator=<std::vector<char>>(std::vector<char> &&str) noexcept;

template <>
std::string_view Body::as<std::string_view>() const;
template <>
std::string Body::as<std::string>() const;
template <>
std::string_view Body::as<std::string_view>() const;

template <typename String>
class TMultiPart {
    friend class Body;

public:
    struct Part : public THeaders<String> {
        String body;

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
    std::string _boundary;
    std::vector<Part> _parts;

    [[nodiscard]] static std::string
    generate_boundary() {
        std::mt19937 generator{std::random_device{}()};
        std::uniform_int_distribution<int> distribution{'0', '9'};

        std::string result = "----------------------------qb00000000000000000000000000000000";
        for (auto i = result.begin() + 30; i != result.end(); ++i)
            *i = static_cast<char>(distribution(generator));

        return result;
    }

public:
    TMultiPart()
        : _boundary(generate_boundary()) {}
    explicit TMultiPart(std::string boundary)
        : _boundary(std::move(boundary)) {}

    [[nodiscard]] Part &
    create_part() {
        return _parts.emplace_back();
    }

    [[nodiscard]] std::size_t
    content_length() const {
        std::size_t ret = 0;

        for (const auto &part : _parts)
            ret += _boundary.size() + part.size() + 4;
        ret += _boundary.size() + 4; // end

        return ret;
    }

    [[nodiscard]] std::string const &
    boundary() const {
        return _boundary;
    }
    [[nodiscard]] std::vector<Part> const &
    parts() const {
        return _parts;
    }

    [[nodiscard]] std::vector<Part> &
    parts() {
        return _parts;
    }
};
using Multipart = TMultiPart<std::string>;
using multipart = TMultiPart<std::string>;
using MultipartView = TMultiPart<std::string_view>;
using multipart_view = TMultiPart<std::string_view>;

template <>
Body &Body::operator=<Multipart>(Multipart const &mp);
template <>
Multipart Body::as<Multipart>() const;

namespace internal {

template <typename String>
struct MessageBase
    : public THeaders<String>
    , Body {
    using string_type = String;

    uint16_t major_version;
    uint16_t minor_version;

    bool upgrade{};

    MessageBase() noexcept
        : major_version(1)
        , minor_version(1) {
        reset();
    }

    MessageBase(MessageBase const &) = default;
    MessageBase(qb::icase_unordered_map<std::vector<String>> headers, Body body)
        : THeaders<String>(std::move(headers))
        , Body(std::move(body))
        , major_version(1)
        , minor_version(1) {}
    MessageBase(MessageBase &&) noexcept = default;
    MessageBase &operator=(MessageBase const &) = default;
    MessageBase &operator=(MessageBase &&) noexcept = default;

    void
    reset() {
        this->_headers.clear();
    };

public:
    [[nodiscard]] inline Body &
    body() {
        return static_cast<Body &>(*this);
    }

    [[nodiscard]] inline Body const &
    body() const {
        return static_cast<Body const &>(*this);
    }
};

} // namespace internal

template <typename MessageType>
struct Parser : public llhttp_t {
    using String = typename MessageType::string_type;

    static int
    on_message_begin(llhttp_t *) {
        return 0;
    }

    static int
    on_url(llhttp_t *parser, const char *at, size_t length) {
        if constexpr (MessageType::type == HTTP_REQUEST) {
            static const std::regex query_regex("(\\?|&)([^=]*)=([^&]*)");
            auto &msg = static_cast<Parser *>(parser->data)->msg;
            msg.method = static_cast<http_method>(parser->method);
            msg._uri = std::string{at, length};
            //            msg.url = String(at, length);
            //            auto has_query = msg.url.find('?');
            //            if (has_query != std::string::npos) {
            //                msg.path = String(at, has_query);
            //
            //                const char *search = at + has_query;
            //                std::cmatch what;
            //                while (std::regex_search(search, at + length, what, query_regex)) {
            //                    msg._queries[String(what[2].first,
            //                    static_cast<std::size_t>(what[2].length()))].push_back(
            //                        io::uri::decode(what[3].first, static_cast<std::size_t>(what[3].length())));
            //                    search += what[0].length();
            //                }
            //            } else
            //                msg.path = msg.url;
        } else {
	  (void)at;
	  (void)length;
	}
        return 0;
    }

    static int
    on_status(llhttp_t *parser, const char *at, size_t length) {
        if constexpr (MessageType::type == HTTP_RESPONSE) {
            auto &msg = static_cast<Parser *>(parser->data)->msg;
            msg.status_code = static_cast<http_status>(parser->status_code);
            msg.status = String(at, length);
        }
        return 0;
    }

    static int
    on_header_field(llhttp_t *parser, const char *at, size_t length) {
        static_cast<Parser *>(parser->data)->_last_header_key = String(at, length);
        return 0;
    }

    static int
    on_header_value(llhttp_t *parser, const char *at, size_t length) {
        auto &msg = static_cast<Parser *>(parser->data)->msg;
        msg.headers()[String{static_cast<Parser *>(parser->data)->_last_header_key}].push_back(String(at, length));
        return 0;
    }

    static int
    on_headers_complete(llhttp_t *parser) {
        auto &msg = static_cast<Parser *>(parser->data)->msg;
        msg.major_version = parser->http_major;
        msg.minor_version = parser->http_major;
        if (parser->content_length != ULLONG_MAX) {
            msg.body().raw().reserve(parser->content_length);
        }
        msg.upgrade = static_cast<bool>(parser->upgrade);
        static_cast<Parser *>(parser->data)->_headers_completed = true;
        return HPE_PAUSED;
    }

    static int
    on_body(llhttp_t *parser, const char *at, size_t length) {
        auto &chunked = static_cast<Parser *>(parser->data)->_chunked;
        std::copy_n(at, length, chunked.allocate_back(length));
        return 0;
    }

    static int
    on_message_complete(llhttp_t *parser) {
        auto p = static_cast<Parser *>(parser->data);
        p->msg.set_content_type(p->msg.header("Content-Type"));
        p->msg.body().raw() = std::move(p->_chunked);
        return 1;
    }

    /* When on_chunk_header is called, the current chunk length is stored
     * in parser->content_length.
     */
    static int
    on_chunk_header(llhttp_t *) {
        return 0;
    }

    static int
    on_chunk_complete(llhttp_t *) {
        return 0;
    }

protected:
    MessageType msg;

private:
    static const llhttp_settings_s inline settings{
        &Parser::on_message_begin,
        &Parser::on_url,
        &Parser::on_status,
        &Parser::on_header_field,
        &Parser::on_header_value,
        &Parser::on_headers_complete,
        &Parser::on_body,
        &Parser::on_message_complete,
        &Parser::on_chunk_header,
        &Parser::on_chunk_complete};
    String _last_header_key;
    bool _headers_completed = false;
    qb::allocator::pipe<char> _chunked;

public:
    Parser() noexcept
        : llhttp__internal_s() {
        reset();
    };

    llhttp_errno_t
    parse(const char *buffer, std::size_t const size) {
        return llhttp_execute(static_cast<llhttp_t *>(this), buffer, size);
    }

    void
    reset() noexcept {
        llhttp_init(static_cast<llhttp_t *>(this), MessageType::type, &settings);
        this->data = this;
        msg.reset();
        _headers_completed = false;
        _chunked.clear();
    }

    void
    resume() noexcept {
        llhttp_resume(static_cast<llhttp_t *>(this));
    }

    [[nodiscard]] MessageType &
    get_parsed_message() noexcept {
        return msg;
    }

    [[nodiscard]] bool
    headers_completed() const noexcept {
        return _headers_completed;
    }
};

/// Date class working with formats specified in RFC 7231 Date/Time Formats
class Date {
public:
    /// Returns the given std::chrono::system_clock::time_point as a string with the
    /// following format: Wed, 31 Jul 2019 11:34:23 GMT.
    static std::string
    to_string(qb::Timestamp const ts) noexcept {
        std::string result;
        result.reserve(29);

        const auto time = static_cast<int64_t>(ts.seconds());
        tm tm{};
#if defined(_MSC_VER) || defined(__MINGW32__)
        if (gmtime_s(&tm, &time) != 0)
            return {};
        auto gmtime = &tm;
#else
        const auto crt_time = static_cast<time_t>(time);
        const auto gmtime = gmtime_r(&crt_time, &tm);
        if (!gmtime)
            return {};
#endif

        switch (gmtime->tm_wday) {
        case 0:
            result += "Sun, ";
            break;
        case 1:
            result += "Mon, ";
            break;
        case 2:
            result += "Tue, ";
            break;
        case 3:
            result += "Wed, ";
            break;
        case 4:
            result += "Thu, ";
            break;
        case 5:
            result += "Fri, ";
            break;
        case 6:
            result += "Sat, ";
            break;
        }

        result += gmtime->tm_mday < 10 ? '0' : static_cast<char>(gmtime->tm_mday / 10 + 48);
        result += static_cast<char>(gmtime->tm_mday % 10 + 48);

        switch (gmtime->tm_mon) {
        case 0:
            result += " Jan ";
            break;
        case 1:
            result += " Feb ";
            break;
        case 2:
            result += " Mar ";
            break;
        case 3:
            result += " Apr ";
            break;
        case 4:
            result += " May ";
            break;
        case 5:
            result += " Jun ";
            break;
        case 6:
            result += " Jul ";
            break;
        case 7:
            result += " Aug ";
            break;
        case 8:
            result += " Sep ";
            break;
        case 9:
            result += " Oct ";
            break;
        case 10:
            result += " Nov ";
            break;
        case 11:
            result += " Dec ";
            break;
        }

        const auto year = gmtime->tm_year + 1900;
        result += static_cast<char>(year / 1000 + 48);
        result += static_cast<char>((year / 100) % 10 + 48);
        result += static_cast<char>((year / 10) % 10 + 48);
        result += static_cast<char>(year % 10 + 48);
        result += ' ';

        result += gmtime->tm_hour < 10 ? '0' : static_cast<char>(gmtime->tm_hour / 10 + 48);
        result += static_cast<char>(gmtime->tm_hour % 10 + 48);
        result += ':';

        result += gmtime->tm_min < 10 ? '0' : static_cast<char>(gmtime->tm_min / 10 + 48);
        result += static_cast<char>(gmtime->tm_min % 10 + 48);
        result += ':';

        result += gmtime->tm_sec < 10 ? '0' : static_cast<char>(gmtime->tm_sec / 10 + 48);
        result += static_cast<char>(gmtime->tm_sec % 10 + 48);

        result += " GMT";

        return result;
    }
};
using date = Date;

template <typename String = std::string>
struct TResponse : public internal::MessageBase<String> {
    constexpr static const llhttp_type_t type = HTTP_RESPONSE;
    http_status status_code;
    String status;

    TResponse() noexcept
        : status_code(HTTP_STATUS_OK) {}

    void
    reset() {
        status_code = HTTP_STATUS_OK;
        status = {};
        static_cast<internal::MessageBase<String> &>(*this).reset();
    }

    template <typename Session>
    class Router {
    public:
        struct Context {
            Session &session;
            TResponse &response;

            const auto &
            header(String const &name, String const &not_found = "") const {
                return response.header(name, not_found);
            }
        };

    private:
        class IRoute {
        public:
            virtual ~IRoute() = default;
            virtual void process(Context &ctx) = 0;
        };

        template <typename Func>
        class TRoute : public IRoute {
            Func _func;

        public:
            TRoute(TRoute const &) = delete;
            explicit TRoute(Func &&func)
                : _func(func) {}

            virtual ~TRoute() = default;

            void
            process(Context &ctx) final {
                _func(ctx);
            }
        };

        qb::unordered_map<int, IRoute *> _routes;

    public:
        Router() = default;
        ~Router() noexcept {
            for (auto const &it : _routes)
                delete it.second;
        }

        bool
        route(Session &session, TResponse &response) const {
            const auto &it = _routes.find(response.status_code);
            if (it != _routes.end()) {
                Context ctx{session, response};
                it->second->process(ctx);
                return true;
            }
            return false;
        }

#define REGISTER_ROUTE_FUNCTION(num, name, description)                                               \
    template <typename _Func>                                                                         \
    Router &name(_Func &&func) {                                                                      \
        _routes.emplace(static_cast<http_status>(num), new TRoute<_Func>(std::forward<_Func>(func))); \
        return *this;                                                                                 \
    }

        HTTP_STATUS_MAP(REGISTER_ROUTE_FUNCTION)

#undef REGISTER_ROUTE_FUNCTION
    };

    template <typename session>
    using router = Router<session>;
};

using Response = TResponse<std::string>;
using response = TResponse<std::string>;
using ResponseView = TResponse<std::string_view>;
using response_view = TResponse<std::string_view>;

namespace route {
#define REGISTER_ROUTE_FUNCTION(num, name, description) \
    template <typename _Func>                           \
    struct name {                                       \
        std::string _path;                              \
        mutable _Func _func;                            \
        const int _num = num;                           \
        name(std::string path, _Func &&func)            \
            : _path(std::move(path))                    \
            , _func(std::move(func)) {}                 \
    };

HTTP_METHOD_MAP(REGISTER_ROUTE_FUNCTION)

#undef REGISTER_ROUTE_FUNCTION
} // namespace route

// class Queries : public qb::icase_unordered_map<std::vector<std::string>> {
// public:
//     Queries() = default;
//
//     template <typename T>
//     [[nodiscard]] std::string const &
//     query(T &&name, std::size_t const index = 0, std::string const &not_found = "") const {
//         const auto &it = find(std::forward<T>(name));
//         if (it != cend() && index < it->second.size())
//             return it->second[index];
//
//         return not_found;
//     }
// };
// using queries = Queries;

class PathParameters : public qb::unordered_map<std::string, std::string> {
public:
    PathParameters() = default;

    [[nodiscard]] std::string const &
    param(std::string const &name, std::string const &not_found = "") const {
        const auto &it = find(name);
        return it != cend() ? it->second : not_found;
    }
};
using path_parameters = PathParameters;

template <typename String = std::string>
struct TRequest : public internal::MessageBase<String> {
    constexpr static const llhttp_type_t type = HTTP_REQUEST;
    http_method method;
    qb::io::uri _uri;

public:
    TRequest() noexcept
        : method(HTTP_GET) {}
    TRequest(
        http::method method, qb::io::uri url, qb::icase_unordered_map<std::vector<String>> headers = {}, Body body = {})
        : internal::MessageBase<String>(std::move(headers), std::move(body))
        , method(method)
        , _uri{std::move(url)} {}
    TRequest(qb::io::uri url, qb::icase_unordered_map<std::vector<String>> headers = {}, Body body = {})
        : internal::MessageBase<String>(std::move(headers), std::move(body))
        , method(HTTP_GET)
        , _uri{std::move(url)} {}
    TRequest(TRequest const &) = default;
    TRequest(TRequest &&) noexcept = default;
    TRequest &operator=(TRequest const &) = default;
    TRequest &operator=(TRequest &&) noexcept = default;

    qb::io::uri const &
    uri() const {
        return _uri;
    }

    qb::io::uri &
    uri() {
        return _uri;
    }

    template <typename T>
    [[nodiscard]] std::string const &
    query(T &&name, std::size_t const index = 0, std::string const &not_found = "") const {
        return _uri.query<T>(std::forward<T>(name), index, not_found);
    }

    auto &
    queries() {
        return _uri.queries();
    }
    [[nodiscard]] auto const &
    queries() const {
        return _uri.queries();
    }

    void
    reset() {
        method = HTTP_GET;
        _uri = qb::io::uri{};
        static_cast<internal::MessageBase<String> &>(*this).reset();
    }

    template <typename Session>
    class Router {

    public:
        struct Context {
            String match;
            Session &session;
            TRequest &request;
            PathParameters parameters;
            Response &response;

            template <typename T>
            [[nodiscard]] std::string const &
            header(T &&name, std::size_t const index = 0, std::string const &not_found = "") const {
                return request.header(std::forward<T>(name), index, not_found);
            }

            [[nodiscard]] std::string
            auth(std::string const &auth_type, std::size_t const index = 0, std::string const &not_found = "") const {
                const auto h_value = request.header("Authorization", index, not_found);
                if (h_value.size() > auth_type.size() &&
                    std::equal(auth_type.begin(), auth_type.end(), h_value.begin(), [](auto c1, auto c2) {
                        return tolower(c1) == tolower(c2);
                    })) {
                    auto begin = h_value.begin() + auth_type.size();
                    while (begin != h_value.end() && std::isblank(*begin))
                        ++begin;
                    return h_value.substr(begin - h_value.begin());
                }
                return not_found;
            }

            [[nodiscard]] std::string const &
            param(std::string const &name, std::string const &not_found = "") const {
                return parameters.param(name, not_found);
            }

            template <typename T>
            [[nodiscard]] std::string const &
            query(T &&name, std::size_t const index = 0, std::string const &not_found = "") const {
                return request.query(std::forward<T>(name), index, not_found);
            }
        };

    private:
        class IRoute {
        public:
            virtual ~IRoute() = default;
            virtual void process(Context &ctx) = 0;
        };

        class ARoute : public IRoute {
        public:
            using ParameterNames = std::vector<std::string>;

        private:
            const std::string _path;
            ParameterNames _param_names;
            PathParameters _parameters;
            const std::regex _regex;

            std::string
            init(std::string const &request_path) {
                std::string build_regex = request_path, search = request_path;
                const std::regex pieces_regex(R"(/:((\w+)(\(.+\))?))");
                std::smatch what;
                while (std::regex_search(search, what, pieces_regex)) {
                    _param_names.push_back(what[2]);
                    _parameters.emplace(*_param_names.rbegin(), "");
                    const auto user_regex = "/" + (what[3].length() ? what[3].str() : "(.+)");
                    build_regex = build_regex.replace(
                        build_regex.find(what[0]),
                        what[0].length(),
                        what[2] == "controller" ? "(/?.*)" : user_regex);
                    search = what.suffix();
                }

                return build_regex;
            }

        public:
            explicit ARoute(std::string const &path)
                : _path(path)
                , _regex(init(path)) {}

            virtual ~ARoute() = default;

            template <typename Path>
            bool
            match(Path const &request_path) {
                std::match_results<typename Path::const_iterator> what;
                auto ret = std::regex_match(request_path.cbegin(), request_path.cend(), what, _regex);
                if (ret) {
                    for (size_t i = 1; i < what.size(); ++i) {
                        _parameters[_param_names[i - 1]] = std::move(io::uri::decode(what[i].str()));
                    }
                }
                return ret;
            }

            [[nodiscard]] std::string const &
            path() const {
                return _path;
            }

            [[nodiscard]] PathParameters &
            parameters() {
                return _parameters;
            }

            virtual void process(Context &ctx) = 0;
        };

        template <typename Func>
        class TRoute : public ARoute {
            Func _func;

        public:
            TRoute(TRoute const &) = delete;
            TRoute(std::string const &path, Func &&func)
                : ARoute(path)
                , _func(func) {}

            virtual ~TRoute() = default;

            void
            process(Context &ctx) final {
                for (auto &p : this->parameters())
                    ctx.parameters.template insert_or_assign(p.first, std::move(p.second));
                _func(ctx);
            }
        };

        using Routes = std::vector<ARoute *>;
        qb::unordered_map<int, Routes> _routes;
        Response _default_response;

    public:
        class Route {
            ARoute *route;

        public:
            Route() = delete;
            template <typename Func>
            Route(std::string const &path, Func &&func)
                : route(new TRoute<Func>(path, std::forward<Func>(func))) {}

            ARoute *
            get() {
                return route;
            }
        };

        Router() = default;
        ~Router() noexcept {
            for (auto const &it : _routes) {
                for (auto route : it.second)
                    delete route;
            }
        }

        class Controller : public Route {
            Router _router;

        public:
            explicit Controller(std::string const &path)
                : Route(path + "/:controller", [this](auto &ctx) {
                    ctx.match = ctx.param("controller");
                    if (!_router.route(ctx)) {
                        ctx.response.status_code = HTTP_STATUS_NOT_FOUND;
                        ctx.session << ctx.response;
                    }
                }) {}

            Router &
            router() {
                return _router;
            }
        };
        friend class Controler;

        Router &
        set_default_response(Response &&res) {
            _default_response = std::forward<Response>(res);
            return *this;
        }

        [[nodiscard]] Response const &
        default_response() const {
            return _default_response;
        }

        [[nodiscard]] Response &
        default_response() {
            return _default_response;
        }

        qb::unordered_map<int, Routes> const &
        routes() const {
            return _routes;
        }

        bool
        route(Session &session, TRequest &request) const {
            Context ctx{
                {request.uri().path().data(), request.uri().path().size()},
                session,
                request,
                {},
                session.response()};
            return route(ctx);
        }

        bool
        route(Context &ctx) const {
            const auto &it = _routes.find(ctx.request.method);
            if (it != _routes.end()) {
                for (const auto route : it->second) {
                    if (route->match(ctx.match)) {
                        route->process(ctx);
                        return true;
                    }
                }
            }
            return false;
        }

#define REGISTER_ROUTE_FUNCTION(num, name, description)                                           \
    template <typename _Func>                                                                     \
    Router &name(std::string const &path, _Func &&func) {                                         \
        _routes[num].push_back(new TRoute<_Func>(path, std::forward<_Func>(func)));               \
        return *this;                                                                             \
    }                                                                                             \
    template <typename T, typename... Args>                                                       \
    Router &name(Args &&...args) {                                                                \
        static_assert(std::is_base_of_v<Route, T>, "Router registering Route not base of Route"); \
        auto route = new T{std::forward<Args>(args)...};                                          \
        _routes[num].push_back(route->get());                                                     \
        return *this;                                                                             \
    }                                                                                             \
    template <typename _Func>                                                                     \
    Router &name(std::vector<std::string> const &paths, _Func &&func) {                           \
        for (const auto &path : paths)                                                            \
            name(path, std::forward<_Func>(func));                                                \
        return *this;                                                                             \
    }

        template <typename T, typename... Args>
        Router &
        controller(Args &&...args) {
            static_assert(std::is_base_of_v<Controller, T>, "Router registering Route not base of Route");
            auto ctr = new T(std::forward<Args>(args)...);
            qb::unordered_set<int> methods;
            for (auto [key, route] : ctr->router().routes()) {
                if (methods.emplace(key).second)
                    _routes[key].push_back(ctr->get());
            }
            return *this;
        }

        HTTP_METHOD_MAP(REGISTER_ROUTE_FUNCTION)

#undef REGISTER_ROUTE_FUNCTION

        template <typename T>
        Router &
        operator|(T &&r) {
            using Func = decltype(r._func);
            _routes[r._num].push_back(new TRoute<Func>(std::move(r._path), std::move(r._func)));
            return *this;
        }
    };
};

using Request = TRequest<std::string>;
using request = TRequest<std::string>;
using RequestView = TRequest<std::string_view>;
using request_view = TRequest<std::string_view>;

class Chunk {
    const char *_data;
    std::size_t _size;

public:
    Chunk()
        : _data(nullptr)
        , _size(0) {}
    Chunk(const char *data, std::size_t size)
        : _data(data)
        , _size(size) {}
    [[nodiscard]] const char *
    data() const {
        return _data;
    }
    [[nodiscard]] std::size_t
    size() const {
        return _size;
    }
};
using chunk = Chunk;

} // namespace qb::http

namespace qb::protocol {
namespace http_internal {

template <typename IO_Handler, typename Trait>
class base : public qb::io::async::AProtocol<IO_Handler> {
    using String = typename qb::http::Parser<std::remove_const_t<Trait>>::String;
    std::size_t body_offset = 0;

protected:
    qb::http::Parser<std::remove_const_t<Trait>> _http_obj;

public:
    using Router = typename Trait::template Router<IO_Handler>;
    typedef String string_type;

    base() = delete;
    explicit base(IO_Handler &io) noexcept
        : qb::io::async::AProtocol<IO_Handler>(io) {}

    std::size_t
    getMessageSize() noexcept final {
        if (!_http_obj.headers_completed()) {
            // parse headers
            const auto ret = _http_obj.parse(this->_io.in().begin(), this->_io.in().size());
            if (ret == HPE_OK) {
                // restart parsing for next time;
                _http_obj.reset();
                return 0;
            }

            if (!_http_obj.headers_completed()) {
                this->not_ok();
                return 0;
            }

            body_offset = _http_obj.error_pos - this->_io.in().begin();
        }

        auto &msg = _http_obj.get_parsed_message();

        if (msg.has_header("Transfer-Encoding")) {
            _http_obj.resume();
            const auto ret = _http_obj.parse(this->_io.in().begin() + body_offset, this->_io.in().size() - body_offset);

            if (ret == HPE_CB_MESSAGE_COMPLETE) {
                body_offset = 0;
                return _http_obj.error_pos - this->_io.in().begin();
            } else if (ret == HPE_OK) {
                if constexpr (std::is_same_v<std::string_view, String>) {
                    _http_obj.reset();
                    body_offset = 0;
                } else
                    body_offset = this->_io.in().size();
            } else
                this->not_ok();
            return 0;
        }

        const auto full_size = body_offset + _http_obj.content_length;
        if (this->_io.in().size() < full_size) {
            // if is protocol view reset parser for next read
            if constexpr (std::is_same_v<std::string_view, String>) {
                _http_obj.reset();
                body_offset = 0;
            }
            return 0; // incomplete body
        }

        if (_http_obj.content_length)
            _http_obj.get_parsed_message().body() =
                std::string_view(this->_io.in().cbegin() + body_offset, _http_obj.content_length);

        body_offset = 0;

        return full_size;
    }

    void
    reset() noexcept final {
        body_offset = 0;
        _http_obj.reset();
    }
};

} // namespace http_internal

template <typename IO_Handler>
class http_server : public http_internal::base<IO_Handler, qb::http::Request> {
    using base_t = http_internal::base<IO_Handler, qb::http::Request>;

public:
    http_server() = delete;
    explicit http_server(IO_Handler &io) noexcept
        : base_t(io) {}

    struct request {
        const std::size_t size{};
        const char *data{};
        qb::http::Request http;
    };

    void
    onMessage(std::size_t size) noexcept final {
        this->_io.on(request{size, this->_io.in().begin(), std::move(this->_http_obj.get_parsed_message())});
        this->_http_obj.reset();
    }
};

template <typename IO_Handler>
class http_server_view : public http_internal::base<IO_Handler, qb::http::RequestView> {
    using base_t = http_internal::base<IO_Handler, qb::http::RequestView>;

public:
    http_server_view() = delete;
    explicit http_server_view(IO_Handler &io) noexcept
        : base_t(io) {}

    struct request {
        const std::size_t size{};
        const char *data{};
        qb::http::RequestView http;
    };

    void
    onMessage(std::size_t size) noexcept final {
        this->_io.on(request{size, this->_io.in().begin(), std::move(this->_http_obj.get_parsed_message())});
        this->_http_obj.reset();
    }
};

template <typename IO_Handler>
class http_client : public http_internal::base<IO_Handler, qb::http::Response> {
    using base_t = http_internal::base<IO_Handler, qb::http::Response>;

public:
    http_client() = delete;
    explicit http_client(IO_Handler &io) noexcept
        : base_t(io) {}

    struct response {
        const std::size_t size{};
        const char *data{};
        qb::http::Response http;
    };

    void
    onMessage(std::size_t size) noexcept final {
        this->_io.on(response{size, this->_io.in().begin(), std::move(this->_http_obj.get_parsed_message())});
        this->_http_obj.reset();
    }
};

template <typename IO_Handler>
class http_client_view : public http_internal::base<IO_Handler, qb::http::ResponseView> {
    using base_t = http_internal::base<IO_Handler, qb::http::ResponseView>;

public:
    http_client_view() = delete;
    explicit http_client_view(IO_Handler &io) noexcept
        : base_t(io) {}

    struct response {
        const std::size_t size{};
        const char *data{};
        qb::http::ResponseView http;
    };

    void
    onMessage(std::size_t size) noexcept final {
        this->_io.on(response{size, this->_io.in().begin(), std::move(this->_http_obj.get_parsed_message())});
        this->_http_obj.reset();
    }
};

} // namespace qb::protocol

namespace qb::http {

namespace internal {

template <typename IO_Handler, bool has_server = IO_Handler::has_server>
struct side {
    using protocol = qb::protocol::http_server<IO_Handler>;
    using protocol_view = qb::protocol::http_server_view<IO_Handler>;
};

template <typename IO_Handler>
struct side<IO_Handler, false> {
    using protocol = qb::protocol::http_client<IO_Handler>;
    using protocol_view = qb::protocol::http_client_view<IO_Handler>;
};

} // namespace internal

template <typename IO_Handler>
using protocol = typename internal::side<IO_Handler>::protocol;

template <typename IO_Handler>
using protocol_view = typename internal::side<IO_Handler>::protocol_view;

namespace async {

struct Reply {
    Request request;
    Response response;
};

template <typename Func, typename Transport>
class session : public io::async::tcp::client<session<Func, Transport>, Transport> {
    Func _func;
    Request _request;

public:
    using http_protocol = http::protocol<session<Func, Transport>>;

    session(Func &&func, Request &request)
        : _func(std::forward<Func>(func))
        , _request(std::move([](auto &req) -> auto & {
            if (!req.has_header("User-Agent"))
                req.headers()["User-Agent"] = {"qb/1.0.0"};
            req.headers()["Accept-Encoding"] = {accept_encoding()};
            return req;
        }(request))) {
        this->template switch_protocol<http_protocol>(*this);
    }
    ~session() = default;

    void
    connect(qb::io::uri const &remote, double timeout = 0) {
        qb::io::async::tcp::connect<typename Transport::transport_io_type>(
            remote,
            [this](auto &&transport) {
                if (!transport.is_open()) {
                    Response response;
                    response.status_code = HTTP_STATUS_SERVICE_UNAVAILABLE;

                    _func(Reply{std::move(_request), std::move(response)});
                    delete this;
                } else {
                    this->transport() = std::forward<decltype(transport)>(transport);
                    this->start();

                    *this << _request;
                }
            },
            timeout);
    }

    void
    on(typename http_protocol::response event) {
        auto &response = event.http;
#ifdef QB_IO_WITH_ZLIB
        try {
            if (response.has_header("Content-Encoding")) {
                response.body().uncompress(response.header("Content-Encoding"));
            }
        } catch (std::exception &e) {
            LOG_WARN("[http] failed to decompress: " << e.what());
            response.status_code = HTTP_STATUS_BAD_REQUEST;
        }
#endif
        _func(Reply{std::move(_request), std::move(event.http)});
        this->disconnect(1);
    }

    void
    on(qb::io::async::event::disconnected const &event) {
        if (!event.reason) {
            Response response;
            response.status_code = HTTP_STATUS_GONE;

            _func(Reply{std::move(_request), std::move(response)});
        }
    }

    void
    on(qb::io::async::event::dispose const &) {
        delete this;
    }
};

template <typename Func>
using HTTP = session<Func, qb::io::transport::tcp>;

#ifdef QB_IO_WITH_SSL
template <typename Func>
using HTTPS = session<Func, qb::io::transport::stcp>;

} // namespace async

#    define EXEC_REQUEST()                                                                                  \
        if (request.uri().scheme() == "https")                                                              \
            (new async::HTTPS<_Func>(std::forward<_Func>(func), request))->connect(request.uri(), timeout); \
        else                                                                                                \
            (new async::HTTP<_Func>(std::forward<_Func>(func), request))->connect(request.uri(), timeout);

#else
#    define EXEC_REQUEST() (new HTTP<_Func>(std::forward<_Func>(func), request))->connect(remote, timeout);
#endif

#define REGISTER_HTTP_ASYNC_FUNCTION(num, name, description)                  \
    template <typename _Func>                                                 \
    std::enable_if_t<std::is_invocable_v<_Func, async::Reply &&>, void> name( \
        Request request,                                                      \
        _Func &&func,                                                         \
        double timeout = 0.) {                                                \
                                                                              \
        if constexpr ((num) >= 0)                                             \
            request.method = static_cast<http_method>(num);                   \
                                                                              \
        request.headers()["host"].emplace_back(request.uri().host());         \
        EXEC_REQUEST()                                                        \
    }

#define REGISTER_HTTP_SYNC_FUNCTION_P(num, name, description) Response name(Request request, double timeout = 3.);

REGISTER_HTTP_ASYNC_FUNCTION(-1, REQUEST, USER_DEFINED)

HTTP_METHOD_MAP(REGISTER_HTTP_ASYNC_FUNCTION)

REGISTER_HTTP_SYNC_FUNCTION_P(-1, REQUEST, USER_DEFINED)

HTTP_METHOD_MAP(REGISTER_HTTP_SYNC_FUNCTION_P)

#undef REGISTER_HTTP_ASYNC_FUNCTION
#undef REGISTER_HTTP_SYNC_FUNCTION_P
#undef EXEC_REQUEST

} // namespace qb::http

namespace qb::allocator {

template <>
pipe<char> &pipe<char>::put<qb::http::Request>(const qb::http::Request &r);

template <>
pipe<char> &pipe<char>::put<qb::http::Response>(const qb::http::Response &r);

template <>
pipe<char> &pipe<char>::put<qb::http::Chunk>(const qb::http::Chunk &c);

template <>
pipe<char> &pipe<char>::put<qb::http::Multipart>(const qb::http::Multipart &f);

} // namespace qb::allocator

namespace qb::http {
enum DisconnectedReason : int {
    ByUser = 0,
    ByTimeout,
    ResponseTransmitted,
    ServerError,
    Undefined // should never happen
};

namespace event {
using eos = qb::io::async::event::eos;
using disconnected = qb::io::async::event::disconnected;
struct request {};
struct timeout {};
} // namespace event

namespace internal {
template <typename Derived, typename Transport, template <typename T> typename TProtocol, typename Handler>
class session
    : public qb::io::async::tcp::client<session<Derived, Transport, TProtocol, Handler>, Transport, Handler>
    , public qb::io::use<session<Derived, Transport, TProtocol, Handler>>::timeout {
public:
    using Protocol = TProtocol<session<Derived, Transport, TProtocol, Handler>>;
    using string_type = typename Protocol::string_type;

private:
    friend qb::io::async::io<session>;
    friend class has_method_on<session, void, qb::io::async::event::pending_write>;
    friend class has_method_on<session, void, qb::io::async::event::eos>;
    friend class has_method_on<session, void, qb::io::async::event::disconnected>;
    friend Protocol;
    friend qb::io::async::with_timeout<session>;

    std::string _host;
    qb::http::TRequest<string_type> _request;
    qb::http::Response _response;

    // client is receiving a new message
    void
    on(typename Protocol::request &&msg) {
        // get real host if in proxy
        _host = msg.http.header("x-real-ip", 0, this->transport().peer_endpoint().ip());
        _request = std::move(msg.http);
        // has compression ?
        auto ce = qb::http::content_encoding(_request.header("Accept-Encoding", 0, "identity"));
        if (!ce.empty())
            _response.headers()["Content-Encoding"] = {std::move(ce)};

        // handle your message here
        LOG_DEBUG(
            "HttpSession(" << this->id() << ") " << _host << " request " << http_method_name(_request.method) << " "
                           << _request.uri().path());
        if constexpr (has_method_on<Derived, void, event::request>::value) {
            static_cast<Derived &>(*this).on(event::request{});
        }
        // reset session time out
        this->updateTimeout();
        try {
            if (!this->server().router().route(*this, _request)) {
                _response.status_code = HTTP_STATUS_NOT_FOUND;
                this->publish(_response);
            }
        } catch (std::exception &e) {
            LOG_WARN("HttpSession(" << this->id() << ") " << _host << " error: " << e.what());

            qb::http::Response &res = _response;
            res.status_code = HTTP_STATUS_BAD_REQUEST;
            *this << res;
        }
    }
    // client is receiving timeout
    void
    on(qb::io::async::event::timeout const &e) {
        // disconnect session on timeout
        // add reason for timeout
        if constexpr (has_method_on<Derived, void, event::timeout const &>::value) {
            static_cast<Derived &>(*this).on(e);
        } else
            this->disconnect(DisconnectedReason::ByTimeout);
    }
    // client write buffer has pending bytes
    void
    on(qb::io::async::event::pending_write &&) {
        this->updateTimeout();
    }
    // client write buffer is empty
    void
    on(event::eos &&e) {
        if constexpr (has_method_on<Derived, void, event::eos>::value) {
            static_cast<Derived &>(*this).on(std::forward<event::eos>(e));
        } else
            this->disconnect(ResponseTransmitted);
    }
    // client is being disconnected
    void
    on(qb::io::async::event::disconnected &&e) {
        if constexpr (has_method_on<Derived, void, event::disconnected>::value) {
            static_cast<Derived &>(*this).on(std::forward<event::disconnected>(e));
        } else {
            static const auto reason = [](auto why) {
                switch (why) {
                case DisconnectedReason::ByUser:
                    return "by user";
                case DisconnectedReason::ByTimeout:
                    return "by timeout";
                case DisconnectedReason::ResponseTransmitted:
                    return "response transmitted";
                case DisconnectedReason::ServerError:
                    return "server error";
                default:
                    return "unhandled reason";
                }
            };
            LOG_DEBUG("HttpSession(" << this->id() << ") " << host() << " disconnected -> " << reason(e.reason));
        }
    }

public:
    using handler_type = Handler;

    session() = delete;
    explicit session(Handler &server)
        : qb::io::async::tcp::client<session<Derived, Transport, TProtocol, Handler>, Transport, Handler>(server)
        , _response(server.router().default_response()) {
        this->setTimeout(60);
    }

    [[nodiscard]] std::string const &
    host() const {
        return _host;
    }
    [[nodiscard]] qb::http::TRequest<string_type> &
    request() {
        return _request;
    }
    [[nodiscard]] qb::http::Response &
    response() {
        return _response;
    }
};

template <typename Derived, typename Session>
class io_handler : public qb::io::async::io_handler<Derived, Session> {
public:
    using Router = typename Session::Protocol::Router;
    using Route = typename Session::Protocol::Router::Route;
    using Controller = typename Session::Protocol::Router::Controller;

private:
    Router _router;

public:
    io_handler() = default;

    Router &
    router() {
        return _router;
    }
};

template <typename Derived, typename Session, typename Transport>
class server
    : public qb::io::async::tcp::acceptor<server<Derived, Session, Transport>, Transport>
    , public io_handler<Derived, Session> {
    friend qb::io::async::tcp::acceptor<server<Derived, Session, Transport>, Transport>;
    friend io_handler<Derived, Session>;
    using acceptor_type = qb::io::async::tcp::acceptor<server<Derived, Session, Transport>, Transport>;

    void
    on(typename acceptor_type::accepted_socket_type &&new_io) {
        this->registerSession(std::forward<typename acceptor_type::accepted_socket_type>(new_io));
    }

    void
    on(event::disconnected &&event) {
        if constexpr (has_method_on<Derived, void, event::disconnected>::value) {
            static_cast<Derived &>(*this).on(std::forward<event::disconnected>(event));
        }
        LOG_WARN("HttpServer disconnected");
    }

public:
    server() = default;
};
} // namespace internal

template <typename Derived>
struct use {
    template <typename Server>
    using session = internal::session<Derived, qb::io::transport::tcp, qb::protocol::http_server, Server>;
    template <typename Server>
    using session_view = internal::session<Derived, qb::io::transport::tcp, qb::protocol::http_server_view, Server>;
    template <typename Session>
    using io_handler = internal::io_handler<Derived, Session>;
    template <typename Session>
    using server = internal::server<Derived, Session, qb::io::transport::accept>;

    struct ssl {
        template <typename Server>
        using session = internal::session<Derived, qb::io::transport::stcp, qb::protocol::http_server, Server>;
        template <typename Server>
        using session_view =
            internal::session<Derived, qb::io::transport::stcp, qb::protocol::http_server_view, Server>;
        template <typename Session>
        using io_handler = internal::io_handler<Derived, Session>;
        template <typename Session>
        using server = internal::server<Derived, Session, qb::io::transport::saccept>;
    };
};

} // namespace qb::http

#if defined(_WIN32)
#    define DELETE (0x00010000L)
#endif

#endif // QB_MODULE_HTTP_H_
