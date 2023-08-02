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
#include <qb/io/async/tcp/connector.h>
#include <qb/io/transport/file.h>
#include <qb/system/allocator/pipe.h>
#include <qb/system/container/unordered_map.h>
#include <qb/system/timestamp.h>
#ifdef QB_IO_WITH_ZLIB
#    include <qb/io/gzip.h>
#endif
#include <regex>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include "not-qb/llhttp/include/llhttp.h"

#if defined(_WIN32)
#    undef DELETE // Windows :/
#endif

namespace qb::http {
using method = llhttp_method;
using status = http_status;
using headers_map = qb::icase_unordered_map<std::vector<std::string>>;
constexpr const char endl[] = "\r\n";
constexpr const char sep = ' ';

namespace internal {

template <typename String>
struct MessageBase {
    using string_type = String;

    uint16_t major_version;
    uint16_t minor_version;
    qb::icase_unordered_map<std::vector<String>> headers;
    uint64_t content_length;
    bool upgrade{};
    String body;

    MessageBase() noexcept
        : major_version(1)
        , minor_version(1)
        , content_length(0) {
        reset();
    }

    MessageBase(MessageBase const &) = default;
    MessageBase(MessageBase &&) noexcept = default;
    MessageBase &operator=(MessageBase const &) = default;
    MessageBase &operator=(MessageBase &&) noexcept = default;

    template <typename T>
    const auto &
    header(T &&name, std::size_t const index = 0, String const &not_found = "") const {
        const auto &it = this->headers.find(std::forward<T>(name));
        if (it != this->headers.cend() && index < it->second.size())
            return it->second[index];
        return not_found;
    }

    void
    reset() {
        headers.clear();
        body = {};
    };

    class FormData {
        friend MessageBase;

    public:
        struct Data {
            String content;
            String file_name;
            String content_type;
        };

        using DataMap = qb::unordered_map<String, std::vector<Data>>;

    private:
        std::string _boundary;
        std::size_t _content_length;
        DataMap _data_map;

        [[nodiscard]] std::string
        parseBoundary(MessageBase const &base) const {
            static const std::regex boundary_regex("^multipart/form-data;\\s{0,}boundary=(.+)$");
            std::smatch what;

            return std::regex_match(base.header("Content-Type"), what, boundary_regex) ? what[1].str() : "";
        }

        [[nodiscard]] std::string
        generateBoundary() const {
            std::mt19937 generator{std::random_device{}()};
            std::uniform_int_distribution<int> distribution{'0', '9'};

            std::string result = "----------------------------qb00000000000000000000000000000000";
            for (auto i = result.begin() + 30; i != result.end(); ++i)
                *i = distribution(generator);

            return result;
        }

    public:
        FormData()
            : _boundary(generateBoundary())
            , _content_length(_boundary.size() + 4) {}
        FormData(MessageBase const &base)
            : _boundary(parseBoundary(base)) {}

        void
        add(std::string const &name, Data data) {
            if (name.empty())
                return;                             // do nothing
            _content_length += _boundary.size() + 8 // -- and \r\n + 2 \r\n at the end
                               + 39                 // Content-Disposition: form-data; name=""
                               + name.size();
            if (!data.file_name.empty()) {
                _content_length += data.file_name.size() + 13; // ; filename=""
            }

            if (!data.content_type.empty()) {
                _content_length += data.content_type.size() + 16; // Content-Type: + \r\n
            }

            _content_length += data.content.size() + 2;

            _data_map[name].emplace_back(std::move(data));
        }

        [[nodiscard]] std::string const &
        boundary() const {
            return _boundary;
        }
        [[nodiscard]] DataMap const &
        map() const {
            return _data_map;
        }
        [[nodiscard]] std::size_t
        length() const {
            return _content_length;
        }
    };

    FormData form;
    FormData &
    new_form() {
        headers["Content-Type"] = {"multipart/form-data;boundary=" + form.boundary()};
        return form;
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
        static const std::regex query_regex("(\\?|&)([^=]*)=([^&]*)");
        if constexpr (MessageType::type == HTTP_REQUEST) {
            auto &msg = static_cast<Parser *>(parser->data)->msg;
            msg.method = static_cast<llhttp_method>(parser->method);
            msg.url = String(at, length);
            auto has_query = msg.url.find('?');
            if (has_query != std::string::npos) {
                msg.path = String(at, has_query);

                const char *search = at + has_query;
                std::cmatch what;
                while (std::regex_search(search, at + length, what, query_regex)) {
                    msg._queries[String(what[2].first, static_cast<std::size_t>(what[2].length()))]
                        .push_back(
                            io::uri::decode(what[3].first, static_cast<std::size_t>(what[3].length())));
                    search += what[0].length();
                }
            } else
                msg.path = msg.url;
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
        msg.headers[String{static_cast<Parser *>(parser->data)->_last_header_key}].push_back(
            String(at, length));
        return 0;
    }

    static int
    on_headers_complete(llhttp_t *parser) {
        auto &msg = static_cast<Parser *>(parser->data)->msg;
        msg.major_version = parser->http_major;
        msg.minor_version = parser->http_major;
        if (parser->content_length != ULLONG_MAX)
            msg.content_length = parser->content_length;
        msg.upgrade = static_cast<bool>(parser->upgrade);
        static_cast<Parser *>(parser->data)->_headers_completed = true;
        return HPE_PAUSED;
    }

    static int
    on_body(llhttp_t *parser, const char *at, size_t length) {
        auto &chunked = static_cast<Parser *>(parser->data)->_chunked;
        const auto begin = chunked.size();
        chunked.resize(begin + length);
        std::copy_n(at, length, chunked.begin() + begin);
        // static_cast<Parser *>(parser->data)->msg.body = String(at, length);
        return 0;
    }

    static int
    on_message_complete(llhttp_t *parser) {
        auto p = static_cast<Parser *>(parser->data);
        p->msg.body = String(&(*(p->_chunked.begin())), p->_chunked.size());
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
    std::vector<char> _chunked;

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
    getParsedMessage() noexcept {
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

template <typename String = std::string>
struct Response : public internal::MessageBase<String> {
    constexpr static const llhttp_type_t type = HTTP_RESPONSE;
    http_status status_code;
    String status;

    Response() noexcept
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
            Response &response;

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
        route(Session &session, Response &response) const {
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
};

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

class Queries : public qb::icase_unordered_map<std::vector<std::string>> {
public:
    Queries() = default;

    template <typename T>
    [[nodiscard]] std::string const &
    query(T &&name, std::size_t const index = 0, std::string const &not_found = "") const {
        const auto &it = find(std::forward<T>(name));
        if (it != cend() && index < it->second.size())
            return it->second[index];

        return not_found;
    }
};

class PathParameters : public qb::unordered_map<std::string, std::string> {
public:
    PathParameters() = default;

    [[nodiscard]] std::string const &
    param(std::string const &name, std::string const &not_found = "") const {
        const auto &it = find(name);
        return it != cend() ? it->second : not_found;
    }
};

template <typename String = std::string>
struct Request : public internal::MessageBase<String> {
    constexpr static const llhttp_type_t type = HTTP_REQUEST;
    llhttp_method method;
    String url;
    String path;
    Queries _queries;

public:
    Request() noexcept
        : method(HTTP_GET) {}
    Request(Request const &) = default;
    Request(Request &&) = default;
    Request &operator=(Request const &) = default;
    Request &operator=(Request &&) = default;

    template <typename T>
    [[nodiscard]] std::string const &
    query(T &&name, std::size_t const index = 0, std::string const &not_found = "") const {
        return _queries.query<T>(std::forward<T>(name), index, not_found);
    }

    Queries &
    queries() {
        return _queries;
    }
    Queries const &
    queries() const {
        return _queries;
    }

    void
    reset() {
        method = HTTP_GET;
        url = {};
        path = {};
        _queries.clear();
        static_cast<internal::MessageBase<String> &>(*this).reset();
    }

    template <typename Session>
    class Router {

    public:
        struct Context {
            Session &session;
            const Request &request;
            PathParameters parameters;
            Response<std::string> response;

            template <typename T>
            [[nodiscard]] std::string const &
            header(T &&name, std::size_t const index = 0, std::string const &not_found = "") const {
                return request.header(std::forward<T>(name), index, not_found);
            }

            [[nodiscard]] std::string
            auth(
                std::string const &auth_type, std::size_t const index = 0,
                std::string const &not_found = "") const {
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
            ParameterNames _param_names;
            PathParameters _parameters;
            const std::regex _regex;

            std::string
            init(std::string const &request_path) {
                std::string build_regex = request_path, search = request_path;
                const std::regex pieces_regex("/:(\\w+)");
                std::smatch what;
                while (std::regex_search(search, what, pieces_regex)) {
                    _param_names.push_back(what[1]);
                    _parameters.emplace(*_param_names.rbegin(), "");
                    build_regex = build_regex.replace(build_regex.find(what[0]), what[0].length(), "/(.+)");
                    search = what.suffix();
                }

                return std::move(build_regex);
            }

        public:
            explicit ARoute(std::string const &path)
                : _regex(init(path)) {}

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

            PathParameters &
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
                ctx.parameters = std::move(this->parameters());
                _func(ctx);
            }
        };

        using Routes = std::vector<ARoute *>;
        qb::unordered_map<int, Routes> _routes;
        Response<std::string> _default_response;

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

        Router &
        setDefaultResponse(Response<std::string> res) {
            _default_response = std::move(res);
            return *this;
        }

        [[nodiscard]] Response<std::string> const &
        getDefaultResponse() const {
            return _default_response;
        }

        [[nodiscard]] Response<std::string> &
        getDefaultResponse() {
            return _default_response;
        }

        bool
        route(Session &session, Request const &request) const {
            const auto &it = _routes.find(request.method);
            if (it != _routes.end()) {
                for (const auto route : it->second) {
                    if (route->match(request.path)) {
                        Context ctx{session, request, {}, _default_response};
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
    template <typename T, typename... _Args>                                                      \
    Router &name(_Args &&...args) {                                                               \
        static_assert(std::is_base_of_v<Route, T>, "Router registering Route not base of Route"); \
        auto route = new T{std::forward<_Args>(args)...};                                         \
        _routes[num].push_back(route->get());                                                     \
        return *this;                                                                             \
    }                                                                                             \
    template <typename _Func>                                                                     \
    Router &name(std::vector<std::string> paths, _Func &&func) {                                  \
        for (const auto &path : paths)                                                            \
            name(path, std::forward<_Func>(func));                                                \
        return *this;                                                                             \
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

            auto &msg = _http_obj.getParsedMessage();
            if (!_http_obj.headers_completed()) {
                this->not_ok();
                return 0;
            }

            body_offset = _http_obj.error_pos - this->_io.in().begin();
        }

        auto &msg = _http_obj.getParsedMessage();

        if (msg.headers.has("Transfer-Encoding")) {
            _http_obj.resume();
            const auto ret =
                _http_obj.parse(this->_io.in().begin() + body_offset, this->_io.in().size() - body_offset);

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

        const auto full_size = body_offset + msg.content_length;
        if (this->_io.in().size() < full_size) {
            // if is protocol view reset parser for next read
            if constexpr (std::is_same_v<std::string_view, String>) {
                _http_obj.reset();
                body_offset = 0;
            }
            return 0; // incomplete body
        }

        if (msg.content_length)
            _http_obj.getParsedMessage().body =
                String(this->_io.in().cbegin() + body_offset, msg.content_length);

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
class http_server : public http_internal::base<IO_Handler, qb::http::Request<std::string>> {
    using base_t = http_internal::base<IO_Handler, qb::http::Request<std::string>>;

public:
    http_server() = delete;
    explicit http_server(IO_Handler &io) noexcept
        : base_t(io) {}

    struct request {
        const std::size_t size{};
        const char *data{};
        const qb::http::Request<std::string> http;
    };

    void
    onMessage(std::size_t size) noexcept final {
        this->_io.on(request{size, this->_io.in().begin(), std::move(this->_http_obj.getParsedMessage())});
        this->_http_obj.reset();
    }
};

template <typename IO_Handler>
class http_server_view : public http_internal::base<IO_Handler, qb::http::Request<std::string_view>> {
    using base_t = http_internal::base<IO_Handler, qb::http::Request<std::string_view>>;

public:
    http_server_view() = delete;
    explicit http_server_view(IO_Handler &io) noexcept
        : base_t(io) {}

    struct request {
        const std::size_t size{};
        const char *data{};
        const qb::http::Request<std::string_view> http;
    };

    void
    onMessage(std::size_t size) noexcept final {
        this->_io.on(request{size, this->_io.in().begin(), std::move(this->_http_obj.getParsedMessage())});
        this->_http_obj.reset();
    }
};

template <typename IO_Handler>
class http_client : public http_internal::base<IO_Handler, qb::http::Response<std::string>> {
    using base_t = http_internal::base<IO_Handler, qb::http::Response<std::string>>;

public:
    http_client() = delete;
    explicit http_client(IO_Handler &io) noexcept
        : base_t(io) {}

    struct response {
        const std::size_t size{};
        const char *data{};
        qb::http::Response<std::string> http;
    };

    void
    onMessage(std::size_t size) noexcept final {
        this->_io.on(response{size, this->_io.in().begin(), std::move(this->_http_obj.getParsedMessage())});
        this->_http_obj.reset();
    }
};

template <typename IO_Handler>
class http_client_view : public http_internal::base<IO_Handler, qb::http::Response<std::string_view>> {
    using base_t = http_internal::base<IO_Handler, qb::http::Response<std::string_view>>;

public:
    http_client_view() = delete;
    explicit http_client_view(IO_Handler &io) noexcept
        : base_t(io) {}

    struct response {
        const std::size_t size{};
        const char *data{};
        const qb::http::Response<std::string_view> http;
    };

    void
    onMessage(std::size_t size) noexcept final {
        this->_io.on(response{size, this->_io.in().begin(), std::move(this->_http_obj.getParsedMessage())});
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

struct result {
    const Request<> &request;
    Response<> &response;
};

template <typename Func, typename Transport>
class Session : public io::async::tcp::client<Session<Func, Transport>, Transport> {
    Func _func;
    const Request<> _request;

public:
    using http_protocol = http::protocol<Session<Func, Transport>>;

    Session(Func &&func, Request<> &request)
        : _func(std::forward<Func>(func))
        , _request(std::move([](auto &r) -> auto & {
#ifdef QB_IO_WITH_ZLIB
            r.headers["Accept-Encoding"] = {"gzip"};
#endif
            return r;
        }(request))) {
        this->template switch_protocol<http_protocol>(*this);
    }
    ~Session() = default;

    void
    connect(qb::io::uri const &remote, double timeout = 0) {
        qb::io::async::tcp::connect<typename Transport::transport_io_type>(
            remote,
            [this](auto &&transport) {
                if (!transport.is_open()) {
                    Response<> response;
                    response.status_code = HTTP_STATUS_SERVICE_UNAVAILABLE;

                    _func(result{_request, response});
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
        if (response.header("Content-Encoding").find("gzip") != std::string::npos)
            response.body = qb::gzip::uncompress(response.body.c_str(), response.body.size());
#endif
        _func(result{_request, event.http});
        this->disconnect(1);
    }

    void
    on(qb::io::async::event::disconnected const &event) {
        if (!event.reason) {
            Response<> response;
            response.status_code = HTTP_STATUS_GONE;

            _func(result{_request, response});
        }
    }

    void
    on(qb::io::async::event::dispose const &) {
        delete this;
    }
};

template <typename Func>
using HTTP = Session<Func, qb::io::transport::tcp>;

#ifdef QB_IO_WITH_SSL
template <typename Func>
using HTTPS = Session<Func, qb::io::transport::stcp>;

#    define EXEC_REQUEST()                                                                    \
        if (remote.scheme() == "https")                                                       \
            (new HTTPS<_Func>(std::forward<_Func>(func), request))->connect(remote, timeout); \
        else                                                                                  \
            (new HTTP<_Func>(std::forward<_Func>(func), request))->connect(remote, timeout);

#else
#    define EXEC_REQUEST() (new HTTP<_Func>(std::forward<_Func>(func), request))->connect(remote, timeout);
#endif

#define REGISTER_HTTP_ASYNC_FUNCTION(num, name, description)           \
    template <typename _Func>                                          \
    void name(Request<> &request, _Func &&func, double timeout = 0.) { \
        qb::io::uri remote(request.url);                               \
        if (num >= 0)                                                  \
            request.method = static_cast<llhttp_method>(num);          \
        request.path = remote.full_path();                             \
        request.headers["host"].emplace_back(remote.host());           \
        EXEC_REQUEST()                                                 \
    }

REGISTER_HTTP_ASYNC_FUNCTION(-1, REQUEST, USER_DEFINED)
HTTP_METHOD_MAP(REGISTER_HTTP_ASYNC_FUNCTION)

#undef REGISTER_HTTP_ASYNC_FUNCTION
#undef EXEC_REQUEST

} // namespace async
} // namespace qb::http

namespace qb::allocator {

template <>
pipe<char> &pipe<char>::put<qb::http::Request<std::string>>(const qb::http::Request<std::string> &r);

template <>
pipe<char> &pipe<char>::put<qb::http::Response<std::string>>(const qb::http::Response<std::string> &r);

template <>
pipe<char> &pipe<char>::put<qb::http::Chunk>(const qb::http::Chunk &c);

template <>
pipe<char> &pipe<char>::put<qb::http::Request<std::string>::FormData>(
    const qb::http::Response<std::string>::FormData &f);

} // namespace qb::allocator

#if defined(_WIN32)
#    define DELETE (0x00010000L)
#endif

#endif // QB_MODULE_HTTP_H_
