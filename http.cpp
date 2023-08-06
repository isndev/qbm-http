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

namespace qb::allocator {
template <>
pipe<char> &
pipe<char>::put<qb::http::Request<std::string>>(
    const qb::http::Request<std::string> &r) {
    // HTTP Status Line
    *this << ::llhttp_method_name(static_cast<llhttp_method_t>(r.method)) << qb::http::sep
          << r.path << qb::http::sep << "HTTP/" << r.major_version << "."
          << r.minor_version << qb::http::endl;
    // HTTP Headers
    for (const auto &it : r.headers) {
        for (const auto &value : it.second)
            *this << it.first << ": " << value << qb::http::endl;
    }
    // Body
    const auto has_form = static_cast<bool>(r.form.map().size());
    auto length = has_form ? r.form.length() : r.content_length + r.body.size();
    if (length) {
        *this << "Content-Length: " << length << qb::http::endl
              << qb::http::endl;
        if (has_form)
            *this << r.form;
        else
            *this << r.body;
    } else
        *this << qb::http::endl;
    return *this;
}

template <>
pipe<char> &
pipe<char>::put<qb::http::Response<std::string>>(
    const qb::http::Response<std::string> &r) {
    // HTTP Status Line
    *this << "HTTP/" << r.major_version << "." << r.minor_version << qb::http::sep
          << r.status_code << qb::http::sep
          << (r.status.empty()
                  ? ::http_status_str(static_cast<http_status>(r.status_code))
                  : r.status.c_str())
          << qb::http::endl;
    // HTTP Headers
    for (const auto &it : r.headers) {
        for (const auto &value : it.second)
            *this << it.first << ": " << value << qb::http::endl;
    }
    // Body
    auto length = r.content_length + r.body.size();
    if (length) {
        *this << "Content-Length: " << length << qb::http::endl
              << qb::http::endl
              << r.body;
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

template<>
pipe<char> &
pipe<char>::put<qb::http::Request<std::string>::FormData>(const qb::http::Response<std::string>::FormData &f) {
    this->reserve(f.length());
    const auto &map = f.map();

    for (const auto &[name, vec] : map) {
        for (const auto &data : vec) {
            *this << "--" << f.boundary() << qb::http::endl
                  << "Content-Disposition: form-data; name=\"" << name << "\"";

            if (!data.file_name.empty())
                *this << "; filename=\"" << data.file_name << "\"";

            *this << qb::http::endl;

            if (!data.content_type.empty())
                *this << "Content-Type: " << data.content_type << qb::http::endl;

            *this << qb::http::endl << data.content << qb::http::endl;
        }
    }

    *this << "--" << f.boundary() << "--";

    return *this;
}

} // namespace qb::allocator

// templates instantiation
// objects
template struct qb::http::Request<std::string>;
template struct qb::http::Request<std::string_view>;
template struct qb::http::Response<std::string>;
template struct qb::http::Response<std::string_view>;
