/**
 * @file qbm/http/src/qbm/http/sse.cpp
 * @brief The wire form of a Server-Sent Event (Huly QB-86): `sse.h`'s non-template half.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
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
 * @ingroup Http
 */

#include <string>
#include <string_view>

#include "./sse.h"

namespace qb::http::sse {

namespace {
/// A field value on one line: a CR or LF inside `name`, `id` or a comment would start another field (and let a value
/// a client supplied forge an event), so each is dropped. The data is split into lines instead (format()).
std::string
one_line(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const char c : value) {
        if (c != '\r' && c != '\n') {
            out.push_back(c);
        }
    }
    return out;
}
} // namespace

std::string
format(Event const &event) {
    std::string out;
    out.reserve(event.data.size() + event.name.size() + event.id.size() + 48);
    // A value that is only line breaks is no value: the field is left out, as an empty one is -- an `id:` with an
    // empty value would reset the client's Last-Event-ID.
    if (const std::string name = one_line(event.name); !name.empty()) {
        out.append("event: ").append(name).push_back('\n');
    }
    if (const std::string id = one_line(event.id); !id.empty()) {
        out.append("id: ").append(id).push_back('\n');
    }
    if (event.retry) {
        out.append("retry: ").append(std::to_string(event.retry->count())).push_back('\n');
    }
    // One `data:` line per line of the data: a LF, a CR or a CRLF ends a line. The client appends each value and a LF
    // to its buffer and drops the LAST LF when it dispatches, so a data that ends with a line break gets an empty last
    // line and arrives as it was sent ("a\n" -> `data: a`, `data: `); an empty data still writes its one line, since a
    // client dispatches nothing without a `data:` line.
    std::string_view rest = event.data;
    for (;;) {
        const auto cut = rest.find_first_of("\r\n");
        out.append("data: ").append(rest.substr(0, cut)).push_back('\n');
        if (cut == std::string_view::npos) {
            break;
        }
        const bool crlf = rest[cut] == '\r' && cut + 1 < rest.size() && rest[cut + 1] == '\n';
        rest.remove_prefix(cut + (crlf ? 2 : 1));
    }
    out.push_back('\n');
    return out;
}

std::string
comment_line(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 4);
    out.append(": ").append(one_line(text)).append("\n\n");
    return out;
}

std::string
retry_line(std::chrono::milliseconds retry) {
    std::string out("retry: ");
    out.append(std::to_string(retry.count())).append("\n\n");
    return out;
}

std::string const &
last_event_id(Request const &request) {
    return request.header("Last-Event-ID");
}

} // namespace qb::http::sse
