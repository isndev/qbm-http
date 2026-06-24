/**
 * @file qbm/http/types.cpp
 * @brief Out-of-line definitions for core HTTP types
 *
 * Houses the non-trivial, non-template member bodies of `qb::http::Method`
 * (case-insensitive name parsing and the canonical name-to-value lookup table)
 * that were factored out of `types.h` to keep the header lightweight.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./types.h"

namespace qb::http {

Method::Method(std::string_view sv)
    : _value(Value::UNINITIALIZED) {
    // `icase_unordered_map::find` accepts any string-like key and performs
    // the lowercase conversion internally, so passing the view directly
    // avoids the double-allocation of wrapping it in a temporary `std::string`.
    const auto &map = get_string_to_method_map();
    const auto  it  = map.find(sv);
    if (it != map.end()) {
        _value = it->second;
    }
}

std::string_view
Method::name_view() const {
    if (_value == Value::UNINITIALIZED)
        return "UNINITIALIZED";
    return ::http_method_name(static_cast<::http_method>(_value));
}

const qb::icase_unordered_map<Method::Value> &
Method::get_string_to_method_map() {
    static qb::icase_unordered_map<Value> string_to_method_map = {
        {"DELETE", Value::DEL},
        {"GET", Value::GET},
        {"HEAD", Value::HEAD},
        {"POST", Value::POST},
        {"PUT", Value::PUT},
        {"CONNECT", Value::CONNECT},
        {"OPTIONS", Value::OPTIONS},
        {"TRACE", Value::TRACE},
        {"COPY", Value::COPY},
        {"LOCK", Value::LOCK},
        {"MKCOL", Value::MKCOL},
        {"MOVE", Value::MOVE},
        {"PROPFIND", Value::PROPFIND},
        {"PROPPATCH", Value::PROPPATCH},
        {"SEARCH", Value::SEARCH},
        {"UNLOCK", Value::UNLOCK},
        {"BIND", Value::BIND},
        {"REBIND", Value::REBIND},
        {"UNBIND", Value::UNBIND},
        {"ACL", Value::ACL},
        {"REPORT", Value::REPORT},
        {"MKACTIVITY", Value::MKACTIVITY},
        {"CHECKOUT", Value::CHECKOUT},
        {"MERGE", Value::MERGE},
        {"M-SEARCH", Value::MSEARCH},
        {"NOTIFY", Value::NOTIFY},
        {"SUBSCRIBE", Value::SUBSCRIBE},
        {"UNSUBSCRIBE", Value::UNSUBSCRIBE},
        {"PATCH", Value::PATCH},
        {"PURGE", Value::PURGE},
        {"MKCALENDAR", Value::MKCALENDAR},
        {"LINK", Value::LINK},
        {"UNLINK", Value::UNLINK},
        {"SOURCE", Value::SOURCE},
        {"PRI", Value::PRI},
        {"DESCRIBE", Value::DESCRIBE},
        {"ANNOUNCE", Value::ANNOUNCE},
        {"SETUP", Value::SETUP},
        {"PLAY", Value::PLAY},
        {"PAUSE", Value::PAUSE},
        {"TEARDOWN", Value::TEARDOWN},
        {"GET_PARAMETER", Value::GET_PARAMETER},
        {"SET_PARAMETER", Value::SET_PARAMETER},
        {"REDIRECT", Value::REDIRECT},
        {"RECORD", Value::RECORD},
        {"FLUSH", Value::FLUSH},
        {"QUERY", Value::QUERY}
    };
    return string_to_method_map;
}

} // namespace qb::http
