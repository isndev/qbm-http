/**
 * @file qbm/http/message_base.cpp
 * @brief Out-of-line definitions for the base class of HTTP messages.
 *
 * Contains the non-inline member function bodies for the `MessageBase`
 * class declared in `message_base.h`.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "message_base.h"

#include <string>

namespace qb::http {
namespace internal {

Headers *
TrailerSection::create() {
    return new Headers();
}

Headers *
TrailerSection::clone(const Headers &fields) {
    return new Headers(fields);
}

void
TrailerSection::destroy(Headers *fields) noexcept {
    delete fields;
}

void
TrailerSection::assign(const TrailerSection &other) {
    // The copy is made first: a throwing allocation leaves this section as it was.
    Headers *const copy = other._fields ? clone(*other._fields) : nullptr;
    if (_fields) {
        destroy(_fields);
    }
    _fields = copy;
}

void
MessageBase::reset() noexcept {
    this->Headers::_headers.clear();
    this->Headers::_content_type         = typename Headers::ContentType{};
    this->Headers::_content_type_derived = false;
    major_version                        = 1;
    minor_version                        = 1;
    upgrade                              = false;
    stream_id                            = 0;
    keep_alive                           = false;
    _trailers.reset();
}

const Headers &
MessageBase::trailers() const noexcept {
    if (const Headers *const fields = _trailers.get()) {
        return *fields;
    }
    static const Headers none;
    return none;
}

} // namespace internal

namespace detail {
void
store_received_trailer(internal::MessageBase &message, std::string_view name, std::string_view value) {
    message.trailers().add_header(std::string(name), std::string(value));
    // 3.x: the header fields keep receiving the trailer fields, after the header-section values.
    message.add_header(std::string(name), std::string(value));
}
} // namespace detail
} // namespace qb::http
