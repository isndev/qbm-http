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

namespace qb::http {
namespace internal {

void
MessageBase::reset() noexcept {
    this->Headers::_headers.clear();
    this->Headers::_content_type = typename Headers::ContentType{};
    major_version                = 1;
    minor_version                = 1;
    upgrade                      = false;
    stream_id                    = 0;
    keep_alive                   = false;
}

} // namespace internal
} // namespace qb::http
