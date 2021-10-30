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

#include <qb/event.h>
#include "../http.h"

#ifndef QB_MODULE_HTTP_REQUEST_EVENT_H_
#define QB_MODULE_HTTP_REQUEST_EVENT_H_

namespace qb::http {
    struct RequestEvent : public qb::Event {
        uint64_t id_request;
        struct Data {
            qb::io::uri uri;
            Request<> request;
        } &data;

        RequestEvent () : data(*new Data()) {}
        ~RequestEvent() {
            delete &data;
        }
    };
}

#endif //QB_MODULE_HTTP_REQUEST_EVENT_H_
