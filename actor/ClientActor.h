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

#include <qb/actor.h>
#include <qb/io/async.h>

#include "../http.h"
#include "../tag/ClientTag.h"
#include "../event/RequestEvent.h"
#include "../event/ResponseEvent.h"

#ifndef QB_MODULE_HTTP_CLIENT_EVENT_H_
#define QB_MODULE_HTTP_CLIENT_EVENT_H_

namespace qb::http {
    class ClientActor
            : public ServiceActor<ClientTag> {

    public:

        ClientActor() {
            registerEvent<RequestEvent>(*this);
        }

        void on(RequestEvent &event) {
            const auto scheme = event.data.uri.scheme();
            const auto &uri = event.data.uri;
            const auto reply_to = event.getSource();
            const auto id_request = event.id_request;
            auto &request = event.data.request;
            request.url = uri.source();

            async::REQUEST(request, [this, id_request, reply_to](auto &&result) {
                switch(result.response.status_code) {
                    case HTTP_STATUS_SERVICE_UNAVAILABLE:
                        LOG_WARN(*this << "[Fail] request "
                                       << http_method_name(result.request.method) << " " << result.request.url
                                       << " couldn't connect");
                        break;
                    case HTTP_STATUS_GONE:
                        LOG_WARN(*this << "[Fail] request "
                                       << http_method_name(result.request.method) << " " << result.request.url
                                       << " lost connection");
                        break;
                    default:
                        LOG_DEBUG(*this << "[Success] request "
                                       << http_method_name(result.request.method) << " " << result.request.url);
                        break;
                }
                auto &e = this->template push<ResponseEvent>(reply_to);
                e.id_request = id_request;
                e.data.response = std::move(result.response);

            }, 3);
        }
    };
}

#endif //QB_MODULE_HTTP_CLIENT_EVENT_H_
