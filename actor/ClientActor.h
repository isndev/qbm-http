/*
 * qb - C++ Actor Framework
 * Copyright (C) 2011-2020 isndev (www.qbaf.io). All rights reserved.
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
#include <qb/io/async/tcp/connector.h>

#include "../http.h"
#include "../tag/ClientTag.h"
#include "../event/RequestEvent.h"
#include "../event/ResponseEvent.h"

#ifndef QB_MODULE_HTTP_CLIENT_EVENT_H_
#define QB_MODULE_HTTP_CLIENT_EVENT_H_

namespace qb::http {
    class ClientActor
            : public ServiceActor<ClientTag> {
        class ISession {
        public:
            virtual ~ISession() = default;
            virtual void connect(io::uri const &) = 0;
        };

        template <typename Transport>
        struct Session
                : public io::async::tcp::client<Session<Transport>, Transport>
                        , public ISession {
            ClientActor &actor;
            const uint64_t id_request;
            const Request<> request;
            const ActorId reply_to;

        public:
            using Protocol = protocol<Session<Transport>>;
            Session(ClientActor &actor,
                    uint64_t req_id,
                    Request<> &request,
                    ActorId reply)
                    : actor(actor)
                    , id_request(req_id)
                    , request(std::move(request))
                    , reply_to(reply){}
            ~Session() = default;

            void connect(qb::io::uri const &remote) final {
                qb::io::async::tcp::connect<typename Transport::transport_io_type>(
                        remote, [this](auto &transport) {
                            if (!transport.is_open()) {
                                auto &e = actor.push<ResponseEvent>(reply_to);
                                e.id_request = id_request;
                                e.data.response.status_code = HTTP_STATUS_SERVICE_UNAVAILABLE;
                                LOG_WARN(actor << "[Fail] request "
                                                  << llhttp_method_name(request.method) << " " << request.url
                                                  << " unresolved");
                                delete this;
                            } else {
                                this->transport() = transport;
                                this->start();
                                *this << request;
                            }
                        });
            }

            void on(typename Protocol::response &&event) {
                auto &e = actor.template push<ResponseEvent>(reply_to);
                e.id_request = id_request;
                e.data.response = std::move(event.http);
                this->disconnect(1);
                LOG_INFO(actor << "[Success] request " << llhttp_method_name(request.method) << " " << request.url);
            }

            void on(qb::io::async::event::disconnected const &event) {
                if (!event.reason) {
                    auto &e = actor.push<ResponseEvent>(reply_to);
                    e.id_request = id_request;
                    e.data.response.status_code = HTTP_STATUS_REQUEST_TIMEOUT;
                    LOG_WARN(actor << "[Fail] request "
                                   << llhttp_method_name(request.method) << " " << request.url
                                   << " lost connection");
                }
            }

            void on(qb::io::async::event::dispose const &) {
                delete this;
            }
        };

    public:

        ClientActor() {
            registerEvent<RequestEvent>(*this);
        }

        void on(RequestEvent &event) {
            const auto scheme = event.data.uri.scheme();
            const auto &uri = event.data.uri;
            auto &request = event.data.request;
            ISession *session = nullptr;

            request.url = uri.source();
            request.path = uri.full_path();
            request.headers["host"].emplace_back(uri.host());

            if (scheme == "http") {
                session = new Session<io::transport::tcp>(*this, event.id_request, request, event.getSource());
            } else if (scheme == "https")
                session = new Session<io::transport::stcp>(*this, event.id_request, request, event.getSource());

            session->connect(uri);
        }
    };
}

#endif //QB_MODULE_HTTP_CLIENT_EVENT_H_
