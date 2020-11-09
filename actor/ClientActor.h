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
            virtual bool connect(io::uri const &) = 0;
            virtual void send(Request<> const &) = 0;
        };

        template <typename Transport>
        class Session
                : public io::async::tcp::client<Session<Transport>, Transport>
                        , public ISession {
            ClientActor &actor;
            const ActorId reply_to;
            const uint64_t id_request;

        public:
            using Protocol = protocol<Session<Transport>>;
            Session(ClientActor &actor, uint64_t req_id, ActorId reply)
                    : actor(actor)
                    , id_request(req_id)
                    , reply_to(reply){}
            ~Session() = default;

            bool connect(qb::io::uri const &remote) final {
                if (qb::io::SocketStatus::Done != this->transport().connect(remote))
                    return false;

                this->start();
                return true;
            }

            void send(Request<> const &request) {
                *this << request;
            }

            void on(typename Protocol::response &&event) {
                auto &e = actor.template push<ResponseEvent>(reply_to);
                e.id_request = id_request;
                e.data.response = std::move(event.http);
                this->disconnect();
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
            if (scheme == "http") {
                session = new Session<io::transport::tcp>(*this, event.id_request, event.getSource());
            } else if (scheme == "https")
                session = new Session<io::transport::stcp>(*this, event.id_request, event.getSource());

            if (session && session->connect(uri)){
                request.path = uri.full_path();
                request.headers["host"].emplace_back(uri.host());
                session->send(request);
                LOG_INFO(*this << "[Success] request " << llhttp_method_name(request.method) << " " << uri.source());
            } else {
                delete session;
                auto &e = push<ResponseEvent>(event.getSource());
                e.id_request = event.id_request;
                e.data.response.status_code = HTTP_STATUS_SERVICE_UNAVAILABLE;
                //Todo: may be send error in body
                LOG_WARN(*this << "[Fail] cannot resolve " << uri.source());
            }
        }
    };
}

#endif //QB_MODULE_HTTP_CLIENT_EVENT_H_
