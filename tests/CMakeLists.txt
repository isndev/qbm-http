#
# qb - C++ Actor Framework
# Copyright (c) 2011-2025 qb - isndev (cpp.actor). All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#         limitations under the License.
#

# Define test files and their corresponding test names
set(HTTP_TESTS
        uri-only
        body
        cookie
        headers
        validation
        router
        router-api
        router-match
        router-async
        router-error-handling
        router-middleware
        router-controller
        router-route-group
        router-all
        middleware-conditional
        middleware-transform
        middleware-logging
        middleware-timing
        middleware-rate_limit
        middleware-security-headers
        middleware-compression
        middleware-cors
        middleware-recaptcha
        middleware-error-handling
        middleware-validator
        middleware-static-files
        http1-client
        session-http
        integration-basic
        integration-advanced
        dos-protection
        multipart-security
        date-parsing
        context-slots
        coro-client
        coro-server
        coro-integration
)

if(QB_HAS_SSL)
    list(APPEND HTTP_TESTS
        middleware-auth
        middleware-jwt
        integration-middleware
        integration-make-server
        http2-header-validator
        http2-hpack
        integration-http2-client
        coro-http2-client
        ws-session
        ws-client
        ws-robustness
        ws-stress
        ws-security
        ws-coro-client
        ws-coro-server
        ws-coro-integration
        ws-coro-negative
        ws-framing-edge
        ws-api-hardening
    )
endif()

if(QBM_HTTP_HAS_HTTP3)
    list(APPEND HTTP_TESTS
        http3-client
    )
endif()

# Register each standard test
foreach (TEST ${HTTP_TESTS})
    qb_register_module_test(
        MODULE_NAME http
        TEST_NAME ${TEST}
        SOURCES test-${TEST}.cpp
    )
    # QBM_HTTP_HAS_HTTP3 is inherited transitively from qbm-http (defined PUBLIC),
    # so tests linking the module already see it — no per-test define needed.
endforeach ()

# SSL resources are automatically copied by qb_setup_test_resources()
# which is called in qb/CMakeLists.txt. Tests will find them in their working directory.
