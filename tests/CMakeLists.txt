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

include(CTest)

# Find OpenSSL for the authentication tests
find_package(OpenSSL REQUIRED)

# Define test files and their corresponding test names
set(HTTP_TESTS
        uri-only
        body
        cookie
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
        middleware-auth
        middleware-error-handling
        middleware-jwt
        middleware-validator
        middleware-static-files
        session-http
        integration-basic
        integration-advanced
        integration-middleware
        http2-hpack
        integration-make-server
        integration-http2-client
)

# Register each standard test
foreach (TEST ${HTTP_TESTS})
    qb_register_module_test(
        MODULE_NAME http
        TEST_NAME ${TEST}
        SOURCES test-${TEST}.cpp
    )
endforeach ()

# SSL resources are automatically copied by qb_setup_test_resources()
# which is called in qb/CMakeLists.txt. Tests will find them in their working directory.
