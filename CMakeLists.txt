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

project(qbm-http)

# Check if qb framework is available
if(NOT QB_FOUND)
    qb_status_message("qb framework not found, skipping HTTP module")
    return()
endif()

# Check if SSL support is available
if(NOT QB_HAS_SSL)
    qb_status_message("HTTP module requires SSL support - skipping")
    return()
endif()

# Add the internal llhttp dependency
add_subdirectory(not-qb/llhttp)

# Register the HTTP module using the new framework functions
qb_register_module(
    NAME http
    VERSION 1.0.0
    DEPENDS qb-core llhttp
    SOURCES
        # Core files
        headers.cpp
        date.cpp
        cookie.cpp
        multipart.cpp
        auth/manager.cpp
        # Body
        request.cpp
        response.cpp
        body.cpp
        1.1/http.cpp
        # Validation
        validation/parameter_validator.cpp
        validation/request_validator.cpp
        validation/rule.cpp
        validation/sanitizer.cpp
        validation/schema_validator.cpp
        # HTTP/2
        2/http2.cpp
        2/client.cpp
    DEFINES
        QBM_HTTP_VERSION=1.0.0
)

# Add tests if enabled
if(QB_BUILD_TESTS)
    add_subdirectory(tests)
endif()