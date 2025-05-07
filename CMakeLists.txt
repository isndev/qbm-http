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

if (NOT QB_FOUND)
    message(STATUS "qb project not found, skipping HTTP module")
    return()
endif ()

if (NOT OPENSSL_FOUND OR NOT QB_IO_WITH_SSL)
    message(INFO: qbm-http will not be loaded, missing openssl)
    return()
endif ()

add_subdirectory(not-qb/llhttp)

qb_register_module(
        NAME http
        VERSION 1.0.0
        DEPENDENCIES
        llhttp
        SOURCES
        # Core files
        headers.cpp
        date.cpp
        cookie.cpp
        multipart.cpp
        auth/manager.cpp
        http.cpp
        # Body
        body.cpp
        # Routing
        routing/radix_tree.cpp
        routing/routing.cpp
        # Validation
        validation/validation.cpp
        validation/json_schema.cpp
        validation/query_validator.cpp
        validation/sanitizer.cpp
        # OpenAPI Documentation
        openapi/document.cpp
        openapi/swagger_ui.cpp
)

if (QB_BUILD_TEST)
    enable_testing()
    add_subdirectory(tests)
endif ()