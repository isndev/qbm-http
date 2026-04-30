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

set(QBM_HTTP_EXTRA_SOURCES)
set(QBM_HTTP_EXTRA_DEPENDS)
set(QBM_HTTP_EXTRA_DEFINES)

find_package(PkgConfig QUIET)
if(QB_HAS_QUIC AND PKG_CONFIG_FOUND)
    pkg_check_modules(PC_NGHTTP3 QUIET libnghttp3)
endif()

if(QB_HAS_QUIC AND PC_NGHTTP3_FOUND)
    set(QBM_HTTP_HAS_HTTP3 TRUE)
    add_library(Nghttp3::nghttp3 INTERFACE IMPORTED)
    target_include_directories(Nghttp3::nghttp3 INTERFACE ${PC_NGHTTP3_INCLUDE_DIRS})
    target_link_directories(Nghttp3::nghttp3 INTERFACE ${PC_NGHTTP3_LIBRARY_DIRS})
    target_link_libraries(Nghttp3::nghttp3 INTERFACE ${PC_NGHTTP3_LIBRARIES})
    list(APPEND QBM_HTTP_EXTRA_SOURCES
        3/client.cpp
    )
    list(APPEND QBM_HTTP_EXTRA_DEPENDS Nghttp3::nghttp3)
    list(APPEND QBM_HTTP_EXTRA_DEFINES QBM_HTTP_HAS_HTTP3=1)
    qb_status_message("HTTP/3 support enabled (nghttp3)")
else()
    set(QBM_HTTP_HAS_HTTP3 FALSE)
    qb_status_message("HTTP/3 support disabled (requires QB_HAS_QUIC and libnghttp3)")
endif()

# Register the HTTP module using the new framework functions
qb_register_module(
    NAME http
    VERSION 1.0.0
    DEPENDS qb-core llhttp ${QBM_HTTP_EXTRA_DEPENDS}
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
        ws/ws.cpp
        1.1/http.cpp
        1.1/client.cpp
        # Validation
        validation/parameter_validator.cpp
        validation/request_validator.cpp
        validation/rule.cpp
        validation/sanitizer.cpp
        validation/schema_validator.cpp
        # HTTP/2
        2/http2.cpp
        2/client.cpp
        ${QBM_HTTP_EXTRA_SOURCES}
    DEFINES
        QBM_HTTP_VERSION=1.0.0
        ${QBM_HTTP_EXTRA_DEFINES}
)

if(QBM_HTTP_HAS_HTTP3)
    target_compile_definitions(qbm-http PUBLIC QBM_HTTP_HAS_HTTP3=1)
endif()

# Add tests if enabled
if(QB_BUILD_TESTS)
    add_subdirectory(tests)
endif()
