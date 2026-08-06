#
# qb - C++ Actor Framework
# Copyright (c) 2011-2026 qb - isndev (cpp.actor). All rights reserved.
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

cmake_minimum_required(VERSION 3.24)

project(qbm-http VERSION 3.0.0)

# This module is NOT standalone-configurable, and it says so here rather than dying on whichever
# qb_* command it happens to reach first.
#
# qbm modules are built as part of the qb-dev superproject, which include()s qb's cmake/ helpers
# before add_subdirectory()ing them: this file calls qb_status_message(), qb_register_module() and
# qb_add_test(), and an INSTALLED qb ships none of those (they are development-time helpers, not
# package content -- lib/cmake/qb/ carries only qbConfig, qbConfigVersion, qbTargets and the
# Find modules). Pointing CMAKE_PREFIX_PATH at an installed qb therefore does not help, which is
# exactly the mistake this guard is here to name: without it the first symptom is
#     CMake Error at CMakeLists.txt:22 (qb_status_message):
#       Unknown CMake command "qb_status_message".
# which reads like a missing include, not like "wrong entry point".
#
# To build this module: configure the qb-dev superproject root. To get an INSTALLABLE one:
#     cmake --preset package && cmake --build --preset package
#     cmake --install build/presets/package --prefix <prefix>
# then consume it with find_package(qbm-http CONFIG REQUIRED) -> qbm::http.
if(NOT COMMAND qb_status_message)
    message(FATAL_ERROR
        "[qbm-http] this module cannot be configured on its own.\n"
        "     It is built from the qb-dev superproject, which loads qb's CMake helpers "
        "(qb_status_message / qb_register_module / qb_add_test) first; an installed qb does not "
        "ship them, so CMAKE_PREFIX_PATH will not fix this.\n"
        "     Configure the superproject root instead, or use its `package` preset to produce an "
        "installable qbm-http and consume that with find_package(qbm-http CONFIG REQUIRED).")
endif()

# Check if qb framework is available
if(NOT QB_FOUND)
    qb_status_message("qb framework not found, skipping HTTP module")
    return()
endif()

if(QB_HAS_SSL)
    qb_status_message("HTTP SSL-backed features enabled")
else()
    qb_status_message("HTTP SSL-backed features disabled: HTTPS/WSS/JWT/HTTP3 and the HTTP/2 "
                      "transport (client + server session) will not be built; the HTTP/2 wire "
                      "codec under 2/protocol/ still is, so its unit tests keep running")
endif()

# Add the internal llhttp dependency
add_subdirectory(not-qb/llhttp)

set(QBM_HTTP_EXTRA_SOURCES)
set(QBM_HTTP_EXTRA_DEPENDS)
set(QBM_HTTP_EXTRA_DEFINES)

# SSL-only sources: the TRANSPORT halves of HTTP/2 only. 2/http2.cpp (server session +
# acceptor) and 2/client.cpp name qb::io::transport::stcp / saccept and qb::io::ssl::Context
# at class-definition scope, so they cannot even parse with QB_HAS_SSL=OFF. The four
# 2/protocol/*.cpp files below do NOT — see the unconditional SOURCES list.
if(QB_HAS_SSL)
    list(APPEND QBM_HTTP_EXTRA_SOURCES
        src/qbm/http/auth/manager.cpp
        src/qbm/http/ws/ws.cpp
        src/qbm/http/2/http2.cpp
        src/qbm/http/2/client.cpp
    )
    list(APPEND QBM_HTTP_EXTRA_DEFINES QBM_HTTP_HAS_SSL=1)
endif()

# Through the same FindNghttp3.cmake that this module installs for its find_package()
# consumers, so "HTTP/3 is available" is decided by ONE piece of code in both trees. It also
# produces an UNKNOWN IMPORTED target holding an absolute library path, which survives export
# intact -- the previous inline pkg_check_modules target carried link *directories* plus a
# bare `nghttp3` name, which does not.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
if(QB_HAS_QUIC)
    find_package(Nghttp3 QUIET)
endif()

if(QB_HAS_SSL AND QB_HAS_QUIC AND Nghttp3_FOUND)
    set(QBM_HTTP_HAS_HTTP3 TRUE)
    list(APPEND QBM_HTTP_EXTRA_SOURCES
        src/qbm/http/3/client.cpp
    )
    list(APPEND QBM_HTTP_EXTRA_DEPENDS Nghttp3::nghttp3)
    # QBM_HTTP_HAS_HTTP3 is defined PUBLIC below (after the target exists) so it
    # reaches both the module sources and consumers; no PRIVATE duplicate here.
    qb_status_message("HTTP/3 support enabled (nghttp3)")
else()
    set(QBM_HTTP_HAS_HTTP3 FALSE)
    qb_status_message("HTTP/3 support disabled (requires QB_HAS_SSL, QB_HAS_QUIC and libnghttp3)")
endif()

# Register the HTTP module using the new framework functions
qb_register_module(
    NAME http
    VERSION ${PROJECT_VERSION}
    DEPENDS qb-core llhttp ${QBM_HTTP_EXTRA_DEPENDS}
    SOURCES
        # Core files
        src/qbm/http/headers.cpp
        src/qbm/http/date.cpp
        src/qbm/http/cookie.cpp
        src/qbm/http/multipart.cpp
        # Body
        src/qbm/http/request.cpp
        src/qbm/http/response.cpp
        src/qbm/http/body.cpp
        src/qbm/http/1.1/http.cpp
        src/qbm/http/1.1/client.cpp
        # HTTP/2 wire codec — frame layer, HPACK (+ Huffman) and the stream state
        # machine. Transport-independent and OpenSSL-free (verified: no stcp/saccept/
        # ssl::Context anywhere under 2/protocol/), so it is built UNCONDITIONALLY and
        # the 12 pure-logic http2 unit tests link on QB_HAS_SSL=OFF. The TLS-bound
        # halves (2/http2.cpp, 2/client.cpp) stay in QBM_HTTP_EXTRA_SOURCES above.
        # Trade-off, stated plainly: an SSL-off libqbm-http then carries a codec no
        # transport can reach — h2 is TLS+ALPN only here, there is no h2c upgrade path.
        # Cost, measured on the feature-gates preset (Debug, arm64, clang): 2289 KiB of
        # objects and 3.8 s of compile CPU across the four TUs. Paid ONLY by SSL-off
        # builds — every other preset already compiled these exact files.
        src/qbm/http/2/protocol/base.cpp
        src/qbm/http/2/protocol/hpack.cpp
        src/qbm/http/2/protocol/hpack_huffman.cpp
        src/qbm/http/2/protocol/stream.cpp
        # Core (decl/def split)
        src/qbm/http/message_base.cpp
        src/qbm/http/types.cpp
        src/qbm/http/utility.cpp
        src/qbm/http/origin.cpp
        # Auth
        src/qbm/http/auth/options.cpp
        src/qbm/http/auth/user.cpp
        # Validation
        src/qbm/http/validation/error.cpp
        src/qbm/http/validation/parameter_validator.cpp
        src/qbm/http/validation/request_validator.cpp
        src/qbm/http/validation/rule.cpp
        src/qbm/http/validation/sanitizer.cpp
        src/qbm/http/validation/schema_validator.cpp
        # Middleware (non-template helpers split out of headers)
        src/qbm/http/middleware/cors.cpp
        src/qbm/http/middleware/compression.cpp
        src/qbm/http/middleware/rate_limit.cpp
        src/qbm/http/middleware/recaptcha.cpp
        src/qbm/http/middleware/security_headers.cpp
        src/qbm/http/middleware/static_files.cpp
        ${QBM_HTTP_EXTRA_SOURCES}
    DEFINES
        QBM_HTTP_VERSION="${PROJECT_VERSION}"
        ${QBM_HTTP_EXTRA_DEFINES}
    # llhttp is a bundled STATIC target that qbm-http links PUBLIC (1.1/protocol/base.h calls
    # http_init/http_execute inline), so its name appears in qbm-httpTargets.cmake and it must
    # travel in the same export set.
    EXPORT_EXTRA_TARGETS
        llhttp
    CONFIG_DEPENDENCIES
        cmake/qbm-httpDependencies.cmake.in
    INSTALL_CMAKE_FILES
        cmake/FindNghttp3.cmake
)

if(QBM_HTTP_HAS_HTTP3)
    target_compile_definitions(qbm-http PUBLIC QBM_HTTP_HAS_HTTP3=1)
endif()

# Add tests if enabled
if(QB_BUILD_TESTS)
    add_subdirectory(tests)
endif()
