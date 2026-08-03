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

project(qbm-http VERSION 3.0.0)

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
        auth/manager.cpp
        ws/ws.cpp
        2/http2.cpp
        2/client.cpp
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
        3/client.cpp
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
        headers.cpp
        date.cpp
        cookie.cpp
        multipart.cpp
        # Body
        request.cpp
        response.cpp
        body.cpp
        1.1/http.cpp
        1.1/client.cpp
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
        2/protocol/base.cpp
        2/protocol/hpack.cpp
        2/protocol/hpack_huffman.cpp
        2/protocol/stream.cpp
        # Core (decl/def split)
        message_base.cpp
        types.cpp
        utility.cpp
        origin.cpp
        # Auth
        auth/options.cpp
        auth/user.cpp
        # Validation
        validation/error.cpp
        validation/parameter_validator.cpp
        validation/request_validator.cpp
        validation/rule.cpp
        validation/sanitizer.cpp
        validation/schema_validator.cpp
        # Middleware (non-template helpers split out of headers)
        middleware/cors.cpp
        middleware/compression.cpp
        middleware/rate_limit.cpp
        middleware/recaptcha.cpp
        middleware/security_headers.cpp
        middleware/static_files.cpp
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
