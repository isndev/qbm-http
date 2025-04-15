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

add_subdirectory(not-qb/llhttp)

qb_register_module(
        NAME http
        VERSION 1.0.0
        SOURCES
        headers.cpp
        date.cpp
        cookie.cpp
        multipart.cpp
        body.cpp
        auth.cpp
        routing/cors_options.cpp
        routing/radix_tree.cpp
        routing/router.cpp
        validation/validator.cpp
        validation/json_schema.cpp
        validation/query_validator.cpp
        validation/sanitizer.cpp
        validation/validation_context.cpp
        validation/validation_types.cpp
        http.cpp
        DEPENDENCIES
        llhttp
)

# Add example directory
# add_subdirectory(examples)

if (QB_BUILD_TEST)
    add_subdirectory(tests)
endif ()