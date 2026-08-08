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

# -----------------------------------------------------------------------------
# Minimal superproject root -- the entry point from which this module's own CI (and
# a contributor's laptop) configures, builds and runs this module's test suite.
#
# WHY IT EXISTS
# -------------
# This module cannot be configured on its own, and its CMakeLists.txt says so with a
# FATAL_ERROR rather than dying on whichever qb_* command it reaches first: it calls
# qb_status_message() / qb_register_module() / qb_add_test(), which live in
# qb/cmake/qbFunctions.cmake and are DEVELOPMENT-TIME helpers an installed qb does not
# ship (lib/cmake/qb/ carries only qbConfig, qbConfigVersion, qbTargets and the Find
# modules). Pointing CMAKE_PREFIX_PATH at an installed qb therefore does not help.
#
# What the module does need is a root that add_subdirectory()es a qb SOURCE tree first
# and the module second -- which is exactly what the qb-dev superproject root does.
# qb-dev is private, so this file reproduces the handful of its lines that matter and
# takes the two trees as cache variables instead of assuming a fixed layout.
#
# HOW TO USE IT -- this is verbatim what .github/workflows/tests.yml runs
#     git clone --depth 1 -b develop https://github.com/isndev/qb ../qb
#     cmake -S .github/ci/superbuild -B ../build -G Ninja \
#           -DCMAKE_BUILD_TYPE=Release \
#           -DQBM_CI_QB_DIR="$PWD/../qb" \
#           -DQBM_CI_MODULE_DIR="$PWD"
#     cmake --build ../build --parallel
#     ctest --test-dir ../build -L 'module:qbm-<mod>'
# Build the module's test targets only (not qb's own ~174) by naming them; `ctest -N -L
# module:qbm-<mod>` lists them and every entry but one is also its target name.
#
# It is BYTE-IDENTICAL in qbm-http, qbm-pgsql and qbm-redis -- nothing in it names a
# module -- so it is reviewed once, and qb-dev's dev/agent/verify.sh asserts the three
# copies have not drifted.
#
# WHAT IT DELIBERATELY IS NOT
# ---------------------------
# Not a packaging entry point, and it cannot become one by accident: QB_INSTALL and
# QBM_INSTALL are forced OFF below, exactly as every qb-dev dev preset forces them. The
# only way to produce an INSTALLABLE qbm-<mod> is still qb-dev's `package` preset --
# see this module's CMakeLists.txt header.
#
# Not a substitute for qb-dev either. This root builds ONE module against qb; the
# superproject builds qb, all three modules and the examples together, and is what
# catches a change that is fine for one module and breaks another.
# -----------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.24)

# NONE first, then enable_language() after the argument checks below: a missing -D
# should report itself immediately, not after a compiler-identification probe.
project(qbm-ci-superbuild NONE)

foreach(_qbm_ci_var IN ITEMS QBM_CI_QB_DIR QBM_CI_MODULE_DIR)
    if(NOT ${_qbm_ci_var})
        message(FATAL_ERROR
            "${_qbm_ci_var} is required. Configure this root with:\n"
            "    cmake -S .github/ci/superbuild -B <build dir>"
            " -DQBM_CI_QB_DIR=<path to an isndev/qb checkout>"
            " -DQBM_CI_MODULE_DIR=<path to this module's checkout>")
    endif()
    get_filename_component(_qbm_ci_abs "${${_qbm_ci_var}}" ABSOLUTE)
    if(NOT EXISTS "${_qbm_ci_abs}/CMakeLists.txt")
        message(FATAL_ERROR
            "${_qbm_ci_var}=${${_qbm_ci_var}} does not contain a CMakeLists.txt "
            "(resolved to ${_qbm_ci_abs}).")
    endif()
    set(${_qbm_ci_var} "${_qbm_ci_abs}")
endforeach()

enable_language(C CXX)

# Position-independent code for the whole tree. qbConfig also sets this for the qb
# subtree, but a module's bundled static dependencies (qbm-http's llhttp) are loaded
# from THIS root scope, so it has to be set here too -- same reason, same line, as in
# the qb-dev superproject root.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Tests ON is the entire point of this root, so it is FORCEd: a stale cache or a
# generator that ignores a plain default must not be able to configure a "test" build
# with no tests in it. Benchmarks and examples are OFF because this root builds neither.
set(QB_BUILD_TESTS ON CACHE BOOL "Build tests" FORCE)
set(QB_BUILD_BENCHMARKS OFF CACHE BOOL "Build benchmarks" FORCE)
set(QB_BUILD_EXAMPLES OFF CACHE BOOL "Build examples" FORCE)

# See the header: this root is a test super-build, never an install target. Forcing both
# OFF also avoids qb's install(EXPORT qbTargets) hard generate error when a bundled
# dependency (zlib as `zlibstatic`) is built from source and is in no export set.
set(QB_INSTALL OFF CACHE BOOL "Install qb framework" FORCE)
set(QBM_INSTALL OFF CACHE BOOL "Install qbm modules" FORCE)

enable_testing()

add_subdirectory("${QBM_CI_QB_DIR}" "${CMAKE_BINARY_DIR}/qb")

# qb's helpers are the whole reason this root exists. If a checkout ever stops providing
# them, say that here -- the alternative is the module's own FATAL_ERROR firing one line
# later and reading as "you configured the module directly", which would be wrong and
# would send the next person looking in the wrong file.
foreach(_qbm_ci_cmd IN ITEMS qb_status_message qb_register_module qb_register_module_test)
    if(NOT COMMAND ${_qbm_ci_cmd})
        message(FATAL_ERROR
            "the qb checkout at ${QBM_CI_QB_DIR} defines no ${_qbm_ci_cmd}(). This root "
            "add_subdirectory()s a qb SOURCE tree precisely to get qb/cmake/qbFunctions.cmake; "
            "an installed qb, or a qb too old to carry that helper, cannot be used here.")
    endif()
endforeach()

# ANTI-VACUITY, at configure time. The module's CMakeLists.txt returns EARLY and silently
# when QB_FOUND is false, and its tests/ subtree is behind if(QB_BUILD_TESTS) -- either
# would leave this root configuring cleanly, building nothing, and letting `ctest -L
# module:qbm-<mod>` report `No tests were found!!!` with exit code 0. So count the
# registered test targets across the module's add_subdirectory() and require growth.
get_property(_qbm_ci_tests_before GLOBAL PROPERTY QB_TEST_TARGETS)
list(LENGTH _qbm_ci_tests_before _qbm_ci_before)

get_filename_component(_qbm_ci_name "${QBM_CI_MODULE_DIR}" NAME)
if(NOT _qbm_ci_name)
    set(_qbm_ci_name module)
endif()
add_subdirectory("${QBM_CI_MODULE_DIR}" "${CMAKE_BINARY_DIR}/qbm/${_qbm_ci_name}")

get_property(_qbm_ci_tests_after GLOBAL PROPERTY QB_TEST_TARGETS)
list(LENGTH _qbm_ci_tests_after _qbm_ci_after)
math(EXPR _qbm_ci_added "${_qbm_ci_after} - ${_qbm_ci_before}")

get_property(_qbm_ci_modules GLOBAL PROPERTY QB_MODULE_LIBRARIES)
if(NOT _qbm_ci_modules)
    message(FATAL_ERROR
        "${QBM_CI_MODULE_DIR} registered no qbm module. Its CMakeLists.txt returns early "
        "when QB_FOUND is false; this root would then build nothing and every count taken "
        "afterwards would be vacuous.")
endif()
if(_qbm_ci_added LESS 1)
    message(FATAL_ERROR
        "${_qbm_ci_modules} registered ${_qbm_ci_added} test targets. A test super-build "
        "with no tests in it is the one thing this root must not produce.")
endif()

qb_status_message("ci-superbuild: module ${_qbm_ci_modules}, ${_qbm_ci_added} test targets registered")
