#
# Find libnghttp3 (the HTTP/3 message layer used by qbm-http's HTTP/3 support).
#
# Result variables:
#   Nghttp3_FOUND
#   Nghttp3_VERSION
#
# Imported targets:
#   Nghttp3::nghttp3
#
# Deliberately modelled on qb/cmake/FindNgtcp2.cmake, and used from BOTH sides:
# qbm/http/CMakeLists.txt calls find_package(Nghttp3) when building the module, and the
# installed qbm-httpDependencies.cmake calls find_dependency(Nghttp3) to re-create the same
# imported target for a find_package(qbm-http) consumer. One detection path, so the build
# tree and the installed tree cannot disagree about what "HTTP/3 is available" means.
#
# pkg-config is a HINT source only. The previous in-tree code built the imported target
# straight out of pkg_check_modules -- include dirs, link *directories* and a bare `nghttp3`
# link name. Exported verbatim, that leaves a consumer depending on a -L path that is right
# only by luck; find_library() resolves an absolute file instead.
#

find_package(PkgConfig QUIET)

if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_NGHTTP3 QUIET libnghttp3)
endif()

find_path(NGHTTP3_INCLUDE_DIR
    NAMES nghttp3/nghttp3.h
    HINTS ${PC_NGHTTP3_INCLUDEDIR} ${PC_NGHTTP3_INCLUDE_DIRS}
    PATHS /opt/homebrew/opt/libnghttp3 /usr/local/opt/libnghttp3
    PATH_SUFFIXES include
)

find_library(NGHTTP3_LIBRARY
    NAMES nghttp3
    HINTS ${PC_NGHTTP3_LIBDIR} ${PC_NGHTTP3_LIBRARY_DIRS}
    PATHS /opt/homebrew/opt/libnghttp3 /usr/local/opt/libnghttp3
    PATH_SUFFIXES lib
)

set(Nghttp3_VERSION "${PC_NGHTTP3_VERSION}")

# pkg-config is a HINT source, so on a host without it Nghttp3_VERSION came back EMPTY and no
# version constraint could ever have been enforced. version.h always ships beside the header.
if(NOT Nghttp3_VERSION AND NGHTTP3_INCLUDE_DIR AND EXISTS "${NGHTTP3_INCLUDE_DIR}/nghttp3/version.h")
    file(STRINGS "${NGHTTP3_INCLUDE_DIR}/nghttp3/version.h" _ng3_ver
         REGEX "^#define[ \t]+NGHTTP3_VERSION[ \t]+\"")
    if(_ng3_ver)
        string(REGEX REPLACE ".*\"([^\"]+)\".*" "\\1" Nghttp3_VERSION "${_ng3_ver}")
    endif()
    unset(_ng3_ver)
endif()

# Validate the API qbm-http ACTUALLY CALLS, not merely that some libnghttp3 exists.
#
# `3/protocol/connection.h` uses `nghttp3_tstamp` (the return type of its own now_ts()),
# `nghttp3_conn_read_stream2` and the `nghttp3_rand` callbacks field. None of the three exists
# in libnghttp3 1.8.0 -- which is what Debian ships. Header + library were found, so HTTP/3
# switched itself ON and the build then FAILED to compile, with a cascade whose first message
# ("no member named 'rand'") names neither the version nor the real cause. Detecting the API is
# what makes the gate honest: it is the same contract FindNgtcp2.cmake states for its crypto
# headers -- QUIC ON where the install is complete, a clean fallback-OFF where it is partial,
# never a hard compile error. Grepping the header rather than try_compile keeps this usable
# when cross-compiling and costs nothing.
set(NGHTTP3_HAS_REQUIRED_API FALSE)
if(NGHTTP3_INCLUDE_DIR AND EXISTS "${NGHTTP3_INCLUDE_DIR}/nghttp3/nghttp3.h")
    set(_ng3_missing "")
    foreach(_sym nghttp3_tstamp nghttp3_conn_read_stream2 nghttp3_rand)
        file(STRINGS "${NGHTTP3_INCLUDE_DIR}/nghttp3/nghttp3.h" _ng3_hit REGEX "${_sym}" LIMIT_COUNT 1)
        if(NOT _ng3_hit)
            list(APPEND _ng3_missing "${_sym}")
        endif()
    endforeach()
    if(_ng3_missing)
        message(STATUS "[qbm-http] libnghttp3 ${Nghttp3_VERSION} at ${NGHTTP3_INCLUDE_DIR} lacks "
                       "${_ng3_missing} — too old for qbm-http's HTTP/3 layer; HTTP/3 stays OFF.")
    else()
        set(NGHTTP3_HAS_REQUIRED_API TRUE)
    endif()
    unset(_ng3_missing)
    unset(_ng3_hit)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Nghttp3
    REQUIRED_VARS
        NGHTTP3_INCLUDE_DIR
        NGHTTP3_LIBRARY
        NGHTTP3_HAS_REQUIRED_API
    VERSION_VAR Nghttp3_VERSION
)

if(Nghttp3_FOUND AND NOT TARGET Nghttp3::nghttp3)
    add_library(Nghttp3::nghttp3 UNKNOWN IMPORTED)
    set_target_properties(Nghttp3::nghttp3 PROPERTIES
        IMPORTED_LOCATION "${NGHTTP3_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${NGHTTP3_INCLUDE_DIR}"
    )
endif()

mark_as_advanced(
    NGHTTP3_INCLUDE_DIR
    NGHTTP3_LIBRARY
)
