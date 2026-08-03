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

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Nghttp3
    REQUIRED_VARS
        NGHTTP3_INCLUDE_DIR
        NGHTTP3_LIBRARY
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
