project(llhttp)

# An OBJECT library, folded into qbm-http's own archive (qbm/http/CMakeLists.txt), never a library of
# its own (Huly QB-1139). As a STATIC target it travelled in qbm-http's export set and installed
# lib/libllhttp.a (lib/llhttp.lib), the very file name the vcpkg and Debian llhttp packages install:
# a file conflict for any packaging of qbm-http. Folded, there is no llhttp archive, no qbm::llhttp
# and nothing in the export set; its symbols link as qb_llhttp_* (src/qbm/http/vendor/llhttp.h).
add_library(llhttp OBJECT
        src/llhttp.c
        src/api.c
        src/http.c
)
# Its objects land in qbm-http, which may be a shared library: compile them position-independent
# whatever the parent project's CMAKE_POSITION_INDEPENDENT_CODE says.
set_target_properties(llhttp PROPERTIES POSITION_INDEPENDENT_CODE ON)

# No PUBLIC include directory, on purpose.
#
# This is a FORK, not a swappable dependency: it is llhttp (upstream commit 8371b40, whose version
# macros still say 9.2.1; THIRD-PARTY-NOTICES lists its local changes) regenerated with the `http_`
# symbol prefix (http_t, http_errno, http_init/http_execute), and a system llhttp cannot
# substitute for it. So it gets the same treatment as qb's own forks under
# qb/src/qb/vendor/ -- qbm-http OWNS the name and ships it inside its own header root:
# the single public header lives at qbm/http/src/qbm/http/vendor/llhttp.h and is included as
# <qbm/http/vendor/llhttp.h> (qbm/http/src/qbm/http/types.h). Two consequences:
#
#   * nothing named `llhttp.h` (nor the generator's `api.h` fragment left in include/, which
#     no translation unit includes) ever lands on a consumer's include path, where it would
#     shadow -- or be shadowed by -- a real llhttp;
#   * the header resolves through the SAME `qbm/` root as every other qbm header, in the
#     build tree and in the installed tree alike, so there is no second BUILD_INTERFACE /
#     INSTALL_INTERFACE pair to drift, and no bespoke install rule for this one file.
#
# The fork's own C sources say #include "llhttp.h"; the PRIVATE entry below keeps that
# working without editing vendored source. PRIVATE also means this target contributes no
# include directory to the export set -- a relative, genex-free PUBLIC include directory
# (what this line used to be) makes install(TARGETS llhttp EXPORT ...) a hard generate error.
target_include_directories(llhttp PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../src/qbm/http/vendor")
