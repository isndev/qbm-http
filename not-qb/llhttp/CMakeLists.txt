project(llhttp)

add_library(llhttp STATIC
        src/llhttp.c
        src/api.c
        src/http.c
)

# No PUBLIC include directory, on purpose.
#
# This is a FORK, not a swappable dependency: it is llhttp 9.2.1 regenerated with the `http_`
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
