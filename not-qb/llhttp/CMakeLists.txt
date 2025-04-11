project(llhttp)

add_library(llhttp STATIC
        src/llhttp.c
        src/api.c
        src/http.c
)

target_include_directories(llhttp PUBLIC include)