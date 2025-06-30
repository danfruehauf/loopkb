cmake_minimum_required (VERSION 3.14)
project (loopkb)

set(CMAKE_C_COMPILER gcc)

add_compile_options(-Wall -Wpedantic -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wno-unused-but-set-parameter -Wno-pragmas -Werror)
set(CMAKE_INCLUDE_CURRENT_DIR 1)

# libloopkb.so
file(GLOB_RECURSE LOOPKB_SRCS
	src/*.c
)
add_library(loopkb SHARED "${LOOPKB_SRCS}")
target_include_directories(loopkb PRIVATE include)
