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
target_include_directories(loopkb PUBLIC include)

# Testing (CUnit)
enable_testing()
find_package(PkgConfig REQUIRED)
pkg_check_modules(CUNIT REQUIRED cunit)
add_executable(test_libloopkb test/test_loopkb.c)
target_include_directories(test_libloopkb PRIVATE ${CUNIT_INCLUDE_DIRS} include)
target_link_libraries(test_libloopkb PRIVATE ${CUNIT_LIBRARIES} loopkb)
add_test(NAME LoopKB COMMAND test_libloopkb)
