# An app of the C API, the two ways README.md gives: the package installed
# (-DLANTERN_CONSUMER=package, with CMAKE_PREFIX_PATH), or c/ as a
# subdirectory (-DLANTERN_CONSUMER=subdirectory). The CI builds and runs both.
cmake_minimum_required(VERSION 3.28)
project(LanternCConsumer LANGUAGES C CXX)

set(LANTERN_CONSUMER package CACHE STRING "package or subdirectory")
if (LANTERN_CONSUMER STREQUAL "package")
    find_package(LanternC 0.5 REQUIRED)
else ()
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../.. lantern-c)
endif ()

add_executable(lantern_c_consumer main.c)
set_target_properties(lantern_c_consumer PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
target_link_libraries(lantern_c_consumer PRIVATE Lantern::c)

# And the static library, linked by a C program with the C++ runtime
add_executable(lantern_c_consumer_static main.c)
set_target_properties(lantern_c_consumer_static PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
target_link_libraries(lantern_c_consumer_static PRIVATE Lantern::c_static)
