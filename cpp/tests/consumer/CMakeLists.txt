# An app that uses Lantern, both ways README.md gives: the installed
# package (find_package), or the source folder (add_subdirectory, as a
# submodule). The CI builds and runs it each way.
cmake_minimum_required(VERSION 3.28)
project(LanternConsumer LANGUAGES CXX)

set(LANTERN_CONSUMER "package" CACHE STRING "package (find_package) or subdirectory (add_subdirectory)")
if (LANTERN_CONSUMER STREQUAL "subdirectory")
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../.. lantern)
else ()
    find_package(Lantern 0.4 REQUIRED)
endif ()

add_executable(lantern_consumer main.cpp)
target_link_libraries(lantern_consumer PRIVATE Lantern::lantern)
