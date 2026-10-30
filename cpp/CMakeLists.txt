# The C++23 library of the Lantern protocol: Lantern::lantern.
#
# Usable in two ways (README.md): as a subdirectory of an app (a submodule,
# add_subdirectory), or installed and found with find_package(Lantern).
cmake_minimum_required(VERSION 3.28)

project(Lantern
    VERSION 0.3.0
    DESCRIPTION "Client library of the Lantern protocol"
    HOMEPAGE_URL "https://github.com/JigSawFr/lantern-sdk"
    LANGUAGES C CXX)

# Tests, examples and the desktop adapter only when Lantern is the project
# being built, on a machine that can run them; an app that adds this folder
# gets the library alone
if (PROJECT_IS_TOP_LEVEL AND NOT CMAKE_CROSSCOMPILING)
    set(LANTERN_TESTS_DEFAULT ON)
else ()
    set(LANTERN_TESTS_DEFAULT OFF)
endif ()

option(LANTERN_BUILD_TESTS "Unit and integration tests (doctest)" ${LANTERN_TESTS_DEFAULT})
option(LANTERN_BUILD_EXAMPLES "The example client, over the loopback adapter" ${LANTERN_TESTS_DEFAULT})
option(LANTERN_BUILD_FUZZERS "libFuzzer targets (clang only)" OFF)
option(LANTERN_WERROR "Warnings are errors (the CI sets it)" OFF)
option(LANTERN_NO_EXCEPTIONS "Build everything with -fno-exceptions -fno-rtti" OFF)
option(LANTERN_INSTALL "Install rules and the CMake package" ${PROJECT_IS_TOP_LEVEL})

include(GNUInstallDirs)

# C++23 without GNU extensions, for every target of this folder
set(CMAKE_CXX_EXTENSIONS OFF)
# No C++ modules here: no dependency scan, which some cross toolchains lack
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)
include(cmake/LanternWarnings.cmake)

add_library(lantern
    src/digest.cpp
    src/document.cpp
    src/encoding.cpp
    src/error.cpp
    src/json.cpp
    src/memory.cpp
    src/sha256.cpp)
add_library(Lantern::lantern ALIAS lantern)

target_compile_features(lantern PUBLIC cxx_std_23)
set_target_properties(lantern PROPERTIES
    CXX_EXTENSIONS OFF
    EXPORT_NAME lantern
    VERSION ${PROJECT_VERSION}
    SOVERSION 0)
target_include_directories(lantern
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
lantern_warnings(lantern)

if (LANTERN_NO_EXCEPTIONS)
    lantern_no_exceptions(lantern)
endif ()

if (LANTERN_INSTALL)
    include(CMakePackageConfigHelpers)
    install(TARGETS lantern EXPORT LanternTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(DIRECTORY include/lantern DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(EXPORT LanternTargets
        NAMESPACE Lantern::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Lantern)
    configure_package_config_file(cmake/LanternConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/LanternConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Lantern)
    write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/LanternConfigVersion.cmake
        COMPATIBILITY SameMinorVersion)
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/LanternConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/LanternConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Lantern)
    install(FILES THIRD_PARTY_NOTICES.md third_party/monocypher/LICENCE.md
        DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/lantern)
endif ()
