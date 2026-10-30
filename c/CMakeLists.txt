# The C API of the Lantern client library: Lantern::c (shared) and
# Lantern::c_static, over the C++ library of ../cpp (README.md).
#
# Built on its own (cmake -S c), it adds ../cpp as a subdirectory, with the
# TLS adapters it finds; added by an app that already has Lantern::lantern
# (add_subdirectory of cpp/, then of c/), it uses that one; with
# -DLANTERN_C_CPP=PACKAGE, the installed one (find_package(Lantern)).
cmake_minimum_required(VERSION 3.28)

# The versions, from the header that states them
file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/include/lantern/lantern.h LANTERN_C_VERSION_LINES
    REGEX "^#define LANTERN_(C_API_VERSION|C_ABI_VERSION|VERSION_STRING) ")
foreach (line IN LISTS LANTERN_C_VERSION_LINES)
    if (line MATCHES "^#define LANTERN_C_API_VERSION ([0-9]+)")
        set(LANTERN_C_API_VERSION ${CMAKE_MATCH_1})
    elseif (line MATCHES "^#define LANTERN_C_ABI_VERSION ([0-9]+)")
        set(LANTERN_C_ABI_VERSION ${CMAKE_MATCH_1})
    elseif (line MATCHES "^#define LANTERN_VERSION_STRING \"([0-9.]+)\"")
        set(LANTERN_C_VERSION ${CMAKE_MATCH_1})
    endif ()
endforeach ()

project(LanternC
    VERSION ${LANTERN_C_VERSION}
    DESCRIPTION "C API of the Lantern protocol's client library"
    HOMEPAGE_URL "https://github.com/JigSawFr/lantern-sdk"
    LANGUAGES C CXX)

if (PROJECT_IS_TOP_LEVEL AND NOT CMAKE_CROSSCOMPILING)
    set(LANTERN_C_TESTS_DEFAULT ON)
else ()
    set(LANTERN_C_TESTS_DEFAULT OFF)
endif ()
# A console builds no shared library
if (CMAKE_SYSTEM_NAME MATCHES "^(Generic|NintendoSwitch|Nintendo3DS|Emscripten)$" OR VITA OR PS4)
    set(LANTERN_C_SHARED_DEFAULT OFF)
else ()
    set(LANTERN_C_SHARED_DEFAULT ON)
endif ()

option(LANTERN_C_BUILD_TESTS "The C API's tests (C11), the reference server's included" ${LANTERN_C_TESTS_DEFAULT})
option(LANTERN_C_BUILD_EXAMPLES "The example in C (examples/read_library.c)" ${LANTERN_C_TESTS_DEFAULT})
option(LANTERN_C_SHARED "Lantern::c, the shared library" ${LANTERN_C_SHARED_DEFAULT})
option(LANTERN_C_INSTALL "Install rules and the CMake package LanternC" ${PROJECT_IS_TOP_LEVEL})
option(LANTERN_HARDENING "Hardening flags for every target, the C++ library's and the tests included (the presets set it)" OFF)
set(LANTERN_C_CPP SOURCE CACHE STRING "Where Lantern::lantern comes from: SOURCE (../cpp) or PACKAGE (find_package)")
set_property(CACHE LANTERN_C_CPP PROPERTY STRINGS SOURCE PACKAGE)

include(GNUInstallDirs)

# Before the C++ library, whose folder takes them too
if (LANTERN_HARDENING)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../cpp/cmake/LanternHardening.cmake)
endif ()

# The C++ library ---------------------------------------------------------
if (NOT TARGET Lantern::lantern)
    if (LANTERN_C_CPP STREQUAL "PACKAGE")
        find_package(Lantern ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR} REQUIRED)
    else ()
        # Linked into a shared library: position-independent code everywhere
        set(CMAKE_POSITION_INDEPENDENT_CODE ON)
        # The adapters, as cpp/ builds them on its own for this machine
        if (PROJECT_IS_TOP_LEVEL AND NOT CMAKE_CROSSCOMPILING)
            if (NOT DEFINED LANTERN_CURL)
                set(LANTERN_CURL AUTO CACHE STRING "Lantern::curl, over libcurl: AUTO, ON or OFF")
            endif ()
            if (NOT DEFINED LANTERN_MBEDTLS)
                set(LANTERN_MBEDTLS AUTO CACHE STRING "Lantern::mbedtls, over mbedTLS: AUTO, ON or OFF")
            endif ()
        endif ()
        set(LANTERN_BUILD_TESTS OFF)
        set(LANTERN_BUILD_EXAMPLES OFF)
        # The static library's install needs Lantern::lantern's
        set(LANTERN_INSTALL ${LANTERN_C_INSTALL})
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../cpp ${CMAKE_CURRENT_BINARY_DIR}/cpp)
    endif ()
endif ()

if (NOT COMMAND lantern_warnings)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../cpp/cmake/LanternWarnings.cmake)
endif ()

# The C warnings: lantern_warnings() is C++'s
function(lantern_c_warnings target)
    if (MSVC)
        target_compile_options(${target} PRIVATE /W4 /utf-8 $<$<BOOL:${LANTERN_WERROR}>:/WX>)
    else ()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wcast-align
            -Wdouble-promotion -Wformat=2 -Wundef -Wvla
            $<$<COMPILE_LANGUAGE:C>:-Wstrict-prototypes -Wmissing-prototypes>
            $<$<BOOL:${LANTERN_WERROR}>:-Werror>)
    endif ()
endfunction()

# The library -------------------------------------------------------------
set(LANTERN_C_SOURCES
    src/callbacks.cpp
    src/client.cpp
    src/common.cpp
    src/crypto.cpp
    src/discovery.cpp
    src/events.cpp
    src/generated/documents.cpp
    src/homebrew.cpp
    src/peers.cpp
    src/saves.cpp
    src/state.cpp
    src/static_library.cpp
    src/sync.cpp
    src/transports.cpp)

# Compiled once, for both libraries
add_library(lantern_c_objects OBJECT ${LANTERN_C_SOURCES})
target_compile_features(lantern_c_objects PUBLIC cxx_std_23)
set_target_properties(lantern_c_objects PROPERTIES
    CXX_EXTENSIONS OFF
    CXX_SCAN_FOR_MODULES OFF
    POSITION_INDEPENDENT_CODE ON
    # Only what LANTERN_API marks leaves the library
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON)
target_include_directories(lantern_c_objects
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(lantern_c_objects PRIVATE LANTERN_C_BUILD)
target_link_libraries(lantern_c_objects PRIVATE Lantern::lantern)
lantern_warnings(lantern_c_objects)
if (LANTERN_NO_EXCEPTIONS)
    lantern_no_exceptions(lantern_c_objects)
endif ()

# The library's own transports, when cpp/ built them
set(LANTERN_C_ADAPTERS Lantern::lantern)
if (TARGET Lantern::curl)
    # curl_global_init(): libcurl's own target, imported here too
    find_package(CURL 7.85 REQUIRED)
    target_compile_definitions(lantern_c_objects PRIVATE LANTERN_C_HAS_CURL)
    target_link_libraries(lantern_c_objects PRIVATE Lantern::curl CURL::libcurl)
    list(APPEND LANTERN_C_ADAPTERS Lantern::curl CURL::libcurl)
endif ()
if (TARGET Lantern::mbedtls)
    target_compile_definitions(lantern_c_objects PRIVATE LANTERN_C_HAS_MBEDTLS)
    target_link_libraries(lantern_c_objects PRIVATE Lantern::mbedtls)
    list(APPEND LANTERN_C_ADAPTERS Lantern::mbedtls)
endif ()
if (WIN32)
    list(APPEND LANTERN_C_ADAPTERS bcrypt)
endif ()

# Lantern::c_static
add_library(lantern_c_static STATIC $<TARGET_OBJECTS:lantern_c_objects>)
add_library(Lantern::c_static ALIAS lantern_c_static)
target_include_directories(lantern_c_static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_definitions(lantern_c_static INTERFACE LANTERN_C_STATIC)
target_link_libraries(lantern_c_static PUBLIC ${LANTERN_C_ADAPTERS})
set_target_properties(lantern_c_static PROPERTIES
    EXPORT_NAME c_static
    # The static library is a C++ one inside: a C program links it with the C++ runtime
    LINKER_LANGUAGE CXX)
# liblantern_c.a next to liblantern_c.so; on Windows, the DLL's import
# library has that name
if (WIN32)
    set_target_properties(lantern_c_static PROPERTIES OUTPUT_NAME lantern_c_static)
else ()
    set_target_properties(lantern_c_static PROPERTIES OUTPUT_NAME lantern_c)
endif ()

# Lantern::c, the shared library: a versioned SONAME (liblantern_c.so.1),
# and nothing exported but lantern_*
if (LANTERN_C_SHARED)
    add_library(lantern_c SHARED $<TARGET_OBJECTS:lantern_c_objects>)
    add_library(Lantern::c ALIAS lantern_c)
    target_include_directories(lantern_c PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    target_link_libraries(lantern_c PRIVATE ${LANTERN_C_ADAPTERS})
    set_target_properties(lantern_c PROPERTIES
        EXPORT_NAME c
        LINKER_LANGUAGE CXX
        # liblantern_c.so.1 -> liblantern_c.so.1.<API version>.0
        VERSION ${LANTERN_C_ABI_VERSION}.${LANTERN_C_API_VERSION}.0
        SOVERSION ${LANTERN_C_ABI_VERSION})
    if (APPLE)
        target_link_options(lantern_c PRIVATE
            "LINKER:-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/src/exports.apple")
        set_property(TARGET lantern_c APPEND PROPERTY LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/exports.apple)
    elseif (NOT WIN32)
        # GNU ld, gold and lld: the static libraries' symbols stay inside
        target_link_options(lantern_c PRIVATE
            "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/src/exports.map"
            "LINKER:--exclude-libs,ALL")
        # Every symbol resolved at link time; but a sanitizer's runtime comes
        # with the program (clang links it into executables only)
        if (NOT CMAKE_CXX_FLAGS MATCHES "-fsanitize")
            target_link_options(lantern_c PRIVATE "LINKER:--no-undefined")
        endif ()
        set_property(TARGET lantern_c APPEND PROPERTY LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/exports.map)
    endif ()
endif ()

# The example, README.md's, built to keep it true
if (LANTERN_C_BUILD_EXAMPLES)
    add_executable(lantern_c_read_library examples/read_library.c)
    set_target_properties(lantern_c_read_library PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        LINKER_LANGUAGE CXX)
    target_link_libraries(lantern_c_read_library PRIVATE Lantern::c_static)
    # Plain fopen, as README.md shows it; Microsoft's CRT calls it unsafe
    target_compile_definitions(lantern_c_read_library PRIVATE $<$<BOOL:${WIN32}>:_CRT_SECURE_NO_WARNINGS>)
    lantern_c_warnings(lantern_c_read_library)
endif ()

# Tests -------------------------------------------------------------------
if (LANTERN_C_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif ()

# Install -----------------------------------------------------------------
if (LANTERN_C_INSTALL)
    include(CMakePackageConfigHelpers)
    set(LANTERN_C_TARGETS lantern_c_static)
    if (TARGET lantern_c)
        list(APPEND LANTERN_C_TARGETS lantern_c)
    endif ()
    install(TARGETS ${LANTERN_C_TARGETS} EXPORT LanternCTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES include/lantern/lantern.h include/lantern/lantern_documents.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/lantern)
    install(EXPORT LanternCTargets
        NAMESPACE Lantern::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LanternC)
    configure_package_config_file(cmake/LanternCConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/LanternCConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LanternC)
    write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/LanternCConfigVersion.cmake
        COMPATIBILITY SameMajorVersion)
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/LanternCConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/LanternCConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LanternC)
endif ()
