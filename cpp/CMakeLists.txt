# The C++23 library of the Lantern protocol: Lantern::lantern.
#
# Usable in two ways (README.md): as a subdirectory of an app (a submodule,
# add_subdirectory), or installed and found with find_package(Lantern).
cmake_minimum_required(VERSION 3.28)

project(Lantern
    VERSION 0.5.0 # x-release-please-version (the SDK's one version: RELEASING.md)
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

# Monocypher (third_party/monocypher, THIRD_PARTY_NOTICES.md): ed25519
# checks, XChaCha20-Poly1305 and the wipe of secrets. Built as its own object library, with its own (lower) warnings: it is
# vendored as published and never edited
add_library(lantern_monocypher OBJECT
    third_party/monocypher/monocypher.c
    third_party/monocypher/monocypher-ed25519.c)
target_include_directories(lantern_monocypher PRIVATE third_party/monocypher)
set_target_properties(lantern_monocypher PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON)

add_library(lantern
    src/admin.cpp
    src/client.cpp
    src/device_key.cpp
    src/digest.cpp
    src/discovery.cpp
    src/document.cpp
    src/download.cpp
    src/ed25519.cpp
    src/encoding.cpp
    src/encrypted_save.cpp
    src/error.cpp
    src/event_stream.cpp
    src/events.cpp
    src/generated/types.cpp
    src/hkdf.cpp
    src/homebrew.cpp
    src/http_signature.cpp
    src/json.cpp
    src/memory.cpp
    src/pairing.cpp
    src/paths.cpp
    src/peers.cpp
    src/pinning.cpp
    src/profiles.cpp
    src/requires.cpp
    src/sha256.cpp
    src/sharing.cpp
    src/static_library.cpp
    src/sync.cpp
    src/sync_client.cpp
    src/tls.cpp
    src/url.cpp
    src/writes.cpp
    $<TARGET_OBJECTS:lantern_monocypher>)
add_library(Lantern::lantern ALIAS lantern)

target_compile_features(lantern PUBLIC cxx_std_23)
# Position-independent, so that a shared library (the C API, an app's
# plugin) can link the static one
set_target_properties(lantern PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_EXTENSIONS OFF
    EXPORT_NAME lantern
    VERSION ${PROJECT_VERSION}
    SOVERSION 0)
target_include_directories(lantern
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        third_party/monocypher)
lantern_warnings(lantern)

if (LANTERN_NO_EXCEPTIONS)
    lantern_no_exceptions(lantern_monocypher)
    lantern_no_exceptions(lantern)
endif ()

# The TLS adapters, optional (cmake/LanternAdapters.cmake)
include(cmake/LanternAdapters.cmake)

if (LANTERN_BUILD_TESTS OR LANTERN_BUILD_EXAMPLES OR LANTERN_BUILD_FUZZERS)
    # The blocking HTTP/1.1 client over POSIX sockets, plain HTTP on
    # loopback only, /dev/urandom and a UDP socket: for tests and examples,
    # never for an app
    if (NOT WIN32)
        add_subdirectory(adapters/posix)
    endif ()
endif ()

if (LANTERN_BUILD_TESTS OR LANTERN_BUILD_FUZZERS)
    enable_testing()
    add_subdirectory(tests)
endif ()

if (LANTERN_BUILD_EXAMPLES AND NOT WIN32)
    add_subdirectory(examples)
endif ()

if (LANTERN_INSTALL)
    include(CMakePackageConfigHelpers)
    install(TARGETS lantern EXPORT LanternTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(DIRECTORY include/lantern DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    foreach (adapter curl mbedtls)
        if (TARGET lantern_${adapter})
            install(TARGETS lantern_${adapter} EXPORT LanternTargets
                ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
                LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
                RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
            install(FILES adapters/${adapter}/${adapter}_transport.hpp
                DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/lantern/adapters)
        endif ()
    endforeach ()
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
    # The library's own licence (the repository's, MIT), with what it vendors
    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/../LICENSES/MIT.txt)
        install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../LICENSES/MIT.txt
            DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/lantern RENAME LICENSE)
    endif ()
endif ()
