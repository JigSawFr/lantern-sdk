# The TLS adapters (adapters/curl, adapters/mbedtls): optional targets, so
# that Lantern::lantern itself needs nothing. Each is AUTO (built when its
# library is found), ON (required) or OFF. AUTO is the default only when
# Lantern is the project being built for the machine it runs on; an app
# that adds this folder, and a cross build, ask for them with ON.

if (PROJECT_IS_TOP_LEVEL AND NOT CMAKE_CROSSCOMPILING)
    set(LANTERN_ADAPTERS_DEFAULT AUTO)
else ()
    set(LANTERN_ADAPTERS_DEFAULT OFF)
endif ()
set(LANTERN_CURL ${LANTERN_ADAPTERS_DEFAULT} CACHE STRING "Lantern::curl, over libcurl: AUTO, ON or OFF")
set(LANTERN_MBEDTLS ${LANTERN_ADAPTERS_DEFAULT} CACHE STRING "Lantern::mbedtls, over mbedTLS: AUTO, ON or OFF")
set_property(CACHE LANTERN_CURL PROPERTY STRINGS AUTO ON OFF)
set_property(CACHE LANTERN_MBEDTLS PROPERTY STRINGS AUTO ON OFF)

set(LANTERN_HAS_CURL OFF)
if (NOT LANTERN_CURL STREQUAL "OFF")
    if (LANTERN_CURL STREQUAL "ON")
        find_package(CURL 7.85 REQUIRED)
    else ()
        find_package(CURL 7.85 QUIET)
    endif ()
    if (CURL_FOUND)
        set(LANTERN_HAS_CURL ON)
    endif ()
endif ()

# mbedTLS 3 installs a CMake package; 2.28, as most distributions and
# devkitPro's portlibs ship it, its headers and three libraries alone
set(LANTERN_HAS_MBEDTLS OFF)
set(LANTERN_MBEDTLS_PACKAGE OFF)
if (NOT LANTERN_MBEDTLS STREQUAL "OFF")
    find_package(MbedTLS CONFIG QUIET)
    if (TARGET MbedTLS::mbedtls)
        set(LANTERN_HAS_MBEDTLS ON)
        set(LANTERN_MBEDTLS_PACKAGE ON)
    else ()
        find_path(LANTERN_MBEDTLS_INCLUDE_DIR mbedtls/ssl.h)
        find_library(LANTERN_MBEDTLS_LIBRARY mbedtls)
        find_library(LANTERN_MBEDX509_LIBRARY mbedx509)
        find_library(LANTERN_MBEDCRYPTO_LIBRARY mbedcrypto)
        if (LANTERN_MBEDTLS_INCLUDE_DIR AND LANTERN_MBEDTLS_LIBRARY AND LANTERN_MBEDX509_LIBRARY
            AND LANTERN_MBEDCRYPTO_LIBRARY)
            set(LANTERN_HAS_MBEDTLS ON)
        endif ()
    endif ()
    if (LANTERN_MBEDTLS STREQUAL "ON" AND NOT LANTERN_HAS_MBEDTLS)
        message(FATAL_ERROR "LANTERN_MBEDTLS=ON, and mbedTLS is not found")
    endif ()
endif ()

# Both connect with POSIX sockets or libcurl's own; on Windows, libcurl only
if (WIN32)
    set(LANTERN_HAS_MBEDTLS OFF)
endif ()

if (LANTERN_HAS_CURL)
    add_subdirectory(adapters/curl)
endif ()
if (LANTERN_HAS_MBEDTLS)
    add_subdirectory(adapters/mbedtls)
endif ()
message(STATUS "Lantern: libcurl adapter ${LANTERN_HAS_CURL}, mbedTLS adapter ${LANTERN_HAS_MBEDTLS}")
