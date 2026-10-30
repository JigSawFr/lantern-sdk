# The tests (doctest, third_party/doctest): unit tests with no network, and
# integration tests against the specification's reference server.
set(LANTERN_SPEC_DIR "${PROJECT_SOURCE_DIR}/../spec" CACHE PATH "The specification (the submodule spec/)")
# The repository's malicious test server, shared between languages: the
# integration tests run each of its scenarios when it is there (a sparse
# checkout of cpp/ alone has none)
set(LANTERN_HOSTILE_SERVER "${PROJECT_SOURCE_DIR}/../python/tools/hostile_server.py" CACHE FILEPATH
    "python/tools/hostile_server.py, or empty for none")
if (LANTERN_HOSTILE_SERVER AND EXISTS "${LANTERN_HOSTILE_SERVER}")
    set(LANTERN_HOSTILE_ARGS --hostile-server ${LANTERN_HOSTILE_SERVER})
else ()
    set(LANTERN_HOSTILE_ARGS)
endif ()

add_library(lantern_doctest INTERFACE)
target_include_directories(lantern_doctest SYSTEM INTERFACE ${PROJECT_SOURCE_DIR}/third_party/doctest)
# The real <ostream> rather than doctest's own declarations, which Microsoft's
# standard library does not accept when a std::string_view is printed. On
# Windows only: elsewhere it pulls in <ciso646>, which libstdc++ 15 warns
# about in C++20.
target_compile_definitions(lantern_doctest INTERFACE $<$<BOOL:${WIN32}>:DOCTEST_CONFIG_USE_STD_HEADERS>)
# doctest names its test cases with __COUNTER__, which recent clang reports as
# a C2y extension; an older clang does not know the warning, hence the first
# flag. Under clang it also includes <ciso646>, whose #warning libstdc++ 15
# raises in C++20.
target_compile_options(lantern_doctest INTERFACE
    $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-unknown-warning-option;-Wno-c2y-extensions;-Wno-\#warnings>)
if (LANTERN_NO_EXCEPTIONS)
    # REQUIRE ends the run instead of throwing
    target_compile_definitions(lantern_doctest INTERFACE DOCTEST_CONFIG_NO_EXCEPTIONS_BUT_WITH_ALL_ASSERTS)
endif ()

if (LANTERN_BUILD_TESTS)
    add_executable(lantern_unit_tests
        unit/main.cpp
        unit/client_tests.cpp
        unit/crypto_tests.cpp
        unit/document_tests.cpp
        unit/homebrew_tests.cpp
        unit/json_tests.cpp
        unit/paths_tests.cpp
        unit/profiles_tests.cpp
        unit/requires_tests.cpp
        unit/signing_tests.cpp
        unit/v04_client_tests.cpp
        unit/v05_client_tests.cpp
        unit/v05_vectors_tests.cpp)
    target_link_libraries(lantern_unit_tests PRIVATE Lantern::lantern lantern_doctest)
    target_compile_definitions(lantern_unit_tests PRIVATE LANTERN_SPEC_DIR="${LANTERN_SPEC_DIR}"
        $<$<BOOL:${WIN32}>:_CRT_SECURE_NO_WARNINGS>)
    lantern_warnings(lantern_unit_tests)
    if (LANTERN_NO_EXCEPTIONS)
        lantern_no_exceptions(lantern_unit_tests)
    endif ()
    add_test(NAME unit COMMAND lantern_unit_tests)

    # Against the reference server (spec/server), on loopback: Python 3 and
    # the POSIX adapter
    find_package(Python3 COMPONENTS Interpreter)
    if (Python3_FOUND AND TARGET lantern_posix_http)
        add_executable(lantern_integration_tests integration/main.cpp integration/client_tests.cpp
            integration/v04_tests.cpp integration/v05_tests.cpp integration/hostile_tests.cpp)
        target_link_libraries(lantern_integration_tests PRIVATE Lantern::lantern Lantern::posix_http lantern_doctest)
        lantern_warnings(lantern_integration_tests)
        if (LANTERN_NO_EXCEPTIONS)
            lantern_no_exceptions(lantern_integration_tests)
        endif ()
        add_test(NAME integration
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/integration/run_server.py
                --spec ${LANTERN_SPEC_DIR} ${LANTERN_HOSTILE_ARGS} -- $<TARGET_FILE:lantern_integration_tests>)
        set_tests_properties(integration PROPERTIES TIMEOUT 600)

        # Each TLS adapter against the reference server over HTTPS
        # (run_server.py --tls, which needs openssl)
        find_program(LANTERN_OPENSSL openssl)
        foreach (adapter curl mbedtls)
            if (TARGET lantern_${adapter} AND LANTERN_OPENSSL)
                add_executable(lantern_tls_${adapter}_tests integration/main.cpp integration/tls_tests.cpp
                    integration/tls_${adapter}.cpp integration/hostile_tests.cpp)
                target_compile_definitions(lantern_tls_${adapter}_tests PRIVATE LANTERN_HOSTILE_TLS)
                target_link_libraries(lantern_tls_${adapter}_tests PRIVATE
                    Lantern::lantern Lantern::${adapter} Lantern::posix_http lantern_doctest)
                if (adapter STREQUAL "curl")
                    target_link_libraries(lantern_tls_${adapter}_tests PRIVATE CURL::libcurl)
                elseif (TARGET MbedTLS::mbedtls)
                    target_link_libraries(lantern_tls_${adapter}_tests PRIVATE MbedTLS::mbedtls)
                else ()
                    target_include_directories(lantern_tls_${adapter}_tests SYSTEM PRIVATE ${LANTERN_MBEDTLS_INCLUDE_DIR})
                endif ()
                lantern_warnings(lantern_tls_${adapter}_tests)
                if (LANTERN_NO_EXCEPTIONS)
                    lantern_no_exceptions(lantern_tls_${adapter}_tests)
                endif ()
                add_test(NAME tls_${adapter}
                    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/integration/run_server.py
                        --spec ${LANTERN_SPEC_DIR} --tls ${LANTERN_HOSTILE_ARGS} -- $<TARGET_FILE:lantern_tls_${adapter}_tests>)
                set_tests_properties(tls_${adapter} PROPERTIES TIMEOUT 600)
            endif ()
        endforeach ()
    endif ()
endif ()

if (LANTERN_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif ()
