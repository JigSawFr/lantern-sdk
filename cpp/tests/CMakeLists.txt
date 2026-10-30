# The tests (doctest, third_party/doctest): unit tests with no network, and
# integration tests against the specification's reference server.
set(LANTERN_SPEC_DIR "${PROJECT_SOURCE_DIR}/../spec" CACHE PATH "The specification (the submodule spec/)")

add_library(lantern_doctest INTERFACE)
target_include_directories(lantern_doctest SYSTEM INTERFACE ${PROJECT_SOURCE_DIR}/third_party/doctest)
# The real <ostream> rather than doctest's own declarations, which Microsoft's
# standard library does not accept when a std::string_view is printed.
target_compile_definitions(lantern_doctest INTERFACE DOCTEST_CONFIG_USE_STD_HEADERS)
# doctest names its test cases with __COUNTER__, which recent clang reports as
# a C2y extension; an older clang does not know the warning, hence the first
# flag.
target_compile_options(lantern_doctest INTERFACE
    $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-unknown-warning-option;-Wno-c2y-extensions>)
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
        unit/requires_tests.cpp)
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
        add_executable(lantern_integration_tests integration/main.cpp integration/client_tests.cpp)
        target_link_libraries(lantern_integration_tests PRIVATE Lantern::lantern Lantern::posix_http lantern_doctest)
        lantern_warnings(lantern_integration_tests)
        if (LANTERN_NO_EXCEPTIONS)
            lantern_no_exceptions(lantern_integration_tests)
        endif ()
        add_test(NAME integration
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/integration/run_server.py
                --spec ${LANTERN_SPEC_DIR} -- $<TARGET_FILE:lantern_integration_tests>)
        set_tests_properties(integration PROPERTIES TIMEOUT 300)
    endif ()
endif ()

if (LANTERN_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif ()
