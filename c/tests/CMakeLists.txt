# The C API's tests, in C11: unit tests (no network; the specification's
# examples and vectors), integration tests against the specification's
# reference server on loopback, the header compiled as C11, C17 and C++,
# and the ABI dump compared with c/abi/lantern.abi.
set(LANTERN_SPEC_DIR "${PROJECT_SOURCE_DIR}/../spec" CACHE PATH "The specification (the submodule spec/)")
find_package(Python3 COMPONENTS Interpreter REQUIRED)

# spec/vectors as a C header
set(LANTERN_C_VECTORS ${CMAKE_CURRENT_BINARY_DIR}/generated/vectors.h)
add_custom_command(OUTPUT ${LANTERN_C_VECTORS}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/generated
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/support/vectors.py
        --spec ${LANTERN_SPEC_DIR} --out ${LANTERN_C_VECTORS}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/support/vectors.py
        ${LANTERN_SPEC_DIR}/vectors/signatures.json ${LANTERN_SPEC_DIR}/vectors/spki.json
        ${LANTERN_SPEC_DIR}/vectors/paths.json
    COMMENT "spec/vectors as a C header")
add_custom_target(lantern_c_vectors DEPENDS ${LANTERN_C_VECTORS})

add_library(lantern_c_test_support STATIC support/harness.c support/support.c)
target_include_directories(lantern_c_test_support PUBLIC support ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_compile_definitions(lantern_c_test_support PUBLIC LANTERN_SPEC_DIR="${LANTERN_SPEC_DIR}"
    $<$<BOOL:${WIN32}>:_CRT_SECURE_NO_WARNINGS>)
target_include_directories(lantern_c_test_support PUBLIC ${PROJECT_SOURCE_DIR}/include)
set_target_properties(lantern_c_test_support PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
lantern_c_warnings(lantern_c_test_support)
add_dependencies(lantern_c_test_support lantern_c_vectors)

set(LANTERN_C_UNIT_SOURCES
    unit/main.c
    unit/basics_tests.c
    unit/client_tests.c
    unit/crypto_tests.c
    unit/discovery_tests.c
    unit/documents_tests.c
    unit/homebrew_tests.c
    unit/v05_tests.c)

# Against the shared library (what it exports is enough) and the static one
set(LANTERN_C_UNIT_VARIANTS static)
if (TARGET lantern_c)
    list(PREPEND LANTERN_C_UNIT_VARIANTS shared)
endif ()
foreach (variant IN LISTS LANTERN_C_UNIT_VARIANTS)
    set(target lantern_c_unit_tests_${variant})
    add_executable(${target} ${LANTERN_C_UNIT_SOURCES})
    # Linked as C++: a sanitizer's C++ runtime (UBSan's vptr checks) comes
    # with the program, and the shared library's C++ needs it
    set_target_properties(${target} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        LINKER_LANGUAGE CXX)
    if (variant STREQUAL "shared")
        target_link_libraries(${target} PRIVATE Lantern::c lantern_c_test_support)
    else ()
        target_link_libraries(${target} PRIVATE Lantern::c_static lantern_c_test_support)
    endif ()
    lantern_c_warnings(${target})
    add_test(NAME c_unit_${variant} COMMAND ${target})
    if (WIN32 AND variant STREQUAL "shared")
        set_tests_properties(c_unit_${variant} PROPERTIES
            ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:$<TARGET_FILE_DIR:lantern_c>")
    endif ()
endforeach ()

# The header alone, as C11, C17 and C++23, with every warning
add_library(lantern_c_header_c11 OBJECT support/header_check.c)
set_target_properties(lantern_c_header_c11 PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_library(lantern_c_header_c17 OBJECT support/header_check.c)
set_target_properties(lantern_c_header_c17 PROPERTIES C_STANDARD 17 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
add_library(lantern_c_header_cpp OBJECT support/header_check.cpp)
target_compile_features(lantern_c_header_cpp PRIVATE cxx_std_23)
foreach (target lantern_c_header_c11 lantern_c_header_c17 lantern_c_header_cpp)
    target_include_directories(${target} PRIVATE ${PROJECT_SOURCE_DIR}/include)
endforeach ()
lantern_c_warnings(lantern_c_header_c11)
lantern_c_warnings(lantern_c_header_c17)
lantern_warnings(lantern_c_header_cpp)
add_dependencies(lantern_c_test_support lantern_c_header_c11 lantern_c_header_c17 lantern_c_header_cpp)

# The ABI: the headers' dump is the one kept in c/abi, and the shared
# library exports exactly the functions it lists
set(LANTERN_C_ABI_ARGS)
if (TARGET lantern_c AND NOT WIN32)
    set(LANTERN_C_ABI_ARGS --library $<TARGET_FILE:lantern_c>)
endif ()
add_test(NAME c_abi
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/abi_dump.py --check ${LANTERN_C_ABI_ARGS})

# Against the reference server (spec/server), on loopback, through
# cpp/tests/integration/run_server.py and a transport of callbacks over the
# C++ tests' POSIX adapter
if (NOT WIN32)
    if (NOT TARGET lantern_posix_http)
        add_subdirectory(${PROJECT_SOURCE_DIR}/../cpp/adapters/posix ${CMAKE_CURRENT_BINARY_DIR}/posix)
    endif ()
    add_executable(lantern_c_integration_tests integration/integration_tests.c support/loopback.cpp)
    set_target_properties(lantern_c_integration_tests PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    target_compile_features(lantern_c_integration_tests PRIVATE cxx_std_23)
    if (TARGET lantern_c)
        target_link_libraries(lantern_c_integration_tests PRIVATE Lantern::c)
    else ()
        target_link_libraries(lantern_c_integration_tests PRIVATE Lantern::c_static)
    endif ()
    target_link_libraries(lantern_c_integration_tests PRIVATE lantern_c_test_support Lantern::posix_http)
    lantern_c_warnings(lantern_c_integration_tests)
    add_test(NAME c_integration
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/../cpp/tests/integration/run_server.py
            --spec ${LANTERN_SPEC_DIR} -- $<TARGET_FILE:lantern_c_integration_tests>)
    set_tests_properties(c_integration PROPERTIES TIMEOUT 300)
endif ()

# The JNI sketch's glue, where a JDK is (c/bindings/kotlin); Android's is
# the CI's NDK job
find_package(JNI QUIET)
if (JNI_FOUND AND NOT WIN32)
    add_subdirectory(${PROJECT_SOURCE_DIR}/bindings/kotlin/src/main/c ${CMAKE_CURRENT_BINARY_DIR}/jni)
endif ()

# README.md shows examples/read_library.c in full: the same text
add_test(NAME c_readme_example
    COMMAND ${Python3_EXECUTABLE} -c
        "import sys; sys.exit(0 if open(sys.argv[1], encoding='utf-8').read() in open(sys.argv[2], encoding='utf-8').read() else 'README.md does not show examples/read_library.c as it is')"
        ${PROJECT_SOURCE_DIR}/examples/read_library.c ${PROJECT_SOURCE_DIR}/README.md)
