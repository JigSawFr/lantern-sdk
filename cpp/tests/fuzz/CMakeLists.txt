# libFuzzer targets (clang): the JSON tokenizer and DOM, manifests and
# paths, the problem reader, the homebrew entry reader and what a client
# does with an entry, ed25519, discovery datagrams, signed requests and
# certificates. The fuzz preset builds them with ASan and UBSan;
# corpus/<target> holds their seeds.
if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "LANTERN_BUILD_FUZZERS needs clang (libFuzzer)")
endif ()

foreach (target json paths problem homebrew signature discovery http_signature certificate)
    add_executable(lantern_fuzz_${target} fuzz_${target}.cpp)
    target_link_libraries(lantern_fuzz_${target} PRIVATE Lantern::lantern)
    target_link_options(lantern_fuzz_${target} PRIVATE -fsanitize=fuzzer)
    lantern_warnings(lantern_fuzz_${target})
endforeach ()
