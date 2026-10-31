# The warnings of Lantern's own code: high everywhere, errors with
# LANTERN_WERROR (the CI). Vendored code keeps its own. Left out, as the code
# would need changes per platform rather than fixes: -Wuseless-cast (a cast to
# std::size_t is needed on the 32-bit consoles), -Wcomma (the generated
# types), -Wzero-as-null-pointer-constant and -Wunused-macros (system headers'
# macros differ between the consoles' libraries).

function(lantern_warnings target)
    if (MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
        if (LANTERN_WERROR)
            target_compile_options(${target} PRIVATE /WX)
        endif ()
    else ()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic
            -Wconversion -Wsign-conversion
            -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
            -Woverloaded-virtual -Wnull-dereference -Wdouble-promotion
            -Wformat=2 -Wimplicit-fallthrough -Wundef
            -Wcast-qual -Wmissing-declarations
            $<$<COMPILE_LANGUAGE:CXX>:-Wextra-semi -Wsuggest-override -Wmismatched-tags>
            $<$<CXX_COMPILER_ID:GNU>:-Wduplicated-cond -Wduplicated-branches -Wlogical-op>
            $<$<AND:$<CXX_COMPILER_ID:GNU>,$<COMPILE_LANGUAGE:CXX>>:-Wredundant-tags>)
        if (LANTERN_WERROR)
            target_compile_options(${target} PRIVATE -Werror)
        endif ()
    endif ()
endfunction()

# -fno-exceptions -fno-rtti: the library throws nothing and asks nothing of
# RTTI; tests and examples are built the same way in the CI's job
function(lantern_no_exceptions target)
    if (MSVC)
        target_compile_options(${target} PRIVATE /EHs-c- /GR-)
        target_compile_definitions(${target} PRIVATE _HAS_EXCEPTIONS=0)
    else ()
        target_compile_options(${target} PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions -fno-rtti>)
    endif ()
endfunction()
