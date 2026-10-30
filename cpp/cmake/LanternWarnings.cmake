# The warnings of Lantern's own code: high everywhere, errors with
# LANTERN_WERROR (the CI). Vendored code keeps its own.

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
            $<$<CXX_COMPILER_ID:GNU>:-Wduplicated-cond -Wduplicated-branches -Wlogical-op>)
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
