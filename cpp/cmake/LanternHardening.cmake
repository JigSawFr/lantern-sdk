# The hardened build of the presets (CMakePresets.json: dev, release,
# noexcept): what a hardened distribution's compiler turns on, the same
# with every compiler and standard library of the CI. Off by default, so an
# app that adds this folder, a cross toolchain and the release builds keep
# their own flags; for every target of the folder that includes it, tests
# included. GCC and clang only: the Windows jobs build without the presets.
#
# - Every configuration: the stack protector, stack clash protection and, on
#   x86, control-flow protection (CET); full RELRO on ELF.
# - Optimised builds: _FORTIFY_SOURCE=3 (the libc's checked string and memory
#   functions; it needs optimisation, so not in Debug).
# - Debug: the standard library's own checks (_GLIBCXX_ASSERTIONS for
#   libstdc++, the debug hardening mode for libc++: bounds, iterators,
#   preconditions), and every automatic variable left uninitialised filled
#   with a pattern, so that reading one shows instead of passing by chance.
#
# Each flag is checked first: a compiler or target without it goes on
# without.

include_guard(GLOBAL)
include(CheckCXXCompilerFlag)
include(CheckLinkerFlag)

if (MSVC)
    return()
endif ()

foreach (flag -fstack-protector-strong -fstack-clash-protection -fcf-protection=full)
    string(MAKE_C_IDENTIFIER "LANTERN_HAS${flag}" var)
    check_cxx_compiler_flag(${flag} ${var})
    if (${var})
        add_compile_options(${flag})
    endif ()
endforeach ()

add_compile_options(
    "$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE;-D_FORTIFY_SOURCE=3>"
    "$<$<CONFIG:Debug>:-D_GLIBCXX_ASSERTIONS;-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG>")

check_cxx_compiler_flag(-ftrivial-auto-var-init=pattern LANTERN_HAS_AUTO_VAR_INIT)
if (LANTERN_HAS_AUTO_VAR_INIT)
    add_compile_options("$<$<CONFIG:Debug>:-ftrivial-auto-var-init=pattern>")
endif ()

if (NOT APPLE)
    check_linker_flag(CXX "LINKER:-z,relro,-z,now" LANTERN_HAS_RELRO)
    if (LANTERN_HAS_RELRO)
        add_link_options("LINKER:-z,relro,-z,now")
    endif ()
endif ()
