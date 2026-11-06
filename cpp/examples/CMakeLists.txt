# The README's examples, over the loopback adapter
foreach (example read_library pair_device)
    add_executable(lantern_${example} ${example}.cpp)
    target_link_libraries(lantern_${example} PRIVATE Lantern::lantern Lantern::posix_http)
    lantern_warnings(lantern_${example})
    if (LANTERN_NO_EXCEPTIONS)
        lantern_no_exceptions(lantern_${example})
    endif ()
endforeach ()

# The server core over a fictional library, for the conformance run
# (tests/integration/run_conformance.py)
add_executable(lantern_demo_server demo_server.cpp)
target_link_libraries(lantern_demo_server PRIVATE Lantern::lantern Lantern::posix_http Lantern::posix_server)
lantern_warnings(lantern_demo_server)
if (LANTERN_NO_EXCEPTIONS)
    lantern_no_exceptions(lantern_demo_server)
endif ()
