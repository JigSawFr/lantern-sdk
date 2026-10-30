# The README's examples, over the loopback adapter
foreach (example read_library pair_device)
    add_executable(lantern_${example} ${example}.cpp)
    target_link_libraries(lantern_${example} PRIVATE Lantern::lantern Lantern::posix_http)
    lantern_warnings(lantern_${example})
    if (LANTERN_NO_EXCEPTIONS)
        lantern_no_exceptions(lantern_${example})
    endif ()
endforeach ()
