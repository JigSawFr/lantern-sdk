# The POSIX adapters: tests and examples only, never installed. The
# loopback HTTP client (plain HTTP to 127.0.0.0/8 and ::1), /dev/urandom,
# and a UDP socket for discovery.
add_library(lantern_posix_http STATIC
    posix_http.cpp
    posix_system.cpp
    ../http1/http1.cpp
    ../http1/tcp.cpp)
add_library(Lantern::posix_http ALIAS lantern_posix_http)
target_include_directories(lantern_posix_http PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../http1)
target_link_libraries(lantern_posix_http PUBLIC Lantern::lantern)
lantern_warnings(lantern_posix_http)
if (LANTERN_NO_EXCEPTIONS)
    lantern_no_exceptions(lantern_posix_http)
endif ()
