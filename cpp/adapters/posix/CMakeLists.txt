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

# A minimal HTTP/1.1 listener for the server core (include/lantern/server.hpp):
# for the demo server and the conformance run, never for an app
add_library(lantern_posix_server STATIC server_posix.cpp)
add_library(Lantern::posix_server ALIAS lantern_posix_server)
target_include_directories(lantern_posix_server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(lantern_posix_server PUBLIC Lantern::lantern PRIVATE Lantern::posix_http)
lantern_warnings(lantern_posix_server)
if (LANTERN_NO_EXCEPTIONS)
    lantern_no_exceptions(lantern_posix_server)
endif ()
