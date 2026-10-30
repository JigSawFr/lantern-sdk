# The loopback adapter: tests and examples only, never installed
add_library(lantern_posix_http STATIC posix_http.cpp)
add_library(Lantern::posix_http ALIAS lantern_posix_http)
target_include_directories(lantern_posix_http PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(lantern_posix_http PUBLIC Lantern::lantern)
lantern_warnings(lantern_posix_http)
if (LANTERN_NO_EXCEPTIONS)
    lantern_no_exceptions(lantern_posix_http)
endif ()
