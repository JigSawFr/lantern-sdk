# Lantern::curl: a Transport over libcurl and its TLS (curl_transport.hpp).
add_library(lantern_curl curl_transport.cpp)
add_library(Lantern::curl ALIAS lantern_curl)
set_target_properties(lantern_curl PROPERTIES EXPORT_NAME curl POSITION_INDEPENDENT_CODE ON)
target_include_directories(lantern_curl PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/lantern/adapters>)
target_link_libraries(lantern_curl PUBLIC Lantern::lantern PRIVATE CURL::libcurl)
lantern_warnings(lantern_curl)
if (LANTERN_NO_EXCEPTIONS)
    lantern_no_exceptions(lantern_curl)
endif ()
