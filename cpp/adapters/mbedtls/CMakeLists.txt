# Lantern::mbedtls: a Transport over mbedTLS and POSIX sockets
# (mbedtls_transport.hpp), with the HTTP/1.1 of adapters/http1 compiled in.
add_library(lantern_mbedtls
    mbedtls_transport.cpp
    ../http1/http1.cpp
    ../http1/tcp.cpp)
add_library(Lantern::mbedtls ALIAS lantern_mbedtls)
set_target_properties(lantern_mbedtls PROPERTIES EXPORT_NAME mbedtls)
target_include_directories(lantern_mbedtls
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/lantern/adapters>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../http1)
target_link_libraries(lantern_mbedtls PUBLIC Lantern::lantern)
if (TARGET MbedTLS::mbedtls)
    target_link_libraries(lantern_mbedtls PRIVATE MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::mbedcrypto)
else ()
    target_include_directories(lantern_mbedtls SYSTEM PRIVATE ${LANTERN_MBEDTLS_INCLUDE_DIR})
    target_link_libraries(lantern_mbedtls PRIVATE
        ${LANTERN_MBEDTLS_LIBRARY} ${LANTERN_MBEDX509_LIBRARY} ${LANTERN_MBEDCRYPTO_LIBRARY})
endif ()
lantern_warnings(lantern_mbedtls)
if (LANTERN_NO_EXCEPTIONS)
    lantern_no_exceptions(lantern_mbedtls)
endif ()
