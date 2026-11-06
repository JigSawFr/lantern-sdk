// Draft 0.11: the form of a server's `uid` (SPEC.md § 4.2, L-4.2-9) and the
// TLS floor (§ 2, L-2-9).
#include <doctest.h>

#include <lantern/lantern.hpp>

using namespace lantern;

TEST_CASE("v11: a uid is a lower case random UUID, version 4 or 7")
{
    CHECK(is_valid_server_uid("6f1c2a8e-0b3d-4c5e-9a7f-1d2e3f4a5b6c"));
    CHECK(is_valid_server_uid("01926f3c-7a4e-7b2a-8c9d-0e1f2a3b4c5d"));
    CHECK_FALSE(is_valid_server_uid("6f1c2a8e-0b3d-1c5e-9a7f-1d2e3f4a5b6c")); // version 1
    CHECK_FALSE(is_valid_server_uid("6f1c2a8e-0b3d-6c5e-9a7f-1d2e3f4a5b6c")); // version 6
    CHECK_FALSE(is_valid_server_uid("6f1c2a8e-0b3d-5c5e-9a7f-1d2e3f4a5b6c")); // version 5
    CHECK_FALSE(is_valid_server_uid("6f1c2a8e-0b3d-4c5e-1a7f-1d2e3f4a5b6c")); // variant
    CHECK_FALSE(is_valid_server_uid("6F1C2A8E-0B3D-4C5E-9A7F-1D2E3F4A5B6C")); // upper case
    CHECK_FALSE(is_valid_server_uid("6f1c2a8e0b3d4c5e9a7f1d2e3f4a5b6c")); // no dashes
    CHECK_FALSE(is_valid_server_uid("6f1c2a8e-0b3d-4c5e-9a7f-1d2e3f4a5b6")); // short
    CHECK_FALSE(is_valid_server_uid("6f1c2a8e-0b3d-4c5e-9a7f-1d2e3f4a5b6g")); // not hex
    CHECK_FALSE(is_valid_server_uid(""));
}

TEST_CASE("v11: the TLS floor is 1.2")
{
    CHECK(minimum_tls_version == TlsVersion::tls_1_2);
    CHECK(static_cast<unsigned>(minimum_tls_version) == 0x0303U);
}
