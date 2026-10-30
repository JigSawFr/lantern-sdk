#include <doctest.h>

#include <string>

#include "support.hpp"

using namespace lantern;

TEST_CASE("profiles: Annex A's platforms")
{
    for (const char* name : { "switch", "3ds", "vita", "ps4", "android", "linux" })
    {
        CAPTURE(name);
        REQUIRE(find_profile(name) != nullptr);
    }
    CHECK_FALSE(find_profile("switch")->draft);
    CHECK(find_profile("vita")->draft);
    // Open platforms (A.7): no profile, nothing installed
    for (const char* name : { "ios", "windows", "macos", "web", "steam", "gog", "xbox", "x-example-console" })
    {
        CAPTURE(name);
        CHECK(find_profile(name) == nullptr);
    }
    CHECK_FALSE(find_profile("linux")->installs_apps);
    CHECK(find_profile("android")->newer_base_is_update);
    CHECK(profiles().size() == 6);
}

TEST_CASE("profiles: names of the core")
{
    CHECK(is_platform_name("switch"));
    CHECK(is_platform_name("3ds"));
    CHECK(is_platform_name("x-example-console"));
    CHECK_FALSE(is_platform_name("Switch"));
    CHECK_FALSE(is_platform_name("-switch"));
    CHECK_FALSE(is_platform_name(""));
    CHECK_FALSE(is_platform_name(std::string(33, 'a')));
    CHECK_FALSE(is_platform_name("swi tch"));

    CHECK(is_arch_name("aarch64"));
    CHECK(is_arch_name("x86_64"));
    CHECK(is_arch_name("loongarch64"));
    CHECK_FALSE(is_arch_name("arm64-v8a"));
    CHECK_FALSE(is_arch_name("X86"));
    CHECK_FALSE(is_arch_name(""));

    CHECK(is_homebrew_id("org.example.frostline"));
    CHECK(is_homebrew_id("org.example.frostline-port"));
    CHECK(is_homebrew_id("local.4f2a"));
    CHECK(is_homebrew_id("org.example.2048"));
    CHECK_FALSE(is_homebrew_id("frostline"));
    CHECK_FALSE(is_homebrew_id("Org.example.frostline"));
    CHECK_FALSE(is_homebrew_id("org..frostline"));
    CHECK_FALSE(is_homebrew_id("org.example."));
    CHECK_FALSE(is_homebrew_id("1org.example"));
    CHECK_FALSE(is_homebrew_id("org.example/x"));

    CHECK(is_core_id("0100ABCD00010000"));
    CHECK(is_core_id("org.example.frostlinetales"));
    CHECK_FALSE(is_core_id("a/b"));
    CHECK_FALSE(is_core_id(std::string(129, 'a')));
}

TEST_CASE("profiles: the Switch's ids (A.1)")
{
    const Profile& p = *find_profile("switch");
    CHECK(p.title_id("0100ABCD00010000"));
    CHECK_FALSE(p.title_id("0100ABCD00010800")); // an update's id
    CHECK_FALSE(p.title_id("0100abcd00010000")); // lower case
    CHECK_FALSE(p.title_id("0100ABCD0001000"));
    CHECK(p.app_id("base", "0100ABCD00010000", "0100ABCD00010000"));
    CHECK(p.app_id("update", "0100ABCD00010000", "0100ABCD00010800"));
    CHECK_FALSE(p.app_id("update", "0100ABCD00010000", "0100EFEF00020800"));
    CHECK(p.app_id("dlc", "0100ABCD00010000", "0100ABCD00011001"));
    CHECK_FALSE(p.app_id("dlc", "0100ABCD00010000", "0100ABCD00010000"));
    CHECK_FALSE(p.app_id("base", "0100ABCD00010000", "0100ABCD00010800"));
    CHECK_FALSE(p.app_id("mod", "0100ABCD00010000", "0100ABCD00010000"));
    CHECK(has_app_type(p, "dlc"));
    CHECK(has_app_format(p, "xcz"));
    CHECK_FALSE(has_app_format(p, "cia"));
}

TEST_CASE("profiles: the drafts' ids (A.2 to A.5)")
{
    const Profile& ds = *find_profile("3ds");
    CHECK(ds.title_id("0004000000ABCD00"));
    CHECK(ds.title_id("0004000200ABCD00"));
    CHECK_FALSE(ds.title_id("0004000E00ABCD00"));
    CHECK(ds.app_id("update", "0004000000ABCD00", "0004000E00ABCD00"));
    CHECK(ds.app_id("dlc", "0004000000ABCD00", "0004008C00ABCD00"));
    CHECK_FALSE(ds.app_id("update", "0004000000ABCD00", "0004000E00ABCD01"));

    const Profile& vita = *find_profile("vita");
    CHECK(vita.title_id("PCSE00000"));
    CHECK_FALSE(vita.title_id("pcse00000"));
    CHECK(vita.app_id("update", "PCSE00000", "PCSE00000"));
    CHECK(vita.app_id("dlc", "PCSE00000", "EP0001-PCSE00000_00-FROSTLINEPACK001"));
    CHECK_FALSE(vita.app_id("dlc", "PCSE00000", "EP0001-PCSE00001_00-FROSTLINEPACK001"));
    CHECK_FALSE(vita.app_id("dlc", "PCSE00000", "PCSE00000"));

    const Profile& ps4 = *find_profile("ps4");
    CHECK(ps4.title_id("CUSA00000"));
    CHECK_FALSE(ps4.title_id("CUSA0000"));
    CHECK_FALSE(ps4.title_id("CUS000000"));
    CHECK(ps4.app_id("dlc", "CUSA00000", "EP0001-CUSA00000_00-FROSTLINEPACK001"));

    const Profile& android = *find_profile("android");
    CHECK(android.title_id("org.example.frostlinetales"));
    CHECK(android.title_id("Org.Example_2.app"));
    CHECK_FALSE(android.title_id("frostline"));
    CHECK_FALSE(android.title_id("org.2example"));
    CHECK(android.app_id("base", "org.example.frostlinetales", "org.example.frostlinetales"));
    CHECK_FALSE(android.app_id("update", "org.example.frostlinetales", "org.example.frostlinetales"));
}

TEST_CASE("profiles: version_code (A.1 to A.5)")
{
    CHECK(find_profile("switch")->version_code("196608") == 196608U);
    CHECK(find_profile("switch")->version_code("v196608") == 196608U);
    CHECK(find_profile("switch")->version_code("0") == 0U);
    CHECK_FALSE(find_profile("switch")->version_code("1.3.0"));
    CHECK_FALSE(find_profile("switch")->version_code("4294967296"));
    CHECK_FALSE(find_profile("switch")->version_code("0196608"));
    CHECK(find_profile("3ds")->version_code("2069") == 2069U);
    CHECK_FALSE(find_profile("3ds")->version_code("65536"));
    CHECK(find_profile("vita")->version_code("01.03") == 103U);
    CHECK(find_profile("ps4")->version_code("12.50") == 1250U);
    CHECK_FALSE(find_profile("ps4")->version_code("1.03"));
    CHECK_FALSE(find_profile("ps4")->version_code("01.3"));
    CHECK(find_profile("android")->version_code("12") == 12U);
    CHECK_FALSE(find_profile("linux")->version_code("1"));

    CHECK(version_name_3ds(2069) == "2.1.5");
    CHECK(version_name_3ds(0) == "0.0.0");
    CHECK(version_name_3ds(65535) == "63.63.15");
    CHECK_FALSE(version_name_3ds(65536));
}

TEST_CASE("profiles: homebrew formats and their placement")
{
    const Profile& p = *find_profile("switch");
    REQUIRE(find_homebrew_format(p, "nro") != nullptr);
    CHECK(find_homebrew_format(p, "nro")->placement == Placement::single_file);
    CHECK(find_homebrew_format(p, "zip")->placement == Placement::archive);
    CHECK(find_homebrew_format(p, "nsp") == nullptr);
    CHECK(find_homebrew_format(*find_profile("3ds"), "cia")->client_asks_first);
    CHECK(find_homebrew_format(*find_profile("vita"), "vpk")->placement == Placement::system_installer);
    CHECK_FALSE(find_homebrew_format(*find_profile("android"), "apk")->client_asks_first);
    CHECK(find_homebrew_format(*find_profile("linux"), "nro") == nullptr);
}
