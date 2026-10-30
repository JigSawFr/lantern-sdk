#include <doctest.h>

#include <string>
#include <string_view>
#include <utility>

#include "support.hpp"

using namespace lantern;

TEST_CASE("paths: SPEC.md 8.2's device paths")
{
    for (const char* good :
        { "/switch/org.example.frostline/frostline.nro", "/config/org.example.frostline/settings.ini", "/a",
            "/Harbor Lights.sh", "/switch/Fr\xC3\xB8stline/x", "/.hidden/file", "/a/..b/c..", "/x/.../y" })
    {
        CAPTURE(good);
        CHECK(check_device_path(good) == PathProblem::none);
    }
    const std::pair<const char*, PathProblem> bad[] = {
        { "", PathProblem::empty },
        { "switch/x.nro", PathProblem::not_absolute },
        { "/", PathProblem::empty_part },
        { "/switch//x", PathProblem::empty_part },
        { "/switch/x/", PathProblem::empty_part },
        { "/switch/../atmosphere/x", PathProblem::dot_part },
        { "/switch/./x", PathProblem::dot_part },
        { "/..", PathProblem::dot_part },
        { "/switch/x/..", PathProblem::dot_part },
        { "C:/switch/x", PathProblem::drive_letter },
        { "c:\\switch", PathProblem::drive_letter },
        { "\\\\server\\share\\x", PathProblem::backslash },
        { "/switch\\..\\x", PathProblem::backslash },
        { "/switch/a:b", PathProblem::colon },
        { "/switch/\"x\"", PathProblem::quote },
        { "/switch/a\x01", PathProblem::control },
        { "/switch/a\x7F", PathProblem::control },
        { "/switch/a\nb", PathProblem::control },
    };
    for (const auto& [path, problem] : bad)
    {
        CAPTURE(path);
        CHECK(check_device_path(path) == problem);
    }
    CHECK(check_device_path(std::string_view("/a\0b", 4)) == PathProblem::control);
    CHECK(check_device_path("/" + std::string(255, 'a')) == PathProblem::none);
    CHECK(check_device_path("/" + std::string(256, 'a')) == PathProblem::part_too_long);
    std::string long_path;
    while (long_path.size() < 1024)
        long_path += "/abcdefg";
    long_path.resize(1024);
    CHECK(check_device_path(long_path) == PathProblem::none);
    CHECK(check_device_path(long_path + "x") == PathProblem::too_long);
    CHECK_FALSE(describe(PathProblem::dot_part).empty());
}

TEST_CASE("paths: SPEC.md 8.6's data paths and data roots")
{
    CHECK(check_data_path("data/frost.pak") == PathProblem::none);
    CHECK(check_data_path("Extras/Bonus Maps.pak") == PathProblem::none);
    CHECK(check_data_path("HARBOR.PAK") == PathProblem::none);
    CHECK(check_data_path("/switch/frostline/frost.pak") == PathProblem::absolute);
    CHECK(check_data_path("../../atmosphere/contents/x") == PathProblem::dot_part);
    CHECK(check_data_path("music/../../x") == PathProblem::dot_part);
    CHECK(check_data_path("C:/Games/frost.pak") == PathProblem::drive_letter);
    CHECK(check_data_path("C:frost.pak") == PathProblem::drive_letter);
    CHECK(check_data_path("data\\frost.pak") == PathProblem::backslash);
    CHECK(check_data_path("data/") == PathProblem::empty_part);
    CHECK(check_data_path("") == PathProblem::empty);

    CHECK(check_data_root("/switch/frostline/") == PathProblem::none);
    CHECK(check_data_root("/org.example.harborlights/data/") == PathProblem::none);
    CHECK(check_data_root("/switch/frostline") == PathProblem::not_a_folder);
    CHECK(check_data_root("switch/frostline/") == PathProblem::not_absolute);
    CHECK(check_data_root("/switch/../atmosphere/") == PathProblem::dot_part);
    CHECK(check_data_root("/") == PathProblem::empty_part);
    CHECK(check_data_root("/switch//x/") == PathProblem::empty_part);
}

TEST_CASE("paths: case-insensitive equality")
{
    CHECK(same_path_ignoring_case("/switch/A.nro", "/SWITCH/a.NRO"));
    CHECK_FALSE(same_path_ignoring_case("/switch/a.nro", "/switch/a.nr"));
    // Beyond ASCII, bytes as they are
    CHECK_FALSE(same_path_ignoring_case("/\xC3\xA9", "/\xC3\x89"));
}

TEST_CASE("paths: the profiles' roots")
{
    const Profile& switch_profile = *find_profile("switch");
    const std::string_view id     = "org.example.frostline";
    CHECK(match_roots(switch_profile, id, "/switch/org.example.frostline/frostline.nro") == RootMatch::free);
    CHECK(match_roots(switch_profile, id, "/config/org.example.frostline/a/b.ini") == RootMatch::free);
    CHECK(match_roots(switch_profile, id, "/switch/org.example.frostline") == RootMatch::outside);
    CHECK(match_roots(switch_profile, id, "/switch/org.example.frostlinex/a") == RootMatch::outside);
    CHECK(match_roots(switch_profile, id, "/switch/org.example.other/a") == RootMatch::outside);
    CHECK(match_roots(switch_profile, id, "/atmosphere/contents/0100000000001000/exefs.nsp")
        == RootMatch::consent);
    CHECK(match_roots(switch_profile, id, "/switch/.overlays/ember.ovl") == RootMatch::consent);
    CHECK(match_roots(switch_profile, id, "/bootloader/hekate_ipl.ini") == RootMatch::outside);
    CHECK(match_roots(switch_profile, id, "/atmosphere") == RootMatch::outside);

    const Profile& ds = *find_profile("3ds");
    CHECK(match_roots(ds, id, "/3ds/org.example.frostline/frostline.3dsx") == RootMatch::free);
    CHECK(match_roots(ds, id, "/boot.firm") == RootMatch::consent);
    CHECK(match_roots(ds, id, "/boot.firm/x") == RootMatch::outside);
    CHECK(match_roots(ds, id, "/luma/plugins/x.3gx") == RootMatch::consent);

    const Profile& linux_profile = *find_profile("linux");
    CHECK(match_roots(linux_profile, "org.example.harborlights", "/org.example.harborlights/harbor.aarch64")
        == RootMatch::free);
    CHECK(match_roots(linux_profile, "org.example.harborlights", "/Harbor Lights.sh") == RootMatch::consent);

    const Profile& android = *find_profile("android");
    CHECK(match_roots(android, "org.example.mossremote", "/sdcard/x") == RootMatch::outside);
}
