#include <doctest.h>

#include <array>
#include <span>
#include <string>
#include <string_view>

#include "support.hpp"

using namespace lantern;
using lantern::test::spec_file;

namespace
{

Requires requires_of(std::string_view text)
{
    const std::string entry = R"({"schema":1,"id":"org.example.harborlights","platform":"linux","kind":"port",
        "name":"Harbor Lights","version":"2.1.0","build":20100,"requires":)"
        + std::string(text) + R"(,"package":{"format":"zip","file":"/f","size":1,
        "sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4",
        "manifest_sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4"}})";
    auto read = read_homebrew(entry);
    REQUIRE(read);
    REQUIRE(*read);
    REQUIRE((*read)->requires_);
    return *(*read)->requires_;
}

const Condition* condition(const RequiresCheck& check, std::string_view key)
{
    for (const Condition& c : check.conditions)
    {
        if (c.key == key)
            return &c;
    }
    return nullptr;
}

} // namespace

TEST_CASE("requires: dotted versions compare part by part")
{
    CHECK(compare_dotted("2.30", "2.28") == 1);
    CHECK(compare_dotted("2.9", "2.30") == -1);
    CHECK(compare_dotted("1.7", "1.7.0") == 0);
    CHECK(compare_dotted("18.0.0", "18") == 0);
    CHECK(compare_dotted("1.10.0.1", "1.10") == 1);
    CHECK_FALSE(compare_dotted("2.30-ubuntu", "2.30"));
    CHECK_FALSE(compare_dotted("1..2", "1"));
    CHECK_FALSE(compare_dotted("1.2.3.4.5", "1"));
    CHECK_FALSE(compare_dotted("", "1"));
}

TEST_CASE("requires: the reference library's Harbor Lights (SPEC.md 8.7)")
{
    // glibc 2.30, OpenGL ES 2 or Vulkan, 512 MiB, 640x480, and two
    // conditions this client cannot read: min.kernel and vram_mb
    const Requires harbor
        = requires_of(R"({"text":"glibc 2.30, OpenGL ES 2 or Vulkan, 512 MiB of memory, a 640x480 screen",
        "min":{"glibc":"2.30","ram_mb":512,"screen":"640x480","kernel":"5.10"},"gpu":["gles2","vulkan"],"vram_mb":256})");
    const Profile& linux_profile = *find_profile("linux");
    const std::array<DeviceFacts::Version, 1> glibc { { { "glibc", "2.35" } } };
    const std::array<std::string_view, 1> gles2 { "gles2" };
    DeviceFacts handheld;
    handheld.versions         = glibc;
    handheld.ram_mb           = 1024;
    handheld.screen_width     = 640;
    handheld.screen_height    = 480;
    handheld.gpus             = std::span<const std::string_view>(gles2);
    const RequiresCheck check = check_requires(harbor, linux_profile, handheld);
    CHECK(check.offer == Offer::warn);
    CHECK(condition(check, "min.glibc")->state == ConditionState::met);
    CHECK(condition(check, "min.ram_mb")->state == ConditionState::met);
    CHECK(condition(check, "min.screen")->state == ConditionState::met);
    CHECK(condition(check, "min.kernel")->state == ConditionState::unreadable);
    CHECK(condition(check, "gpu")->state == ConditionState::met);
    CHECK(condition(check, "vram_mb")->state == ConditionState::unreadable);

    // A device that fails glibc: refused, and the client says why
    const std::array<DeviceFacts::Version, 1> old_glibc { { { "glibc", "2.28" } } };
    DeviceFacts old_device        = handheld;
    old_device.versions           = old_glibc;
    const RequiresCheck old_check = check_requires(harbor, linux_profile, old_device);
    CHECK(old_check.offer == Offer::refuse);
    CHECK(condition(old_check, "min.glibc")->detail == "glibc 2.30 or later; this device has 2.28");

    // Too little memory, too small a screen, no graphics interface it needs
    const std::array<std::string_view, 1> gl { "gl" };
    DeviceFacts small               = handheld;
    small.ram_mb                    = 256;
    small.screen_width              = 480;
    small.gpus                      = std::span<const std::string_view>(gl);
    const RequiresCheck small_check = check_requires(harbor, linux_profile, small);
    CHECK(small_check.offer == Offer::refuse);
    CHECK(condition(small_check, "min.ram_mb")->state == ConditionState::failed);
    CHECK(condition(small_check, "min.screen")->state == ConditionState::failed);
    CHECK(condition(small_check, "gpu")->state == ConditionState::failed);

    // What the app does not know of the device: a warning
    const RequiresCheck unknown = check_requires(harbor, linux_profile, DeviceFacts {});
    CHECK(unknown.offer == Offer::warn);
    CHECK(condition(unknown, "min.glibc")->state == ConditionState::unreadable);
    CHECK(condition(unknown, "gpu")->state == ConditionState::unreadable);
}

TEST_CASE("requires: the profile's keys, and values of another form")
{
    const Profile& switch_profile = *find_profile("switch");
    const std::array<DeviceFacts::Version, 2> versions { { { "firmware", "18.1.0" },
        { "atmosphere", "1.6.2" } } };
    DeviceFacts console;
    console.versions = versions;

    const RequiresCheck atmosphere
        = check_requires(requires_of(R"({"text":"Atmosphère 1.7 or later","min":{"atmosphere":"1.7.0"}})"),
            switch_profile, console);
    CHECK(atmosphere.offer == Offer::refuse);
    CHECK(condition(atmosphere, "min.atmosphere")->detail
        == "atmosphere 1.7.0 or later; this device has 1.6.2");

    CHECK(check_requires(requires_of(R"({"text":"x","min":{"firmware":"18.0.0"}})"), switch_profile, console)
              .offer
        == Offer::offer);
    // Another profile's key on the Switch: unreadable
    CHECK(
        check_requires(requires_of(R"({"text":"x","min":{"goldhen":"2.4"}})"), switch_profile, console).offer
        == Offer::warn);

    // The specification's invalid examples a client reads as warnings
    for (const char* name : { "glibc-not-dotted", "ram-as-text", "screen-form", "gpu-unknown" })
    {
        CAPTURE(name);
        auto read = read_homebrew(spec_file("examples/v1/invalid/homebrew." + std::string(name) + ".json"));
        REQUIRE(read);
        REQUIRE(*read);
        REQUIRE((*read)->requires_);
        const std::array<std::string_view, 1> gles { "gles2" };
        const std::array<DeviceFacts::Version, 2> current { { { "firmware", "18.1.0" },
            { "atmosphere", "1.8.0" } } };
        DeviceFacts device = console;
        device.versions    = current;
        device.ram_mb      = 4096;
        device.gpus        = std::span<const std::string_view>(gles);
        CHECK(check_requires(*(*read)->requires_, switch_profile, device).offer == Offer::warn);
    }

    // A vendor's own member is ignored
    CHECK(check_requires(requires_of(R"({"text":"x","x-example-cooling":"fan"})"), switch_profile, console)
              .offer
        == Offer::offer);
}
