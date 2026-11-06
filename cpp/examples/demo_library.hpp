// The demo server's library: games that do not exist, for the demo, the
// tests and the conformance run. The same apps as python/tests/demo.py and
// typescript/test/demo.ts (anonymous, without their titles, homebrew and cheat sets,
// which this server does not serve yet), so that the same checks find the
// same things. The packages' bytes are made from their names, the same each
// run, and are no real game's.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <lantern/lantern.hpp>

namespace lantern::demo
{

inline constexpr std::string_view uid  = "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f";
inline constexpr std::string_view base = "/api/lantern";
// The one origin whose pages may read the demo (SPEC.md § 2.5); the suite's --origin.
inline constexpr std::string_view origin = "https://app.example.org";

// `size` bytes: SHA-256 of "<label>:<counter>", end to end.
inline std::vector<std::byte> blob(std::string_view label, std::size_t size)
{
    std::vector<std::byte> out;
    out.reserve(size + 32);
    for (std::uint64_t counter = 0; out.size() < size; ++counter)
    {
        const std::string text = std::string(label) + ":" + std::to_string(counter);
        const Digest digest    = Sha256::of(std::string_view(text));
        for (const std::uint8_t byte : digest)
            out.push_back(static_cast<std::byte>(byte));
    }
    out.resize(size);
    return out;
}

struct DemoApp
{
    std::string_view name;
    std::string_view platform;
    std::string_view title_id;
    std::string_view app_id;
    std::string_view type;
    std::uint64_t version_code;
    std::string_view version_name;
    std::string_view format;
    std::size_t size;
    std::string_view added;
    std::span<const std::string_view> requires_ {};
    std::span<const AppInclude> includes {};
    std::span<const std::string_view> mirrors {};
};

// Adds the demo's apps to `library`; false, and the reason, if one is refused.
inline Result<void> fill(MemoryLibrary& library)
{
    static constexpr std::array<std::string_view, 1> compression { "fs-compression" };
    static constexpr std::array<std::string_view, 2> compression_and_patch { "fs-compression", "sigpatch" };
    static constexpr std::array<std::string_view, 1> mirror {
        "https://mirror.example.org/lumen-drift-1.2.0.apk"
    };
    std::array<AppInclude, 1> includes {};
    includes[0].app_id       = "0100CD3400020800";
    includes[0].version_code = 196608;

    // Switch games: a base, two updates and an add-on; a second game; a third
    const std::array<DemoApp, 10> apps { {
        { "Lumen Drift", "switch", "0100AB1200010000", "0100AB1200010000", "base", 0, "1.0.0", "nsp", 5000,
            "2026-10-10T12:00:00Z" },
        { "Lumen Drift", "switch", "0100AB1200010000", "0100AB1200010800", "update", 65536, "1.1.0", "nsz",
            1200, "2026-10-11T12:00:00Z" },
        { "Lumen Drift", "switch", "0100AB1200010000", "0100AB1200010800", "update", 131072, "1.2.0", "nsz",
            1500, "2026-10-12T12:00:00Z" },
        { "Lumen Drift: Comet Pack", "switch", "0100AB1200010000", "0100AB1200011001", "dlc", 0, "", "nsp",
            600, "2026-10-13T12:00:00Z" },
        { "Copper Moth", "switch", "0100CD3400020000", "0100CD3400020000", "base", 0, "1.0.0", "xci", 4000,
            "2026-10-14T12:00:00Z" },
        { "Copper Moth", "switch", "0100CD3400020000", "0100CD3400020800", "update", 196608, "1.3.0", "nsp",
            900, "2026-10-15T12:00:00Z" },
        { "Quiet Tide", "switch", "0100EF5600030000", "0100EF5600030000", "base", 0, "1.0.0", "nsp", 0,
            "2026-10-16T12:00:00Z" },
        // Variants of one game (SPEC.md § 6.1): the same app_id and version_code in another format, one
        // needing the firmware's compression layer; and a package that includes the update it was built from
        { "Quiet Tide", "switch", "0100EF5600030000", "0100EF5600030000", "base", 0, "1.0.0", "nsz", 0,
            "2026-10-16T12:00:00Z", compression },
        { "Copper Moth", "switch", "0100CD3400020000", "0100CD3400020000", "base", 0, "1.3.0", "xcz", 3000,
            "2026-10-17T12:00:00Z", compression_and_patch, includes },
        { "Lumen Drift", "android", "org.example.lumendrift", "org.example.lumendrift", "base", 12, "1.2.0",
            "apk", 2048, "2026-10-20T12:00:00Z", {}, {}, mirror },
    } };
    for (const DemoApp& app : apps)
    {
        AppDraft draft;
        draft.platform     = app.platform;
        draft.title_id     = app.title_id;
        draft.app_id       = app.app_id;
        draft.type         = app.type;
        draft.version_code = app.version_code;
        draft.version_name = app.version_name;
        draft.name         = app.name;
        draft.format       = app.format;
        draft.added        = app.added;
        draft.requires_    = app.requires_;
        draft.includes     = app.includes;
        draft.mirrors      = app.mirrors;
        // Each package's bytes come from what identifies it
        const std::string label
            = std::string(app.app_id) + "v" + std::to_string(app.version_code) + std::string(app.format);
        const auto content = blob(label, app.size);
        auto added         = library.add_app(draft, content);
        if (!added)
            return std::unexpected(added.error());
    }
    return {};
}

} // namespace lantern::demo
