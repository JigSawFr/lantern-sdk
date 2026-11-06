// The demo server's library: games that do not exist, for the demo, the
// tests and the conformance run. The same apps, titles and sections as
// python/tests/demo.py and typescript/test/demo.ts, so that the same checks
// find the same things; with a journal for the changes, a few images on the
// server's origin, homebrew (signed archives, single files, a port whose data
// the user brings, a package per architecture) and cheat sets, which clients
// with the scope cheats.write may add to. The packages' bytes are made from
// their names, the same each run, and are no real game's.
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
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

// CRC-32 (IEEE), the checksum of a file in a zip archive.
inline std::uint32_t crc32(std::span<const std::byte> data)
{
    std::uint32_t crc = 0xFFFFFFFFU;
    for (const std::byte byte : data)
    {
        crc ^= static_cast<std::uint32_t>(byte);
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1U) ^ (0xEDB88320U & (0U - (crc & 1U)));
    }
    return ~crc;
}

struct ZipFile
{
    std::string name; // without the leading "/"
    std::vector<std::byte> data;
};

// A zip archive that stores its files as they are, which a client reads like any other.
inline std::vector<std::byte> zipped(const std::vector<ZipFile>& files)
{
    std::vector<std::byte> out;
    const auto put = [&](std::uint64_t value, int width)
    {
        for (int i = 0; i < width; ++i)
            out.push_back(static_cast<std::byte>((value >> (8 * i)) & 0xFFU));
    };
    constexpr std::uint64_t time = 12U << 11U; // 12:00:00
    constexpr std::uint64_t date = ((2026U - 1980U) << 9U) | (10U << 5U) | 30U; // 2026-10-30
    std::vector<std::size_t> offsets;
    for (const ZipFile& file : files)
    {
        offsets.push_back(out.size());
        put(0x04034B50, 4);
        put(20, 2);
        put(0, 2);
        put(0, 2); // stored
        put(time, 2);
        put(date, 2);
        put(crc32(file.data), 4);
        put(file.data.size(), 4);
        put(file.data.size(), 4);
        put(file.name.size(), 2);
        put(0, 2);
        for (const char c : file.name)
            out.push_back(static_cast<std::byte>(c));
        out.insert(out.end(), file.data.begin(), file.data.end());
    }
    const std::size_t directory = out.size();
    for (std::size_t i = 0; i < files.size(); ++i)
    {
        const ZipFile& file = files[i];
        put(0x02014B50, 4);
        put(0x0314, 2);
        put(20, 2);
        put(0, 2);
        put(0, 2);
        put(time, 2);
        put(date, 2);
        put(crc32(file.data), 4);
        put(file.data.size(), 4);
        put(file.data.size(), 4);
        put(file.name.size(), 2);
        put(0, 2);
        put(0, 2);
        put(0, 2);
        put(0, 2);
        put(std::uint64_t { 0100644U } << 16U, 4);
        put(offsets[i], 4);
        for (const char c : file.name)
            out.push_back(static_cast<std::byte>(c));
    }
    const std::size_t size = out.size() - directory;
    put(0x06054B50, 4);
    put(0, 2);
    put(0, 2);
    put(files.size(), 2);
    put(files.size(), 2);
    put(size, 4);
    put(directory, 4);
    put(0, 2);
    return out;
}

inline std::vector<std::byte> text_bytes(std::string_view text)
{
    const auto view = std::as_bytes(std::span(text.data(), text.size()));
    return { view.begin(), view.end() };
}

// A package and its bytes, before the library serves them.
struct Built
{
    Package package;
    std::vector<std::byte> bytes;
};

// An archive: each file lands at "/" + its name (§ 8.2).
inline Built archive_package(const std::vector<ZipFile>& files, std::span<const std::string_view> arch = {})
{
    Built built;
    built.bytes             = zipped(files);
    built.package.format    = "zip";
    built.package.size      = built.bytes.size();
    built.package.sha256    = Sha256::of(built.bytes);
    std::uint64_t installed = 0;
    for (const ZipFile& file : files)
    {
        built.package.manifest.emplace_back();
        ManifestEntry& entry = built.package.manifest.back();
        entry.path           = "/" + file.name;
        entry.size           = file.data.size();
        entry.sha256         = Sha256::of(file.data);
        installed += file.data.size();
    }
    built.package.installed_size  = installed;
    built.package.manifest_sha256 = manifest_digest(built.package.manifest);
    for (const std::string_view name : arch)
        built.package.arch.emplace_back(name);
    return built;
}

// One file that goes to `path` on the device, or that the system installs (no path).
inline Built single_package(std::string_view format, std::string_view path, std::vector<std::byte> bytes)
{
    Built built;
    built.bytes                  = std::move(bytes);
    built.package.format         = format;
    built.package.size           = built.bytes.size();
    built.package.sha256         = Sha256::of(built.bytes);
    built.package.path           = path;
    built.package.installed_size = built.bytes.size();
    ManifestEntry single;
    single.path                   = path;
    single.size                   = built.bytes.size();
    single.sha256                 = built.package.sha256;
    built.package.manifest_sha256 = manifest_digest(std::span(&single, 1));
    return built;
}

// Signs the entry's packages (§ 8.4) with the demo's author key: the SHA-256 of a phrase, for the demo only.
inline void sign_homebrew(Homebrew& entry)
{
    static constexpr std::string_view phrase = "Mira's fictional signing key";
    const DeviceKey key                      = DeviceKey::from_seed(Sha256::of(phrase));
    String public_key;
    base64_encode(key.public_key(), public_key);
    const auto signature_of = [&](const Package& package)
    {
        String message;
        signed_message(
            entry.id, entry.platform, entry.build, package.sha256, package.manifest_sha256, message);
        const SignatureBytes bytes
            = key.sign(std::span(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()));
        Signature signature;
        signature.alg        = "ed25519";
        signature.public_key = public_key;
        base64_encode(bytes, signature.value);
        return signature;
    };
    entry.signature = signature_of(entry.package);
    for (Package& package : entry.packages)
        package.signature = signature_of(package);
}

// Serves the entry with the bytes of its packages (the first is `built`'s, then the others').
inline Result<void> put_homebrew(
    MemoryLibrary& library, Homebrew& entry, std::vector<Built>& built, bool signed_ = false)
{
    entry.package = std::move(built.front().package);
    std::vector<std::span<const std::byte>> contents { built.front().bytes };
    for (std::size_t i = 1; i < built.size(); ++i)
    {
        entry.packages.push_back(std::move(built[i].package));
        contents.emplace_back(built[i].bytes);
    }
    if (signed_)
        sign_homebrew(entry);
    auto added = library.add_homebrew(entry, contents);
    if (!added)
        return std::unexpected(added.error());
    return {};
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

// A 1 by 1 PNG: the demo's icons, which are no game's.
inline constexpr std::array<std::uint8_t, 67> pixel_png { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08,
    0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78,
    0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00,
    0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82 };

// The demo's titles (§ 7): an icon on the server's origin for the first, a
// banner and a video elsewhere for it too, and sparser sheets for the others.
inline Result<void> fill_titles(MemoryLibrary& library)
{
    const auto put = [&](const Title& title) -> Result<void>
    {
        auto added = library.add_title(title);
        if (!added)
            return std::unexpected(added.error());
        return {};
    };

    Image icon;
    {
        const auto bytes = std::as_bytes(std::span(pixel_png));
        auto image       = library.add_media(bytes, "png");
        if (!image)
            return std::unexpected(image.error());
        icon        = std::move(*image);
        icon.width  = 1;
        icon.height = 1;
    }
    Title lumen;
    lumen.platform  = "switch";
    lumen.title_id  = "0100AB1200010000";
    lumen.name      = "Lumen Drift";
    lumen.language  = "en";
    lumen.publisher = "Northwind Toys";
    lumen.developer = "Northwind Toys";
    lumen.release   = "2025-11-02";
    lumen.updated   = "2026-10-28T19:02:11Z";
    lumen.genres    = { "adventure", "puzzle" };
    lumen.tags      = { "co-op", "space" };
    lumen.players.emplace();
    lumen.players->min    = 1;
    lumen.players->max    = 2;
    lumen.players->online = false;
    lumen.ratings.emplace_back();
    lumen.ratings.back().system = "PEGI";
    lumen.ratings.back().rating = "7";
    lumen.languages             = { "en", "fr" };
    lumen.summary               = "Guide a drifting lantern between quiet planets.";
    lumen.icon                  = icon;
    lumen.banner.emplace();
    lumen.banner->url      = "https://images.example.org/lumen-drift-banner.jpg";
    lumen.banner->external = true;
    lumen.screenshots.push_back(icon);
    lumen.video.emplace();
    lumen.video->url      = "https://video.example.org/lumen-drift";
    lumen.video->external = true;
    if (auto done = put(lumen); !done)
        return done;

    Title moth;
    moth.platform = "switch";
    moth.title_id = "0100CD3400020000";
    moth.name     = "Copper Moth";
    moth.language = "en";
    moth.release  = "2026-02-14";
    moth.genres   = { "platformer" };
    moth.summary  = "A moth of copper looks for the moon.";
    if (auto done = put(moth); !done)
        return done;

    Title tide;
    tide.platform = "switch";
    tide.title_id = "0100EF5600030000";
    tide.name     = "Quiet Tide";
    tide.release  = "2024-06-30";
    tide.genres   = { "simulation" };
    if (auto done = put(tide); !done)
        return done;

    Title android;
    android.platform = "android";
    android.title_id = "org.example.lumendrift";
    android.name     = "Lumen Drift";
    android.release  = "2026-03-01";
    android.genres   = { "adventure" };
    return put(android);
}

// The demo's homebrew (§ 8): a signed archive, single files (one under a root that asks for
// consent, with a loader it needs), a port whose data the user brings, and a signed port for Linux
// with a package per architecture.
inline Result<void> fill_homebrew(MemoryLibrary& library)
{
    const auto base_entry
        = [](std::string_view id, std::string_view platform, std::string_view kind, std::string_view name,
              std::string_view author, std::string_view version, std::uint64_t build)
    {
        Homebrew entry;
        entry.id       = id;
        entry.platform = platform;
        entry.kind     = kind;
        entry.name     = name;
        entry.author   = author;
        entry.version  = version;
        entry.build    = build;
        return entry;
    };

    // A signed archive, with a manifest under the Switch's free roots
    {
        Homebrew entry
            = base_entry("org.example.starjar", "switch", "tool", "Star Jar", "Mira", "1.2.0", 10200);
        entry.license  = "MIT";
        entry.language = "en";
        entry.summary  = "Keep the stars you saw tonight.";
        entry.genres   = { "education" };
        entry.tags     = { "notes" };
        entry.updated  = "2026-10-29T08:00:00Z";
        entry.requires_.emplace();
        entry.requires_->text = "Atmosphere 1.7 or later";
        entry.requires_->min.emplace();
        entry.requires_->min->members.emplace_back("atmosphere", "\"1.7.0\"");
        std::vector<Built> built;
        built.push_back(
            archive_package({ { "switch/org.example.starjar/starjar.nro", blob("starjar.nro", 700) },
                { "config/org.example.starjar/settings.ini", text_bytes("[jar]\nstars=12\n") } }));
        if (auto put = put_homebrew(library, entry, built, true); !put)
            return put;
    }
    // A single .nro, a game
    {
        Homebrew entry
            = base_entry("org.example.mothclock", "switch", "game", "Moth Clock", "Oren", "0.4.0", 400);
        entry.genres = { "puzzle" };
        std::vector<Built> built;
        built.push_back(single_package(
            "nro", "/switch/org.example.mothclock/org.example.mothclock.nro", blob("mothclock.nro", 400)));
        if (auto put = put_homebrew(library, entry, built); !put)
            return put;
    }
    // An overlay: a root that needs the user's consent, and a loader it needs
    {
        Homebrew entry
            = base_entry("org.example.glowmeter", "switch", "overlay", "Glow Meter", "Oren", "1.0.0", 100);
        entry.requires_.emplace();
        entry.requires_->text = "An overlay loader";
        entry.requires_->homebrew.emplace_back();
        entry.requires_->homebrew.back().id        = "org.example.overlay-loader";
        entry.requires_->homebrew.back().min_build = 1;
        std::vector<Built> built;
        built.push_back(single_package("ovl", "/switch/.overlays/glowmeter.ovl", blob("glow.ovl", 256)));
        if (auto put = put_homebrew(library, entry, built); !put)
            return put;
    }
    // A port: the user brings the original game's data
    {
        Homebrew entry = base_entry(
            "org.example.tidewalk-port", "switch", "port", "Tidewalk Port", "Oren", "0.3.0", 300);
        entry.license = "GPL-2.0-or-later";
        entry.genres  = { "adventure" };
        entry.port.emplace();
        Port& port              = *entry.port;
        port.original.name      = "Tidewalk";
        port.original.year      = 1999;
        port.original.developer = "Northwind Toys";
        port.engine.name        = "Shoreline";
        port.engine.version     = "0.3.0";
        port.data_root          = "/switch/tidewalk/";
        port.assets             = "user_owned";
        const auto pak          = blob("tide.pak 1.0", 512);
        port.requires_data.emplace_back();
        RequiredData& tide = port.requires_data.back();
        tide.path          = "data/tide.pak";
        tide.size          = pak.size();
        tide.accept.emplace_back();
        tide.accept.back().sha256 = Sha256::of(pak);
        tide.accept.back().label  = "1.0";
        tide.hint                 = "tide.pak, in the folder where Tidewalk is installed.";
        port.requires_data.emplace_back();
        RequiredData& music = port.requires_data.back();
        music.optional      = true;
        using Alternative   = std::pair<std::string_view, std::string_view>;
        const std::array<Alternative, 2> alternatives { { { "music/full.pak", "From the soundtrack." },
            { "music/demo.pak", "From the free demo." } } };
        for (const auto& [path, hint] : alternatives)
        {
            music.one_of.emplace_back();
            music.one_of.back().emplace_back();
            music.one_of.back().back().path = path;
            music.one_of.back().back().hint = hint;
        }
        std::vector<Built> built;
        built.push_back(
            archive_package({ { "switch/org.example.tidewalk-port/tidewalk.nro", blob("tidewalk.nro", 500) },
                { "switch/org.example.tidewalk-port/readme.txt",
                    text_bytes("Bring tide.pak from your own copy.\n") } }));
        if (auto put = put_homebrew(library, entry, built); !put)
            return put;
    }
    // A Linux port, a signed package per architecture
    {
        Homebrew entry
            = base_entry("org.example.harborglow", "linux", "port", "Harbor Glow", "Mira", "2.0.0", 20000);
        entry.genres   = { "simulation" };
        entry.language = "en";
        entry.summary  = "A lighthouse keeper's evening, ported.";
        entry.requires_.emplace();
        entry.requires_->text = "glibc 2.30, OpenGL ES 2, 512 MiB";
        entry.requires_->min.emplace();
        entry.requires_->min->members.emplace_back("glibc", "\"2.30\"");
        entry.requires_->min->members.emplace_back("ram_mb", "512");
        entry.requires_->gpu = { "gles2" };
        entry.port.emplace();
        entry.port->original.name = "Harbor Glow";
        entry.port->engine.name   = "Beacon";
        entry.port->data_root     = "/org.example.harborglow/data/";
        entry.port->assets        = "user_owned";
        entry.port->requires_data.emplace_back();
        entry.port->requires_data.back().path = "HARBOR.PAK";
        entry.port->requires_data.back().hint = "From your own copy.";
        static constexpr std::array<std::string_view, 2> arm { "aarch64", "armhf" };
        static constexpr std::array<std::string_view, 1> x86 { "x86_64" };
        const auto launcher = text_bytes("#!/bin/sh\nexec ./org.example.harborglow/harbor\n");
        std::vector<Built> built;
        built.push_back(
            archive_package({ { "Harbor Glow.sh", launcher },
                                { "org.example.harborglow/harbor.aarch64", blob("harbor.aarch64", 300) } },
                arm));
        built.push_back(
            archive_package({ { "Harbor Glow.sh", launcher },
                                { "org.example.harborglow/harbor.x86_64", blob("harbor.x86_64", 300) } },
                x86));
        if (auto put = put_homebrew(library, entry, built, true); !put)
            return put;
    }
    return {};
}

// The demo's cheat sets (§ 10): two sources for one build of a game, one for another.
inline Result<void> fill_cheats(MemoryLibrary& library)
{
    struct DemoCheat
    {
        std::string_view title_id;
        std::string_view build_id;
        std::string_view source;
        std::string_view note;
        std::string_view text;
    };
    const std::array<DemoCheat, 3> sets { {
        { "0100AB1200010000", "AB12CD34EF560789", "Community list", "Endless lamp oil",
            "[Endless lamp oil]\n04000000 0011A0B0 00000063\n" },
        { "0100AB1200010000", "AB12CD34EF560789", "Mira", "", "[Slow comets]\n04000000 0011A0C8 00000001\n" },
        { "0100CD3400020000", "0123456789ABCDEF", "Community list", "",
            "[Moon jump]\n04000000 00ABC010 0000FFFF\n" },
    } };
    // Clients with the scope cheats.write may add and replace sets
    library.accept_cheat_writes();
    for (const DemoCheat& demo : sets)
    {
        CheatWrite set;
        set.platform = "switch";
        set.title_id = demo.title_id;
        set.build_id = demo.build_id;
        set.source   = demo.source;
        set.note     = demo.note;
        set.text     = demo.text;
        if (auto added = library.add_cheat(set); !added)
            return std::unexpected(added.error());
    }
    return {};
}

// Adds the demo's apps, titles, sections, homebrew and cheat sets to `library`, and a journal of
// its changes; false, and the reason, if one is refused.
inline Result<void> fill(MemoryLibrary& library)
{
    if (auto kept = library.keep_journal(); !kept)
        return kept;
    // Files of 128 KiB or more carry a chunk index (§ 22): the two updates of Lumen Drift below
    ChunkingOptions chunking;
    chunking.min_file_size = std::uint64_t { 128 } << 10U;
    if (auto offered = library.offer_deltas(chunking); !offered)
        return offered;
    std::vector<App> listed;
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
            200000, "2026-10-11T12:00:00Z" },
        { "Lumen Drift", "switch", "0100AB1200010000", "0100AB1200010800", "update", 131072, "1.2.0", "nsz",
            260000, "2026-10-12T12:00:00Z" },
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
        // (the two updates of Lumen Drift are one payload, the second grown and changed in the middle: what
        // a chunk index lets a client keep, § 22)
        const bool update_chain = app.app_id == "0100AB1200010800";
        const std::string label = update_chain
            ? std::string(app.app_id)
            : std::string(app.app_id) + "v" + std::to_string(app.version_code) + std::string(app.format);
        auto content            = blob(label, app.size);
        if (update_chain && app.version_code == 131072)
        {
            for (std::size_t i = 100000; i < 100200; ++i)
                content[i] = static_cast<std::byte>(~static_cast<unsigned>(content[i]));
        }
        auto added = library.add_app(draft, content);
        if (!added)
            return std::unexpected(added.error());
        listed.push_back(std::move(*added));
    }
    if (auto titled = fill_titles(library); !titled)
        return std::unexpected(titled.error());
    if (auto brewed = fill_homebrew(library); !brewed)
        return brewed;
    if (auto cheated = fill_cheats(library); !cheated)
        return cheated;

    // The shelves: the four newest apps, and the games to play together
    std::ranges::sort(listed, [](const App& a, const App& b) { return a.added > b.added; });
    std::vector<std::string_view> newest;
    std::vector<std::string_view> together;
    for (const App& app : listed)
    {
        if (newest.size() < 4)
            newest.emplace_back(app.id);
        if (app.title_id == "0100AB1200010000")
            together.emplace_back(app.id);
    }
    if (auto shelf = library.add_section("new", "New this month", newest); !shelf)
        return std::unexpected(shelf.error());
    if (auto shelf = library.add_section("co-op", "Play together", together); !shelf)
        return std::unexpected(shelf.error());
    return {};
}

} // namespace lantern::demo
