// The platform profiles of SPEC.md Annex A: what the core leaves open, per
// platform. The Switch's is complete; the 3DS's, the Vita's, the PS4's,
// Android's and Linux's are drafts (to be reviewed by someone who knows the
// platform); the others are open (A.7): no profile, and a client installs
// nothing of them (§ 4.3).
//
// The ids are checked by hand, not with <regex>, which is heavy on the
// consoles and throws on some of their standard libraries.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/memory.hpp>

namespace lantern
{

// How a homebrew package of a format reaches the device (§ 8.2).
enum class Placement : std::uint8_t
{
    single_file, // one file, at the package's `path`
    archive, // a zip and its manifest
    system_installer, // the platform's own installer: no `path`, an empty manifest
};

struct HomebrewFormat
{
    std::string_view format;
    Placement placement;
    // single_file: where it goes. "<id>" is the homebrew's id; a template
    // ending with "/" is a folder the file goes into under its own name.
    std::string_view where;
    // system_installer: the client asks the user before it hands the
    // package over (the 3DS, the Vita, the PS4: their installers do not ask).
    bool client_asks_first;
};

struct Profile
{
    std::string_view platform;
    bool draft; // Annex A says "to be reviewed"
    bool installs_apps; // false: a client installs none of its apps (Linux, A.6)
    bool newer_base_is_update; // a newer `base` of the same app_id replaces it (Android)
    std::span<const std::string_view> app_types;
    std::span<const std::string_view> app_formats;
    // Several architectures (§ 8.2): the names a package's `arch` takes.
    // Empty: one architecture, and a package carries no `arch`.
    std::span<const std::string_view> arches;
    std::span<const HomebrewFormat> homebrew_formats;
    // Where a homebrew writes without asking ("<id>" is its id), and where
    // only with the user's consent; "/" means every other path. A root
    // ending with "/" is a folder, any other a file.
    std::span<const std::string_view> free_roots;
    std::span<const std::string_view> consent_roots;
    // The areas a port's `data_root` lies in (§ 8.6), strictly below one.
    std::span<const std::string_view> port_areas;
    // The profile's keys of `requires.min` (§ 8.7), besides glibc, ram_mb
    // and screen, which any profile may use.
    std::span<const std::string_view> min_keys;
    bool has_system_id;
    // The forms of a title_id, and of an app_id for a type and its game.
    bool (*title_id)(std::string_view title_id) noexcept;
    bool (*app_id)(std::string_view type, std::string_view title_id, std::string_view app_id) noexcept;
    // `version_code` from the version as the platform writes it
    // (Switch: "196608" or "v196608"; Vita and PS4: APP_VER "01.03").
    std::optional<std::uint64_t> (*version_code)(std::string_view text) noexcept;
};

// The profile of a platform; null for an open platform, or an unknown one.
[[nodiscard]] const Profile* find_profile(std::string_view platform) noexcept;
[[nodiscard]] std::span<const Profile> profiles() noexcept;
[[nodiscard]] const HomebrewFormat* find_homebrew_format(
    const Profile& profile, std::string_view format) noexcept;
[[nodiscard]] bool has_app_type(const Profile& profile, std::string_view type) noexcept;
[[nodiscard]] bool has_app_format(const Profile& profile, std::string_view format) noexcept;

// The core's forms.
// A platform name (§ 4.3): 1 to 32 lower-case letters, digits and "-",
// starting with a letter or a digit.
[[nodiscard]] bool is_platform_name(std::string_view name) noexcept;
// An architecture's name (§ 8.2): 1 to 32 lower-case letters, digits and "_".
[[nodiscard]] bool is_arch_name(std::string_view name) noexcept;
// A homebrew id (§ 8.1): reverse-DNS, lower-case, at most 128 bytes.
[[nodiscard]] bool is_homebrew_id(std::string_view id) noexcept;
// A title or app id of the core (§ 6.1): 1 to 128 letters, digits, ".", "_", "-".
[[nodiscard]] bool is_core_id(std::string_view id) noexcept;

// Annex A.2: a 3DS version_code's version_name, major.minor.micro from its
// top 6, next 6 and low 4 bits (2069 is "2.1.5"); nothing above 65535.
[[nodiscard]] std::optional<String> version_name_3ds(std::uint64_t version_code, Allocator allocator = {});

} // namespace lantern
