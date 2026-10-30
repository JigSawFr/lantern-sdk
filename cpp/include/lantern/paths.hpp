// Paths on the device (SPEC.md § 8.2, § 8.6) and the profiles' roots
// (Annex A). Every check refuses rather than repairs: a path that breaks
// the rules makes the client install nothing of its package.
#pragma once

#include <cstdint>
#include <string_view>

#include <lantern/profiles.hpp>

namespace lantern
{

enum class PathProblem : std::uint8_t
{
    none,
    empty,
    not_absolute, // a device path or a data_root that does not start with "/"
    absolute, // a data path (relative to data_root) that starts with "/"
    drive_letter, // "C:…"
    empty_part, // "//", or a trailing "/" where a file is meant
    dot_part, // a part that is "." or ".."
    backslash, // "\": Windows' separator, UNC paths
    colon, // ":"
    quote, // '"'
    control, // a control character or NUL (U+0000 to U+001F, U+007F)
    part_too_long, // a part above 255 bytes
    too_long, // a path above 1024 bytes
    not_a_folder, // a data_root that does not end with "/"
};

[[nodiscard]] std::string_view describe(PathProblem problem) noexcept;

// § 8.2: absolute, parts separated by "/", none empty, "." or "..", no "\",
// ":", '"', control character or NUL, a part 255 bytes at most, the path 1024.
[[nodiscard]] PathProblem check_device_path(std::string_view path) noexcept;
// § 8.6: a data path, relative to its port's data_root: the same parts,
// without the leading "/", and no drive letter.
[[nodiscard]] PathProblem check_data_path(std::string_view path) noexcept;
// § 8.6: a data_root, a device path that ends with "/".
[[nodiscard]] PathProblem check_data_root(std::string_view path) noexcept;

// Two paths the same when ASCII case is ignored (§ 8.2: no two paths of a
// manifest are; bytes beyond ASCII are compared as they are).
[[nodiscard]] bool same_path_ignoring_case(std::string_view a, std::string_view b) noexcept;

enum class RootMatch : std::uint8_t
{
    outside, // in none of the profile's roots: refused
    free, // under a root that needs no consent
    consent, // under a root that needs the user's consent
};

// Where `path` lies among the profile's roots, "<id>" being `homebrew_id`.
// A free root wins over a consent root ("/" on Linux).
[[nodiscard]] RootMatch match_roots(
    const Profile& profile, std::string_view homebrew_id, std::string_view path) noexcept;

// Whether `path` lies strictly inside `folder` (which ends with "/").
[[nodiscard]] bool strictly_under(std::string_view folder, std::string_view path) noexcept;

} // namespace lantern
