// Packages a device cannot use and variants of one game (SPEC.md § 6.1,
// Annex B.15): whether a client installs an app, which update an installed
// app already contains, and which variant it prefers by default.
#pragma once

#include <cstdint>
#include <span>
#include <string_view>

#include <lantern/memory.hpp>
#include <lantern/types.hpp>

namespace lantern
{

enum class Install : std::uint8_t
{
    install, // the client knows the format and every token, and the device has no update inside
    unavailable, // listed, not installed, with `reasons`
};

struct InstallDecision
{
    using allocator_type = Allocator;

    Install verdict = Install::install;
    // For people, one each: "format 'xcz'", "requires 'sigpatch'", "already included by an installed app".
    Vector<String> reasons;

    InstallDecision()
        : InstallDecision(allocator_type {})
    {
    }
    explicit InstallDecision(const allocator_type& allocator)
        : reasons(allocator)
    {
    }
    InstallDecision(const InstallDecision& other, const allocator_type& allocator)
        : verdict(other.verdict)
        , reasons(other.reasons, allocator)
    {
    }
    InstallDecision(InstallDecision&& other, const allocator_type& allocator)
        : verdict(other.verdict)
        , reasons(std::move(other.reasons), allocator)
    {
    }
    InstallDecision(const InstallDecision&)            = default;
    InstallDecision(InstallDecision&&) noexcept        = default;
    InstallDecision& operator=(const InstallDecision&) = default;
    InstallDecision& operator=(InstallDecision&&)      = default;
    ~InstallDecision()                                 = default;
};

// § 6.1: whether a client installs `app`. `formats`: the package formats it
// knows; `satisfies`: the `requires` tokens it knows and the device provides;
// `installed`: the apps the device has installed. A format or a token it does
// not know is refused as one it cannot satisfy (L-6.1-3, L-6.1-4), and so is
// an update that an installed app includes (L-6.1-5).
[[nodiscard]] InstallDecision install_decision(const App& app, std::span<const std::string_view> formats,
    std::span<const std::string_view> satisfies, std::span<const App> installed = {},
    const Allocator& allocator = {});
// The same, with the installed apps as pointers (apps held in several pages).
[[nodiscard]] InstallDecision install_decision(const App& app, std::span<const std::string_view> formats,
    std::span<const std::string_view> satisfies, std::span<const App* const> installed,
    const Allocator& allocator = {});

// L-6.1-5: whether `app` is an update that an installed app `includes` at its
// `version_code` or above.
[[nodiscard]] bool included(const App& app, std::span<const App> installed) noexcept;
[[nodiscard]] bool included(const App& app, std::span<const App* const> installed) noexcept;

// Annex B.15: the variant to install by default among apps that share an
// `app_id` and a `version_code`: the fewest `requires`, then the smallest
// `size`, then the smaller `id`, so that two clients agree. Nothing for no
// variant. The pointer is into `variants`.
[[nodiscard]] const App* prefer_variant(std::span<const App> variants) noexcept;
[[nodiscard]] const App* prefer_variant(std::span<const App* const> variants) noexcept;

} // namespace lantern
