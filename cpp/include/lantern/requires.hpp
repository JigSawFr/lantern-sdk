// Requirements (SPEC.md § 8.7): whether a client offers a package, warns,
// or refuses it, from the entry's `requires` and what the app knows of the
// device.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/error.hpp>
#include <lantern/memory.hpp>
#include <lantern/profiles.hpp>
#include <lantern/types.hpp>

namespace lantern
{

// What the app knows of the device. What it leaves out is "something it
// cannot learn of the device": a condition on it gives a warning.
struct DeviceFacts
{
    struct Version
    {
        std::string_view key; // "firmware", "atmosphere", "glibc"…
        std::string_view value; // dotted, "18.0.0"
    };
    std::span<const Version> versions;
    std::optional<std::uint64_t> ram_mb;
    std::optional<std::uint32_t> screen_width;
    std::optional<std::uint32_t> screen_height;
    // The graphics interfaces it offers ("gles2", "vulkan"…); nothing: unknown.
    std::optional<std::span<const std::string_view>> gpus;
};

enum class Offer : std::uint8_t
{
    offer, // every condition holds
    warn, // a condition the client cannot read: offered, with a warning naming it, and `text` shown
    refuse, // a condition the device fails: not installed, and the client says which and why
};

enum class ConditionState : std::uint8_t
{
    met,
    failed,
    unreadable,
};

struct Condition
{
    using allocator_type = Allocator;

    String key; // "min.glibc", "gpu", or an unknown member's key
    String detail; // for people: "glibc 2.30 or later; this device has 2.28"
    ConditionState state = ConditionState::met;

    explicit Condition(const allocator_type& allocator)
        : key(allocator)
        , detail(allocator)
    {
    }
    Condition(const Condition& other, const allocator_type& allocator)
        : key(other.key, allocator)
        , detail(other.detail, allocator)
        , state(other.state)
    {
    }
    Condition(Condition&& other, const allocator_type& allocator)
        : key(std::move(other.key), allocator)
        , detail(std::move(other.detail), allocator)
        , state(other.state)
    {
    }
    Condition(const Condition&)            = default;
    Condition(Condition&&) noexcept        = default;
    Condition& operator=(const Condition&) = default;
    Condition& operator=(Condition&&)      = default;
    ~Condition()                           = default;
};

struct RequiresCheck
{
    Offer offer = Offer::offer;
    Vector<Condition> conditions;

    explicit RequiresCheck(const Allocator& allocator)
        : conditions(allocator)
    {
    }
};

// Two dotted versions compared part by part as numbers, a missing part
// being 0 (§ 8.7): <0, 0 or >0; nothing when either is not dotted.
[[nodiscard]] std::optional<int> compare_dotted(std::string_view a, std::string_view b) noexcept;

// § 8.7's decision. `profile` gives the keys of `min` the platform has.
// `requires.homebrew` (dependencies) is the app's to install first; it is
// not a condition here.
[[nodiscard]] RequiresCheck check_requires(
    const Requires& requires_, const Profile& profile, const DeviceFacts& device, Allocator allocator = {});

} // namespace lantern
