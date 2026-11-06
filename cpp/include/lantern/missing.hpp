// What a device is missing (SPEC.md § 6.3), computed over the whole listing
// of its platform: by a client over a static library (L-21.3-2), by a
// server for POST <base>/v1/apps/missing.
#pragma once

#include <span>
#include <string_view>

#include <lantern/memory.hpp>
#include <lantern/types.hpp>

namespace lantern
{

// The apps of `apps` (all of `platform`, every variant) that `request` says the
// device is missing: for each installed game its newest update, if it is newer
// than the installed one, and its add-ons not installed; with `base`, the games
// not installed at all. The versions an installed app includes count as
// installed (L-6.3-4); `formats` and `satisfies`, when present, keep only what
// the device reads and provides (L-6.3-3). In the order of `apps`, grouped by
// game; a server sorts and pages them.
[[nodiscard]] Vector<App> missing_apps(std::span<const App> apps, std::string_view platform,
    const MissingRequest& request, const Allocator& allocator = {});

} // namespace lantern
