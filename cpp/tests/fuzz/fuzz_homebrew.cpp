// A homebrew entry from a server, any bytes, and what a client does with
// it: choose a package, plan its install, check its port, its signature
// and its requirements. Nothing crashes, and a plan never holds a path
// outside the profile's roots.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <lantern/ed25519.hpp>
#include <lantern/homebrew.hpp>
#include <lantern/paths.hpp>
#include <lantern/requires.hpp>
#include <lantern/types.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    const auto read = lantern::read_homebrew(text);
    if (!read || !*read)
        return 0;
    const lantern::Homebrew& entry = **read;
    static_cast<void>(lantern::check_port(entry));
    const lantern::Profile* profile = lantern::find_profile(entry.platform);
    if (profile != nullptr && entry.requires_)
        static_cast<void>(lantern::check_requires(*entry.requires_, *profile, {}));
    for (const char* arch : { "aarch64", "x86_64" })
    {
        const auto package = lantern::pick_package(entry, arch);
        if (!package)
            continue;
        static_cast<void>(lantern::verify_package_signature(entry, **package));
        const auto plan = lantern::plan_install(entry, **package);
        if (!plan)
            continue;
        for (const lantern::PlannedFile& file : plan->files)
        {
            if (lantern::check_device_path(file.path) != lantern::PathProblem::none
                || lantern::match_roots(*profile, entry.id, file.path) == lantern::RootMatch::outside)
                __builtin_trap();
        }
    }
    return 0;
}
