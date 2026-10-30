// Paths and manifests: the checks never accept what SPEC.md 8.2 refuses,
// whatever the bytes. The input is a device path, then a manifest of the
// lines that follow.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <lantern/homebrew.hpp>
#include <lantern/paths.hpp>
#include <lantern/types.hpp>

namespace
{

// What SPEC.md 8.2 says, written again the slow way, to compare.
bool valid_by_the_text(std::string_view path)
{
    if (path.empty() || path.size() > 1024 || path[0] != '/')
        return false;
    std::size_t start = 1;
    for (;;)
    {
        const std::size_t end = path.find('/', start);
        const std::string_view part
            = path.substr(start, end == std::string_view::npos ? path.npos : end - start);
        if (part.empty() || part == "." || part == ".." || part.size() > 255)
            return false;
        for (const char c : part)
        {
            const auto b = static_cast<unsigned char>(c);
            if (b < 0x20 || b == 0x7F || c == '\\' || c == ':' || c == '"')
                return false;
        }
        if (end == std::string_view::npos)
            return true;
        start = end + 1;
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    const std::string_view first = text.substr(0, text.find('\n'));
    const bool accepted          = lantern::check_device_path(first) == lantern::PathProblem::none;
    if (accepted != valid_by_the_text(first))
        __builtin_trap();
    static_cast<void>(lantern::check_data_path(first));
    static_cast<void>(lantern::check_data_root(first));
    for (const lantern::Profile& profile : lantern::profiles())
        static_cast<void>(lantern::match_roots(profile, "org.example.fuzz", first));

    // A zip entry for the Switch whose manifest is every line
    lantern::Homebrew entry;
    entry.id             = "org.example.fuzz";
    entry.platform       = "switch";
    entry.package.format = "zip";
    std::size_t start    = 0;
    while (start <= text.size() && entry.package.manifest.size() < 64)
    {
        const std::size_t end = std::min(text.find('\n', start), text.size());
        entry.package.manifest.emplace_back();
        entry.package.manifest.back().path.assign(text.substr(start, end - start));
        entry.package.manifest.back().size = end - start;
        start                              = end + 1;
    }
    entry.package.manifest_sha256 = lantern::manifest_digest(entry.package.manifest);
    const auto plan               = lantern::plan_install(entry, entry.package);
    if (plan)
    {
        for (const lantern::PlannedFile& file : plan->files)
        {
            if (!valid_by_the_text(file.path)
                || lantern::match_roots(*lantern::find_profile("switch"), entry.id, file.path)
                    == lantern::RootMatch::outside)
                __builtin_trap();
        }
    }
    return 0;
}
