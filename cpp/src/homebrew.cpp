#include <lantern/homebrew.hpp>

#include <algorithm>
#include <array>

#include <lantern/json.hpp>
#include <lantern/paths.hpp>

namespace lantern
{

namespace
{

constexpr std::size_t max_manifest      = 4096;
constexpr std::size_t max_packages      = 16;
constexpr std::size_t max_requires_data = 256;
constexpr std::size_t max_accept        = 32;

// "<what>: <detail>" in a buffer an Error takes.
struct Message
{
    std::array<char, 200> buffer {};
    std::size_t size = 0;

    Message& operator<<(std::string_view part) noexcept
    {
        const std::size_t n = std::min(part.size(), buffer.size() - size);
        std::copy_n(part.data(), n, buffer.data() + size);
        size += n;
        return *this;
    }
    [[nodiscard]] std::string_view view() const noexcept { return { buffer.data(), size }; }
};

std::unexpected<Error> refuse(std::string_view what, std::string_view detail)
{
    Message message;
    message << what << ": " << detail;
    return fail(Category::refused, message.view());
}

std::unexpected<Error> no_profile(std::string_view platform)
{
    Message message;
    message << "no profile for the platform " << platform
            << ": a client installs nothing of it (SPEC.md 4.3)";
    return fail(Category::unsupported, message.view());
}

// The single file's place in the profile (§ 8.2, Annex A): `where` with
// "<id>" replaced, or a file directly in that folder.
bool single_file_in_place(std::string_view where, std::string_view id, std::string_view path)
{
    std::array<char, 1100> buffer {};
    std::size_t size = 0;
    for (std::size_t i = 0; i < where.size();)
    {
        const std::string_view piece = where.substr(i).starts_with("<id>") ? id : where.substr(i, 1);
        if (size + piece.size() > buffer.size())
            return false;
        std::copy_n(piece.data(), piece.size(), buffer.data() + size);
        size += piece.size();
        i += where.substr(i).starts_with("<id>") ? std::size_t { 4 } : std::size_t { 1 };
    }
    const std::string_view place(buffer.data(), size);
    if (!place.empty() && place.back() == '/')
        return strictly_under(place, path) && path.substr(place.size()).find('/') == std::string_view::npos;
    return path == place;
}

bool has_arch(const Package& package, std::string_view arch)
{
    return std::ranges::any_of(package.arch, [&](const String& name) { return name == arch; });
}

} // namespace

void canonical_manifest(std::span<const ManifestEntry> manifest, String& out)
{
    Vector<const ManifestEntry*> sorted(out.get_allocator());
    sorted.reserve(manifest.size());
    for (const ManifestEntry& entry : manifest)
        sorted.push_back(&entry);
    std::ranges::sort(sorted, [](const ManifestEntry* a, const ManifestEntry* b)
        { return std::string_view(a->path) < std::string_view(b->path); });
    json::Writer writer(out);
    writer.begin_array();
    for (const ManifestEntry* entry : sorted)
    {
        writer.begin_object();
        writer.key("path");
        writer.string(entry->path);
        writer.key("sha256");
        const auto hex = to_hex(entry->sha256);
        writer.string(std::string_view(hex.data(), hex.size()));
        writer.key("size");
        writer.number(entry->size);
        writer.end_object();
    }
    writer.end_array();
}

Digest manifest_digest(std::span<const ManifestEntry> manifest)
{
    String canonical;
    canonical_manifest(manifest, canonical);
    return Sha256::of(canonical);
}

void signed_message(std::string_view id, std::string_view platform, std::uint64_t build, const Digest& sha256,
    const Digest& manifest_sha256, String& out)
{
    json::Writer writer(out);
    writer.begin_object();
    writer.key("build");
    writer.number(build);
    writer.key("id");
    writer.string(id);
    writer.key("manifest_sha256");
    const auto manifest_hex = to_hex(manifest_sha256);
    writer.string(std::string_view(manifest_hex.data(), manifest_hex.size()));
    writer.key("platform");
    writer.string(platform);
    writer.key("purpose");
    writer.string("lantern-homebrew-1");
    writer.key("sha256");
    const auto hex = to_hex(sha256);
    writer.string(std::string_view(hex.data(), hex.size()));
    writer.end_object();
}

Result<const Package*> pick_package(const Homebrew& entry, std::string_view device_arch)
{
    const Profile* profile = find_profile(entry.platform);
    if (profile == nullptr)
        return no_profile(entry.platform);
    if (entry.packages.size() > max_packages)
        return refuse(entry.id, "more than 16 packages (SPEC.md 13)");
    const auto check_names = [](const Package& package)
    { return std::ranges::all_of(package.arch, [](const String& name) { return is_arch_name(name); }); };
    if (!check_names(entry.package)
        || !std::ranges::all_of(entry.packages, [&](const Package& package) { return check_names(package); }))
        return refuse(entry.id, "an architecture name not of SPEC.md 8.2's form");
    if (profile->arches.empty())
    {
        // One architecture: no package carries `arch` (§ 8.2)
        if (!entry.package.arch.empty() || !entry.packages.empty())
            return refuse(entry.id, "a package with an architecture on a platform that has one");
        return &entry.package;
    }
    if (std::ranges::any_of(entry.packages, [](const Package& package) { return package.arch.empty(); }))
        return refuse(entry.id, "a package of packages without its architecture (SPEC.md 8.2)");
    if (has_arch(entry.package, device_arch))
        return &entry.package;
    for (const Package& package : entry.packages)
    {
        if (has_arch(package, device_arch))
            return &package;
    }
    if (entry.package.arch.empty())
        return &entry.package;
    Message message;
    message << entry.id << ": no package for the architecture " << device_arch;
    return fail(Category::unsupported, message.view());
}

Result<InstallPlan> plan_install(const Homebrew& entry, const Package& package, Allocator allocator)
{
    const Profile* profile = find_profile(entry.platform);
    if (profile == nullptr)
        return no_profile(entry.platform);
    if (!is_homebrew_id(entry.id))
        return refuse(entry.id, "not a homebrew id of SPEC.md 8.1's form");
    const HomebrewFormat* format = find_homebrew_format(*profile, package.format);
    if (format == nullptr)
        return refuse(package.format, "not a homebrew format of the platform's profile");

    InstallPlan plan(allocator);
    plan.placement = format->placement;
    if (format->placement == Placement::system_installer)
    {
        if (!package.path.empty() || !package.manifest.empty())
            return refuse(entry.id, "a package the system installs has no path and an empty manifest");
        plan.ask_before_installer = format->client_asks_first;
        return plan;
    }

    // The files: a single file is a manifest of one entry (§ 8.2)
    Vector<ManifestEntry> single(allocator);
    std::span<const ManifestEntry> manifest = package.manifest;
    if (format->placement == Placement::single_file)
    {
        if (package.path.empty())
            return refuse(entry.id, "a single file without its path");
        if (const PathProblem problem = check_device_path(package.path); problem != PathProblem::none)
            return refuse(package.path, describe(problem));
        if (!single_file_in_place(format->where, entry.id, package.path))
            return refuse(package.path, "not where the profile puts this format");
        single.emplace_back();
        single.back().path.assign(package.path);
        single.back().size   = package.size;
        single.back().sha256 = package.sha256;
        if (!package.manifest.empty())
        {
            const ManifestEntry& given = package.manifest.front();
            if (package.manifest.size() != 1 || given.path != package.path || given.size != package.size
                || !same_digest(given.sha256, package.sha256))
                return refuse(entry.id, "a single file's manifest is not that file");
        }
        manifest = single;
    }
    else
    {
        if (package.manifest.empty())
            return refuse(
                entry.id, "an archive without its manifest (a listing leaves it out: read the entry)");
        if (package.manifest.size() > max_manifest)
            return refuse(entry.id, "a manifest of more than 4096 files (SPEC.md 13)");
        if (!package.path.empty())
            return refuse(entry.id, "an archive with a path");
    }

    for (const ManifestEntry& file : manifest)
    {
        if (const PathProblem problem = check_device_path(file.path); problem != PathProblem::none)
            return refuse(file.path, describe(problem));
    }

    // No two paths the same when case is ignored, and no file under another
    Vector<String> folded(allocator);
    folded.reserve(manifest.size());
    for (const ManifestEntry& file : manifest)
    {
        String lower(file.path, allocator);
        std::ranges::transform(lower, lower.begin(),
            [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; });
        folded.push_back(std::move(lower));
    }
    std::ranges::sort(folded);
    if (std::ranges::adjacent_find(folded) != folded.end())
        return refuse(entry.id, "two paths of the manifest are the same when case is ignored");
    for (const String& path : folded)
    {
        for (std::size_t slash = path.find('/', 1); slash != String::npos; slash = path.find('/', slash + 1))
        {
            if (std::ranges::binary_search(
                    folded, std::string_view(path).substr(0, slash),
                    [](std::string_view a, std::string_view b) { return a < b; },
                    [](const auto& s) { return std::string_view(s); }))
                return refuse(path, "a file of the manifest lies under another");
        }
    }

    if (!same_digest(manifest_digest(manifest), package.manifest_sha256))
        return refuse(entry.id, "the manifest does not match its manifest_sha256");

    for (const ManifestEntry& file : manifest)
    {
        const RootMatch match = match_roots(*profile, entry.id, file.path);
        if (match == RootMatch::outside)
            return refuse(file.path, "outside the profile's roots for homebrew (SPEC.md 8.3)");
        plan.files.emplace_back();
        PlannedFile& planned  = plan.files.back();
        planned.path          = file.path;
        planned.size          = file.size;
        planned.sha256        = file.sha256;
        planned.needs_consent = match == RootMatch::consent;
        if (planned.needs_consent)
            ++plan.consent_count;
    }
    return plan;
}

Vector<String> files_to_remove(std::span<const ManifestEntry> old_manifest,
    std::span<const ManifestEntry> new_manifest, Allocator allocator)
{
    Vector<String> out(allocator);
    for (const ManifestEntry& old_file : old_manifest)
    {
        const bool kept = std::ranges::any_of(
            new_manifest, [&](const ManifestEntry& new_file) { return new_file.path == old_file.path; });
        if (!kept)
            out.emplace_back(old_file.path);
    }
    return out;
}

Result<void> check_system_id(const Homebrew& entry, std::span<const InstalledSystemId> installed)
{
    if (entry.system_id.empty())
        return {};
    for (const InstalledSystemId& other : installed)
    {
        if (other.system_id == entry.system_id && other.id != entry.id)
            return refuse(
                entry.id, "its system_id is that of software another homebrew installed (SPEC.md 8.3)");
    }
    return {};
}

Result<void> check_port(const Homebrew& entry)
{
    if (entry.kind != "port")
        return {};
    if (!entry.port)
        return refuse(entry.id, "a port without its port object");
    const Profile* profile = find_profile(entry.platform);
    if (profile == nullptr)
        return no_profile(entry.platform);
    const Port& port = *entry.port;
    if (const PathProblem problem = check_data_root(port.data_root); problem != PathProblem::none)
        return refuse(port.data_root, describe(problem));
    if (profile->port_areas.empty())
        return fail(Category::unsupported, "this platform's profile has no area for ports' data yet");
    if (!std::ranges::any_of(
            profile->port_areas, [&](std::string_view area) { return strictly_under(area, port.data_root); }))
        return refuse(port.data_root, "outside the profile's areas for ports' data (SPEC.md 8.6)");
    if (port.requires_data.size() > max_requires_data)
        return refuse(entry.id, "more than 256 required files (SPEC.md 13)");

    const auto check_file = [&](const RequiredFile& file) -> Result<void>
    {
        if (const PathProblem problem = check_data_path(file.path); problem != PathProblem::none)
            return refuse(file.path, describe(problem));
        if (file.hint.empty())
            return refuse(file.path, "a required file without its hint");
        if (file.accept.size() > max_accept)
            return refuse(file.path, "more than 32 accepted versions (SPEC.md 13)");
        for (const AcceptedVersion& version : file.accept)
        {
            if (!version.sha256 && version.sha1.empty() && version.md5.empty())
                return refuse(file.path, "an accepted version without a hash");
        }
        // A port's data is never in its package (§ 8.6)
        for (const ManifestEntry& packaged : entry.package.manifest)
        {
            if (packaged.path.size() == port.data_root.size() + file.path.size()
                && std::string_view(packaged.path).starts_with(port.data_root)
                && std::string_view(packaged.path).ends_with(file.path))
                return refuse(packaged.path, "the package holds a file the user supplies");
        }
        return {};
    };

    for (const RequiredData& item : port.requires_data)
    {
        if (!item.one_of.empty())
        {
            if (!item.path.empty())
                return refuse(entry.id, "a required item that is both a file and a group");
            if (item.one_of.size() < 2)
                return refuse(entry.id, "a group of required files with fewer than two alternatives");
            for (const Vector<RequiredFile>& alternative : item.one_of)
            {
                if (alternative.empty())
                    return refuse(entry.id, "an empty alternative in a group of required files");
                for (const RequiredFile& file : alternative)
                {
                    if (auto checked = check_file(file); !checked)
                        return checked;
                }
            }
            continue;
        }
        RequiredFile file(item.path.get_allocator());
        file.path = item.path;
        file.hint = item.hint;
        file.size = item.size;
        for (const AcceptedVersion& version : item.accept)
            file.accept.push_back(version);
        if (auto checked = check_file(file); !checked)
            return checked;
    }
    return {};
}

namespace
{

struct FileVerdict
{
    bool ok         = false;
    bool unverified = false;
    DataIssue issue = DataIssue::missing;
};

Result<FileVerdict> probe_file(DataProbe& probe, std::string_view data_root, std::string_view path,
    std::optional<std::uint64_t> expected_size, std::span<const AcceptedVersion> accept)
{
    String full(data_root);
    full.append(path);
    const auto size = probe.size(full);
    if (!size)
        return std::unexpected(size.error());
    if (!*size)
        return FileVerdict { false, false, DataIssue::missing };
    if (expected_size && **size != *expected_size)
        return FileVerdict { false, false, DataIssue::wrong_size };
    if (accept.empty())
        return FileVerdict { true, false, DataIssue::missing };
    const bool any_sha256
        = std::ranges::any_of(accept, [](const AcceptedVersion& v) { return v.sha256.has_value(); });
    const bool other_only
        = std::ranges::any_of(accept, [](const AcceptedVersion& v) { return !v.sha256.has_value(); });
    if (any_sha256)
    {
        const auto digest = probe.sha256(full);
        if (!digest)
            return std::unexpected(digest.error());
        for (const AcceptedVersion& version : accept)
        {
            if (version.sha256 && same_digest(*version.sha256, *digest))
                return FileVerdict { true, false, DataIssue::missing };
        }
    }
    // A version known only by SHA-1 or MD5 may be this one
    if (other_only)
        return FileVerdict { true, true, DataIssue::missing };
    return FileVerdict { false, false, DataIssue::unknown_version };
}

void add_issue(
    LaunchCheck& check, std::string_view path, std::string_view hint, DataIssue issue, bool in_group)
{
    check.issues.emplace_back();
    LaunchIssue& added = check.issues.back();
    added.path.assign(path);
    added.hint.assign(hint);
    added.issue    = issue;
    added.in_group = in_group;
}

} // namespace

Result<LaunchCheck> launch_check(const Port& port, DataProbe& probe, Allocator allocator)
{
    LaunchCheck check(allocator);
    bool ready = true;
    for (const RequiredData& item : port.requires_data)
    {
        const bool optional = item.optional.value_or(false);
        if (item.one_of.empty())
        {
            const auto verdict = probe_file(probe, port.data_root, item.path, item.size, item.accept);
            if (!verdict)
                return std::unexpected(verdict.error());
            if (verdict->ok)
                check.unverified = check.unverified || verdict->unverified;
            else if (!optional)
            {
                ready = false;
                add_issue(check, item.path, item.hint, verdict->issue, false);
            }
            continue;
        }
        bool satisfied  = false;
        bool unverified = false;
        LaunchCheck group(allocator);
        for (const Vector<RequiredFile>& alternative : item.one_of)
        {
            bool complete               = true;
            bool alternative_unverified = false;
            for (const RequiredFile& file : alternative)
            {
                if (file.optional.value_or(false))
                    continue;
                const auto verdict = probe_file(probe, port.data_root, file.path, file.size, file.accept);
                if (!verdict)
                    return std::unexpected(verdict.error());
                if (!verdict->ok)
                {
                    complete = false;
                    add_issue(group, file.path, file.hint, verdict->issue, true);
                }
                alternative_unverified = alternative_unverified || verdict->unverified;
            }
            if (complete)
            {
                satisfied  = true;
                unverified = alternative_unverified;
                break;
            }
        }
        if (satisfied)
            check.unverified = check.unverified || unverified;
        else if (!optional)
        {
            ready = false;
            for (LaunchIssue& issue : group.issues)
                check.issues.push_back(std::move(issue));
        }
    }
    check.ready = ready;
    return check;
}

} // namespace lantern
