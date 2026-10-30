// Homebrew (SPEC.md § 8): what a client checks before it installs a
// package, what it writes and where, which package fits the device, and
// whether a port has its data before it launches. The library decides; the
// app writes the files, asks the user, and keeps the manifests.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <lantern/error.hpp>
#include <lantern/memory.hpp>
#include <lantern/profiles.hpp>
#include <lantern/sha256.hpp>
#include <lantern/types.hpp>

namespace lantern
{

// § 8.2: the canonical form of a manifest, the JSON array of its entries
// sorted by path (as UTF-8 bytes), each {"path":…,"sha256":…,"size":…}.
void canonical_manifest(std::span<const ManifestEntry> manifest, String& out);
[[nodiscard]] Digest manifest_digest(std::span<const ManifestEntry> manifest);

// § 8.4: the bytes an author signs for a package.
void signed_message(std::string_view id, std::string_view platform, std::uint64_t build, const Digest& sha256,
    const Digest& manifest_sha256, String& out);

// § 8.2: the package of `entry` for a device of architecture `device_arch`:
// the one whose `arch` lists it, else one without `arch`. Refused
// (Category::refused) when an `arch` name is malformed, when a platform
// with one architecture gets a package with `arch`, or when the platform has
// no profile; Category::unsupported when no package fits the device.
[[nodiscard]] Result<const Package*> pick_package(const Homebrew& entry, std::string_view device_arch);

struct PlannedFile
{
    using allocator_type = Allocator;

    String path;
    std::uint64_t size = 0;
    Digest sha256 {};
    bool needs_consent = false;

    explicit PlannedFile(const allocator_type& allocator)
        : path(allocator)
    {
    }
    PlannedFile(const PlannedFile& other, const allocator_type& allocator)
        : path(other.path, allocator)
        , size(other.size)
        , sha256(other.sha256)
        , needs_consent(other.needs_consent)
    {
    }
    PlannedFile(PlannedFile&& other, const allocator_type& allocator)
        : path(std::move(other.path), allocator)
        , size(other.size)
        , sha256(other.sha256)
        , needs_consent(other.needs_consent)
    {
    }
    PlannedFile(const PlannedFile&)            = default;
    PlannedFile(PlannedFile&&) noexcept        = default;
    PlannedFile& operator=(const PlannedFile&) = default;
    PlannedFile& operator=(PlannedFile&&)      = default;
    ~PlannedFile()                             = default;
};

// What installing a package writes (§ 8.3).
struct InstallPlan
{
    Placement placement = Placement::archive;
    // system_installer: whether the client asks the user before it hands
    // the package to the platform's installer (Annex A).
    bool ask_before_installer = false;
    // Every file, in the manifest's order; a single file is a manifest of one.
    Vector<PlannedFile> files;
    // How many of them need the user's consent: the app shows each of
    // those paths and installs only when the user agrees.
    std::size_t consent_count = 0;

    explicit InstallPlan(const Allocator& allocator)
        : files(allocator)
    {
    }
};

// § 8.2 and § 8.3, before anything is downloaded: the package's format is
// one of the profile's; a single file's path is where the profile puts that
// format; a manifest has 4096 entries at most, valid paths, no two the same
// when case is ignored, no file under another, and matches its
// `manifest_sha256`; every path lies in the profile's roots. Anything else
// is refused (Category::refused) and nothing of the package is installed.
[[nodiscard]] Result<InstallPlan> plan_install(
    const Homebrew& entry, const Package& package, Allocator allocator = {});

// § 8.3: the files of an old manifest the new one no longer has, which an
// update removes.
[[nodiscard]] Vector<String> files_to_remove(std::span<const ManifestEntry> old_manifest,
    std::span<const ManifestEntry> new_manifest, Allocator allocator = {});

// § 8.3: an entry whose `system_id` is that of software another `id`
// installed is refused. `installed` holds (id, system_id) of what the
// device has.
struct InstalledSystemId
{
    std::string_view id;
    std::string_view system_id;
};
[[nodiscard]] Result<void> check_system_id(
    const Homebrew& entry, std::span<const InstalledSystemId> installed);

// § 8.6: a port's data_root lies strictly inside one of the profile's areas
// for ports' data, every data path is valid, a group has two alternatives
// at least, and the limits of § 13 hold. Anything else is refused.
[[nodiscard]] Result<void> check_port(const Homebrew& entry);

// What the device has of a port's data files: the app reads its storage.
class DataProbe
{
  public:
    DataProbe()                            = default;
    DataProbe(const DataProbe&)            = default;
    DataProbe(DataProbe&&)                 = default;
    DataProbe& operator=(const DataProbe&) = default;
    DataProbe& operator=(DataProbe&&)      = default;
    virtual ~DataProbe()                   = default;

    // The size of the file at `path` (data_root and the data path joined),
    // or nothing when it is not there.
    [[nodiscard]] virtual Result<std::optional<std::uint64_t>> size(std::string_view path) = 0;
    // Its SHA-256 (Sha256 hashes it as the app reads it).
    [[nodiscard]] virtual Result<Digest> sha256(std::string_view path) = 0;
};

enum class DataIssue : std::uint8_t
{
    missing, // not there
    unknown_version, // there, but its SHA-256 is none of `accept`'s
    wrong_size, // there, but not of the size the entry gives
};

struct LaunchIssue
{
    using allocator_type = Allocator;

    String path; // as the entry writes it, relative to data_root
    String hint; // where the user finds it in their copy
    DataIssue issue = DataIssue::missing;
    bool in_group   = false; // one of a group's alternatives

    explicit LaunchIssue(const allocator_type& allocator)
        : path(allocator)
        , hint(allocator)
    {
    }
    LaunchIssue(const LaunchIssue& other, const allocator_type& allocator)
        : path(other.path, allocator)
        , hint(other.hint, allocator)
        , issue(other.issue)
        , in_group(other.in_group)
    {
    }
    LaunchIssue(LaunchIssue&& other, const allocator_type& allocator)
        : path(std::move(other.path), allocator)
        , hint(std::move(other.hint), allocator)
        , issue(other.issue)
        , in_group(other.in_group)
    {
    }
    LaunchIssue(const LaunchIssue&)            = default;
    LaunchIssue(LaunchIssue&&) noexcept        = default;
    LaunchIssue& operator=(const LaunchIssue&) = default;
    LaunchIssue& operator=(LaunchIssue&&)      = default;
    ~LaunchIssue()                             = default;
};

struct LaunchCheck
{
    // Every file that is not optional is there and of a known version: the
    // port may launch.
    bool ready = false;
    // A file was taken on its presence alone: its `accept` gives only
    // SHA-1 or MD5, which this library does not compute (§ 8.6 makes them a
    // MAY).
    bool unverified = false;
    // What to show the user when it is not ready: each missing or unknown
    // file, with its hint.
    Vector<LaunchIssue> issues;

    explicit LaunchCheck(const Allocator& allocator)
        : issues(allocator)
    {
    }
};

// § 8.6: before a port launches. The port must have passed check_port().
[[nodiscard]] Result<LaunchCheck> launch_check(const Port& port, DataProbe& probe, Allocator allocator = {});

} // namespace lantern
