// Homebrew (§ 8): packages, install plans, signatures and pins, ports'
// data, requirements, paths and profiles.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/ed25519.hpp>
#include <lantern/homebrew.hpp>
#include <lantern/paths.hpp>
#include <lantern/pinning.hpp>
#include <lantern/profiles.hpp>
#include <lantern/requires.hpp>

#include "callbacks.hpp"

using namespace lantern_c;

namespace
{

const lantern::InstallPlan* as_plan(const lantern_install_plan* plan) noexcept
{
    return reinterpret_cast<const lantern::InstallPlan*>(plan);
}

const lantern::LaunchCheck* as_launch(const lantern_launch_check* check) noexcept
{
    return reinterpret_cast<const lantern::LaunchCheck*>(check);
}

const lantern::RequiresCheck* as_requires(const lantern_requires_check* check) noexcept
{
    return reinterpret_cast<const lantern::RequiresCheck*>(check);
}

lantern_pin pin_of(const lantern::PinnedKey& key) noexcept
{
    lantern_pin out {};
    out.is_signed = key.is_signed;
    std::memcpy(out.public_key, key.public_key.data(), key.public_key.size());
    return out;
}

lantern::PinnedKey key_of(const lantern_pin& pin) noexcept
{
    lantern::PinnedKey out;
    out.is_signed = pin.is_signed;
    std::memcpy(out.public_key.data(), pin.public_key, out.public_key.size());
    return out;
}

} // namespace

// NOLINTBEGIN(readability-identifier-naming,misc-use-internal-linkage)
extern "C" {

LANTERN_API lantern_status lantern_pick_package(
    const lantern_homebrew* entry, const char* device_arch, const lantern_package** out, lantern_error* error)
{
    if (entry == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out              = nullptr;
    const auto picked = lantern::pick_package(*as(entry), text(device_arch));
    if (!picked)
        return fail(error, picked.error());
    *out = wrap(*picked);
    return ok(error);
}

LANTERN_API lantern_status lantern_plan_install(const lantern_homebrew* entry, const lantern_package* package,
    const lantern_allocator* allocator, lantern_install_plan** out, lantern_error* error)
{
    if (entry == nullptr || package == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    auto plan = lantern::plan_install(*as(entry), *as(package), lantern::Allocator(resource.get()));
    if (!plan)
        return fail(error, plan.error());
    *out = reinterpret_cast<lantern_install_plan*>(
        box_new<lantern::InstallPlan>(resource.get(), std::move(*plan)));
    return ok(error);
}

LANTERN_API void lantern_install_plan_free(lantern_install_plan* plan)
{
    unbox(reinterpret_cast<lantern::InstallPlan*>(plan));
}

LANTERN_API lantern_placement lantern_install_plan_get_placement(const lantern_install_plan* plan)
{
    return plan == nullptr ? LANTERN_PLACEMENT_ARCHIVE
                           : static_cast<lantern_placement>(as_plan(plan)->placement);
}

LANTERN_API bool lantern_install_plan_get_ask_before_installer(const lantern_install_plan* plan)
{
    return plan != nullptr && as_plan(plan)->ask_before_installer;
}

LANTERN_API size_t lantern_install_plan_get_consent_count(const lantern_install_plan* plan)
{
    return plan == nullptr ? 0 : as_plan(plan)->consent_count;
}

LANTERN_API size_t lantern_install_plan_get_file_count(const lantern_install_plan* plan)
{
    return plan == nullptr ? 0 : as_plan(plan)->files.size();
}

LANTERN_API bool lantern_install_plan_get_file(
    const lantern_install_plan* plan, size_t index, lantern_planned_file* out)
{
    if (plan == nullptr || out == nullptr || index >= as_plan(plan)->files.size())
        return false;
    const lantern::PlannedFile& file = as_plan(plan)->files[index];
    lantern_planned_file result {};
    result.struct_size   = sizeof(result);
    result.path          = view(file.path);
    result.size          = file.size;
    result.needs_consent = file.needs_consent;
    copy_digest(file.sha256, result.sha256);
    give_struct(result, out);
    return true;
}

LANTERN_API lantern_status lantern_files_to_remove(const lantern_package* old_package,
    const lantern_package* new_package, const lantern_allocator* allocator, lantern_strings** out,
    lantern_error* error)
{
    if (old_package == nullptr || new_package == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    auto files = lantern::files_to_remove(
        as(old_package)->manifest, as(new_package)->manifest, lantern::Allocator(resource.get()));
    *out = reinterpret_cast<lantern_strings*>(
        box_new<lantern::Vector<lantern::String>>(resource.get(), std::move(files)));
    return ok(error);
}

LANTERN_API lantern_status lantern_check_system_id(const lantern_homebrew* entry,
    const lantern_installed_system_id* installed, size_t count, lantern_error* error)
{
    if (entry == nullptr || (installed == nullptr && count != 0))
        return usage(error, "a NULL argument");
    lantern::Vector<lantern::InstalledSystemId> list { lantern::Allocator(Resource::standard()) };
    list.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
        list.push_back({ text(installed[i].id), text(installed[i].system_id) });
    const auto checked = lantern::check_system_id(*as(entry), list);
    if (!checked)
        return fail(error, checked.error());
    return ok(error);
}

LANTERN_API lantern_status lantern_check_port(const lantern_homebrew* entry, lantern_error* error)
{
    if (entry == nullptr)
        return usage(error, "entry is NULL");
    const auto checked = lantern::check_port(*as(entry));
    if (!checked)
        return fail(error, checked.error());
    return ok(error);
}

LANTERN_API void lantern_manifest_digest(const lantern_package* package, uint8_t out[32])
{
    if (package == nullptr || out == nullptr)
        return;
    copy_digest(lantern::manifest_digest(as(package)->manifest), out);
}

LANTERN_API lantern_status lantern_verify_package_signature(const lantern_homebrew* entry,
    const lantern_package* package, lantern_package_signature* out, lantern_error* error)
{
    if (entry == nullptr || package == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    const auto verified = lantern::verify_package_signature(*as(entry), *as(package));
    if (!verified)
        return fail(error, verified.error());
    lantern_package_signature result {};
    result.struct_size = sizeof(result);
    result.is_signed   = verified->is_signed;
    std::memcpy(result.public_key, verified->public_key.data(), verified->public_key.size());
    give_struct(result, out);
    return ok(error);
}

LANTERN_API lantern_status lantern_check_pin(lantern_pin_store* store, const char* platform, const char* id,
    const lantern_package_signature* signature, lantern_pin_check* out, lantern_error* error)
{
    if (store == nullptr || signature == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    const lantern_package_signature s = copy_struct(signature);
    lantern::PackageSignature offered;
    offered.is_signed = s.is_signed;
    std::memcpy(offered.public_key.data(), s.public_key, offered.public_key.size());
    const auto checked = lantern::check_pin(*store, text(platform), text(id), offered);
    if (!checked)
        return fail(error, checked.error());
    lantern_pin_check result {};
    result.struct_size = sizeof(result);
    result.verdict     = static_cast<lantern_pin_verdict>(checked->verdict);
    if (checked->pinned)
    {
        result.has_pinned = true;
        result.pinned     = pin_of(*checked->pinned);
    }
    result.offered       = pin_of(checked->offered);
    result.needs_consent = checked->needs_consent();
    give_struct(result, out);
    return ok(error);
}

LANTERN_API lantern_status lantern_commit_pin(lantern_pin_store* store, const char* platform, const char* id,
    const lantern_pin_check* check, bool user_accepted_change, lantern_error* error)
{
    if (store == nullptr || check == nullptr)
        return usage(error, "a NULL argument");
    const lantern_pin_check c = copy_struct(check);
    lantern::PinCheck in;
    in.verdict = static_cast<lantern::PinVerdict>(c.verdict);
    if (c.has_pinned)
        in.pinned = key_of(c.pinned);
    in.offered        = key_of(c.offered);
    const auto stored = lantern::commit_pin(*store, text(platform), text(id), in, user_accepted_change);
    if (!stored)
        return fail(error, stored.error());
    return ok(error);
}

LANTERN_API lantern_status lantern_launch_check_run(const lantern_port* port, lantern_data_probe* probe,
    const lantern_allocator* allocator, lantern_launch_check** out, lantern_error* error)
{
    if (port == nullptr || probe == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    auto check = lantern::launch_check(*as(port), *probe, lantern::Allocator(resource.get()));
    if (!check)
        return fail(error, check.error());
    *out = reinterpret_cast<lantern_launch_check*>(
        box_new<lantern::LaunchCheck>(resource.get(), std::move(*check)));
    return ok(error);
}

LANTERN_API void lantern_launch_check_free(lantern_launch_check* check)
{
    unbox(reinterpret_cast<lantern::LaunchCheck*>(check));
}

LANTERN_API bool lantern_launch_check_get_ready(const lantern_launch_check* check)
{
    return check != nullptr && as_launch(check)->ready;
}

LANTERN_API bool lantern_launch_check_get_unverified(const lantern_launch_check* check)
{
    return check != nullptr && as_launch(check)->unverified;
}

LANTERN_API size_t lantern_launch_check_get_issue_count(const lantern_launch_check* check)
{
    return check == nullptr ? 0 : as_launch(check)->issues.size();
}

LANTERN_API bool lantern_launch_check_get_issue(
    const lantern_launch_check* check, size_t index, lantern_launch_issue* out)
{
    if (check == nullptr || out == nullptr || index >= as_launch(check)->issues.size())
        return false;
    const lantern::LaunchIssue& issue = as_launch(check)->issues[index];
    lantern_launch_issue result {};
    result.struct_size = sizeof(result);
    result.path        = view(issue.path);
    result.hint        = view(issue.hint);
    result.issue       = static_cast<lantern_data_issue>(issue.issue);
    result.in_group    = issue.in_group;
    give_struct(result, out);
    return true;
}

LANTERN_API lantern_status lantern_check_requires(const lantern_requires* requires_, const char* platform,
    const lantern_device_facts* device, const lantern_allocator* allocator, lantern_requires_check** out,
    lantern_error* error)
{
    if (requires_ == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                            = nullptr;
    const lantern::Profile* profile = lantern::find_profile(text(platform));
    if (profile == nullptr)
        return fail(error, lantern::Category::unsupported, "no profile for this platform (Annex A)");
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    const lantern::Allocator memory(resource.get());
    const lantern_device_facts d = copy_struct(device);
    if ((d.versions == nullptr && d.version_count != 0) || (d.gpus == nullptr && d.gpu_count != 0))
        return usage(error, "a NULL array with items");
    lantern::Vector<lantern::DeviceFacts::Version> versions(memory);
    versions.reserve(d.version_count);
    for (std::size_t i = 0; i < d.version_count; ++i)
        versions.push_back({ text(d.versions[i].key), text(d.versions[i].value) });
    lantern::Vector<std::string_view> gpus(memory);
    gpus.reserve(d.gpu_count);
    for (std::size_t i = 0; i < d.gpu_count; ++i)
        gpus.push_back(text(d.gpus[i]));
    lantern::DeviceFacts facts;
    facts.versions = versions;
    if (d.has_ram_mb)
        facts.ram_mb = d.ram_mb;
    if (d.has_screen)
    {
        facts.screen_width  = d.screen_width;
        facts.screen_height = d.screen_height;
    }
    if (d.has_gpus)
        facts.gpus = std::span<const std::string_view>(gpus);
    auto check = lantern::check_requires(*as(requires_), *profile, facts, memory);
    *out       = reinterpret_cast<lantern_requires_check*>(
        box_new<lantern::RequiresCheck>(resource.get(), std::move(check)));
    return ok(error);
}

LANTERN_API void lantern_requires_check_free(lantern_requires_check* check)
{
    unbox(reinterpret_cast<lantern::RequiresCheck*>(check));
}

LANTERN_API lantern_offer lantern_requires_check_get_offer(const lantern_requires_check* check)
{
    return check == nullptr ? LANTERN_REFUSE : static_cast<lantern_offer>(as_requires(check)->offer);
}

LANTERN_API size_t lantern_requires_check_get_condition_count(const lantern_requires_check* check)
{
    return check == nullptr ? 0 : as_requires(check)->conditions.size();
}

LANTERN_API bool lantern_requires_check_get_condition(
    const lantern_requires_check* check, size_t index, lantern_condition* out)
{
    if (check == nullptr || out == nullptr || index >= as_requires(check)->conditions.size())
        return false;
    const lantern::Condition& condition = as_requires(check)->conditions[index];
    lantern_condition result {};
    result.struct_size = sizeof(result);
    result.key         = view(condition.key);
    result.detail      = view(condition.detail);
    result.state       = static_cast<lantern_condition_state>(condition.state);
    give_struct(result, out);
    return true;
}

LANTERN_API lantern_path_problem lantern_check_device_path(const char* path, size_t size)
{
    if (path == nullptr && size != 0)
        return LANTERN_PATH_EMPTY;
    return static_cast<lantern_path_problem>(
        lantern::check_device_path(std::string_view(path == nullptr ? "" : path, size)));
}

LANTERN_API lantern_path_problem lantern_check_data_path(const char* path, size_t size)
{
    if (path == nullptr && size != 0)
        return LANTERN_PATH_EMPTY;
    return static_cast<lantern_path_problem>(
        lantern::check_data_path(std::string_view(path == nullptr ? "" : path, size)));
}

LANTERN_API lantern_path_problem lantern_check_data_root(const char* path, size_t size)
{
    if (path == nullptr && size != 0)
        return LANTERN_PATH_EMPTY;
    return static_cast<lantern_path_problem>(
        lantern::check_data_root(std::string_view(path == nullptr ? "" : path, size)));
}

LANTERN_API const char* lantern_path_problem_text(lantern_path_problem problem)
{
    if (problem < LANTERN_PATH_OK || problem > LANTERN_PATH_NOT_A_FOLDER)
        return "";
    // describe() gives views of literals: NUL-terminated
    return lantern::describe(static_cast<lantern::PathProblem>(problem)).data();
}

LANTERN_API lantern_root_match lantern_match_roots(
    const char* platform, const char* homebrew_id, const char* path)
{
    const lantern::Profile* profile = lantern::find_profile(text(platform));
    if (profile == nullptr)
        return LANTERN_ROOT_NO_PROFILE;
    return static_cast<lantern_root_match>(lantern::match_roots(*profile, text(homebrew_id), text(path)));
}

LANTERN_API bool lantern_is_platform_name(const char* name)
{
    return lantern::is_platform_name(text(name));
}

LANTERN_API bool lantern_is_homebrew_id(const char* id)
{
    return lantern::is_homebrew_id(text(id));
}

LANTERN_API bool lantern_has_profile(const char* platform)
{
    return lantern::find_profile(text(platform)) != nullptr;
}

} // extern "C"
// NOLINTEND(readability-identifier-naming,misc-use-internal-linkage)
