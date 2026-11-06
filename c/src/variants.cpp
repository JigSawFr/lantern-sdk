// Packages a device cannot use and variants of one game (§ 6.1, Annex B.15).
#include <cstddef>
#include <string_view>

#include <lantern/variants.hpp>

#include "callbacks.hpp"

using namespace lantern_c;

namespace
{

const lantern::InstallDecision* as_decision(const lantern_install_decision* decision) noexcept
{
    return reinterpret_cast<const lantern::InstallDecision*>(decision);
}

const lantern::App* const* apps_of(const lantern_app* const* items) noexcept
{
    static_assert(sizeof(const lantern_app*) == sizeof(const lantern::App*));
    return reinterpret_cast<const lantern::App* const*>(items);
}

} // namespace

// NOLINTBEGIN(readability-identifier-naming,misc-use-internal-linkage)
extern "C" {

LANTERN_API lantern_status lantern_app_install_decision(const lantern_app* app, const char* const* formats,
    size_t formats_count, const char* const* satisfies, size_t satisfies_count,
    const lantern_app* const* installed, size_t installed_count, const lantern_allocator* allocator,
    lantern_install_decision** out, lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    if (app == nullptr)
        return usage(error, "a NULL argument");
    if ((formats == nullptr && formats_count != 0) || (satisfies == nullptr && satisfies_count != 0)
        || (installed == nullptr && installed_count != 0))
        return usage(error, "a NULL array with items");
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    const lantern::Allocator memory(resource.get());
    lantern::Vector<std::string_view> known(memory);
    lantern::Vector<std::string_view> provided(memory);
    known.reserve(formats_count);
    provided.reserve(satisfies_count);
    for (std::size_t i = 0; i < formats_count; ++i)
        known.push_back(text(formats[i]));
    for (std::size_t i = 0; i < satisfies_count; ++i)
        provided.push_back(text(satisfies[i]));
    const std::span<const lantern::App* const> held(apps_of(installed), installed_count);
    auto decision = lantern::install_decision(*as(app), known, provided, held, memory);
    *out          = reinterpret_cast<lantern_install_decision*>(
        box_new<lantern::InstallDecision>(resource.get(), std::move(decision)));
    return ok(error);
}

LANTERN_API void lantern_install_decision_free(lantern_install_decision* decision)
{
    unbox(reinterpret_cast<lantern::InstallDecision*>(decision));
}

LANTERN_API lantern_install lantern_install_decision_get_verdict(const lantern_install_decision* decision)
{
    return decision == nullptr ? LANTERN_UNAVAILABLE
                               : static_cast<lantern_install>(as_decision(decision)->verdict);
}

LANTERN_API size_t lantern_install_decision_get_reason_count(const lantern_install_decision* decision)
{
    return decision == nullptr ? 0 : as_decision(decision)->reasons.size();
}

LANTERN_API lantern_str lantern_install_decision_get_reason_at(
    const lantern_install_decision* decision, size_t index)
{
    if (decision == nullptr || index >= as_decision(decision)->reasons.size())
        return empty_str();
    return view(as_decision(decision)->reasons[index]);
}

LANTERN_API bool lantern_app_included(
    const lantern_app* app, const lantern_app* const* installed, size_t installed_count)
{
    if (app == nullptr || (installed == nullptr && installed_count != 0))
        return false;
    return lantern::included(
        *as(app), std::span<const lantern::App* const>(apps_of(installed), installed_count));
}

LANTERN_API const lantern_app* lantern_prefer_variant(const lantern_app* const* variants, size_t count)
{
    if (variants == nullptr)
        return nullptr;
    return wrap(lantern::prefer_variant(std::span<const lantern::App* const>(apps_of(variants), count)));
}

} // extern "C"
// NOLINTEND(readability-identifier-naming,misc-use-internal-linkage)
