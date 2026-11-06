// Rating caps (SPEC.md § 5.6): a token may carry a cap, set when its device is
// approved and never by the device itself. A server hides from a capped token
// every title above it, the apps of such a title and each homebrew above it,
// everywhere: the routes of the library ask a CapFilter.
#include <algorithm>
#include <array>

#include "server_internal.hpp"

namespace lantern::detail
{

namespace
{

struct AgeRow
{
    std::string_view system;
    std::string_view rating;
    std::uint64_t age;
};

// § 5.6's table: the age each rating of each system is read as.
constexpr std::array<AgeRow, 37> ages { {
    { "PEGI", "3", 3 },
    { "PEGI", "7", 7 },
    { "PEGI", "12", 12 },
    { "PEGI", "16", 16 },
    { "PEGI", "18", 18 },
    { "ESRB", "EC", 3 },
    { "ESRB", "E", 6 },
    { "ESRB", "E10+", 10 },
    { "ESRB", "T", 13 },
    { "ESRB", "M", 17 },
    { "ESRB", "AO", 18 },
    { "CERO", "A", 0 },
    { "CERO", "B", 12 },
    { "CERO", "C", 15 },
    { "CERO", "D", 17 },
    { "CERO", "Z", 18 },
    { "USK", "0", 0 },
    { "USK", "6", 6 },
    { "USK", "12", 12 },
    { "USK", "16", 16 },
    { "USK", "18", 18 },
    { "ACB", "G", 0 },
    { "ACB", "PG", 8 },
    { "ACB", "M", 15 },
    { "ACB", "MA15+", 15 },
    { "ACB", "R18+", 18 },
    { "ACB", "X18+", 18 },
    { "CLASSIND", "L", 0 },
    { "CLASSIND", "10", 10 },
    { "CLASSIND", "12", 12 },
    { "CLASSIND", "14", 14 },
    { "CLASSIND", "16", 16 },
    { "CLASSIND", "18", 18 },
    { "GRAC", "ALL", 0 },
    { "GRAC", "12", 12 },
    { "GRAC", "15", 15 },
    { "GRAC", "18", 18 },
} };

// The age a cap allows: its `age`, or its rating's; nothing when the table cannot read it.
std::optional<std::uint64_t> cap_age(const RatingCap& cap) noexcept
{
    if (cap.age)
        return cap.age;
    if (!cap.system.empty() && !cap.rating.empty())
        return rating_age(cap.system, cap.rating);
    return std::nullopt;
}

// The age of what has `ratings`, for `cap`: its rating of the cap's system when it has one the table reads,
// otherwise the highest age of its ratings the table reads; nothing when unrated.
std::optional<std::uint64_t> age_of(const Vector<Rating>& ratings, const RatingCap& cap) noexcept
{
    std::optional<std::uint64_t> own;
    std::optional<std::uint64_t> any;
    for (const Rating& rating : ratings)
    {
        const std::optional<std::uint64_t> age = rating_age(rating.system, rating.rating);
        if (!age)
            continue;
        any = std::max(any.value_or(std::uint64_t { 0 }), *age);
        if (!cap.system.empty() && rating.system == cap.system)
            own = std::max(own.value_or(std::uint64_t { 0 }), *age);
    }
    return own ? own : any;
}

} // namespace

std::optional<std::uint64_t> rating_age(std::string_view system, std::string_view rating) noexcept
{
    if (rating.empty())
        return std::nullopt;
    for (const AgeRow& row : ages)
    {
        if (row.system == system && row.rating == rating)
            return row.age;
    }
    return std::nullopt;
}

bool above_cap(const RatingCap& cap, const Vector<Rating>& ratings) noexcept
{
    const std::optional<std::uint64_t> age = age_of(ratings, cap);
    if (!age)
        return cap.unrated == "hide";
    const std::optional<std::uint64_t> limit = cap_age(cap);
    return !limit || *age > *limit;
}

std::string_view cap_problem(const RatingCap& cap) noexcept
{
    if (cap.age)
    {
        if (!cap.system.empty() || !cap.rating.empty())
            return "a rating cap is an age, or a rating of one system, not both";
    }
    else if (cap.system.empty() || cap.rating.empty())
        return "a rating cap is an age, or a system and its rating";
    if (!cap.unrated.empty() && cap.unrated != "show" && cap.unrated != "hide")
        return "unrated is show or hide";
    return {};
}

void write_rating_cap(json::Writer& w, const RatingCap& cap)
{
    w.begin_object();
    if (cap.age)
    {
        w.key("age");
        w.number(*cap.age);
    }
    if (!cap.system.empty())
    {
        w.key("system");
        w.string(cap.system);
    }
    if (!cap.rating.empty())
    {
        w.key("rating");
        w.string(cap.rating);
    }
    if (!cap.unrated.empty())
    {
        w.key("unrated");
        w.string(cap.unrated);
    }
    w.end_object();
}

std::expected<CapFilter, ProblemError> CapFilter::of(const ServerState& state, const Caller& caller)
{
    CapFilter filter(state.allocator);
    if (!caller.rating_cap)
        return filter;
    filter.cap_.emplace(*caller.rating_cap, state.allocator);
    if (state.library->offers_titles())
    {
        auto titles = state.library->titles({}, state.allocator);
        if (!titles)
            return std::unexpected(internal_error(state));
        filter.titles_ = std::move(*titles);
    }
    return filter;
}

bool CapFilter::hides(const Vector<Rating>& ratings) const noexcept
{
    return cap_.has_value() && above_cap(*cap_, ratings);
}

bool CapFilter::hides_title(std::string_view platform, std::string_view title_id) const noexcept
{
    if (!cap_)
        return false;
    for (const Title& title : titles_)
    {
        if (title.platform == platform && title.title_id == title_id)
            return above_cap(*cap_, title.ratings);
    }
    // A title the library does not describe has no rating
    return above_cap(*cap_, none_);
}

std::expected<bool, ProblemError> file_hidden(
    const ServerState& state, const CapFilter& filter, std::string_view name)
{
    if (!filter.active())
        return false;
    String suffix("/v1/files/", state.allocator);
    suffix.append(name);
    auto apps = state.library->apps(AppsFilter {}, state.allocator);
    if (!apps)
        return std::unexpected(internal_error(state));
    for (const App& app : *apps)
    {
        if (std::string_view(app.file).ends_with(suffix) && filter.hides_title(app.platform, app.title_id))
            return true;
    }
    if (!state.library->offers_homebrew())
        return false;
    auto entries = state.library->homebrew({}, state.allocator);
    if (!entries)
        return std::unexpected(internal_error(state));
    for (const Homebrew& entry : *entries)
    {
        bool uses = std::string_view(entry.package.file).ends_with(suffix);
        for (const Package& package : entry.packages)
            uses = uses || std::string_view(package.file).ends_with(suffix);
        if (uses && filter.hides(entry.ratings))
            return true;
    }
    return false;
}

} // namespace lantern::detail
