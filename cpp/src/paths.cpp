#include <lantern/paths.hpp>

#include <cstddef>

namespace lantern
{

namespace
{

constexpr std::size_t max_part = 255;
constexpr std::size_t max_path = 1024;

char fold(char c) noexcept
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

bool letter(char c) noexcept
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

// The parts of a path without its leading "/": each checked.
PathProblem check_parts(std::string_view parts) noexcept
{
    std::size_t start = 0;
    for (;;)
    {
        const std::size_t end = parts.find('/', start);
        const std::string_view part
            = parts.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start);
        if (part.empty())
            return PathProblem::empty_part;
        if (part == "." || part == "..")
            return PathProblem::dot_part;
        if (part.size() > max_part)
            return PathProblem::part_too_long;
        for (const char c : part)
        {
            const auto byte = static_cast<unsigned char>(c);
            if (byte < 0x20U || byte == 0x7FU)
                return PathProblem::control;
            if (c == '\\')
                return PathProblem::backslash;
            if (c == ':')
                return PathProblem::colon;
            if (c == '"')
                return PathProblem::quote;
        }
        if (end == std::string_view::npos)
            return PathProblem::none;
        start = end + 1;
    }
}

// The first problem of a path, before its parts: what a reader would see
// first when it read the path.
PathProblem check_whole(std::string_view path) noexcept
{
    if (path.empty())
        return PathProblem::empty;
    if (path.size() > max_path)
        return PathProblem::too_long;
    if (path.size() >= 2 && letter(path[0]) && path[1] == ':')
        return PathProblem::drive_letter;
    if (path[0] == '\\')
        return PathProblem::backslash;
    return PathProblem::none;
}

} // namespace

std::string_view describe(PathProblem problem) noexcept
{
    switch (problem)
    {
        case PathProblem::none:
            return "a valid path";
        case PathProblem::empty:
            return "an empty path";
        case PathProblem::not_absolute:
            return "a path that does not start with /";
        case PathProblem::absolute:
            return "an absolute path where a relative one is meant";
        case PathProblem::drive_letter:
            return "a path with a drive letter";
        case PathProblem::empty_part:
            return "a path with an empty part";
        case PathProblem::dot_part:
            return "a path with a . or .. part";
        case PathProblem::backslash:
            return "a path with a backslash";
        case PathProblem::colon:
            return "a path with a colon";
        case PathProblem::quote:
            return "a path with a quote";
        case PathProblem::control:
            return "a path with a control character";
        case PathProblem::part_too_long:
            return "a path with a part above 255 bytes";
        case PathProblem::too_long:
            return "a path above 1024 bytes";
        case PathProblem::not_a_folder:
            return "a folder that does not end with /";
    }
    return "";
}

PathProblem check_device_path(std::string_view path) noexcept
{
    if (const PathProblem problem = check_whole(path); problem != PathProblem::none)
        return problem;
    if (path[0] != '/')
        return PathProblem::not_absolute;
    return check_parts(path.substr(1));
}

PathProblem check_data_path(std::string_view path) noexcept
{
    if (const PathProblem problem = check_whole(path); problem != PathProblem::none)
        return problem;
    if (path[0] == '/')
        return PathProblem::absolute;
    return check_parts(path);
}

PathProblem check_data_root(std::string_view path) noexcept
{
    if (const PathProblem problem = check_whole(path); problem != PathProblem::none)
        return problem;
    if (path[0] != '/')
        return PathProblem::not_absolute;
    if (path.back() != '/')
        return PathProblem::not_a_folder;
    if (path.size() == 1)
        return PathProblem::empty_part;
    return check_parts(path.substr(1, path.size() - 2));
}

bool same_path_ignoring_case(std::string_view a, std::string_view b) noexcept
{
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i)
    {
        if (fold(a[i]) != fold(b[i]))
            return false;
    }
    return true;
}

bool strictly_under(std::string_view folder, std::string_view path) noexcept
{
    return !folder.empty() && folder.back() == '/' && path.size() > folder.size() && path.starts_with(folder);
}

namespace
{

// Whether `path` lies in `root`, "<id>" in it being `id`.
bool in_root(std::string_view root, std::string_view id, std::string_view path) noexcept
{
    const std::size_t marker = root.find("<id>");
    if (marker == std::string_view::npos)
        return root.back() == '/' ? strictly_under(root, path) : path == root;
    const std::string_view before = root.substr(0, marker);
    const std::string_view after  = root.substr(marker + 4);
    if (!path.starts_with(before))
        return false;
    const std::string_view rest = path.substr(before.size());
    if (!rest.starts_with(id))
        return false;
    const std::string_view tail = rest.substr(id.size());
    if (after.empty())
        return tail.empty();
    return after.back() == '/' ? (tail.size() > after.size() && tail.starts_with(after)) : tail == after;
}

} // namespace

RootMatch match_roots(const Profile& profile, std::string_view homebrew_id, std::string_view path) noexcept
{
    for (const std::string_view root : profile.free_roots)
    {
        if (in_root(root, homebrew_id, path))
            return RootMatch::free;
    }
    for (const std::string_view root : profile.consent_roots)
    {
        if (in_root(root, homebrew_id, path))
            return RootMatch::consent;
    }
    return RootMatch::outside;
}

} // namespace lantern
