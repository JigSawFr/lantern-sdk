// The routes of the homebrew (SPEC.md § 8) and of the cheat sets (§ 10): the
// listing and the entry, the updates, the sets with their text, and writing
// them with the scope `cheats.write`.
#include <algorithm>

#include <lantern/json.hpp>
#include <lantern/profiles.hpp>

#include "server_internal.hpp"

namespace lantern::detail
{

namespace
{

// § 8.1: a reader reads a kind it does not know, or none, as `app`.
constexpr std::array<std::string_view, 8> known_kinds { "app", "game", "port", "emulator", "tool", "overlay",
    "sysmodule", "theme" };

// A lower-case word (1 to 32 letters, digits and `_`, starting with a letter): a kind, a genre.
bool is_word(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= 32 && text.front() >= 'a' && text.front() <= 'z'
        && std::ranges::all_of(
            text, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'; });
}

// `^[A-Za-z0-9._-]{1,64}$`: a cheat set's build_id.
bool is_build_id(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= 64
        && std::ranges::all_of(text,
            [](char c)
            {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.'
                    || c == '_' || c == '-';
            });
}

std::string_view languages_of(const ServerRequest& request) noexcept
{
    return request.header("Accept-Language").value_or(std::string_view {});
}

std::string_view effective_kind(const Homebrew& entry) noexcept
{
    return std::ranges::contains(known_kinds, std::string_view(entry.kind)) ? std::string_view(entry.kind)
                                                                            : std::string_view { "app" };
}

void write_hex(json::Writer& w, const Digest& digest)
{
    const auto hex = to_hex(digest);
    w.string(std::string_view(hex.data(), hex.size()));
}

void write_text_member(json::Writer& w, std::string_view name, std::string_view text)
{
    if (text.empty())
        return;
    w.key(name);
    w.string(text);
}

void write_words_member(json::Writer& w, std::string_view name, const Vector<String>& words)
{
    if (words.empty())
        return;
    w.key(name);
    w.begin_array();
    for (const String& word : words)
        w.string(word);
    w.end_array();
}

void write_signature(json::Writer& w, const Signature& signature)
{
    w.begin_object();
    w.key("alg");
    w.string(signature.alg);
    w.key("public_key");
    w.string(signature.public_key);
    w.key("value");
    w.string(signature.value);
    w.end_object();
}

// A package (§ 8.2). A listing leaves the manifest out; an entry of its own
// has it, and an empty one for a package the system installs.
void write_package(json::Writer& w, const Homebrew& entry, const Package& package, bool with_manifest)
{
    w.begin_object();
    w.key("format");
    w.string(package.format);
    w.key("file");
    w.string(package.file);
    w.key("size");
    w.number(package.size);
    if (package.installed_size)
    {
        w.key("installed_size");
        w.number(*package.installed_size);
    }
    w.key("sha256");
    write_hex(w, package.sha256);
    w.key("manifest_sha256");
    write_hex(w, package.manifest_sha256);
    write_text_member(w, "path", package.path);
    if (with_manifest)
    {
        const Profile* profile = find_profile(entry.platform);
        const HomebrewFormat* format
            = profile != nullptr ? find_homebrew_format(*profile, package.format) : nullptr;
        const bool by_system = format != nullptr && format->placement == Placement::system_installer;
        if (!package.manifest.empty() || by_system)
        {
            w.key("manifest");
            w.begin_array();
            for (const ManifestEntry& file : package.manifest)
            {
                w.begin_object();
                w.key("path");
                w.string(file.path);
                w.key("size");
                w.number(file.size);
                w.key("sha256");
                write_hex(w, file.sha256);
                w.end_object();
            }
            w.end_array();
        }
    }
    write_words_member(w, "arch", package.arch);
    if (package.signature)
    {
        w.key("signature");
        write_signature(w, *package.signature);
    }
    if (package.signer_sha256)
    {
        w.key("signer_sha256");
        write_hex(w, *package.signer_sha256);
    }
    if (!package.mirrors.empty())
    {
        w.key("mirrors");
        w.begin_array();
        for (const Mirror& mirror : package.mirrors)
        {
            w.begin_object();
            w.key("url");
            w.string(mirror.url);
            w.end_object();
        }
        w.end_array();
    }
    if (package.chunks)
    {
        w.key("chunks");
        w.begin_object();
        w.key("url");
        w.string(package.chunks->url);
        w.key("size");
        w.number(package.chunks->size);
        w.key("sha256");
        write_hex(w, package.chunks->sha256);
        w.end_object();
    }
    w.end_object();
}

// § 8.7: the keys and values it does not read are kept as the author wrote them.
void write_requires(json::Writer& w, const Requires& requires_)
{
    w.begin_object();
    w.key("text");
    w.string(requires_.text);
    if (requires_.min)
    {
        w.key("min");
        w.begin_object();
        for (const auto& [name, value] : requires_.min->members)
        {
            w.key(name);
            w.raw(value);
        }
        w.end_object();
    }
    write_words_member(w, "gpu", requires_.gpu);
    if (!requires_.homebrew.empty())
    {
        w.key("homebrew");
        w.begin_array();
        for (const Dependency& needed : requires_.homebrew)
        {
            w.begin_object();
            w.key("id");
            w.string(needed.id);
            w.key("min_build");
            w.number(needed.min_build);
            w.end_object();
        }
        w.end_array();
    }
    for (const auto& [name, value] : requires_.extra)
    {
        w.key(name);
        w.raw(value);
    }
    w.end_object();
}

void write_accepted(json::Writer& w, const Vector<AcceptedVersion>& accept)
{
    if (accept.empty())
        return;
    w.key("accept");
    w.begin_array();
    for (const AcceptedVersion& version : accept)
    {
        w.begin_object();
        if (version.sha256)
        {
            w.key("sha256");
            write_hex(w, *version.sha256);
        }
        write_text_member(w, "sha1", version.sha1);
        write_text_member(w, "md5", version.md5);
        write_text_member(w, "label", version.label);
        w.end_object();
    }
    w.end_array();
}

// The members of a file the user brings (§ 8.6), in an object the caller has opened.
template <typename File> void write_required_members(json::Writer& w, const File& file)
{
    w.key("path");
    w.string(file.path);
    if (file.size)
    {
        w.key("size");
        w.number(*file.size);
    }
    write_accepted(w, file.accept);
    write_text_member(w, "hint", file.hint);
    if (file.optional)
    {
        w.key("optional");
        w.boolean(*file.optional);
    }
}

void write_port(json::Writer& w, const Port& port)
{
    w.begin_object();
    w.key("original");
    w.begin_object();
    w.key("name");
    w.string(port.original.name);
    if (port.original.year)
    {
        w.key("year");
        w.number(*port.original.year);
    }
    write_text_member(w, "developer", port.original.developer);
    if (!port.original.stores.empty())
    {
        w.key("stores");
        w.begin_array();
        for (const Store& store : port.original.stores)
        {
            w.begin_object();
            w.key("store");
            w.string(store.store);
            write_text_member(w, "id", store.id);
            w.key("url");
            w.string(store.url);
            w.end_object();
        }
        w.end_array();
    }
    if (port.original.title)
    {
        w.key("title");
        w.begin_object();
        w.key("platform");
        w.string(port.original.title->platform);
        w.key("title_id");
        w.string(port.original.title->title_id);
        w.end_object();
    }
    w.end_object();
    w.key("engine");
    w.begin_object();
    w.key("name");
    w.string(port.engine.name);
    write_text_member(w, "version", port.engine.version);
    write_text_member(w, "source", port.engine.source);
    write_text_member(w, "license", port.engine.license);
    w.end_object();
    w.key("data_root");
    w.string(port.data_root);
    w.key("assets");
    w.string(port.assets);
    w.key("requires_data");
    w.begin_array();
    for (const RequiredData& item : port.requires_data)
    {
        w.begin_object();
        if (item.one_of.empty())
            write_required_members(w, item);
        else
        {
            w.key("one_of");
            w.begin_array();
            for (const Vector<RequiredFile>& alternative : item.one_of)
            {
                w.begin_array();
                for (const RequiredFile& file : alternative)
                {
                    w.begin_object();
                    write_required_members(w, file);
                    w.end_object();
                }
                w.end_array();
            }
            w.end_array();
            const std::optional<bool> optional = item.optional;
            if (optional.has_value())
            {
                w.key("optional");
                w.boolean(*optional);
            }
        }
        w.end_object();
    }
    w.end_array();
    w.end_object();
}

// An entry's members (§ 8.1), in an object the caller has opened.
void write_homebrew_members(json::Writer& w, const Homebrew& entry, bool with_manifest)
{
    w.key("id");
    w.string(entry.id);
    write_text_member(w, "system_id", entry.system_id);
    w.key("platform");
    w.string(entry.platform);
    w.key("kind");
    w.string(entry.kind);
    w.key("name");
    w.string(entry.name);
    write_text_member(w, "author", entry.author);
    write_words_member(w, "genres", entry.genres);
    write_words_member(w, "tags", entry.tags);
    w.key("version");
    w.string(entry.version);
    w.key("build");
    w.number(entry.build);
    write_text_member(w, "license", entry.license);
    write_text_member(w, "assets_license", entry.assets_license);
    write_text_member(w, "source", entry.source);
    write_text_member(w, "language", entry.language);
    write_text_member(w, "summary", entry.summary);
    write_text_member(w, "description", entry.description);
    if (entry.icon)
    {
        w.key("icon");
        write_image_object(w, *entry.icon);
    }
    if (!entry.screenshots.empty())
    {
        w.key("screenshots");
        w.begin_array();
        for (const Image& image : entry.screenshots)
            write_image_object(w, image);
        w.end_array();
    }
    if (entry.requires_)
    {
        w.key("requires");
        write_requires(w, *entry.requires_);
    }
    write_text_member(w, "updated", entry.updated);
    w.key("package");
    write_package(w, entry, entry.package, with_manifest);
    if (!entry.packages.empty())
    {
        w.key("packages");
        w.begin_array();
        for (const Package& package : entry.packages)
            write_package(w, entry, package, with_manifest);
        w.end_array();
    }
    if (entry.signature)
    {
        w.key("signature");
        write_signature(w, *entry.signature);
    }
    if (entry.port)
    {
        w.key("port");
        write_port(w, *entry.port);
    }
    write_text_member(w, "atlas", entry.atlas);
    if (!entry.ratings.empty())
    {
        w.key("ratings");
        write_ratings(w, entry.ratings);
    }
}

// A page of entries, sorted by name (§ 8.5).
Answer homebrew_page(const ServerState& state, const ServerRequest& request,
    std::span<const Homebrew* const> items, std::string_view scope)
{
    Vector<SortKey> keys(state.allocator);
    keys.reserve(items.size());
    for (const Homebrew* entry : items)
    {
        SortKey key(state.allocator);
        key.minor = fold(entry->name, state.allocator);
        key.id.assign(entry->platform);
        key.id.push_back('\x1f');
        key.id.append(entry->id);
        keys.push_back(std::move(key));
    }
    const auto window = page_window(state, request, keys, scope);
    if (!window)
        return std::unexpected(window.error());

    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("items");
    w.begin_array();
    for (std::size_t i = window->from; i < window->from + window->count; ++i)
    {
        w.begin_object();
        write_homebrew_members(w, *items[window->order[i]], false);
        w.end_object();
    }
    w.end_array();
    w.key("total");
    w.number(static_cast<std::uint64_t>(items.size()));
    w.key("next");
    if (window->next.empty())
        w.null();
    else
        w.string(window->next);
    w.end_object();
    return json_response(state, request, std::move(out));
}

void write_cheat_members(json::Writer& w, const CheatSet& set)
{
    w.key("id");
    w.string(set.id);
    w.key("platform");
    w.string(set.platform);
    w.key("title_id");
    w.string(set.title_id);
    write_text_member(w, "build_id", set.build_id);
    write_text_member(w, "source", set.source);
    write_text_member(w, "note", set.note);
    write_text_member(w, "updated", set.updated);
    w.key("size");
    w.number(set.size);
    w.key("sha256");
    write_hex(w, set.sha256);
}

// An answer with no body (§ 10: PUT and DELETE answer 204).
ServerResponse no_content(const ServerState& state, const ServerRequest& request)
{
    ServerResponse response(state.allocator);
    response.status = 204;
    caching_headers(response.headers, request);
    response.headers.set("Content-Length", "0");
    return response;
}

bool same_set(const CheatSet& set, const CheatWrite& other) noexcept
{
    return set.platform == other.platform && set.title_id == other.title_id && set.build_id == other.build_id
        && set.source == other.source;
}

// What a set of a platform is (Annex A): its text's format and its build_id's form.
enum class CheatText : std::uint8_t
{
    free, // any text
    hex_lines, // Atmosphère's and Luma3DS's: [name], {master}, words of 8 hex digits
    json, // a document
};

enum class BuildForm : std::uint8_t
{
    none, // the platform's sets depend on no build: a set carries no build_id
    atmosphere, // upper-case hex, 1 to 64 digits
    goldhen, // 12.34, or 12.34_ and a suffix
    other, // optional, of the core's form
};

struct CheatRules
{
    std::string_view platform;
    bool has_cheats;
    BuildForm build;
    CheatText text;
};

constexpr std::array<CheatRules, 6> cheat_rules { {
    { "switch", true, BuildForm::atmosphere, CheatText::hex_lines },
    { "3ds", true, BuildForm::none, CheatText::hex_lines },
    { "vita", true, BuildForm::none, CheatText::free },
    { "ps4", true, BuildForm::goldhen, CheatText::json },
    { "android", false, BuildForm::none, CheatText::free },
    { "linux", false, BuildForm::none, CheatText::free },
} };

bool is_upper_hex(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= 64
        && std::ranges::all_of(text, [](char c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'); });
}

bool is_digits(std::string_view text) noexcept
{
    return std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; });
}

// `^[0-9]{2}\.[0-9]{2}(_[A-Za-z0-9.-]{1,32})?$`
bool is_goldhen_build(std::string_view text) noexcept
{
    if (text.size() < 5 || !is_digits(text.substr(0, 2)) || text[2] != '.' || !is_digits(text.substr(3, 2)))
        return false;
    if (text.size() == 5)
        return true;
    const std::string_view suffix = text.substr(5);
    return suffix.size() >= 2 && suffix.size() <= 33 && suffix.front() == '_'
        && std::ranges::all_of(suffix.substr(1),
            [](char c)
            {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.'
                    || c == '-';
            });
}

// The characters of a UTF-8 text.
std::size_t characters(std::string_view text) noexcept
{
    return static_cast<std::size_t>(
        std::ranges::count_if(text, [](char c) { return (static_cast<unsigned char>(c) & 0xC0U) != 0x80U; }));
}

bool is_space(char c) noexcept
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

std::string_view trim_space(std::string_view text) noexcept
{
    while (!text.empty() && is_space(text.front()))
        text.remove_prefix(1);
    while (!text.empty() && is_space(text.back()))
        text.remove_suffix(1);
    return text;
}

// `[name]`, `{master}`, or words of 8 hex digits, or nothing (Annex A).
bool is_cheat_line(std::string_view line) noexcept
{
    line = trim_space(line);
    if (line.empty())
        return true;
    const auto bracketed = [&](char open, char close)
    {
        if (line.front() != open)
            return false;
        const std::size_t end = line.find(close);
        return end == line.size() - 1 && characters(line.substr(1, end - 1)) <= 255;
    };
    if (bracketed('[', ']') || bracketed('{', '}'))
        return true;
    while (!line.empty())
    {
        const std::size_t end       = line.find_first_of(" \t\r\n\v\f");
        const std::string_view word = line.substr(0, end);
        if (word.size() != 8
            || !std::ranges::all_of(word, [](char c)
                { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }))
            return false;
        line = end == std::string_view::npos ? std::string_view {} : trim_space(line.substr(end));
    }
    return true;
}

// `^[^\W_](?:[^\W_]|[ .'()-]){0,63}(?<! )$`: a letter or a digit first (any non-ASCII
// character is one), then those and the signs, 64 characters at most, no space last.
bool is_cheat_source(std::string_view source) noexcept
{
    if (source.empty() || characters(source) > 64 || source.back() == ' ')
        return false;
    const auto alnum = [](char c)
    {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
            || static_cast<unsigned char>(c) >= 0x80U;
    };
    return alnum(source.front())
        && std::ranges::all_of(source, [&](char c)
            { return alnum(c) || c == ' ' || c == '.' || c == '\'' || c == '(' || c == ')' || c == '-'; });
}

} // namespace

std::string_view cheat_problem(const CheatWrite& set)
{
    if (!is_served_platform(set.platform))
        return "platform is a platform's name (SPEC.md § 4.3).";
    const CheatRules* rules = nullptr;
    for (const CheatRules& item : cheat_rules)
    {
        if (item.platform == set.platform)
        {
            rules = &item;
            break;
        }
    }
    const bool known = rules != nullptr;
    if (known && !rules->has_cheats)
        return "That platform has no cheats (Annex A).";
    const Profile* profile = find_profile(set.platform);
    if (!is_core_id(set.title_id) || (profile != nullptr && !profile->title_id(set.title_id)))
        return "title_id is not a title id of that platform.";
    const BuildForm form = known ? rules->build : BuildForm::other;
    if (form == BuildForm::none && !set.build_id.empty())
        return "That platform's sets have no build_id (Annex A).";
    if (form == BuildForm::atmosphere && !is_upper_hex(set.build_id))
        return "build_id is the game's build, in the platform's form (Annex A).";
    if (form == BuildForm::goldhen && !is_goldhen_build(set.build_id))
        return "build_id is the game's build, in the platform's form (Annex A).";
    if (form == BuildForm::other && !set.build_id.empty() && !is_build_id(set.build_id))
        return "build_id is 1 to 64 letters, digits, '.', '_' and '-'.";
    if (!is_cheat_source(set.source))
        return "source is 1 to 64 letters, digits, spaces and . ' ( ) -, a letter or a digit first.";
    if (set.note.size() > 120
        || std::ranges::any_of(set.note, [](char c)
            { return static_cast<unsigned char>(c) < 0x20U || static_cast<unsigned char>(c) == 0x7FU; }))
        return "note: 120 bytes at most, without control characters.";
    if (set.text.size() > cheat_limit)
        return "A cheat set is 1048576 bytes at most (SPEC.md § 13).";
    if (std::ranges::any_of(set.text,
            [](char c)
            {
                const auto byte = static_cast<unsigned char>(c);
                return (byte < 0x20U && c != '\t' && c != '\r' && c != '\n') || byte == 0x7FU;
            }))
        return "text has a control character.";
    const CheatText format = known ? rules->text : CheatText::free;
    if (format == CheatText::hex_lines)
    {
        std::string_view rest = set.text;
        while (!rest.empty())
        {
            const std::size_t end = rest.find_first_of("\r\n");
            if (!is_cheat_line(rest.substr(0, end)))
                return "a line is neither a [name] nor words of 8 hex digits (Annex A).";
            rest = end == std::string_view::npos ? std::string_view {} : rest.substr(end + 1);
        }
    }
    else if (format == CheatText::json)
    {
        json::Limits limits;
        limits.max_document = cheat_limit;
        limits.max_string   = cheat_limit;
        limits.max_depth    = 64;
        if (!json::parse(set.text, limits, set.text.get_allocator().resource()))
            return "text is a set in JSON (Annex A).";
    }
    return {};
}

Answer homebrew_list_route(const ServerState& state, const ServerRequest& request)
{
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    const std::string_view text  = request.param("q").value_or(std::string_view {});
    const std::string_view kind  = request.param("kind").value_or(std::string_view {});
    const std::string_view genre = request.param("genre").value_or(std::string_view {});
    if (!kind.empty() && !is_word(kind))
        return std::unexpected(
            bad_request(state, "kind is a lower-case word, such as app, game, port or tool."));
    if (!genre.empty() && !is_word(genre))
        return std::unexpected(
            bad_request(state, "genre is a lower-case word, such as adventure or puzzle."));
    if (request.param("sort").value_or("name") != "name")
        return std::unexpected(bad_request(state, "homebrew is sorted by name."));

    auto all = state.library->homebrew(languages_of(request), state.allocator);
    if (!all)
        return std::unexpected(internal_error(state));
    const String needle = fold(text, state.allocator);
    Vector<const Homebrew*> kept(state.allocator);
    for (const Homebrew& entry : *all)
    {
        if ((platform->has_value() && entry.platform != **platform)
            || (!kind.empty() && effective_kind(entry) != kind)
            || (!genre.empty() && !std::ranges::contains(entry.genres, genre))
            || (!needle.empty() && !fold(entry.name, state.allocator).contains(needle)))
            continue;
        kept.push_back(&entry);
    }
    const std::array<std::string_view, 6> parts { "homebrew", platform->has_value() ? "p" : "-",
        platform->value_or(std::string_view {}), text, kind, genre };
    return homebrew_page(state, request, kept, scope_of(parts, state.allocator));
}

Answer homebrew_route(const ServerState& state, const ServerRequest& request, std::string_view id)
{
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    if (!is_homebrew_id(id))
        return std::unexpected(not_found(state, "No such homebrew."));
    auto all = state.library->homebrew(languages_of(request), state.allocator);
    if (!all)
        return std::unexpected(internal_error(state));
    const Homebrew* found = nullptr;
    for (const Homebrew& entry : *all)
    {
        if (entry.id != id || (platform->has_value() && entry.platform != **platform))
            continue;
        if (found != nullptr)
            return std::unexpected(
                bad_request(state, "Several platforms have it: name one (Lantern-Platform)."));
        found = &entry;
    }
    if (found == nullptr)
        return std::unexpected(not_found(state, "No such homebrew."));
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    write_homebrew_members(w, *found, true);
    w.end_object();
    return json_response(state, request, std::move(out));
}

Answer homebrew_updates_route(const ServerState& state, const ServerRequest& request)
{
    const auto prepared = request_document(state, request);
    if (!prepared)
        return std::unexpected(prepared.error());
    auto bound = read_document<HomebrewUpdatesRequest>(prepared->text, known_schema, prepared->options,
        [](BindContext& c, HomebrewUpdatesRequest& value) { return bind(c, value); });
    if (!bound || !*bound)
        return std::unexpected(bad_request(state, "installed is a list of {id, build}."));
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    if (!platform->has_value())
        return std::unexpected(
            bad_request(state, "Name a platform: Lantern-Platform or ?platform= (SPEC.md § 4.3)."));
    const HomebrewUpdatesRequest& document = **bound;
    if (std::ranges::any_of(
            document.installed, [](const InstalledHomebrew& item) { return !is_homebrew_id(item.id); }))
        return std::unexpected(bad_request(state, "installed is a list of {id, build}."));

    // The highest build installed of each id, in the order of the ids
    Vector<InstalledHomebrew> builds(state.allocator);
    for (const InstalledHomebrew& item : document.installed)
    {
        const auto same
            = std::ranges::find_if(builds, [&](const InstalledHomebrew& had) { return had.id == item.id; });
        if (same == builds.end())
            builds.push_back(item);
        else
            same->build = std::max(same->build, item.build);
    }
    std::ranges::sort(
        builds, [](const InstalledHomebrew& a, const InstalledHomebrew& b) { return a.id < b.id; });

    auto all = state.library->homebrew(languages_of(request), state.allocator);
    if (!all)
        return std::unexpected(internal_error(state));
    Vector<const Homebrew*> newer(state.allocator);
    for (const Homebrew& entry : *all)
    {
        if (entry.platform != **platform)
            continue;
        const auto had = std::ranges::find_if(
            builds, [&](const InstalledHomebrew& item) { return item.id == entry.id; });
        if (had != builds.end() && entry.build > had->build)
            newer.push_back(&entry);
    }
    // The listing's identity: the platform and what is installed
    Vector<String> texts(state.allocator);
    texts.emplace_back("updates");
    texts.emplace_back(**platform);
    String installed(state.allocator);
    for (const InstalledHomebrew& item : builds)
    {
        installed.append(item.id);
        installed.push_back(':');
        installed.append(number_text(item.build, state.allocator));
        installed.push_back(',');
    }
    texts.push_back(std::move(installed));
    Vector<std::string_view> parts(state.allocator);
    for (const String& text : texts)
        parts.emplace_back(text);
    return homebrew_page(state, request, newer, scope_of(parts, state.allocator));
}

Answer cheats_route(const ServerState& state, const ServerRequest& request)
{
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    const std::string_view title_id = request.param("title_id").value_or(std::string_view {});
    const std::string_view build_id = request.param("build_id").value_or(std::string_view {});
    if (!title_id.empty() && !is_core_id(title_id))
        return std::unexpected(bad_request(state, "title_id is 1 to 128 letters, digits, '.', '_' and '-'."));
    if (!build_id.empty() && !is_build_id(build_id))
        return std::unexpected(bad_request(state, "build_id is 1 to 64 letters, digits, '.', '_' and '-'."));

    const std::scoped_lock lock(state.cheats_mutex);
    auto all = state.library->cheats(state.allocator);
    if (!all)
        return std::unexpected(internal_error(state));
    Vector<const CheatSet*> kept(state.allocator);
    for (const CheatSet& set : *all)
    {
        if ((platform->has_value() && set.platform != **platform)
            || (!title_id.empty() && set.title_id != title_id)
            || (!build_id.empty() && set.build_id != build_id))
            continue;
        kept.push_back(&set);
    }
    std::ranges::sort(kept,
        [&](const CheatSet* a, const CheatSet* b)
        {
            if (a->platform != b->platform)
                return a->platform < b->platform;
            if (a->title_id != b->title_id)
                return a->title_id < b->title_id;
            if (a->build_id != b->build_id)
                return a->build_id < b->build_id;
            const String source_a = fold(a->source, state.allocator);
            const String source_b = fold(b->source, state.allocator);
            return source_a != source_b ? source_a < source_b : a->id < b->id;
        });
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("cheats");
    w.begin_array();
    for (const CheatSet* set : kept)
    {
        w.begin_object();
        write_cheat_members(w, *set);
        w.end_object();
    }
    w.end_array();
    w.end_object();
    return json_response(state, request, std::move(out));
}

namespace
{

// The set of that id, for a caller who names a platform or not.
const CheatSet* find_cheat(
    const Vector<CheatSet>& all, std::string_view id, const std::optional<std::string_view>& platform)
{
    for (const CheatSet& set : all)
    {
        if (set.id == id && (!platform.has_value() || set.platform == *platform))
            return &set;
    }
    return nullptr;
}

// A set to write (§ 10): the body is {schema, platform, title_id, build_id, source, note, text}.
// The text may be as long as a set is, which no string field may.
std::expected<CheatWrite, ProblemError> read_cheat(const ServerState& state, const ServerRequest& request)
{
    const auto prepared = request_document(state, request, cheat_body);
    if (!prepared)
        return std::unexpected(prepared.error());
    const auto wrong = [&] {
        return bad_request(
            state, "A cheat set is {schema, platform, title_id, build_id, source, note, text}.");
    };
    const auto document = json::parse(prepared->text, prepared->options.limits, state.allocator.resource());
    if (!document || !document->root().is_object())
        return std::unexpected(wrong());
    CheatWrite set(state.allocator);
    const json::Value& root = document->root();
    // A member that is there must be a string; platform, title_id and text must be there
    const auto take = [&](std::string_view name, String& to, bool required) -> bool
    {
        const json::Value* value = root.find(name);
        if (value == nullptr)
            return !required;
        if (!value->is_string())
            return false;
        to.assign(value->text());
        return true;
    };
    if (!take("platform", set.platform, true) || !take("title_id", set.title_id, true)
        || !take("build_id", set.build_id, false) || !take("source", set.source, false)
        || !take("note", set.note, false) || !take("text", set.text, true))
        return std::unexpected(wrong());
    if (root.find("source") == nullptr)
        set.source.assign("Lantern");
    if (set.text.size() > cheat_limit)
        return std::unexpected(make_problem(
            state, 413, Code::too_large, "A cheat set is 1048576 bytes at most (SPEC.md § 13)."));
    if (const std::string_view problem = cheat_problem(set); !problem.empty())
        return std::unexpected(bad_request(state, problem));
    return set;
}

} // namespace

Answer cheat_text_route(const ServerState& state, const ServerRequest& request, std::string_view id)
{
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    const std::scoped_lock lock(state.cheats_mutex);
    auto all = state.library->cheats(state.allocator);
    if (!all)
        return std::unexpected(internal_error(state));
    if (find_cheat(*all, id, *platform) == nullptr)
        return std::unexpected(not_found(state, "No such cheat set."));
    auto file = state.library->cheat_file(id, state.allocator);
    if (!file)
        return std::unexpected(internal_error(state));
    if (!*file)
        return std::unexpected(not_found(state, "No such cheat set."));
    return serve_library_file(state, request, **file);
}

Answer cheat_post_route(const ServerState& state, const ServerRequest& request)
{
    auto set = read_cheat(state, request);
    if (!set)
        return std::unexpected(std::move(set.error()));
    const std::scoped_lock lock(state.cheats_mutex);
    auto all = state.library->cheats(state.allocator);
    if (!all)
        return std::unexpected(internal_error(state));
    for (const CheatSet& same : *all)
    {
        if (same_set(same, *set))
        {
            String why("This set exists, ", state.allocator);
            why.append(same.id);
            why.append(": PUT replaces it (SPEC.md § 10).");
            return std::unexpected(make_problem(state, 409, Code::conflict, why));
        }
    }
    const auto made = state.library->write_cheat(*set, {}, state.allocator);
    if (!made)
        return std::unexpected(internal_error(state));
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    write_cheat_members(w, *made);
    w.end_object();
    return json_response(state, request, std::move(out), 201);
}

Answer cheat_write_route(const ServerState& state, const ServerRequest& request, std::string_view id)
{
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    const std::scoped_lock lock(state.cheats_mutex);
    auto all = state.library->cheats(state.allocator);
    if (!all)
        return std::unexpected(internal_error(state));
    const CheatSet* found = find_cheat(*all, id, *platform);
    if (found == nullptr)
        return std::unexpected(not_found(state, "No such cheat set."));
    if (request.method == "DELETE")
    {
        const auto removed = state.library->delete_cheat(found->id);
        if (!removed)
            return std::unexpected(internal_error(state));
        return no_content(state, request);
    }
    const auto set = read_cheat(state, request);
    if (!set)
        return std::unexpected(set.error());
    if (!same_set(*found, *set))
        return std::unexpected(bad_request(
            state, "PUT replaces a set's text and note; its platform, title, build and source stay."));
    const auto written = state.library->write_cheat(*set, found->id, state.allocator);
    if (!written)
        return std::unexpected(internal_error(state));
    return no_content(state, request);
}

} // namespace lantern::detail
