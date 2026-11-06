// The routes of the save backups (SPEC.md § 9) and of the encrypted ones
// (§ 9.4): the listing, a backup's archive and its removal, a save sent in
// one request, and the resumable upload. The bytes of a body go to the
// SaveStore piece by piece, hashed on the way, so that a large save is never
// held whole.
#include <algorithm>
#include <array>
#include <charconv>
#include <system_error>
#include <tuple>

#include <lantern/digest.hpp>
#include <lantern/document.hpp>
#include <lantern/encoding.hpp>
#include <lantern/encrypted_save.hpp>
#include <lantern/json.hpp>
#include <lantern/profiles.hpp>
#include <lantern/saves.hpp>

#include "server_internal.hpp"

namespace lantern::detail
{

namespace
{

constexpr std::size_t profile_limit = 64;
constexpr std::size_t note_limit    = 120;
// The pieces a streamed body is read in.
constexpr std::size_t piece_size = std::size_t { 32 } * 1024;
// I-JSON's largest integer (§ 2.3): 2^53 - 1.
constexpr std::uint64_t max_safe = 9007199254740991ULL;
constexpr std::array<std::string_view, 5> save_kinds { "account", "device", "bcat", "cache", "other" };
constexpr std::string_view e2e_magic = "LTNE2E01";

bool is_slot(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= 64
        && std::ranges::all_of(text,
            [](char c)
            {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.'
                    || c == '_' || c == '-';
            });
}

bool is_key_id(std::string_view text) noexcept
{
    return text.size() == 16
        && std::ranges::all_of(text, [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

// At most `limit` bytes, without control characters.
bool printable(std::string_view text, std::size_t limit) noexcept
{
    return text.size() <= limit
        && std::ranges::none_of(text,
            [](char c)
            {
                const auto byte = static_cast<unsigned char>(c);
                return byte < 0x20 || byte == 0x7f;
            });
}

bool valid_utf8(std::string_view text) noexcept
{
    std::size_t at = 0;
    while (at < text.size())
    {
        const auto lead    = static_cast<unsigned char>(text[at]);
        std::size_t more   = 0;
        std::uint32_t code = 0;
        if (lead < 0x80)
            code = lead;
        else if (lead >= 0xc2 && lead <= 0xdf)
        {
            more = 1;
            code = lead & 0x1fU;
        }
        else if (lead >= 0xe0 && lead <= 0xef)
        {
            more = 2;
            code = lead & 0x0fU;
        }
        else if (lead >= 0xf0 && lead <= 0xf4)
        {
            more = 3;
            code = lead & 0x07U;
        }
        else
            return false;
        if (more != 0 && at + more >= text.size())
            return false;
        for (std::size_t i = 1; i <= more; ++i)
        {
            const auto next = static_cast<unsigned char>(text[at + i]);
            if ((next & 0xc0U) != 0x80U)
                return false;
            code = (code << 6U) | (next & 0x3fU);
        }
        const bool overlong  = (more == 2 && code < 0x800) || (more == 3 && code < 0x10000);
        const bool surrogate = code >= 0xd800 && code <= 0xdfff;
        if (overlong || surrogate || code > 0x10ffff)
            return false;
        at += more + 1;
    }
    return true;
}

int hex_digit(char c) noexcept
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

// A header's text, UTF-8 percent-encoded (§ 9.2). An escape that is none stays as it is.
std::optional<String> percent_decoded(std::string_view text, const Allocator& allocator)
{
    String out(allocator);
    for (std::size_t i = 0; i < text.size(); ++i)
    {
        if (text[i] == '%' && i + 2 < text.size() && hex_digit(text[i + 1]) >= 0
            && hex_digit(text[i + 2]) >= 0)
        {
            out.push_back(static_cast<char>(hex_digit(text[i + 1]) * 16 + hex_digit(text[i + 2])));
            i += 2;
        }
        else
            out.push_back(text[i]);
    }
    if (!valid_utf8(out))
        return std::nullopt;
    return out;
}

// "s_" or "u_" and a random token (letters, digits, `_` and `-`).
std::expected<String, ProblemError> new_id(
    const ServerState& state, std::string_view prefix, std::size_t bytes)
{
    std::array<std::uint8_t, 18> raw {};
    if (!state.random->fill(std::span(raw.data(), bytes)))
        return std::unexpected(internal_error(state));
    String out(prefix, state.allocator);
    base64url_encode(std::span<const std::uint8_t>(raw.data(), bytes), out);
    return out;
}

ServerResponse empty_response(const ServerState& state, const ServerRequest& request, std::uint16_t status)
{
    ServerResponse response(state.allocator);
    response.status = status;
    caching_headers(response.headers, request);
    response.headers.set("Content-Length", "0");
    return response;
}

std::string_view media_type_of(std::string_view header) noexcept
{
    return trim(header.substr(0, header.find(';')));
}

void write_hex_digest(json::Writer& w, const Digest& digest)
{
    const auto hex = to_hex(digest);
    w.string(std::string_view(hex.data(), hex.size()));
}

// A save's members, as § 9.1 lists them.
void write_save_members(json::Writer& w, const Save& save)
{
    w.key("platform");
    w.string(save.platform);
    w.key("title_id");
    w.string(save.title_id);
    w.key("save_id");
    w.string(save.save_id);
    w.key("created");
    w.string(save.created);
    w.key("size");
    w.number(save.size);
    w.key("sha256");
    write_hex_digest(w, save.sha256);
    const auto text = [&](std::string_view name, const String& value)
    {
        if (value.empty())
            return;
        w.key(name);
        w.string(value);
    };
    text("slot", save.slot);
    text("kind", save.kind);
    if (save.game_version_code)
    {
        w.key("game_version_code");
        w.number(*save.game_version_code);
    }
    text("profile", save.profile);
    text("note", save.note);
    text("device", save.device);
    if (save.encryption)
    {
        w.key("encryption");
        w.begin_object();
        w.key("scheme");
        w.string(save.encryption->scheme);
        w.key("key_id");
        w.string(save.encryption->key_id);
        w.end_object();
    }
}

// What the server reads of a request that makes a backup (§ 9.1, § 9.2, § 9.3).
struct Fields
{
    std::string_view kind;
    std::string_view slot;
    std::optional<std::uint64_t> game_version_code;
    std::string_view profile;
    std::string_view note;
    std::optional<SaveEncryption> encryption;
};

// The platform a save is written for (400 without one, L-4.3-4); its title id in its form.
std::expected<std::string_view, ProblemError> save_platform(
    const ServerState& state, const ServerRequest& request, std::string_view title_id)
{
    const auto named = platform_param(state, request);
    if (!named)
        return std::unexpected(named.error());
    const std::optional<std::string_view> platform = *named;
    if (!platform)
        return std::unexpected(
            bad_request(state, "Name a platform: Lantern-Platform or ?platform= (SPEC.md § 4.3)."));
    if (!is_served_platform(*platform))
        return std::unexpected(
            bad_request(state, "A server keeps no save of that platform (SPEC.md Annex A.7)."));
    const Profile* profile = find_profile(*platform);
    if (!is_core_id(title_id)
        || (profile != nullptr && profile->title_id != nullptr && !profile->title_id(title_id)))
    {
        String why("Not a title id of ", state.allocator);
        why.append(*platform);
        why.push_back('.');
        return std::unexpected(bad_request(state, why));
    }
    return *platform;
}

// A backup's encryption (§ 9.4): of lantern-save-e2e-1 with a key id; 400 for another, and for any when the
// server keeps no encrypted backup (L-9.4-5).
std::expected<std::optional<SaveEncryption>, ProblemError> checked_encryption(
    const ServerState& state, const std::optional<SaveEncryption>& given)
{
    if (!given)
        return std::optional<SaveEncryption> {};
    if (!state.encrypted_saves)
        return std::unexpected(bad_request(state, "This server keeps no encrypted backup (SPEC.md § 9.4)."));
    if (given->scheme != save_scheme || !is_key_id(given->key_id))
        return std::unexpected(bad_request(
            state, "encryption is {scheme: lantern-save-e2e-1, key_id: 16 hex digits} (SPEC.md § 9.4)."));
    return std::optional<SaveEncryption>(SaveEncryption(*given, state.allocator));
}

// The backup a request makes (§ 9.1, § 13), its fields checked; its save_id and `created` are given now.
std::expected<Save, ProblemError> make_backup(const ServerState& state, const Caller& caller,
    std::string_view platform, std::string_view title_id, std::uint64_t size, const Digest& sha256,
    const Fields& fields)
{
    if (!fields.kind.empty() && std::ranges::find(save_kinds, fields.kind) == save_kinds.end())
        return std::unexpected(bad_request(state, "kind is account, device, bcat, cache or other."));
    if (!fields.slot.empty() && !is_slot(fields.slot))
        return std::unexpected(bad_request(state, "slot is 1 to 64 letters, digits, '.', '_' and '-'."));
    if (fields.game_version_code && *fields.game_version_code > max_safe)
        return std::unexpected(bad_request(state, "game_version_code is an integer, 0 or more."));
    if (!printable(fields.profile, profile_limit))
        return std::unexpected(bad_request(state, "profile: 64 bytes at most, without control characters."));
    if (!printable(fields.note, note_limit))
        return std::unexpected(bad_request(state, "note: 120 bytes at most, without control characters."));
    auto encryption = checked_encryption(state, fields.encryption);
    if (!encryption)
        return std::unexpected(std::move(encryption.error()));
    auto id = new_id(state, "s_", 9);
    if (!id)
        return std::unexpected(std::move(id.error()));
    Save save(state.allocator);
    save.platform.assign(platform);
    save.title_id.assign(title_id);
    save.save_id = std::move(*id);
    save.created = utc_text(state.clock->unix_seconds(), state.allocator);
    save.size    = size;
    save.sha256  = sha256;
    save.slot.assign(fields.slot);
    save.kind.assign(fields.kind);
    save.game_version_code = fields.game_version_code;
    save.profile.assign(fields.profile);
    save.note.assign(fields.note);
    save.device     = caller.device;
    save.encryption = std::move(*encryption);
    return save;
}

// A backup's first bytes (§ 9.1, § 9.4): a zip in clear; encrypted, the header of lantern-save-e2e-1 with
// its key id, nothing more being read of it. 400 otherwise.
std::optional<ProblemError> check_archive(const ServerState& state, std::span<const std::byte> head,
    const std::optional<SaveEncryption>& encryption)
{
    const std::string_view bytes(reinterpret_cast<const char*>(head.data()), head.size());
    if (encryption)
    {
        bool fits = bytes.size() >= 16 && bytes.starts_with(e2e_magic);
        if (fits)
        {
            // The key id's 8 bytes as hex
            std::array<char, 16> hex {};
            for (std::size_t i = 0; i < 8; ++i)
            {
                constexpr std::string_view digits = "0123456789abcdef";
                const auto byte                   = static_cast<unsigned char>(bytes[8 + i]);
                hex[2 * i]                        = digits[byte >> 4U];
                hex[2 * i + 1]                    = digits[byte & 0x0fU];
            }
            fits = std::string_view(hex.data(), hex.size()) == encryption->key_id;
        }
        if (!fits)
            return bad_request(
                state, "An encrypted backup begins with LTNE2E01 and its key id (SPEC.md § 9.4).");
        return std::nullopt;
    }
    if (!bytes.starts_with("PK\x03\x04") && !bytes.starts_with("PK\x05\x06"))
        return bad_request(state, "A save is a zip archive (SPEC.md § 9.1).");
    return std::nullopt;
}

ProblemError digest_problem(const ServerState& state)
{
    return make_problem(
        state, 422, Code::digest_mismatch, "The body does not match its Content-Digest.", "Digest mismatch");
}

// What a body weighs once read: its SHA-256 and its first 16 bytes.
class Tally
{
  public:
    void add(std::span<const std::byte> bytes) noexcept
    {
        hash_.update(bytes);
        for (std::size_t i = 0; i < bytes.size() && head_size_ < head_.size(); ++i)
            head_[head_size_++] = bytes[i];
    }
    [[nodiscard]] Digest finish() noexcept { return hash_.finish(); }
    [[nodiscard]] std::span<const std::byte> head() const noexcept { return { head_.data(), head_size_ }; }

  private:
    Sha256 hash_;
    std::array<std::byte, 16> head_ {};
    std::size_t head_size_ = 0;
};

enum class Pumped : std::uint8_t
{
    done,
    cut, // the body ended before its length
    refused, // the sink failed
};

// Hands the request's body to `sink` (a bool(span) that says whether to go on), whole when the adapter
// buffered it, in pieces when it did not.
template <class Sink> Pumped pump(const ServerState& state, const ServerRequest& request, const Sink& sink)
{
    if (request.stream == nullptr)
        return request.body.empty() || sink(request.body) ? Pumped::done : Pumped::refused;
    Vector<std::byte> buffer(piece_size, std::byte {}, state.allocator);
    std::uint64_t left = request.stream_length;
    while (left != 0)
    {
        const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(left, buffer.size()));
        const auto got         = request.stream->read(std::span(buffer.data(), want));
        if (!got || *got == 0 || *got > want)
            return Pumped::cut;
        if (!sink(std::span<const std::byte>(buffer.data(), *got)))
            return Pumped::refused;
        left -= *got;
    }
    return Pumped::done;
}

// The sha-256 a Content-Digest announces: 400 for one this server cannot read.
std::expected<Digest, ProblemError> announced_digest(const ServerState& state, std::string_view header)
{
    const ParsedDigest parsed = parse_digest_field(header);
    if (parsed.state != DigestField::sha256)
        return std::unexpected(bad_request(state, "Content-Digest gives no sha-256 this server reads."));
    return parsed.sha256;
}

// Drops the uploads not finished in time (§ 9.3). Under the lock of saves.
bool purge_uploads(const ServerState& state)
{
    auto open = state.saves->uploads(state.allocator);
    if (!open)
        return false;
    const std::int64_t now = state.clock->unix_seconds();
    for (const StoredUpload& upload : *open)
    {
        if (upload.expires <= now && !state.saves->abandon(upload.id))
            return false;
    }
    return true;
}

// A backup was kept: the oldest beyond saves_kept_per_title dropped (§ 9.1). Under the lock of saves.
bool prune(const ServerState& state, std::string_view user, const Save& kept)
{
    auto all = state.saves->saves(user, state.allocator);
    if (!all)
        return false;
    Vector<const Save*> same(state.allocator);
    for (const Save& save : *all)
    {
        if (save.platform == kept.platform && save.title_id == kept.title_id)
            same.push_back(&save);
    }
    const std::size_t keep = state.save_limits.kept;
    for (std::size_t i = 0; i + keep < same.size(); ++i)
    {
        if (!state.saves->drop(user, same[i]->save_id))
            return false;
    }
    return true;
}

Answer created_answer(const ServerState& state, const ServerRequest& request, const Save& save)
{
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    write_save_members(w, save);
    w.end_object();
    return json_response(state, request, std::move(out), 201);
}

// Marks an upload as written by a request, so that a second one meanwhile is refused.
class WriteGuard
{
  public:
    WriteGuard(const ServerState& state, std::string_view id)
        : state_(state)
        , id_(id, state.allocator)
    {
    }
    WriteGuard(const WriteGuard&)            = delete;
    WriteGuard& operator=(const WriteGuard&) = delete;
    WriteGuard(WriteGuard&&)                 = delete;
    WriteGuard& operator=(WriteGuard&&)      = delete;
    ~WriteGuard()
    {
        if (!held_)
            return;
        const std::scoped_lock lock(state_.saves_mutex);
        std::erase(state_.writing, id_);
    }
    // Under the lock of saves: false when another request writes the upload.
    [[nodiscard]] bool take()
    {
        if (std::ranges::find(state_.writing, id_) != state_.writing.end())
            return false;
        state_.writing.push_back(id_);
        held_ = true;
        return true;
    }

  private:
    const ServerState& state_;
    String id_;
    bool held_ = false;
};

ProblemError conflict_at(const ServerState& state, std::uint64_t offset, std::string_view why)
{
    ProblemError error = make_problem(state, 409, Code::conflict, why);
    error.headers.set("Upload-Offset", number_text(offset, state.allocator));
    return error;
}

String upload_address(const ServerState& state, std::string_view id)
{
    String address(state.base, state.allocator);
    address.append("/v1/uploads/");
    address.append(id);
    return address;
}

} // namespace

Answer saves_route(const ServerState& state, const ServerRequest& request, const Caller& caller)
{
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    const std::string_view title_id = request.param("title_id").value_or(std::string_view {});
    if (!title_id.empty() && !is_core_id(title_id))
        return std::unexpected(bad_request(state, "title_id is 1 to 128 letters, digits, '.', '_' and '-'."));
    auto kept = state.saves->saves(caller.name, state.allocator);
    if (!kept)
        return std::unexpected(internal_error(state));
    Vector<std::size_t> order(state.allocator);
    for (std::size_t i = 0; i < kept->size(); ++i)
    {
        const Save& save = (*kept)[i];
        if ((!platform->has_value() || save.platform == **platform)
            && (title_id.empty() || save.title_id == title_id))
            order.push_back(i);
    }
    // Per title (L-9.1-1), newest first within it
    std::ranges::sort(order,
        [&](std::size_t a, std::size_t b)
        {
            const Save& x = (*kept)[a];
            const Save& y = (*kept)[b];
            if (x.platform != y.platform)
                return x.platform < y.platform;
            if (x.title_id != y.title_id)
                return x.title_id < y.title_id;
            if (x.created != y.created)
                return x.created > y.created;
            return a > b;
        });
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("saves");
    w.begin_array();
    for (const std::size_t i : order)
    {
        w.begin_object();
        write_save_members(w, (*kept)[i]);
        w.end_object();
    }
    w.end_array();
    w.end_object();
    return json_response(state, request, std::move(out));
}

Answer save_route(const ServerState& state, const ServerRequest& request, const Caller& caller,
    std::string_view title_id, std::string_view save_id)
{
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    const std::scoped_lock lock(state.saves_mutex);
    auto kept = state.saves->saves(caller.name, state.allocator);
    if (!kept)
        return std::unexpected(internal_error(state));
    const Save* found = nullptr;
    for (const Save& save : *kept)
    {
        if (save.save_id == save_id && save.title_id == title_id
            && (!platform->has_value() || save.platform == **platform))
            found = &save;
    }
    if (found == nullptr)
        return std::unexpected(not_found(state, "No such save backup."));
    if (request.method == "DELETE")
    {
        if (!state.saves->drop(caller.name, save_id))
            return std::unexpected(internal_error(state));
        return empty_response(state, request, 204);
    }
    auto file = state.saves->archive(caller.name, save_id, state.allocator);
    if (!file)
        return std::unexpected(internal_error(state));
    if (!*file)
        return std::unexpected(not_found(state, "No such save backup."));
    return serve_library_file(state, request, **file);
}

Answer save_post_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view title_id)
{
    const auto platform = save_platform(state, request, title_id);
    if (!platform)
        return std::unexpected(platform.error());
    const auto header = request.header("Content-Digest");
    if (!header)
        return std::unexpected(
            bad_request(state, "Content-Digest: sha-256=:<base64>: is required (SPEC.md § 9.2)."));
    const auto announced = announced_digest(state, *header);
    if (!announced)
        return std::unexpected(announced.error());

    Fields fields;
    fields.kind = trim(request.header("Lantern-Save-Kind").value_or(std::string_view {}));
    fields.slot = trim(request.header("Lantern-Save-Slot").value_or(std::string_view {}));
    if (const auto version = request.header("Lantern-Game-Version"))
    {
        const std::string_view digits = trim(*version);
        std::uint64_t code            = 0;
        const auto parsed             = std::from_chars(digits.data(), digits.data() + digits.size(), code);
        if (digits.empty() || parsed.ec != std::errc {} || parsed.ptr != digits.data() + digits.size()
            || code > max_safe)
            return std::unexpected(bad_request(state, "Lantern-Game-Version is an integer."));
        fields.game_version_code = code;
    }
    // Lantern-Profile and Lantern-Note: UTF-8, percent-encoded
    String profile(state.allocator);
    String note(state.allocator);
    const auto read_text
        = [&](std::string_view name, std::size_t limit, String& into) -> std::optional<ProblemError>
    {
        const auto value = request.header(name);
        if (!value)
            return std::nullopt;
        auto decoded = percent_decoded(*value, state.allocator);
        String why(name, state.allocator);
        if (!decoded)
        {
            why.append(" is UTF-8, percent-encoded.");
            return bad_request(state, why);
        }
        if (!printable(*decoded, limit))
        {
            why.append(": ");
            why.append(number_text(limit, state.allocator));
            why.append(" bytes at most, without control characters.");
            return bad_request(state, why);
        }
        into = std::move(*decoded);
        return std::nullopt;
    };
    if (auto problem = read_text("Lantern-Profile", profile_limit, profile))
        return std::unexpected(std::move(*problem));
    if (auto problem = read_text("Lantern-Note", note_limit, note))
        return std::unexpected(std::move(*problem));
    fields.profile = profile;
    fields.note    = note;
    if (const auto text = request.header("Lantern-Save-Encryption"))
    {
        const std::size_t semicolon = text->find(';');
        SaveEncryption given(state.allocator);
        given.scheme.assign(trim(text->substr(0, semicolon)));
        std::string_view params
            = semicolon == std::string_view::npos ? std::string_view {} : text->substr(semicolon + 1);
        while (!params.empty())
        {
            const std::size_t next      = params.find(';');
            const std::string_view part = trim(params.substr(0, next));
            const std::size_t equals    = part.find('=');
            if (equals != std::string_view::npos && trim(part.substr(0, equals)) == "key_id")
                given.key_id.assign(trim(part.substr(equals + 1)));
            params = next == std::string_view::npos ? std::string_view {} : params.substr(next + 1);
        }
        fields.encryption = std::move(given);
    }
    const std::uint64_t size = request.body_size();
    auto save                = make_backup(state, caller, *platform, title_id, size, *announced, fields);
    if (!save)
        return std::unexpected(std::move(save.error()));
    if (size > state.save_limits.body)
    {
        String why("At most ", state.allocator);
        why.append(number_text(state.save_limits.body, state.allocator));
        why.append(" bytes in one request: upload it (SPEC.md § 9.3).");
        return std::unexpected(make_problem(state, 413, Code::too_large, why));
    }

    // The body goes into an upload of the store's, which is kept once it checks out
    auto id = new_id(state, "u_", 18);
    if (!id)
        return std::unexpected(std::move(id.error()));
    StoredUpload upload(state.allocator);
    upload.id      = *id;
    upload.user    = caller.name;
    upload.save    = *save;
    upload.expires = state.clock->unix_seconds() + std::int64_t { state.save_limits.upload_hours } * 3600;
    {
        const std::scoped_lock lock(state.saves_mutex);
        if (!purge_uploads(state) || !state.saves->open_upload(upload))
            return std::unexpected(internal_error(state));
    }
    Tally tally;
    const Pumped pumped = pump(state, request,
        [&](std::span<const std::byte> piece)
        {
            tally.add(piece);
            return state.saves->append(*id, piece).has_value();
        });
    std::optional<ProblemError> refused;
    if (pumped == Pumped::refused)
        refused = internal_error(state);
    else if (pumped == Pumped::cut)
        refused = bad_request(state, "The body ended before its Content-Length.");
    else if (!same_digest(tally.finish(), *announced))
        refused = digest_problem(state);
    else
        refused = check_archive(state, tally.head(), save->encryption);
    if (refused)
    {
        std::ignore = state.saves->abandon(*id);
        return std::unexpected(std::move(*refused));
    }
    const std::scoped_lock lock(state.saves_mutex);
    if (!state.saves->keep_upload(*id, *save) || !prune(state, caller.name, *save))
        return std::unexpected(internal_error(state));
    return created_answer(state, request, *save);
}

Answer upload_open_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view title_id)
{
    const auto prepared = request_document(state, request);
    if (!prepared)
        return std::unexpected(prepared.error());
    const auto platform = save_platform(state, request, title_id);
    if (!platform)
        return std::unexpected(platform.error());
    auto bound = read_document<UploadRequest>(prepared->text, known_schema, prepared->options,
        [](BindContext& c, UploadRequest& value) { return bind(c, value); });
    if (!bound || !*bound)
        return std::unexpected(bad_request(state,
            "An upload is {schema, size, sha256, kind?, slot?, game_version_code?, profile?, note?, "
            "encryption?}."));
    const UploadRequest& doc = **bound;
    if (doc.size > max_safe)
        return std::unexpected(
            bad_request(state, "size is an integer, 0 or more, and sha256 a lower-case hex SHA-256."));
    if (doc.size > state.save_limits.size)
    {
        String why("A save is ", state.allocator);
        why.append(number_text(state.save_limits.size, state.allocator));
        why.append(" bytes at most here.");
        return std::unexpected(make_problem(state, 413, Code::too_large, why));
    }
    Fields fields;
    fields.kind              = doc.kind;
    fields.slot              = doc.slot;
    fields.game_version_code = doc.game_version_code;
    fields.profile           = doc.profile;
    fields.note              = doc.note;
    fields.encryption        = doc.encryption;
    auto save                = make_backup(state, caller, *platform, title_id, doc.size, doc.sha256, fields);
    if (!save)
        return std::unexpected(std::move(save.error()));
    auto id = new_id(state, "u_", 18);
    if (!id)
        return std::unexpected(std::move(id.error()));
    StoredUpload upload(state.allocator);
    upload.id      = *id;
    upload.user    = caller.name;
    upload.save    = *save;
    upload.expires = state.clock->unix_seconds() + std::int64_t { state.save_limits.upload_hours } * 3600;
    {
        const std::scoped_lock lock(state.saves_mutex);
        if (!purge_uploads(state) || !state.saves->open_upload(upload))
            return std::unexpected(internal_error(state));
    }
    const String address = upload_address(state, *id);
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("upload");
    w.string(address);
    w.key("chunk_size");
    w.number(state.save_limits.chunk);
    w.key("offset");
    w.number(std::uint64_t { 0 });
    w.key("expires");
    w.string(utc_text(upload.expires, state.allocator));
    w.end_object();
    ServerResponse response = json_response(state, request, std::move(out), 201, false);
    response.headers.set("Location", address);
    response.headers.set("Cache-Control", "no-store");
    return response;
}

namespace
{

// PATCH <upload>: a chunk at the offset the upload is at (§ 9.3). `session` is the upload as it stands, and
// this request the only one writing it.
Answer write_chunk(
    const ServerState& state, const ServerRequest& request, const Caller& caller, const StoredUpload& session)
{
    if (!equal_fold(media_type_of(request.header("Content-Type").value_or(std::string_view {})),
            "application/offset+octet-stream"))
        return std::unexpected(
            bad_request(state, "A chunk is application/offset+octet-stream (SPEC.md § 9.3)."));
    const std::string_view text = trim(request.header("Upload-Offset").value_or(std::string_view {}));
    std::uint64_t offset        = 0;
    const auto parsed           = std::from_chars(text.data(), text.data() + text.size(), offset);
    if (text.empty() || parsed.ec != std::errc {} || parsed.ptr != text.data() + text.size())
        return std::unexpected(bad_request(state, "Upload-Offset is the chunk's offset, an integer."));
    const std::uint64_t length = request.body_size();
    if (length > state.save_limits.chunk)
    {
        String why("A chunk is ", state.allocator);
        why.append(number_text(state.save_limits.chunk, state.allocator));
        why.append(" bytes at most here.");
        return std::unexpected(make_problem(state, 413, Code::too_large, why));
    }
    std::optional<Digest> announced;
    if (const auto header = request.header("Content-Digest"))
    {
        const auto digest = announced_digest(state, *header);
        if (!digest)
            return std::unexpected(digest.error());
        announced = *digest;
    }
    if (offset != session.offset)
    {
        String why("This upload is at ", state.allocator);
        why.append(number_text(session.offset, state.allocator));
        why.append(": resume from there.");
        return std::unexpected(conflict_at(state, session.offset, why));
    }
    if (session.offset + length > session.save.size)
    {
        String why("This chunk goes past the upload's size, ", state.allocator);
        why.append(number_text(session.save.size, state.allocator));
        why.append(" bytes.");
        return std::unexpected(bad_request(state, why));
    }

    Tally tally;
    const Pumped pumped = pump(state, request,
        [&](std::span<const std::byte> piece)
        {
            tally.add(piece);
            return state.saves->append(session.id, piece).has_value();
        });
    // Whole chunks are kept when the sender vouched for them; a cut one without a digest stays as far as it
    // came
    if (pumped == Pumped::refused)
        return std::unexpected(internal_error(state));
    if (pumped == Pumped::cut)
    {
        if (announced && !state.saves->truncate(session.id, session.offset))
            return std::unexpected(internal_error(state));
        return std::unexpected(bad_request(state, "The body ended before its Content-Length."));
    }
    if (announced && !same_digest(*announced, tally.finish()))
    {
        if (!state.saves->truncate(session.id, session.offset))
            return std::unexpected(internal_error(state));
        return std::unexpected(digest_problem(state));
    }
    const std::uint64_t at = session.offset + length;
    if (at < session.save.size)
    {
        ServerResponse response = empty_response(state, request, 204);
        response.headers.set("Upload-Offset", number_text(at, state.allocator));
        response.headers.set("Cache-Control", "no-store");
        return response;
    }

    // The chunk that reaches `size` ends the upload: the whole archive's SHA-256 (L-9.3-4)
    const auto held = state.saves->upload_state(session.id);
    if (!held)
        return std::unexpected(internal_error(state));
    std::optional<ProblemError> refused;
    if (!same_digest(held->sha256, session.save.sha256))
        refused = make_problem(state, 422, Code::digest_mismatch,
            "The archive's SHA-256 is not the one announced; the upload was discarded.", "Digest mismatch");
    else
        refused
            = check_archive(state, std::span(held->head.data(), held->head_size), session.save.encryption);
    if (refused)
    {
        std::ignore = state.saves->abandon(session.id);
        return std::unexpected(std::move(*refused));
    }
    Save save(session.save, state.allocator);
    auto id = new_id(state, "s_", 9);
    if (!id)
        return std::unexpected(std::move(id.error()));
    save.save_id = std::move(*id);
    save.created = utc_text(state.clock->unix_seconds(), state.allocator);
    {
        const std::scoped_lock lock(state.saves_mutex);
        if (!state.saves->keep_upload(session.id, save) || !prune(state, caller.name, save))
            return std::unexpected(internal_error(state));
    }
    auto answer = created_answer(state, request, save);
    if (answer)
        answer->headers.set("Upload-Offset", number_text(at, state.allocator));
    return answer;
}

} // namespace

Answer upload_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view upload_id)
{
    WriteGuard guard(state, upload_id);
    StoredUpload session(state.allocator);
    {
        const std::scoped_lock lock(state.saves_mutex);
        auto found = state.saves->upload(upload_id, state.allocator);
        if (!found)
            return std::unexpected(internal_error(state));
        std::optional<StoredUpload> held = std::move(*found);
        if (held && held->expires <= state.clock->unix_seconds())
        {
            if (!state.saves->abandon(upload_id))
                return std::unexpected(internal_error(state));
            held.reset();
        }
        // Only the account that opened an upload sees it
        if (!held || held->user != caller.name)
            return std::unexpected(
                not_found(state, "No such upload: it finished, expired or was abandoned."));
        session = std::move(*held);
        if (request.method == "DELETE")
        {
            if (std::ranges::find(state.writing, upload_id) != state.writing.end())
                return std::unexpected(
                    conflict_at(state, session.offset, "A chunk is being written: try again."));
            if (!state.saves->abandon(upload_id))
                return std::unexpected(internal_error(state));
            return empty_response(state, request, 204);
        }
        if (request.method == "HEAD")
        {
            ServerResponse response = empty_response(state, request, 204);
            response.headers.set("Upload-Offset", number_text(session.offset, state.allocator));
            response.headers.set("Upload-Length", number_text(session.save.size, state.allocator));
            response.headers.set("Lantern-Chunk-Size", number_text(state.save_limits.chunk, state.allocator));
            response.headers.set("Cache-Control", "no-store");
            return response;
        }
        if (!guard.take())
            return std::unexpected(
                conflict_at(state, session.offset, "A chunk of this upload is being written: try again."));
    }
    return write_chunk(state, request, caller, session);
}

} // namespace lantern::detail
