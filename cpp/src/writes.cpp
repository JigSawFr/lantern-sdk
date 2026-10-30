// The routes that write: save backups (SPEC.md § 9), cheat sets (§ 10) and
// requests (§ 11).
#include <lantern/client.hpp>

#include "client_internal.hpp"

#include <algorithm>
#include <array>
#include <charconv>

#include <lantern/encoding.hpp>

namespace lantern
{

using detail::add_query;
using detail::append_segment;
using detail::bytes_of;
using detail::parse_u64;
using detail::plain_text;

namespace
{

constexpr std::size_t max_cheat_text = std::size_t { 1024 } * 1024;
constexpr std::size_t max_profile    = 64;
constexpr std::size_t max_note       = 120;
constexpr unsigned max_stalls        = 3;

// A save's word (kind, slot): 1 to 64 letters, digits, '.', '_' and '-'.
bool save_word(std::string_view word) noexcept
{
    return !word.empty() && word.size() <= 64
        && std::ranges::all_of(word,
            [](char c)
            {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.'
                    || c == '_' || c == '-';
            });
}

} // namespace

Read<Saves> Client::saves(std::string_view title_id, std::string_view platform)
{
    if (auto ok = ready(Family::saves); !ok)
        return std::unexpected(ok.error());
    auto url   = api_url("/saves");
    bool first = true;
    add_query(*url, first, "platform", platform);
    add_query(*url, first, "title_id", title_id);
    return read<Saves>(Method::get, *url, read_saves);
}

Result<void> Client::download_save(const Save& save, DownloadState& state, DownloadSink& sink)
{
    if (auto ok = ready(Family::saves); !ok)
        return std::unexpected(ok.error());
    auto url = api_url("/saves/");
    if (auto added = append_segment(*url, save.title_id); !added)
        return added;
    url->push_back('/');
    if (auto added = append_segment(*url, save.save_id); !added)
        return added;
    bool first = true;
    add_query(*url, first, "platform", save.platform);
    const DownloadTarget target { *url, save.size, save.sha256 };
    return download(target, state, sink);
}

Result<void> Client::delete_save(const Save& save)
{
    if (auto ok = ready(Family::saves); !ok)
        return std::unexpected(ok.error());
    auto url = api_url("/saves/");
    if (auto added = append_segment(*url, save.title_id); !added)
        return added;
    url->push_back('/');
    if (auto added = append_segment(*url, save.save_id); !added)
        return added;
    bool first = true;
    add_query(*url, first, "platform", save.platform);
    Call call;
    call.method = Method::delete_;
    call.url    = *url;
    if (auto done = expect(call); !done)
        return std::unexpected(done.error());
    return {};
}

Read<Save> Client::upload_save(
    std::string_view title_id, std::span<const std::byte> archive, const SaveInfo& info)
{
    if (auto ok = ready(Family::saves); !ok)
        return std::unexpected(ok.error());
    if (info.platform.empty() && platform_.empty())
        return fail(Category::usage, "a save is sent for a platform (SPEC.md 4.3)");
    if (archive.empty())
        return fail(Category::usage, "an empty archive is no save");
    if (handshake_ && handshake_->limits && handshake_->limits->save_body
        && archive.size() > *handshake_->limits->save_body)
        return fail(Category::limit, "a save above limits.save_body: send it resumably (SPEC.md 9.3)");
    if ((!info.kind.empty() && !save_word(info.kind)) || (!info.slot.empty() && !save_word(info.slot)))
        return fail(Category::usage, "a save's kind or slot is 1 to 64 letters, digits, '.', '_' and '-'");
    if (!plain_text(info.profile, max_profile) || !plain_text(info.note, max_note))
        return fail(Category::usage, "a profile of 64 bytes, a note of 120, without control characters");

    auto url = api_url("/saves/");
    if (auto added = append_segment(*url, title_id); !added)
        return std::unexpected(added.error());
    bool first = true;
    add_query(*url, first, "platform", info.platform);

    // § 9.2's headers: ASCII as they are, the texts for people percent-encoded
    String profile(allocator_);
    String note(allocator_);
    percent_encode(info.profile, profile);
    percent_encode(info.note, note);
    std::array<char, 24> version {};
    std::array<Header, 5> extra {};
    std::size_t extras = 0;
    if (!info.kind.empty())
        extra[extras++] = { "Lantern-Save-Kind", info.kind };
    if (!info.slot.empty())
        extra[extras++] = { "Lantern-Save-Slot", info.slot };
    if (info.game_version_code)
    {
        const auto result
            = std::to_chars(version.data(), version.data() + version.size(), *info.game_version_code);
        extra[extras++] = { "Lantern-Game-Version",
            std::string_view(version.data(), static_cast<std::size_t>(result.ptr - version.data())) };
    }
    if (!profile.empty())
        extra[extras++] = { "Lantern-Profile", profile };
    if (!note.empty())
        extra[extras++] = { "Lantern-Note", note };

    Call call;
    call.method       = Method::post;
    call.url          = *url;
    call.body         = archive;
    call.content_type = "application/zip";
    call.extra        = std::span(extra.data(), extras);
    return read<Save>(call, read_save);
}

Read<UploadSession> Client::open_upload(
    std::string_view title_id, const UploadRequest& request, std::string_view platform)
{
    if (auto ok = ready(Family::saves); !ok)
        return std::unexpected(ok.error());
    if (platform.empty() && platform_.empty())
        return fail(Category::usage, "a save is sent for a platform (SPEC.md 4.3)");
    if (request.size == 0)
        return fail(Category::usage, "an empty archive is no save");
    if (handshake_ && handshake_->limits && handshake_->limits->save_size
        && request.size > *handshake_->limits->save_size)
        return fail(Category::limit, "a save above limits.save_size (SPEC.md 9.3)");
    if ((!request.kind.empty() && !save_word(request.kind))
        || (!request.slot.empty() && !save_word(request.slot)) || !plain_text(request.profile, max_profile)
        || !plain_text(request.note, max_note))
        return fail(Category::usage, "an upload's fields are not of SPEC.md 9.3's form");
    auto url = api_url("/saves/");
    if (auto added = append_segment(*url, title_id); !added)
        return std::unexpected(added.error());
    url->append("/uploads");
    bool first = true;
    add_query(*url, first, "platform", platform);
    String body(allocator_);
    write_upload_request(request, body);
    auto session = read<UploadSession>(Method::post, *url, read_upload_session, body);
    if (!session || !*session)
        return session;
    const auto resolved = resolve_url(origin(), (*session)->upload, allocator_);
    if (!resolved)
        return std::unexpected(resolved.error());
    const auto parts = split_url(*resolved);
    if (!parts || !same_origin(*parts, origin()))
        return fail(Category::invalid_response, "an upload's address off the server's origin (SPEC.md 2)");
    return session;
}

Result<std::uint64_t> Client::upload_offset(std::string_view upload)
{
    const auto url = resolve_url(origin(), upload, allocator_);
    if (!url)
        return std::unexpected(url.error());
    Call call;
    call.method       = Method::head;
    call.url          = *url;
    const auto answer = expect(call);
    if (!answer)
        return std::unexpected(answer.error());
    const auto offset = parse_u64(answer->upload_offset);
    if (!offset)
        return fail(Category::invalid_response, "an upload's HEAD without its Upload-Offset (SPEC.md 9.3)");
    return *offset;
}

Result<ChunkResult> Client::upload_chunk(
    std::string_view upload, std::uint64_t offset, std::span<const std::byte> chunk)
{
    if (chunk.empty())
        return fail(Category::usage, "an empty chunk");
    const auto url = resolve_url(origin(), upload, allocator_);
    if (!url)
        return std::unexpected(url.error());
    std::array<char, 24> text {};
    const auto result = std::to_chars(text.data(), text.data() + text.size(), offset);
    const std::array<Header, 1> extra { { { "Upload-Offset",
        std::string_view(text.data(), static_cast<std::size_t>(result.ptr - text.data())) } } };
    Call call;
    call.method       = Method::patch;
    call.url          = *url;
    call.body         = chunk;
    call.content_type = "application/offset+octet-stream";
    call.extra        = extra;
    const auto answer = fetch(call);
    if (!answer)
        return std::unexpected(answer.error());
    if (answer->status < 200 || answer->status >= 300)
        return std::unexpected(problem(*answer));
    ChunkResult out(allocator_);
    const auto at = parse_u64(answer->upload_offset);
    if (answer->status == 201)
    {
        // The last chunk: the save, once the server checked the whole archive
        if (!detail::json_media_type(answer->content_type))
            return fail(Category::invalid_response, "a save entry that is not application/json");
        auto save = read_save(answer->body, decode_);
        if (!save)
            return std::unexpected(save.error());
        if (!*save)
            return fail(Category::unsupported, "a save entry of a newer schema (SPEC.md 3.2)");
        out.save.emplace(std::move(**save), allocator_);
        out.offset = at.value_or(offset + chunk.size());
        return out;
    }
    if (!at || *at > offset + chunk.size())
        return fail(
            Category::invalid_response, "a chunk's answer without a sound Upload-Offset (SPEC.md 9.3)");
    out.offset = *at;
    return out;
}

Result<void> Client::abandon_upload(std::string_view upload)
{
    const auto url = resolve_url(origin(), upload, allocator_);
    if (!url)
        return std::unexpected(url.error());
    Call call;
    call.method = Method::delete_;
    call.url    = *url;
    if (auto done = expect(call); !done)
        return std::unexpected(done.error());
    return {};
}

Read<Save> Client::upload_resumable(std::string_view title_id, const UploadRequest& request,
    UploadSource& source, UploadProgress& progress, std::size_t max_chunk, std::string_view platform)
{
    if (auto ok = ready(Family::saves); !ok)
        return std::unexpected(ok.error());
    if (max_chunk == 0)
        return fail(Category::usage, "a chunk of one byte at least");
    if (progress.url_size == 0)
    {
        auto session = open_upload(title_id, request, platform);
        if (!session)
            return std::unexpected(session.error());
        if (!*session)
            return fail(Category::unsupported, "an upload session of a newer schema (SPEC.md 3.2)");
        const UploadSession& opened = **session;
        if (opened.upload.size() > progress.url.size() || opened.chunk_size == 0)
            return fail(Category::invalid_response, "an upload's address above 512 bytes, or no chunk size");
        std::ranges::copy(opened.upload, progress.url.begin());
        progress.url_size   = opened.upload.size();
        progress.chunk_size = opened.chunk_size;
        progress.offset     = opened.offset;
    }
    else
    {
        // Where the server is, after an interruption (§ 9.3, Annex B.4)
        const auto at = upload_offset(progress.url_view());
        if (!at)
        {
            if (at.error().status() == 404 || at.error().status() == 410)
                progress.reset(); // gone: the next call opens a new one
            return std::unexpected(at.error());
        }
        progress.offset = *at;
    }

    const auto chunk = static_cast<std::size_t>(std::min<std::uint64_t>(progress.chunk_size, max_chunk));
    Vector<std::byte> buffer(allocator_);
    buffer.resize(chunk);
    unsigned stalls = 0;
    while (progress.offset < request.size)
    {
        const auto size
            = static_cast<std::size_t>(std::min<std::uint64_t>(chunk, request.size - progress.offset));
        const std::span<std::byte> bytes(buffer.data(), size);
        if (auto read_ok = source.read(progress.offset, bytes); !read_ok)
            return std::unexpected(read_ok.error());
        const std::uint64_t before = progress.offset;
        auto sent                  = upload_chunk(progress.url_view(), progress.offset, bytes);
        if (!sent)
        {
            if (sent.error().effective_code() != Code::conflict)
                return std::unexpected(sent.error());
            // 409: another offset than the server's; it says where it is
            const auto at = upload_offset(progress.url_view());
            if (!at)
                return std::unexpected(at.error());
            progress.offset = *at;
        }
        else
        {
            if (sent->save)
            {
                progress.reset();
                return std::move(sent->save);
            }
            progress.offset = sent->offset;
        }
        if (progress.offset <= before && ++stalls >= max_stalls)
            return fail(Category::invalid_response, "an upload that does not move forward");
        if (progress.offset > request.size)
            return fail(Category::invalid_response, "an Upload-Offset past the archive's size");
    }
    return fail(Category::invalid_response, "the whole archive sent, and no save entry (SPEC.md 9.3)");
}

Read<CheatSet> Client::create_cheat_set(const CheatWrite& set)
{
    if (auto ok = ready(Family::cheats); !ok)
        return std::unexpected(ok.error());
    if (set.text.size() > max_cheat_text)
        return fail(Category::limit, "a cheat set above 1 MiB (SPEC.md 13)");
    auto url = api_url("/cheats");
    String body(allocator_);
    write_cheat_write(set, body);
    return read<CheatSet>(Method::post, *url, read_cheat_set, body);
}

Result<void> Client::replace_cheat_set(std::string_view id, const CheatWrite& set)
{
    if (auto ok = ready(Family::cheats); !ok)
        return std::unexpected(ok.error());
    if (set.text.size() > max_cheat_text)
        return fail(Category::limit, "a cheat set above 1 MiB (SPEC.md 13)");
    auto url = api_url("/cheats/");
    if (auto added = append_segment(*url, id); !added)
        return added;
    String body(allocator_);
    write_cheat_write(set, body);
    Call call;
    call.method = Method::put;
    call.url    = *url;
    call.body   = bytes_of(body);
    if (auto done = expect(call); !done)
        return std::unexpected(done.error());
    return {};
}

Result<void> Client::delete_cheat_set(std::string_view id)
{
    if (auto ok = ready(Family::cheats); !ok)
        return std::unexpected(ok.error());
    auto url = api_url("/cheats/");
    if (auto added = append_segment(*url, id); !added)
        return added;
    Call call;
    call.method = Method::delete_;
    call.url    = *url;
    if (auto done = expect(call); !done)
        return std::unexpected(done.error());
    return {};
}

Read<TitleRequests> Client::requests(std::string_view platform)
{
    if (auto ok = ready(Family::requests); !ok)
        return std::unexpected(ok.error());
    auto url   = api_url("/requests");
    bool first = true;
    add_query(*url, first, "platform", platform);
    return read<TitleRequests>(Method::get, *url, read_title_requests);
}

Read<TitleRequest> Client::request_title(const RequestCreate& request)
{
    if (auto ok = ready(Family::requests); !ok)
        return std::unexpected(ok.error());
    if (request.platform.empty() && platform_.empty())
        return fail(Category::usage, "a request names its platform, or the client's (SPEC.md 11)");
    auto url = api_url("/requests");
    String body(allocator_);
    write_request_create(request, body);
    return read<TitleRequest>(Method::post, *url, read_title_request, body);
}

Result<void> Client::withdraw_request(std::string_view id)
{
    if (auto ok = ready(Family::requests); !ok)
        return std::unexpected(ok.error());
    auto url = api_url("/requests/");
    if (auto added = append_segment(*url, id); !added)
        return added;
    Call call;
    call.method = Method::delete_;
    call.url    = *url;
    if (auto done = expect(call); !done)
        return std::unexpected(done.error());
    return {};
}

} // namespace lantern
