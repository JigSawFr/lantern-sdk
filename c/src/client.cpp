// The client: the handshake, pairing, the library, homebrew, cheats, saves,
// requests and the administration API.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/client.hpp>

#include "callbacks.hpp"

using namespace lantern_c;

namespace
{

lantern::Pairing* as_pairing(lantern_pairing* pairing) noexcept
{
    return &pairing->pairing;
}

const lantern::Pairing* as_pairing(const lantern_pairing* pairing) noexcept
{
    return &pairing->pairing;
}

Resource* resource_of(const lantern_client* client) noexcept
{
    return client->resource.get();
}

// A read the client made, given to the app.
template <class T, class Out>
lantern_status give(lantern_client* client, lantern::Read<T>&& read, Out** out, lantern_error* error)
{
    const lantern_status status = give_read<T>(resource_of(client), std::move(read), out, error);
    if (status >= 0)
        ok(error);
    return status;
}

lantern_status done(const lantern::Result<void>& result, lantern_error* error)
{
    if (!result)
        return fail(error, result.error());
    return ok(error);
}

// Strings of the app's, as the C++ library takes them.
lantern::Vector<std::string_view> views(
    const char* const* items, std::size_t count, lantern::Allocator allocator)
{
    lantern::Vector<std::string_view> out(allocator);
    if (items == nullptr)
        return out;
    out.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
        out.push_back(text(items[i]));
    return out;
}

void strings(lantern::Vector<lantern::String>& out, const char* const* items, std::size_t count)
{
    if (items == nullptr)
        return;
    out.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
        out.emplace_back(text(items[i]));
}

std::optional<std::uint32_t> page_size(std::uint32_t size) noexcept
{
    return size == 0 ? std::nullopt : std::optional<std::uint32_t>(size);
}

std::optional<lantern::RatingCap> rating_cap(
    const lantern_rating_cap_input* input, lantern::Allocator allocator)
{
    if (input == nullptr)
        return std::nullopt;
    const lantern_rating_cap_input c = copy_struct(input);
    lantern::RatingCap cap(allocator);
    if (c.has_age)
        cap.age = c.age;
    cap.system  = text(c.system);
    cap.rating  = text(c.rating);
    cap.unrated = text(c.unrated);
    return cap;
}

lantern::DownloadTarget target_of(const lantern_download_target& target) noexcept
{
    lantern::DownloadTarget out;
    out.url    = text(target.url);
    out.size   = target.size;
    out.sha256 = digest_of(target.sha256);
    return out;
}

lantern::UploadRequest upload_request(const lantern_upload_request& r, lantern::Allocator allocator)
{
    lantern::UploadRequest out(allocator);
    out.size   = r.size;
    out.sha256 = digest_of(r.sha256);
    out.kind   = text(r.kind);
    out.slot   = text(r.slot);
    if (r.has_game_version_code)
        out.game_version_code = r.game_version_code;
    out.profile = text(r.profile);
    out.note    = text(r.note);
    if (r.encryption_scheme != nullptr || r.encryption_key_id != nullptr)
    {
        out.encryption.emplace(allocator);
        out.encryption->scheme = text(r.encryption_scheme);
        out.encryption->key_id = text(r.encryption_key_id);
    }
    return out;
}

lantern::CheatWrite cheat_write(const lantern_cheat_write& w, lantern::Allocator allocator)
{
    lantern::CheatWrite out(allocator);
    out.platform = text(w.platform);
    out.title_id = text(w.title_id);
    out.build_id = text(w.build_id);
    out.source   = text(w.source);
    out.note     = text(w.note);
    out.text     = text(w.text);
    return out;
}

lantern::PageQuery page_query(const lantern_page_query* page) noexcept
{
    const lantern_page_query p = copy_struct(page);
    lantern::PageQuery out;
    out.page_size = page_size(p.page_size);
    out.cursor    = text(p.cursor);
    return out;
}

} // namespace

// NOLINTBEGIN(readability-identifier-naming,misc-use-internal-linkage)
extern "C" {

LANTERN_API lantern_status lantern_client_create(
    const lantern_client_config* config, lantern_client** out, lantern_error* error)
{
    if (out == nullptr || config == nullptr)
        return usage(error, "a NULL argument");
    *out                          = nullptr;
    const lantern_client_config c = copy_struct(config);
    if (c.transport == nullptr)
        return usage(error, "the configuration has no transport");
    const ScopedResource resource(c.allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    lantern::ClientConfig settings;
    settings.origin          = text(c.origin);
    settings.user_agent      = text(c.user_agent);
    settings.platform        = text(c.platform);
    settings.accept_language = text(c.accept_language);
    settings.decode          = decode_options(c.limits, resource.get());
    if (c.max_error_body != 0)
        settings.max_error_body = c.max_error_body;
    settings.random       = c.random;
    settings.clock        = c.clock;
    settings.trust        = c.trust == nullptr ? nullptr : &c.trust->trust;
    settings.deprecations = c.deprecations;
    auto made             = lantern::Client::create(*c.transport->impl, settings);
    if (!made)
        return fail(error, made.error());
    *out = box_new<lantern_client>(resource.get(), resource.get(), std::move(*made));
    return ok(error);
}

LANTERN_API void lantern_client_free(lantern_client* client)
{
    unbox(client);
}

LANTERN_API lantern_status lantern_client_handshake(
    lantern_client* client, lantern_handshake** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(client, client->client.handshake(), out, error);
}

LANTERN_API const lantern_handshake* lantern_client_server(const lantern_client* client)
{
    return client == nullptr ? nullptr : wrap(client->client.server());
}

LANTERN_API uint64_t lantern_client_offers(const lantern_client* client, lantern_family family)
{
    if (client == nullptr || family < LANTERN_FAMILY_LIBRARY || family > LANTERN_FAMILY_ENCRYPTED_SAVES)
        return 0;
    return client->client.offers(static_cast<lantern::Family>(family));
}

LANTERN_API lantern_status lantern_client_set_bearer_token(
    lantern_client* client, const char* token, lantern_error* error)
{
    if (client == nullptr)
        return usage(error, "client is NULL");
    return done(client->client.set_bearer_token(text(token)), error);
}

LANTERN_API lantern_status lantern_client_set_credentials(
    lantern_client* client, const char* token, const lantern_device_key* key, lantern_error* error)
{
    if (client == nullptr || key == nullptr)
        return usage(error, "a NULL argument");
    return done(
        client->client.set_credentials(text(token), *reinterpret_cast<const lantern::DeviceKey*>(key)),
        error);
}

LANTERN_API void lantern_client_clear_token(lantern_client* client)
{
    if (client != nullptr)
        client->client.clear_bearer_token();
}

LANTERN_API bool lantern_client_has_token(const lantern_client* client)
{
    return client != nullptr && client->client.has_token();
}

LANTERN_API const lantern_device_key* lantern_client_device_key(const lantern_client* client)
{
    if (client == nullptr)
        return nullptr;
    return reinterpret_cast<const lantern_device_key*>(client->client.device_key());
}

LANTERN_API int64_t lantern_client_clock_offset(const lantern_client* client)
{
    return client == nullptr ? 0 : client->client.clock_offset();
}

LANTERN_API lantern_status lantern_client_sign_in(
    lantern_client* client, lantern_credential_store* store, bool* signed_in, lantern_error* error)
{
    if (client == nullptr || store == nullptr || signed_in == nullptr)
        return usage(error, "a NULL argument");
    *signed_in      = false;
    const auto done = client->client.sign_in(*store);
    if (!done)
        return fail(error, done.error());
    *signed_in = *done;
    return ok(error);
}

LANTERN_API lantern_status lantern_client_forget(
    lantern_client* client, lantern_credential_store* store, lantern_error* error)
{
    if (client == nullptr || store == nullptr)
        return usage(error, "a NULL argument");
    return done(client->client.forget(*store), error);
}

LANTERN_API lantern_status lantern_client_start_pairing(lantern_client* client,
    const lantern_pairing_options* options, lantern_pairing** out, lantern_error* error)
{
    if (client == nullptr || options == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                            = nullptr;
    const lantern_pairing_options o = copy_struct(options);
    const lantern::Allocator allocator(resource_of(client));
    const auto scopes = views(o.scopes, o.scope_count, allocator);
    lantern::PairingOptions settings;
    settings.device     = text(o.device);
    settings.scopes     = scopes;
    settings.invitation = text(o.invitation);
    settings.bind_key   = !o.bearer_only;
    auto pairing        = client->client.start_pairing(settings);
    if (!pairing)
        return fail(error, pairing.error());
    *out = box_new<lantern_pairing>(resource_of(client), std::move(*pairing));
    return ok(error);
}

LANTERN_API void lantern_pairing_free(lantern_pairing* pairing)
{
    unbox(pairing);
}

LANTERN_API const lantern_pairing_code* lantern_pairing_get_code(const lantern_pairing* pairing)
{
    return pairing == nullptr ? nullptr : wrap(&as_pairing(pairing)->code);
}

LANTERN_API uint32_t lantern_pairing_get_wait(const lantern_pairing* pairing)
{
    return pairing == nullptr ? 0 : as_pairing(pairing)->wait;
}

LANTERN_API lantern_str lantern_pairing_get_fingerprint(const lantern_pairing* pairing)
{
    if (pairing == nullptr || !as_pairing(pairing)->spki)
        return empty_str();
    return { pairing->fingerprint.data(), std::strlen(pairing->fingerprint.data()) };
}

LANTERN_API bool lantern_pairing_get_spki(const lantern_pairing* pairing, uint8_t out[32])
{
    if (pairing == nullptr || out == nullptr)
        return false;
    const std::optional<lantern::Digest>& spki = as_pairing(pairing)->spki;
    if (!spki)
        return false;
    copy_digest(*spki, out);
    return true;
}

LANTERN_API const lantern_device_key* lantern_pairing_get_key(const lantern_pairing* pairing)
{
    if (pairing == nullptr)
        return nullptr;
    const std::optional<lantern::DeviceKey>& key = as_pairing(pairing)->key;
    return key ? reinterpret_cast<const lantern_device_key*>(&*key) : nullptr;
}

LANTERN_API lantern_status lantern_client_poll_pairing(lantern_client* client, lantern_pairing* pairing,
    lantern_credential_store* store, lantern_poll_state* state, lantern_error* error)
{
    if (client == nullptr || pairing == nullptr || state == nullptr)
        return usage(error, "a NULL argument");
    const auto polled = client->client.poll_pairing(*as_pairing(pairing), store);
    if (!polled)
        return fail(error, polled.error());
    *state = *polled == lantern::PollState::paired ? LANTERN_POLL_PAIRED : LANTERN_POLL_WAITING;
    return ok(error);
}

LANTERN_API lantern_status lantern_client_apps(
    lantern_client* client, const lantern_apps_query* query, lantern_apps_page** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                       = nullptr;
    const lantern_apps_query q = copy_struct(query);
    lantern::AppsQuery settings;
    settings.platform  = text(q.platform);
    settings.type      = text(q.type);
    settings.title_id  = text(q.title_id);
    settings.q         = text(q.q);
    settings.sort      = text(q.sort);
    settings.page_size = page_size(q.page_size);
    settings.cursor    = text(q.cursor);
    return give(client, client->client.apps(settings), out, error);
}

LANTERN_API lantern_status lantern_client_missing(lantern_client* client,
    const lantern_missing_request* request, const char* cursor, const char* platform, lantern_apps_page** out,
    lantern_error* error)
{
    if (client == nullptr || request == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                            = nullptr;
    const lantern_missing_request r = copy_struct(request);
    if ((r.installed == nullptr && r.installed_count != 0) || (r.want == nullptr && r.want_count != 0))
        return usage(error, "a NULL array with items");
    lantern::MissingRequest settings(lantern::Allocator(resource_of(client)));
    settings.installed.reserve(r.installed_count);
    for (std::size_t i = 0; i < r.installed_count; ++i)
    {
        settings.installed.emplace_back();
        settings.installed.back().app_id       = text(r.installed[i].app_id);
        settings.installed.back().version_code = r.installed[i].version_code;
    }
    strings(settings.want, r.want, r.want_count);
    return give(client, client->client.missing(settings, text(cursor), text(platform)), out, error);
}

LANTERN_API lantern_status lantern_client_changes(
    lantern_client* client, const char* since, lantern_changes** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(client, client->client.changes(text(since)), out, error);
}

LANTERN_API lantern_status lantern_client_sections(
    lantern_client* client, lantern_sections** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(client, client->client.sections(), out, error);
}

LANTERN_API lantern_status lantern_client_title(
    lantern_client* client, const char* title_id, lantern_title** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(client, client->client.title(text(title_id)), out, error);
}

LANTERN_API lantern_status lantern_client_titles(
    lantern_client* client, const char* const* ids, size_t count, lantern_titles** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr || (ids == nullptr && count != 0))
        return usage(error, "a NULL argument");
    *out              = nullptr;
    const auto listed = views(ids, count, lantern::Allocator(resource_of(client)));
    return give(client, client->client.titles(listed), out, error);
}

LANTERN_API lantern_status lantern_client_title_changes(
    lantern_client* client, const char* since, lantern_title_changes** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(client, client->client.title_changes(text(since)), out, error);
}

LANTERN_API lantern_status lantern_client_download(lantern_client* client,
    const lantern_download_target* target, lantern_download_state* state, lantern_download_sink* sink,
    lantern_error* error)
{
    if (client == nullptr || target == nullptr || state == nullptr || sink == nullptr)
        return usage(error, "a NULL argument");
    return done(client->client.download(target_of(copy_struct(target)), state->state, *sink->impl), error);
}

LANTERN_API lantern_status lantern_client_homebrew(lantern_client* client,
    const lantern_homebrew_query* query, lantern_homebrew_page** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                           = nullptr;
    const lantern_homebrew_query q = copy_struct(query);
    lantern::HomebrewQuery settings;
    settings.platform  = text(q.platform);
    settings.q         = text(q.q);
    settings.kind      = text(q.kind);
    settings.genre     = text(q.genre);
    settings.page_size = page_size(q.page_size);
    settings.cursor    = text(q.cursor);
    return give(client, client->client.homebrew(settings), out, error);
}

LANTERN_API lantern_status lantern_client_homebrew_entry(
    lantern_client* client, const char* id, lantern_homebrew** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(client, client->client.homebrew_entry(text(id)), out, error);
}

LANTERN_API lantern_status lantern_client_homebrew_updates(lantern_client* client,
    const lantern_homebrew_updates_request* request, const char* cursor, const char* platform,
    lantern_homebrew_page** out, lantern_error* error)
{
    if (client == nullptr || request == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                                     = nullptr;
    const lantern_homebrew_updates_request r = copy_struct(request);
    if (r.installed == nullptr && r.installed_count != 0)
        return usage(error, "a NULL array with items");
    lantern::HomebrewUpdatesRequest settings(lantern::Allocator(resource_of(client)));
    settings.installed.reserve(r.installed_count);
    for (std::size_t i = 0; i < r.installed_count; ++i)
    {
        settings.installed.emplace_back();
        settings.installed.back().id    = text(r.installed[i].id);
        settings.installed.back().build = r.installed[i].build;
    }
    return give(client, client->client.homebrew_updates(settings, text(cursor), text(platform)), out, error);
}

LANTERN_API lantern_status lantern_client_cheats(
    lantern_client* client, const lantern_cheats_query* query, lantern_cheat_sets** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                         = nullptr;
    const lantern_cheats_query q = copy_struct(query);
    lantern::CheatsQuery settings;
    settings.platform = text(q.platform);
    settings.title_id = text(q.title_id);
    settings.build_id = text(q.build_id);
    return give(client, client->client.cheats(settings), out, error);
}

LANTERN_API lantern_status lantern_client_cheat_text(
    lantern_client* client, const lantern_cheat_set* set, lantern_string** out, lantern_error* error)
{
    if (client == nullptr || set == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out      = nullptr;
    auto read = client->client.cheat_text(*as(set));
    if (!read)
        return fail(error, read.error());
    *out = give_string(resource_of(client), std::move(*read));
    return ok(error);
}

LANTERN_API lantern_status lantern_client_create_cheat_set(
    lantern_client* client, const lantern_cheat_write* set, lantern_cheat_set** out, lantern_error* error)
{
    if (client == nullptr || set == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                            = nullptr;
    const lantern::CheatWrite write = cheat_write(copy_struct(set), lantern::Allocator(resource_of(client)));
    return give(client, client->client.create_cheat_set(write), out, error);
}

LANTERN_API lantern_status lantern_client_replace_cheat_set(
    lantern_client* client, const char* id, const lantern_cheat_write* set, lantern_error* error)
{
    if (client == nullptr || set == nullptr)
        return usage(error, "a NULL argument");
    const lantern::CheatWrite write = cheat_write(copy_struct(set), lantern::Allocator(resource_of(client)));
    return done(client->client.replace_cheat_set(text(id), write), error);
}

LANTERN_API lantern_status lantern_client_delete_cheat_set(
    lantern_client* client, const char* id, lantern_error* error)
{
    if (client == nullptr)
        return usage(error, "client is NULL");
    return done(client->client.delete_cheat_set(text(id)), error);
}

LANTERN_API lantern_status lantern_client_saves(lantern_client* client, const char* title_id,
    const char* platform, lantern_saves** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(client, client->client.saves(text(title_id), text(platform)), out, error);
}

LANTERN_API lantern_status lantern_client_download_save(lantern_client* client, const lantern_save* save,
    lantern_download_state* state, lantern_download_sink* sink, lantern_error* error)
{
    if (client == nullptr || save == nullptr || state == nullptr || sink == nullptr)
        return usage(error, "a NULL argument");
    return done(client->client.download_save(*as(save), state->state, *sink->impl), error);
}

LANTERN_API lantern_status lantern_client_delete_save(
    lantern_client* client, const lantern_save* save, lantern_error* error)
{
    if (client == nullptr || save == nullptr)
        return usage(error, "a NULL argument");
    return done(client->client.delete_save(*as(save)), error);
}

LANTERN_API lantern_status lantern_client_upload_save(lantern_client* client, const char* title_id,
    const uint8_t* archive, size_t size, const lantern_save_info* info, lantern_save** out,
    lantern_error* error)
{
    if (client == nullptr || out == nullptr || (archive == nullptr && size != 0))
        return usage(error, "a NULL argument");
    *out                      = nullptr;
    const lantern_save_info i = copy_struct(info);
    lantern::SaveInfo settings;
    settings.platform = text(i.platform);
    settings.kind     = text(i.kind);
    settings.slot     = text(i.slot);
    if (i.has_game_version_code)
        settings.game_version_code = i.game_version_code;
    settings.profile           = text(i.profile);
    settings.note              = text(i.note);
    settings.encryption_key_id = text(i.encryption_key_id);
    return give(client,
        client->client.upload_save(
            text(title_id), std::as_bytes(std::span(archive, archive == nullptr ? 0 : size)), settings),
        out, error);
}

LANTERN_API lantern_status lantern_client_open_upload(lantern_client* client, const char* title_id,
    const lantern_upload_request* request, const char* platform, lantern_upload_session** out,
    lantern_error* error)
{
    if (client == nullptr || request == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    const lantern::UploadRequest settings
        = upload_request(copy_struct(request), lantern::Allocator(resource_of(client)));
    return give(client, client->client.open_upload(text(title_id), settings, text(platform)), out, error);
}

LANTERN_API lantern_status lantern_client_upload_offset(
    lantern_client* client, const char* upload, uint64_t* offset, lantern_error* error)
{
    if (client == nullptr || offset == nullptr)
        return usage(error, "a NULL argument");
    const auto read = client->client.upload_offset(text(upload));
    if (!read)
        return fail(error, read.error());
    *offset = *read;
    return ok(error);
}

LANTERN_API lantern_status lantern_client_upload_chunk(lantern_client* client, const char* upload,
    uint64_t offset, const uint8_t* chunk, size_t size, uint64_t* new_offset, lantern_save** save,
    lantern_error* error)
{
    if (client == nullptr || new_offset == nullptr || save == nullptr || (chunk == nullptr && size != 0))
        return usage(error, "a NULL argument");
    *save     = nullptr;
    auto sent = client->client.upload_chunk(
        text(upload), offset, std::as_bytes(std::span(chunk, chunk == nullptr ? 0 : size)));
    if (!sent)
        return fail(error, sent.error());
    *new_offset = sent->offset;
    if (sent->save)
        *save = wrap_mutable(box_new<lantern::Save>(resource_of(client), std::move(*sent->save)));
    return ok(error);
}

LANTERN_API lantern_status lantern_client_abandon_upload(
    lantern_client* client, const char* upload, lantern_error* error)
{
    if (client == nullptr)
        return usage(error, "client is NULL");
    return done(client->client.abandon_upload(text(upload)), error);
}

LANTERN_API lantern_status lantern_client_upload_resumable(lantern_client* client, const char* title_id,
    const lantern_upload_request* request, lantern_upload_source* source, lantern_upload_progress* progress,
    size_t max_chunk, const char* platform, lantern_save** out, lantern_error* error)
{
    if (client == nullptr || request == nullptr || source == nullptr || progress == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    const lantern::UploadRequest settings
        = upload_request(copy_struct(request), lantern::Allocator(resource_of(client)));
    return give(client,
        client->client.upload_resumable(text(title_id), settings, *source->impl, progress->progress,
            max_chunk == 0 ? std::size_t { 1024 } * 1024 : max_chunk, text(platform)),
        out, error);
}

LANTERN_API lantern_status lantern_client_requests(
    lantern_client* client, const char* platform, lantern_title_requests** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(client, client->client.requests(text(platform)), out, error);
}

LANTERN_API lantern_status lantern_client_request_title(lantern_client* client,
    const lantern_request_create* request, lantern_title_request** out, lantern_error* error)
{
    if (client == nullptr || request == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                           = nullptr;
    const lantern_request_create r = copy_struct(request);
    lantern::RequestCreate settings(lantern::Allocator(resource_of(client)));
    settings.platform = text(r.platform);
    settings.title_id = text(r.title_id);
    return give(client, client->client.request_title(settings), out, error);
}

LANTERN_API lantern_status lantern_client_withdraw_request(
    lantern_client* client, const char* id, lantern_error* error)
{
    if (client == nullptr)
        return usage(error, "client is NULL");
    return done(client->client.withdraw_request(text(id)), error);
}

LANTERN_API lantern_status lantern_client_admin_users(
    lantern_client* client, const lantern_page_query* page, lantern_admin_users** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(client, client->client.admin_users(page_query(page)), out, error);
}

LANTERN_API lantern_status lantern_client_admin_create_user(lantern_client* client,
    const lantern_admin_user_create* user, lantern_admin_user** out, lantern_error* error)
{
    if (client == nullptr || user == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                              = nullptr;
    const lantern_admin_user_create u = copy_struct(user);
    lantern::AdminUserCreate settings(lantern::Allocator(resource_of(client)));
    settings.name = text(u.name);
    strings(settings.scopes, u.scopes, u.scope_count);
    settings.state = text(u.state);
    return give(client, client->client.admin_create_user(settings), out, error);
}

LANTERN_API lantern_status lantern_client_admin_update_user(lantern_client* client, const char* name,
    const lantern_admin_user_update* change, lantern_admin_user** out, lantern_error* error)
{
    if (client == nullptr || change == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                              = nullptr;
    const lantern_admin_user_update u = copy_struct(change);
    lantern::AdminUserUpdate settings(lantern::Allocator(resource_of(client)));
    settings.state = text(u.state);
    strings(settings.scopes, u.scopes, u.scope_count);
    return give(client, client->client.admin_update_user(text(name), settings), out, error);
}

LANTERN_API lantern_status lantern_client_admin_devices(lantern_client* client, const char* user,
    const lantern_page_query* page, lantern_admin_devices** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(client, client->client.admin_devices(text(user), page_query(page)), out, error);
}

LANTERN_API lantern_status lantern_client_admin_revoke_device(
    lantern_client* client, const char* id, lantern_error* error)
{
    if (client == nullptr)
        return usage(error, "client is NULL");
    return done(client->client.admin_revoke_device(text(id)), error);
}

LANTERN_API lantern_status lantern_client_admin_pairings(lantern_client* client,
    const lantern_page_query* page, lantern_admin_pairings** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(client, client->client.admin_pairings(page_query(page)), out, error);
}

LANTERN_API lantern_status lantern_client_admin_decide_pairing(lantern_client* client, const char* id,
    const lantern_admin_pairing_decision* decision, lantern_error* error)
{
    if (client == nullptr || decision == nullptr)
        return usage(error, "a NULL argument");
    const lantern_admin_pairing_decision d = copy_struct(decision);
    const lantern::Allocator allocator(resource_of(client));
    lantern::AdminPairingDecision settings(allocator);
    settings.decision = text(d.decision);
    settings.user     = text(d.user);
    strings(settings.scopes, d.scopes, d.scope_count);
    settings.rating_cap = rating_cap(d.rating_cap, allocator);
    return done(client->client.admin_decide_pairing(text(id), settings), error);
}

LANTERN_API lantern_status lantern_client_admin_invitations(
    lantern_client* client, const lantern_page_query* page, lantern_invitations** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give(client, client->client.admin_invitations(page_query(page)), out, error);
}

LANTERN_API lantern_status lantern_client_admin_create_invitation(lantern_client* client,
    const lantern_invitation_create* invitation, lantern_invitation** out, lantern_error* error)
{
    if (client == nullptr || invitation == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                              = nullptr;
    const lantern_invitation_create i = copy_struct(invitation);
    const lantern::Allocator allocator(resource_of(client));
    lantern::InvitationCreate settings(allocator);
    settings.user = text(i.user);
    strings(settings.scopes, i.scopes, i.scope_count);
    settings.expires    = text(i.expires);
    settings.devices    = i.devices;
    settings.rating_cap = rating_cap(i.rating_cap, allocator);
    settings.note       = text(i.note);
    return give(client, client->client.admin_create_invitation(settings), out, error);
}

LANTERN_API lantern_status lantern_client_admin_revoke_invitation(
    lantern_client* client, const char* id, lantern_error* error)
{
    if (client == nullptr)
        return usage(error, "client is NULL");
    return done(client->client.admin_revoke_invitation(text(id)), error);
}

LANTERN_API lantern_status lantern_client_admin_delete_user(
    lantern_client* client, const char* name, const char* confirm, lantern_error* error)
{
    if (client == nullptr)
        return usage(error, "client is NULL");
    return done(client->client.admin_delete_user(text(name), text(confirm)), error);
}

} // extern "C"
// NOLINTEND(readability-identifier-naming,misc-use-internal-linkage)
