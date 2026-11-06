// The administration API (SPEC.md § 5.7), for the scope `admin`: the accounts,
// the devices, the pairings waiting and the invitations (§ 5.5); the requests
// of every account are in server_requests.cpp. No document of this family
// holds a token, the hash of one, a password or its hash (L-5.7-2).
#include <algorithm>
#include <array>

#include <lantern/accounts.hpp>
#include <lantern/document.hpp>
#include <lantern/encoding.hpp>
#include <lantern/hkdf.hpp>
#include <lantern/requests.hpp>
#include <lantern/saves.hpp>
#include <lantern/tls.hpp>

#include "server_internal.hpp"

namespace lantern
{

namespace
{

using detail::Answer;
using detail::Caller;
using detail::ProblemError;
using detail::ServerState;

// The alphabet of a pairing code (§ 5.2), which an invitation's code is made of (§ 5.5).
constexpr std::string_view code_alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
constexpr std::size_t code_symbols       = 16; // 80 bits
constexpr std::size_t id_bytes           = 9;
// An invitation lives 30 days at most; 1000 may wait at once; its note is 120 bytes.
constexpr std::int64_t invitation_seconds = std::int64_t { 30 } * 86400;
constexpr std::size_t invitations_limit   = 1000;
constexpr std::size_t note_limit          = 120;

bool has_control(std::string_view text) noexcept
{
    return std::ranges::any_of(text,
        [](char c)
        {
            const auto byte = static_cast<unsigned char>(c);
            return byte < 0x20 || byte == 0x7f;
        });
}

// The sort key of a document listed by its id alone.
detail::SortKey key_of(std::int64_t major, std::string_view id, const Allocator& allocator)
{
    detail::SortKey key(allocator);
    key.major = major;
    key.id.assign(id);
    return key;
}

// A page of `count` documents with the keys `keys`: `write` writes the object of one, by its index.
template <typename Write>
Answer page_of(const ServerState& state, const ServerRequest& request, std::span<const detail::SortKey> keys,
    std::string_view scope, Write write)
{
    const auto window = detail::page_window(state, request, keys, scope);
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
        write(w, window->order[i]);
        w.end_object();
    }
    w.end_array();
    w.key("total");
    w.number(static_cast<std::uint64_t>(keys.size()));
    w.key("next");
    if (window->next.empty())
        w.null();
    else
        w.string(window->next);
    w.end_object();
    return detail::json_response(state, request, std::move(out));
}

void write_scopes(json::Writer& w, const Vector<String>& scopes)
{
    w.key("scopes");
    w.begin_array();
    for (const String& scope : scopes)
        w.string(scope);
    w.end_array();
}

// An account as listed (§ 5.7), in an object the caller has opened.
void write_user_members(
    json::Writer& w, const StoredAccount& account, std::uint64_t devices, const Allocator& allocator)
{
    w.key("name");
    w.string(account.name);
    w.key("state");
    w.string(account.frozen ? "frozen" : "active");
    write_scopes(w, account.scopes);
    w.key("devices");
    w.number(devices);
    w.key("created");
    w.string(detail::utc_text(account.created, allocator));
}

// The live devices of an account, counted.
std::expected<std::uint64_t, ProblemError> count_devices(
    const ServerState& state, std::string_view user, std::int64_t now)
{
    auto devices = state.accounts->all_devices(user, now, state.allocator);
    if (!devices)
        return std::unexpected(detail::internal_error(state));
    return static_cast<std::uint64_t>(devices->size());
}

Answer user_answer(const ServerState& state, const ServerRequest& request, const StoredAccount& account,
    std::uint16_t status)
{
    const auto devices = count_devices(state, account.name, state.clock->unix_seconds());
    if (!devices)
        return std::unexpected(devices.error());
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    write_user_members(w, account, *devices, state.allocator);
    w.end_object();
    return detail::json_response(state, request, std::move(out), status, false);
}

// Scopes given by an admin: known ones, each once; 400 otherwise. Ordered as § 4.2 does.
std::expected<Vector<String>, ProblemError> checked_scopes(
    const ServerState& state, const Vector<String>& given, std::string_view what)
{
    for (std::size_t i = 0; i < given.size(); ++i)
    {
        bool repeated = false;
        for (std::size_t j = 0; j < i; ++j)
            repeated = repeated || given[i] == given[j];
        if (!is_known_scope(given[i]) || repeated)
        {
            String why(what, state.allocator);
            why.append(
                " is a list of scopes: library, saves, cheats, cheats.write, requests, admin, sync.read, "
                "sync.write.");
            return std::unexpected(detail::bad_request(state, why));
        }
    }
    Vector<std::string_view> views(state.allocator);
    for (const String& scope : given)
        views.emplace_back(scope);
    return ordered_scopes(views, state.allocator);
}

Answer users_route(const ServerState& state, const ServerRequest& request)
{
    const std::int64_t now = state.clock->unix_seconds();
    if (request.method != "POST")
    {
        auto accounts = state.accounts->accounts(state.allocator);
        if (!accounts)
            return std::unexpected(detail::internal_error(state));
        auto devices = state.accounts->all_devices({}, now, state.allocator);
        if (!devices)
            return std::unexpected(detail::internal_error(state));
        Vector<detail::SortKey> keys(state.allocator);
        for (const StoredAccount& account : *accounts)
            keys.push_back(key_of(0, account.name, state.allocator));
        const std::array<std::string_view, 1> parts { "admin-users" };
        return page_of(state, request, keys, detail::scope_of(parts, state.allocator),
            [&](json::Writer& w, std::size_t i)
            {
                const StoredAccount& account = (*accounts)[i];
                const auto held              = std::ranges::count_if(
                    *devices, [&](const PairedDevice& device) { return device.user == account.name; });
                write_user_members(w, account, static_cast<std::uint64_t>(held), state.allocator);
            });
    }
    const auto prepared = detail::request_document(state, request);
    if (!prepared)
        return std::unexpected(prepared.error());
    auto bound = read_document<AdminUserCreate>(prepared->text, known_schema, prepared->options,
        [](BindContext& c, AdminUserCreate& value) { return bind(c, value); });
    if (!bound || !*bound)
        return std::unexpected(detail::bad_request(state, "An account is {schema, name, scopes, state?}."));
    const AdminUserCreate& doc = **bound;
    if (!is_account_name(doc.name) || (!doc.state.empty() && doc.state != "active" && doc.state != "frozen"))
        return std::unexpected(detail::bad_request(
            state, "name is 1 to 64 letters, digits, '.', '_' and '-'; state is active or frozen."));
    auto scopes = checked_scopes(state, doc.scopes, "scopes");
    if (!scopes)
        return std::unexpected(std::move(scopes.error()));
    StoredAccount account(state.allocator);
    account.name    = doc.name;
    account.scopes  = std::move(*scopes);
    account.frozen  = doc.state == "frozen";
    account.created = now;
    const auto made = state.accounts->create_account(account);
    if (!made)
        return std::unexpected(detail::internal_error(state));
    if (!*made)
        return std::unexpected(
            detail::make_problem(state, 409, Code::conflict, "An account of that name exists already."));
    return user_answer(state, request, account, 201);
}

Answer user_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view name)
{
    if (request.method == "DELETE")
    {
        const auto found = state.accounts->account(name, state.allocator);
        if (!found)
            return std::unexpected(detail::internal_error(state));
        if (!*found)
            return std::unexpected(detail::not_found(state, "No such account."));
        if (request.param("confirm").value_or(std::string_view {}) != name)
            return std::unexpected(detail::bad_request(
                state, "confirm repeats the account's name: ?confirm=<name> (SPEC.md § 5.7)."));
        if (name == caller.name)
            return std::unexpected(detail::make_problem(
                state, 409, Code::conflict, "An admin does not delete the account they use."));
        const auto deleted = state.accounts->delete_account(name);
        if (!deleted)
            return std::unexpected(detail::internal_error(state));
        if (!*deleted)
            return std::unexpected(detail::not_found(state, "No such account."));
        // Its save backups, requests and sync data go with it, at once and whole (L-5.7-7, L-20.5-3)
        if (state.saves != nullptr)
        {
            const std::scoped_lock lock(state.saves_mutex);
            if (auto erased = state.saves->forget(name); !erased)
                return std::unexpected(detail::internal_error(state));
        }
        if (state.requests != nullptr)
        {
            const std::scoped_lock lock(state.requests_mutex);
            if (auto erased = state.requests->forget(name); !erased)
                return std::unexpected(detail::internal_error(state));
        }
        if (auto erased = detail::forget_sync(state, name); !erased)
            return std::unexpected(detail::internal_error(state));
        return detail::no_content(state, request);
    }
    const auto prepared = detail::request_document(state, request);
    if (!prepared)
        return std::unexpected(prepared.error());
    auto bound = read_document<AdminUserUpdate>(prepared->text, known_schema, prepared->options,
        [](BindContext& c, AdminUserUpdate& value) { return bind(c, value); });
    if (!bound || !*bound)
        return std::unexpected(detail::bad_request(state, "A change is {schema, state?, scopes?}."));
    const AdminUserUpdate& doc = **bound;
    if (doc.state.empty() && !doc.scopes)
        return std::unexpected(detail::bad_request(state, "Give state (active or frozen), scopes, or both."));
    if (!doc.state.empty() && doc.state != "active" && doc.state != "frozen")
        return std::unexpected(detail::bad_request(state, "state is active or frozen."));
    std::optional<Vector<String>> scopes;
    if (doc.scopes)
    {
        auto checked = checked_scopes(state, *doc.scopes, "scopes");
        if (!checked)
            return std::unexpected(std::move(checked.error()));
        scopes = std::move(*checked);
    }
    std::optional<bool> frozen;
    if (!doc.state.empty())
        frozen = doc.state == "frozen";
    const Vector<String>* given = scopes ? &*scopes : nullptr;
    const auto changed          = state.accounts->change_account(name, frozen, given);
    if (!changed)
        return std::unexpected(detail::internal_error(state));
    if (!*changed)
        return std::unexpected(detail::not_found(state, "No such account."));
    const auto found = state.accounts->account(name, state.allocator);
    if (!found)
        return std::unexpected(detail::internal_error(state));
    if (!*found)
        return std::unexpected(detail::not_found(state, "No such account."));
    return user_answer(state, request, **found, 200);
}

// A device as the administration API shows it: never its token, nor the token's hash.
Answer devices_route(const ServerState& state, const ServerRequest& request)
{
    const std::string_view user = request.param("user").value_or(std::string_view {});
    auto devices = state.accounts->all_devices(user, state.clock->unix_seconds(), state.allocator);
    if (!devices)
        return std::unexpected(detail::internal_error(state));
    Vector<detail::SortKey> keys(state.allocator);
    for (const PairedDevice& device : *devices)
        keys.push_back(key_of(device.created, device.id, state.allocator));
    const std::array<std::string_view, 2> parts { "admin-devices", user };
    return page_of(state, request, keys, detail::scope_of(parts, state.allocator),
        [&](json::Writer& w, std::size_t i)
        {
            const PairedDevice& device = (*devices)[i];
            w.key("id");
            w.string(device.id);
            w.key("user");
            w.string(device.user);
            w.key("device");
            w.string(device.name);
            write_scopes(w, device.scopes);
            w.key("created");
            w.string(detail::utc_text(device.created, state.allocator));
            w.key("bound");
            w.boolean(device.key.has_value());
            if (device.key)
            {
                const auto shown
                    = short_form(Sha256::of(std::as_bytes(std::span<const std::uint8_t>(*device.key))));
                w.key("key");
                w.string(std::string_view(shown.data(), shown.size()));
            }
            if (device.rating_cap)
            {
                w.key("rating_cap");
                detail::write_rating_cap(w, *device.rating_cap);
            }
            if (!device.invitation.empty())
            {
                w.key("invitation");
                w.string(device.invitation);
            }
            if (device.expires)
            {
                w.key("expires");
                w.string(detail::utc_text(*device.expires, state.allocator));
            }
        });
}

Answer device_route(const ServerState& state, const ServerRequest& request, std::string_view id)
{
    const auto revoked = state.accounts->revoke_device(id);
    if (!revoked)
        return std::unexpected(detail::internal_error(state));
    if (!*revoked)
        return std::unexpected(detail::not_found(state, "No such device."));
    return detail::no_content(state, request);
}

Answer pairings_route(const ServerState& state, const ServerRequest& request)
{
    auto waiting = state.accounts->waiting_pairings(state.clock->unix_seconds(), state.allocator);
    if (!waiting)
        return std::unexpected(detail::internal_error(state));
    Vector<detail::SortKey> keys(state.allocator);
    for (const PendingPairing& entry : *waiting)
        keys.push_back(key_of(entry.created, entry.id, state.allocator));
    const std::array<std::string_view, 1> parts { "admin-pairings" };
    return page_of(state, request, keys, detail::scope_of(parts, state.allocator),
        [&](json::Writer& w, std::size_t i)
        {
            const PendingPairing& entry = (*waiting)[i];
            w.key("id");
            w.string(entry.id);
            w.key("code");
            w.string(entry.code);
            w.key("device");
            w.string(entry.device);
            write_scopes(w, entry.scopes);
            if (entry.key)
            {
                const auto shown
                    = short_form(Sha256::of(std::as_bytes(std::span<const std::uint8_t>(*entry.key))));
                w.key("key");
                w.string(std::string_view(shown.data(), shown.size()));
            }
            w.key("created");
            w.string(detail::utc_text(entry.created, state.allocator));
            w.key("expires");
            w.string(detail::utc_text(entry.expires, state.allocator));
        });
}

Answer pairing_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view id)
{
    const auto prepared = detail::request_document(state, request);
    if (!prepared)
        return std::unexpected(prepared.error());
    auto bound = read_document<AdminPairingDecision>(prepared->text, known_schema, prepared->options,
        [](BindContext& c, AdminPairingDecision& value) { return bind(c, value); });
    if (!bound || !*bound)
        return std::unexpected(
            detail::bad_request(state, "A decision is {schema, decision, user?, scopes?, rating_cap?}."));
    const AdminPairingDecision& doc = **bound;
    const std::int64_t now          = state.clock->unix_seconds();
    const auto entry                = state.accounts->pairing_by_id(id, now, state.allocator);
    if (!entry)
        return std::unexpected(detail::internal_error(state));
    if (!*entry)
        return std::unexpected(
            detail::not_found(state, "No such pairing waiting: approved, refused or expired."));
    if (doc.decision == "refuse")
    {
        // The device's poll then gives 410
        if (const auto refused = state.accounts->refuse_pairing((*entry)->poll, now); !refused)
            return std::unexpected(detail::internal_error(state));
        return detail::no_content(state, request);
    }
    if (doc.decision != "approve")
        return std::unexpected(detail::bad_request(state, "decision is approve or refuse."));
    // `user` is the admin's own account when absent (L-5.7-4)
    const std::string_view name
        = doc.user.empty() ? std::string_view(caller.name) : std::string_view(doc.user);
    const auto account = state.accounts->account(name, state.allocator);
    if (!account)
        return std::unexpected(detail::internal_error(state));
    if (!*account)
        return std::unexpected(detail::bad_request(state, "That account does not exist."));
    const auto scopes = checked_scopes(state, doc.scopes, "scopes");
    if (!scopes)
        return std::unexpected(scopes.error());
    if (doc.rating_cap)
    {
        if (const std::string_view problem = detail::cap_problem(*doc.rating_cap); !problem.empty())
            return std::unexpected(detail::bad_request(state, problem));
    }
    Vector<std::string_view> only(state.allocator);
    for (const String& scope : *scopes)
        only.emplace_back(scope);
    const auto approved = detail::approve_entry(
        state, **entry, **account, !only.empty(), only, doc.rating_cap, {}, state.allocator);
    if (!approved)
        return std::unexpected(detail::internal_error(state));
    if (!*approved)
        return std::unexpected(
            detail::not_found(state, "No such pairing waiting: approved, refused or expired."));
    return detail::no_content(state, request);
}

// An invitation as the administration API shows it, with its code and its link (§ 5.5).
std::expected<String, ProblemError> invitation_link(
    const ServerState& state, const ServerRequest& request, std::string_view code)
{
    auto link = detail::pairing_verify_url(state, request);
    if (!link)
        return std::unexpected(std::move(link.error()));
    link->append(link->contains('?') ? "&invitation=" : "?invitation=");
    link->append(code);
    if (state.spki)
    {
        const auto hex = to_hex(*state.spki);
        link->append("&spki=");
        link->append(hex.data(), hex.size());
    }
    return link;
}

void write_invitation_members(
    json::Writer& w, const StoredInvitation& item, std::string_view link, const Allocator& allocator)
{
    w.key("id");
    w.string(item.id);
    w.key("code");
    w.string(item.code);
    w.key("link");
    w.string(link);
    w.key("user");
    w.string(item.user);
    write_scopes(w, item.scopes);
    w.key("expires");
    w.string(detail::utc_text(item.expires, allocator));
    w.key("devices");
    w.number(static_cast<std::uint64_t>(item.devices));
    w.key("used");
    w.number(static_cast<std::uint64_t>(item.used));
    if (item.rating_cap)
    {
        w.key("rating_cap");
        detail::write_rating_cap(w, *item.rating_cap);
    }
    if (!item.note.empty())
    {
        w.key("note");
        w.string(item.note);
    }
    w.key("created");
    w.string(detail::utc_text(item.created, allocator));
}

Answer invitations_route(const ServerState& state, const ServerRequest& request)
{
    const std::int64_t now = state.clock->unix_seconds();
    auto kept              = state.accounts->invitations(now, state.allocator);
    if (!kept)
        return std::unexpected(detail::internal_error(state));
    if (request.method != "POST")
    {
        Vector<detail::SortKey> keys(state.allocator);
        for (const StoredInvitation& item : *kept)
            keys.push_back(key_of(item.created, item.id, state.allocator));
        Vector<String> links(state.allocator);
        for (const StoredInvitation& item : *kept)
        {
            auto link = invitation_link(state, request, item.code);
            if (!link)
                return std::unexpected(std::move(link.error()));
            links.push_back(std::move(*link));
        }
        const std::array<std::string_view, 1> parts { "admin-invitations" };
        return page_of(state, request, keys, detail::scope_of(parts, state.allocator),
            [&](json::Writer& w, std::size_t i)
            { write_invitation_members(w, (*kept)[i], links[i], state.allocator); });
    }

    const auto prepared = detail::request_document(state, request);
    if (!prepared)
        return std::unexpected(prepared.error());
    auto bound = read_document<InvitationCreate>(prepared->text, known_schema, prepared->options,
        [](BindContext& c, InvitationCreate& value) { return bind(c, value); });
    if (!bound || !*bound)
        return std::unexpected(detail::bad_request(
            state, "An invitation is {schema, user, scopes, expires, devices, rating_cap?, note?}."));
    const InvitationCreate& doc = **bound;
    const auto holder           = state.accounts->account(doc.user, state.allocator);
    if (!holder)
        return std::unexpected(detail::internal_error(state));
    if (!*holder)
        return std::unexpected(
            detail::bad_request(state, "user is the account the devices join, which exists."));
    auto scopes = checked_scopes(state, doc.scopes, "scopes");
    if (!scopes)
        return std::unexpected(std::move(scopes.error()));
    const auto held = [&](const String& scope)
    { return std::ranges::any_of((*holder)->scopes, [&](const String& item) { return item == scope; }); };
    if (scopes->empty() || !std::ranges::all_of(*scopes, held))
        return std::unexpected(
            detail::bad_request(state, "scopes are some of the account's own (SPEC.md § 5.5)."));
    const std::optional<std::int64_t> expires = detail::parse_time(doc.expires);
    if (!expires || *expires <= now || *expires > now + invitation_seconds)
        return std::unexpected(
            detail::bad_request(state, "expires is an RFC 3339 time in the next 30 days (SPEC.md § 5.5)."));
    if (doc.devices < 1 || doc.devices > 100)
        return std::unexpected(
            detail::bad_request(state, "devices is how many devices may redeem it, 1 to 100."));
    if (doc.note.size() > note_limit || has_control(doc.note))
        return std::unexpected(
            detail::bad_request(state, "note: 120 bytes at most, without control characters."));
    if (doc.rating_cap)
    {
        if (const std::string_view problem = detail::cap_problem(*doc.rating_cap); !problem.empty())
            return std::unexpected(detail::bad_request(state, problem));
    }
    if (kept->size() >= invitations_limit)
    {
        ProblemError error
            = detail::make_problem(state, 429, Code::slow_down, "At most 1000 invitations at once.");
        error.headers.set("Retry-After", "3600");
        return std::unexpected(std::move(error));
    }

    std::array<std::uint8_t, id_bytes + code_symbols> raw {};
    if (!state.random->fill(raw))
        return std::unexpected(detail::internal_error(state));
    StoredInvitation made(state.allocator);
    made.id.assign("i_");
    base64url_encode(std::span<const std::uint8_t>(raw).first(id_bytes), made.id);
    for (std::size_t i = 0; i < code_symbols; ++i)
    {
        if (i != 0 && i % 4 == 0)
            made.code.push_back('-');
        made.code.push_back(code_alphabet[raw[id_bytes + i] & 31U]);
    }
    secure_wipe(raw);
    made.user       = doc.user;
    made.scopes     = std::move(*scopes);
    made.expires    = *expires;
    made.devices    = static_cast<std::uint32_t>(doc.devices);
    made.rating_cap = doc.rating_cap;
    made.note       = doc.note;
    made.created    = now;
    if (auto added = state.accounts->add_invitation(made); !added)
        return std::unexpected(detail::internal_error(state));
    const auto link = invitation_link(state, request, made.code);
    if (!link)
        return std::unexpected(link.error());
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    write_invitation_members(w, made, *link, state.allocator);
    w.end_object();
    return detail::json_response(state, request, std::move(out), 201, false);
}

Answer invitation_route(const ServerState& state, const ServerRequest& request, std::string_view id)
{
    const auto revoked = state.accounts->revoke_invitation(id);
    if (!revoked)
        return std::unexpected(detail::internal_error(state));
    if (!*revoked)
        return std::unexpected(detail::not_found(state, "No such invitation."));
    return detail::no_content(state, request);
}

} // namespace

namespace detail
{

std::string_view admin_methods(std::string_view resource, bool has_id) noexcept
{
    if (resource == "users")
        return has_id ? "PATCH, DELETE" : "GET, HEAD, POST";
    if (resource == "devices")
        return has_id ? "DELETE" : "GET, HEAD";
    if (resource == "pairings")
        return has_id ? "POST" : "GET, HEAD";
    if (resource == "invitations")
        return has_id ? "DELETE" : "GET, HEAD, POST";
    if (resource == "requests")
        return has_id ? "POST" : "GET, HEAD";
    return {};
}

Answer admin_route(const ServerState& state, const ServerRequest& request, const Caller& caller,
    std::string_view resource, std::string_view id)
{
    const bool has_id = !id.empty();
    if (resource == "users")
        return has_id ? user_route(state, request, caller, id) : users_route(state, request);
    if (resource == "devices")
        return has_id ? device_route(state, request, id) : devices_route(state, request);
    if (resource == "pairings")
        return has_id ? pairing_route(state, request, caller, id) : pairings_route(state, request);
    if (resource == "invitations")
        return has_id ? invitation_route(state, request, id) : invitations_route(state, request);
    if (resource == "requests")
        return has_id ? admin_request_route(state, request, id) : admin_requests_route(state, request);
    return std::unexpected(not_found(state, "No such route on this server."));
}

} // namespace detail

} // namespace lantern
