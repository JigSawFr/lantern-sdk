// The administration API (SPEC.md § 5.7), scope admin: accounts, devices,
// pairings waiting and invitations (§ 5.5).
#include <lantern/client.hpp>

#include "client_internal.hpp"

namespace lantern
{

using detail::add_query;
using detail::append_segment;
using detail::bytes_of;

namespace
{

void add_page(String& url, bool& first, const PageQuery& page)
{
    add_query(url, first, "page_size", page.page_size);
    add_query(url, first, "cursor", page.cursor);
}

} // namespace

Read<AdminUsers> Client::admin_users(const PageQuery& page)
{
    if (auto ok = ready(Family::admin); !ok)
        return std::unexpected(ok.error());
    auto url   = api_url("/admin/users");
    bool first = true;
    add_page(*url, first, page);
    return read<AdminUsers>(Method::get, *url, read_admin_users);
}

Read<AdminUser> Client::admin_create_user(const AdminUserCreate& user)
{
    if (auto ok = ready(Family::admin); !ok)
        return std::unexpected(ok.error());
    auto url = api_url("/admin/users");
    String body(allocator_);
    write_admin_user_create(user, body);
    return read<AdminUser>(Method::post, *url, read_admin_user, body);
}

Read<AdminUser> Client::admin_update_user(std::string_view name, const AdminUserUpdate& change)
{
    if (auto ok = ready(Family::admin); !ok)
        return std::unexpected(ok.error());
    if (change.state.empty() && change.scopes.empty())
        return fail(
            Category::usage, "an account's change gives its state, its scopes, or both (SPEC.md 5.7)");
    auto url = api_url("/admin/users/");
    if (auto added = append_segment(*url, name); !added)
        return std::unexpected(added.error());
    String body(allocator_);
    write_admin_user_update(change, body);
    return read<AdminUser>(Method::patch, *url, read_admin_user, body);
}

Read<AdminDevices> Client::admin_devices(std::string_view user, const PageQuery& page)
{
    if (auto ok = ready(Family::admin); !ok)
        return std::unexpected(ok.error());
    auto url   = api_url("/admin/devices");
    bool first = true;
    add_query(*url, first, "user", user);
    add_page(*url, first, page);
    return read<AdminDevices>(Method::get, *url, read_admin_devices);
}

Result<void> Client::admin_revoke_device(std::string_view id)
{
    if (auto ok = ready(Family::admin); !ok)
        return std::unexpected(ok.error());
    auto url = api_url("/admin/devices/");
    if (auto added = append_segment(*url, id); !added)
        return added;
    Call call;
    call.method = Method::delete_;
    call.url    = *url;
    if (auto done = expect(call); !done)
        return std::unexpected(done.error());
    return {};
}

Read<AdminPairings> Client::admin_pairings(const PageQuery& page)
{
    if (auto ok = ready(Family::admin); !ok)
        return std::unexpected(ok.error());
    auto url   = api_url("/admin/pairings");
    bool first = true;
    add_page(*url, first, page);
    return read<AdminPairings>(Method::get, *url, read_admin_pairings);
}

Result<void> Client::admin_decide_pairing(std::string_view id, const AdminPairingDecision& decision)
{
    if (auto ok = ready(Family::admin); !ok)
        return std::unexpected(ok.error());
    if (decision.decision != "approve" && decision.decision != "refuse")
        return fail(Category::usage, "a decision is approve or refuse (SPEC.md 5.7)");
    auto url = api_url("/admin/pairings/");
    if (auto added = append_segment(*url, id); !added)
        return added;
    String body(allocator_);
    write_admin_pairing_decision(decision, body);
    Call call;
    call.method = Method::post;
    call.url    = *url;
    call.body   = bytes_of(body);
    if (auto done = expect(call); !done)
        return std::unexpected(done.error());
    return {};
}

Read<Invitations> Client::admin_invitations(const PageQuery& page)
{
    if (auto ok = ready(Family::admin); !ok)
        return std::unexpected(ok.error());
    auto url   = api_url("/admin/invitations");
    bool first = true;
    add_page(*url, first, page);
    return read<Invitations>(Method::get, *url, read_invitations);
}

Read<Invitation> Client::admin_create_invitation(const InvitationCreate& invitation)
{
    if (auto ok = ready(Family::admin); !ok)
        return std::unexpected(ok.error());
    if (invitation.devices == 0 || invitation.devices > 100)
        return fail(Category::usage, "an invitation is for 1 to 100 devices (SPEC.md 5.5)");
    auto url = api_url("/admin/invitations");
    String body(allocator_);
    write_invitation_create(invitation, body);
    return read<Invitation>(Method::post, *url, read_invitation, body);
}

Result<void> Client::admin_revoke_invitation(std::string_view id)
{
    if (auto ok = ready(Family::admin); !ok)
        return std::unexpected(ok.error());
    auto url = api_url("/admin/invitations/");
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
