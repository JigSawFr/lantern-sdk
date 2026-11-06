// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"net/url"
	"regexp"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

// The routes of SPEC.md § 5.7 and § 11, for an admin app: every one needs a token with the scope
// admin (a server answers 403 to another, 401 to none). Lists are read page after page.

var accountName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// adminList reads the pages of a list route of the admin family.
func adminList[T any, P interface {
	*T
	json.Unmarshaler
}, I any](c *Client, ctx context.Context, what, path string, q url.Values, items func(*T) ([]I, *string)) iter.Seq2[*I, error] {
	return pages(ctx, func(cursor string) ([]I, *string, error) {
		query := url.Values{}
		for k, v := range q {
			query[k] = v
		}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		page, err := getJSON[T, P](c, ctx, what, path, query)
		if err != nil {
			return nil, nil, err
		}
		list, next := items(page)
		return list, next, checkNext(next, len(list))
	})
}

// AdminUsers lists the accounts.
func (c *Client) AdminUsers(ctx context.Context) iter.Seq2[*lantern.AdminUser, error] {
	return adminList(c, ctx, "accounts", "/admin/users", nil, func(p *lantern.AdminUsers) ([]lantern.AdminUser, *string) { return p.Items, p.Next })
}

// AdminCreateUser makes an account, which has no password: its devices pair by invitation or are
// approved. A name that is taken is an error that errors.Is(err, lantern.ErrConflict).
func (c *Client) AdminCreateUser(ctx context.Context, name string, scopes []string) (*lantern.AdminUser, error) {
	if !accountName.MatchString(name) {
		return nil, fmt.Errorf("lantern: %q is not an account's name", lantern.Clip(name, 70))
	}
	if scopes == nil {
		scopes = []string{}
	}
	one := int64(1)
	resp, err := c.send(ctx, &call{method: http.MethodPost, path: "/admin/users", body: &lantern.AdminUserCreate{Schema: &one, Name: name, Scopes: scopes}, what: "account"}, lantern.MaxJSONDocument)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, "account", http.StatusCreated); err != nil {
		return nil, err
	}
	return read[lantern.AdminUser](c, "account", resp)
}

// AdminUpdateUser freezes ("frozen") or thaws ("active") an account and changes its scopes; ""
// and nil leave a field as it is.
func (c *Client) AdminUpdateUser(ctx context.Context, name, state string, scopes []string) (*lantern.AdminUser, error) {
	if !accountName.MatchString(name) {
		return nil, fmt.Errorf("lantern: %q is not an account's name", lantern.Clip(name, 70))
	}
	one := int64(1)
	body := &lantern.AdminUserUpdate{Schema: &one, Scopes: scopes}
	if state != "" {
		body.State = &state
	}
	resp, err := c.send(ctx, &call{method: http.MethodPatch, path: "/admin/users/" + url.PathEscape(name), body: body, what: "account"}, lantern.MaxJSONDocument)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, "account", http.StatusOK); err != nil {
		return nil, err
	}
	return read[lantern.AdminUser](c, "account", resp)
}

// AdminDeleteUser deletes an account, its devices, invitations, waiting pairings, save backups,
// requests and sync data, for good. confirm repeats the name, so that a slip deletes nothing: an
// admin app asks its user to type it; a confirm that is not the name is refused here, before
// anything is sent.
func (c *Client) AdminDeleteUser(ctx context.Context, name, confirm string) error {
	if !accountName.MatchString(name) {
		return fmt.Errorf("lantern: %q is not an account's name", lantern.Clip(name, 70))
	}
	if confirm != name {
		return fmt.Errorf("lantern: the confirmation is not the account's name: nothing is deleted")
	}
	q := url.Values{"confirm": {confirm}}
	return c.noContent(ctx, &call{method: http.MethodDelete, path: "/admin/users/" + url.PathEscape(name), query: q, what: "account"})
}

// AdminDevices lists the devices, one token each, of one account or of all ("").
func (c *Client) AdminDevices(ctx context.Context, user string) iter.Seq2[*lantern.AdminDevice, error] {
	q := url.Values{}
	if user != "" {
		q.Set("user", user)
	}
	return adminList(c, ctx, "devices", "/admin/devices", q, func(p *lantern.AdminDevices) ([]lantern.AdminDevice, *string) { return p.Items, p.Next })
}

// AdminRevokeDevice revokes a device's token: it loses its access on its next request.
func (c *Client) AdminRevokeDevice(ctx context.Context, id string) error {
	if !lantern.CoreIDPattern.MatchString(id) {
		return fmt.Errorf("lantern: %q is not a device's id", lantern.Clip(id, 40))
	}
	return c.noContent(ctx, &call{method: http.MethodDelete, path: "/admin/devices/" + url.PathEscape(id), what: "device"})
}

// AdminPairings lists the pairings waiting for approval. An admin app shows each one's code and the
// short fingerprint of the server's key as it pinned it (L-5.7-5): lantern.ShortFingerprint of
// Client.LastSPKI gives it.
func (c *Client) AdminPairings(ctx context.Context) iter.Seq2[*lantern.AdminPairing, error] {
	return adminList(c, ctx, "pairings", "/admin/pairings", nil, func(p *lantern.AdminPairings) ([]lantern.AdminPairing, *string) { return p.Items, p.Next })
}

// PairingDecision is the admin's answer to a waiting pairing.
type PairingDecision struct {
	Approve bool
	// User is the account the device joins ("" for the admin's own); Scopes the scopes it gets (nil
	// for those it asked for): at most those it asked for and the account holds.
	User      string
	Scopes    []string
	RatingCap *lantern.RatingCap
}

// AdminDecidePairing approves or refuses a waiting pairing (the device's poll then gets 410 when
// refused).
func (c *Client) AdminDecidePairing(ctx context.Context, id string, d PairingDecision) error {
	if !lantern.CoreIDPattern.MatchString(id) {
		return fmt.Errorf("lantern: %q is not a pairing's id", lantern.Clip(id, 40))
	}
	one := int64(1)
	body := &lantern.AdminPairingDecision{Schema: &one, Decision: "refuse"}
	if d.Approve {
		body.Decision, body.Scopes, body.RatingCap = "approve", d.Scopes, d.RatingCap
		if d.User != "" {
			if !accountName.MatchString(d.User) {
				return fmt.Errorf("lantern: %q is not an account's name", lantern.Clip(d.User, 70))
			}
			body.User = &d.User
		}
	}
	return c.noContent(ctx, &call{method: http.MethodPost, path: "/admin/pairings/" + url.PathEscape(id), body: body, what: "pairing"})
}

// AdminInvitations lists the invitations that can still be redeemed.
func (c *Client) AdminInvitations(ctx context.Context) iter.Seq2[*lantern.Invitation, error] {
	return adminList(c, ctx, "invitations", "/admin/invitations", nil, func(p *lantern.Invitations) ([]lantern.Invitation, *string) { return p.Items, p.Next })
}

// AdminCreateInvitation makes an invitation: the answer has its code and link.
func (c *Client) AdminCreateInvitation(ctx context.Context, inv lantern.InvitationCreate) (*lantern.Invitation, error) {
	if !accountName.MatchString(inv.User) {
		return nil, fmt.Errorf("lantern: %q is not an account's name", lantern.Clip(inv.User, 70))
	}
	if inv.Devices < 1 {
		return nil, fmt.Errorf("lantern: an invitation is for at least one device")
	}
	if inv.Scopes == nil {
		inv.Scopes = []string{}
	}
	one := int64(1)
	inv.Schema = &one
	resp, err := c.send(ctx, &call{method: http.MethodPost, path: "/admin/invitations", body: &inv, what: "invitation"}, lantern.MaxJSONDocument)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, "invitation", http.StatusCreated); err != nil {
		return nil, err
	}
	return read[lantern.Invitation](c, "invitation", resp)
}

// AdminRevokeInvitation revokes an invitation: its code then gives 410.
func (c *Client) AdminRevokeInvitation(ctx context.Context, id string) error {
	if !lantern.CoreIDPattern.MatchString(id) {
		return fmt.Errorf("lantern: %q is not an invitation's id", lantern.Clip(id, 40))
	}
	return c.noContent(ctx, &call{method: http.MethodDelete, path: "/admin/invitations/" + url.PathEscape(id), what: "invitation"})
}

// AdminRequestFilter filters every account's requests; each field is optional.
type AdminRequestFilter struct {
	Status   string // open, done or declined
	User     string
	Platform string
}

// AdminRequests lists every account's requests (SPEC.md § 11), newest first, each with its user.
func (c *Client) AdminRequests(ctx context.Context, f AdminRequestFilter) iter.Seq2[*lantern.TitleRequest, error] {
	q := url.Values{}
	for k, v := range map[string]string{"status": f.Status, "user": f.User, "platform": f.Platform} {
		if v != "" {
			q.Set(k, v)
		}
	}
	return adminList(c, ctx, "requests", "/admin/requests", q, func(p *lantern.AdminRequests) ([]lantern.TitleRequest, *string) { return p.Items, p.Next })
}

func (c *Client) decideRequest(ctx context.Context, id string, body *lantern.AdminRequestDecision) (*lantern.TitleRequest, error) {
	if !lantern.CoreIDPattern.MatchString(id) {
		return nil, fmt.Errorf("lantern: %q is not a request's id", lantern.Clip(id, 40))
	}
	one := int64(1)
	body.Schema = &one
	resp, err := c.send(ctx, &call{method: http.MethodPost, path: "/admin/requests/" + url.PathEscape(id), body: body, what: "request"}, lantern.MaxJSONDocument)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, "request", http.StatusOK); err != nil {
		return nil, err
	}
	return read[lantern.TitleRequest](c, "request", resp)
}

// AdminDeclineRequest declines an open request; reason (512 bytes at most, "" for none) is the
// admin's words for its requester, as written. A request no longer open is a conflict.
func (c *Client) AdminDeclineRequest(ctx context.Context, id, reason string) (*lantern.TitleRequest, error) {
	if len(reason) > 512 {
		return nil, fmt.Errorf("lantern: a reason of %d bytes, above 512", len(reason))
	}
	body := &lantern.AdminRequestDecision{Decision: "decline"}
	if reason != "" {
		body.Reason = &reason
	}
	return c.decideRequest(ctx, id, body)
}

// AdminCompleteRequest says an open request is done.
func (c *Client) AdminCompleteRequest(ctx context.Context, id string) (*lantern.TitleRequest, error) {
	return c.decideRequest(ctx, id, &lantern.AdminRequestDecision{Decision: "done"})
}
