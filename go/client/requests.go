// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

// Requests lists the account's own requests for games, newest first, of the platform named
// ("" for the client's) (SPEC.md § 11).
func (c *Client) Requests(ctx context.Context, platform string) (*lantern.TitleRequests, error) {
	q := url.Values{}
	if platform != "" {
		if !lantern.IsPlatform(platform) {
			return nil, fmt.Errorf("lantern: %q is not a platform", lantern.Clip(platform, 40))
		}
		q.Set("platform", platform)
	}
	return getJSON[lantern.TitleRequests](c, ctx, "requests", "/requests", q)
}

// RequestTitle asks for a game the server does not have. It gives the new request or, when the
// account has an open one for the same title, that one; created says which.
func (c *Client) RequestTitle(ctx context.Context, titleID, platform string) (req *lantern.TitleRequest, created bool, err error) {
	if !lantern.CoreIDPattern.MatchString(titleID) {
		return nil, false, fmt.Errorf("lantern: %q is not a title id", lantern.Clip(titleID, 40))
	}
	body := map[string]any{"schema": 1, "title_id": titleID}
	if platform != "" {
		if !lantern.IsPlatform(platform) {
			return nil, false, fmt.Errorf("lantern: %q is not a platform", lantern.Clip(platform, 40))
		}
		body["platform"] = platform
	}
	resp, err := c.send(ctx, &call{method: http.MethodPost, path: "/requests", body: body, what: "request"}, lantern.MaxJSONDocument)
	if err != nil {
		return nil, false, err
	}
	if err := c.expect(resp, "request", http.StatusOK, http.StatusCreated); err != nil {
		return nil, false, err
	}
	req, err = read[lantern.TitleRequest](c, "request", resp)
	return req, resp.status == http.StatusCreated, err
}

// WithdrawRequest withdraws the account's own request, whatever its status.
func (c *Client) WithdrawRequest(ctx context.Context, id string) error {
	if !lantern.CoreIDPattern.MatchString(id) {
		return fmt.Errorf("lantern: %q is not a request's id", lantern.Clip(id, 40))
	}
	return c.noContent(ctx, &call{method: http.MethodDelete, path: "/requests/" + url.PathEscape(id), what: "request"})
}
