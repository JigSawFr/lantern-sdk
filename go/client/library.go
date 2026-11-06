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
	"strconv"
	"strings"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

var formatWord = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// ListOptions filter and order a listing of apps (SPEC.md § 6.2). The zero value lists everything
// for the client's platform, in the server's page size.
type ListOptions struct {
	// Platform overrides the client's (Lantern-Platform).
	Platform string
	Type     string
	// Format keeps the apps of one format; a format no app has gives an empty list.
	Format  string
	TitleID string
	// Query keeps the apps whose name holds it (256 bytes at most).
	Query string
	// Sort is "name" (the default), "added" or "release".
	Sort string
	// PageSize asks for this many items a page; the server lowers it to its limit.
	PageSize int
}

func (o ListOptions) values() (url.Values, error) {
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	if len(o.Query) > 256 {
		return nil, fmt.Errorf("lantern: a query is 256 bytes at most, not %d", len(o.Query))
	}
	if o.PageSize < 0 {
		return nil, fmt.Errorf("lantern: a page size is a positive integer, not %d", o.PageSize)
	}
	set("platform", o.Platform)
	set("type", o.Type)
	set("format", o.Format)
	set("title_id", o.TitleID)
	set("q", o.Query)
	set("sort", o.Sort)
	if o.PageSize > 0 {
		q.Set("page_size", strconv.Itoa(o.PageSize))
	}
	return q, nil
}

// getJSON is a GET of path (below <base>/v1) read as a T.
func getJSON[T any, P interface {
	*T
	json.Unmarshaler
}](c *Client, ctx context.Context, what, path string, query url.Values) (*T, error) {
	resp, err := c.send(ctx, &call{method: http.MethodGet, path: path, query: query, what: what}, lantern.MaxJSONDocument)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, what, http.StatusOK); err != nil {
		return nil, err
	}
	return read[T, P](c, what, resp)
}

// AppsPage reads one page of the library: the page cursor gives, "" for the first. A cursor that
// expired is an error that errors.Is(err, lantern.ErrGone) (read the list from its start).
func (c *Client) AppsPage(ctx context.Context, opts ListOptions, cursor string) (*lantern.AppsPage, error) {
	q, err := opts.values()
	if err != nil {
		return nil, err
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	page, err := getJSON[lantern.AppsPage](c, ctx, "apps", "/apps", q)
	if err != nil {
		return nil, err
	}
	return page, checkPage(page)
}

// Apps lists the library, page after page, as far as the caller reads. An error ends the
// sequence; one of a cursor that expired (ErrGone) means starting again.
//
//	for app, err := range c.Apps(ctx, client.ListOptions{Type: "update"}) {
//		if err != nil { … }
//	}
func (c *Client) Apps(ctx context.Context, opts ListOptions) iter.Seq2[*lantern.App, error] {
	return pages(ctx, func(cursor string) ([]lantern.App, *string, error) {
		p, err := c.AppsPage(ctx, opts, cursor)
		if err != nil {
			return nil, nil, err
		}
		return p.Items, p.Next, nil
	})
}

// checkPage holds a server to what a page promises: no more than it was asked for is not enforced
// (a server may choose), but a page that is empty and goes on would loop a client for ever.
func checkPage(p *lantern.AppsPage) error { return checkNext(p.Next, len(p.Items)) }

func checkNext(next *string, items int) error {
	if next != nil && *next == "" {
		return &lantern.DocumentError{Where: "next", Reason: "an empty cursor"}
	}
	if next != nil && items == 0 {
		return &lantern.DocumentError{Where: "items", Reason: "an empty page that is not the last"}
	}
	return nil
}

func pages[T any](ctx context.Context, page func(cursor string) ([]T, *string, error)) iter.Seq2[*T, error] {
	return func(yield func(*T, error) bool) {
		cursor, seen := "", map[string]bool{}
		for {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}
			items, next, err := page(cursor)
			if err != nil {
				yield(nil, err)
				return
			}
			for i := range items {
				if !yield(&items[i], nil) {
					return
				}
			}
			if next == nil {
				return
			}
			if seen[*next] {
				yield(nil, &lantern.DocumentError{Where: "next", Reason: "a cursor given twice"})
				return
			}
			seen[*next] = true
			cursor = *next
		}
	}
}

// MissingOptions say what a device is missing (SPEC.md § 6.3).
type MissingOptions struct {
	// Platform overrides the client's; one of the two is needed.
	Platform string
	// Installed are the apps the device has, which may be none.
	Installed []lantern.InstalledApp
	// Want is one or more of "base", "update" and "dlc".
	Want []string
	// Formats and Satisfies say what the device can install. Nil sends nothing and gets every
	// variant; an empty, non-nil slice is sent and leaves every app out.
	Formats   []string
	Satisfies []string
	PageSize  int
}

func (o MissingOptions) request() (*lantern.MissingRequest, error) {
	if len(o.Want) == 0 {
		return nil, fmt.Errorf("lantern: want holds one or more of base, update and dlc")
	}
	for _, w := range o.Want {
		if w != "base" && w != "update" && w != "dlc" {
			return nil, fmt.Errorf("lantern: %q is not base, update or dlc", w)
		}
	}
	if len(o.Formats) > lantern.MaxWords || len(o.Satisfies) > lantern.MaxWords {
		return nil, fmt.Errorf("lantern: formats and satisfies hold %d words at most", lantern.MaxWords)
	}
	for _, f := range o.Formats {
		if !formatWord.MatchString(f) {
			return nil, fmt.Errorf("lantern: %q is not a format word", f)
		}
	}
	for _, t := range o.Satisfies {
		if !lantern.RequiresTokenPattern.MatchString(t) {
			return nil, fmt.Errorf("lantern: %q is not a requires token", t)
		}
	}
	installed := o.Installed
	if installed == nil {
		installed = []lantern.InstalledApp{}
	}
	return &lantern.MissingRequest{Schema: lantern.Schema, Installed: installed, Want: o.Want, Formats: o.Formats, Satisfies: o.Satisfies}, nil
}

// MissingPage asks what the device is missing and reads one page of the answer.
func (c *Client) MissingPage(ctx context.Context, opts MissingOptions, cursor string) (*lantern.AppsPage, error) {
	req, err := opts.request()
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if opts.Platform != "" {
		q.Set("platform", opts.Platform)
	}
	if opts.PageSize > 0 {
		q.Set("page_size", strconv.Itoa(opts.PageSize))
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	resp, err := c.send(ctx, &call{method: http.MethodPost, path: "/apps/missing", query: q, body: req, what: "missing"}, lantern.MaxJSONDocument)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, "missing", http.StatusOK); err != nil {
		return nil, err
	}
	page, err := read[lantern.AppsPage](c, "missing", resp)
	if err != nil {
		return nil, err
	}
	return page, checkPage(page)
}

// Missing is what the device is missing, page after page.
func (c *Client) Missing(ctx context.Context, opts MissingOptions) iter.Seq2[*lantern.App, error] {
	return pages(ctx, func(cursor string) ([]lantern.App, *string, error) {
		p, err := c.MissingPage(ctx, opts, cursor)
		if err != nil {
			return nil, nil, err
		}
		return p.Items, p.Next, nil
	})
}

// Changes reads what changed in the library since a token (SPEC.md § 6.4). Without one it gives
// no apps and the current token, to start from. A token that is too old is an error that
// errors.Is(err, lantern.ErrGone): read the whole library again. platform is the client's when "".
func (c *Client) Changes(ctx context.Context, since, platform string) (*lantern.Changes, error) {
	q := url.Values{}
	if since != "" {
		q.Set("since", since)
	}
	if platform != "" {
		q.Set("platform", platform)
	}
	return getJSON[lantern.Changes](c, ctx, "changes", "/changes", q)
}

// Sections reads the shelves the server curates (SPEC.md § 6.5).
func (c *Client) Sections(ctx context.Context) (*lantern.Sections, error) {
	return getJSON[lantern.Sections](c, ctx, "sections", "/sections", nil)
}

// Title reads what the server knows about a game (SPEC.md § 7.1). platform is the client's when "".
func (c *Client) Title(ctx context.Context, titleID, platform string) (*lantern.Title, error) {
	if !lantern.CoreIDPattern.MatchString(titleID) {
		return nil, fmt.Errorf("lantern: %q is not a title id", lantern.Clip(titleID, 40))
	}
	q := url.Values{}
	if platform != "" {
		q.Set("platform", platform)
	}
	return getJSON[lantern.Title](c, ctx, "title", "/titles/"+url.PathEscape(titleID), q)
}

// Titles reads many titles (SPEC.md § 7.2), a hundred ids to a request. It gives the titles the
// server has and the ids it does not know. An id asked twice is asked once.
func (c *Client) Titles(ctx context.Context, ids []string, platform string) (titles []lantern.Title, unknown []string, err error) {
	seen := map[string]bool{}
	var want []string
	for _, id := range ids {
		if !lantern.CoreIDPattern.MatchString(id) {
			return nil, nil, fmt.Errorf("lantern: %q is not a title id", lantern.Clip(id, 40))
		}
		if !seen[id] {
			seen[id] = true
			want = append(want, id)
		}
	}
	for len(want) > 0 {
		n := min(len(want), lantern.MaxTitlesAtOnce)
		q := url.Values{"ids": {strings.Join(want[:n], ",")}}
		if platform != "" {
			q.Set("platform", platform)
		}
		got, err := getJSON[lantern.Titles](c, ctx, "titles", "/titles", q)
		if err != nil {
			return nil, nil, err
		}
		titles = append(titles, got.Titles...)
		unknown = append(unknown, got.Unknown...)
		want = want[n:]
	}
	return titles, unknown, nil
}

// TitleChanges reads the titles added, changed or removed since a token (SPEC.md § 7.3). While
// the answer says More, ask again with its Since.
func (c *Client) TitleChanges(ctx context.Context, since, platform string) (*lantern.TitleChanges, error) {
	q := url.Values{}
	if since != "" {
		q.Set("since", since)
	}
	if platform != "" {
		q.Set("platform", platform)
	}
	return getJSON[lantern.TitleChanges](c, ctx, "title changes", "/titles/changes", q)
}

// MaxImage is the most bytes of an image the client reads.
const MaxImage = 16 << 20

// Image reads an image of a title (SPEC.md § 7.1): the bytes, checked against the image's SHA-256
// when it has one. Only an image on the server's origin is read: an external one is the
// application's to fetch, with a client that sends no credential (L-7.1-4), and this gives an
// error for it.
func (c *Client) Image(ctx context.Context, img *lantern.Image) ([]byte, error) {
	if img == nil {
		return nil, fmt.Errorf("lantern: no image")
	}
	if img.External != nil && *img.External {
		return nil, fmt.Errorf("lantern: %q is external: fetch it without the server's credentials", lantern.Clip(img.URL, 80))
	}
	target, err := c.onOrigin(img.URL, "an image")
	if err != nil {
		return nil, err
	}
	resp, err := c.send(ctx, &call{method: http.MethodGet, rawURL: target, headers: http.Header{"Accept": {"image/*"}}, what: "image"}, MaxImage)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, "image", http.StatusOK); err != nil {
		return nil, err
	}
	if img.SHA256 != nil && lantern.SHA256Hex(resp.body) != *img.SHA256 {
		return nil, fmt.Errorf("%w: an image that is not the one its SHA-256 names", lantern.ErrIntegrity)
	}
	return resp.body, nil
}
