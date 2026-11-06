// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"fmt"
	"iter"
	"net/http"
	"net/url"
	"strconv"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

// HomebrewOptions filter the homebrew listing (SPEC.md § 8.5).
type HomebrewOptions struct {
	Platform string // "" for the server's default
	Kind     string // a lower-case word, as a reader reads a kind
	Genre    string // a lower-case word
	Query    string // the name holds it, case ignored (256 bytes at most)
	PageSize int    // 0 for the server's
}

func (o HomebrewOptions) values() (url.Values, error) {
	q := url.Values{}
	if o.Platform != "" {
		if !lantern.IsPlatform(o.Platform) {
			return nil, fmt.Errorf("lantern: %q is not a platform", lantern.Clip(o.Platform, 40))
		}
		q.Set("platform", o.Platform)
	}
	for k, v := range map[string]string{"kind": o.Kind, "genre": o.Genre} {
		if v == "" {
			continue
		}
		if !lantern.WordPattern.MatchString(v) {
			return nil, fmt.Errorf("lantern: %s %q is not a lower-case word", k, lantern.Clip(v, 40))
		}
		q.Set(k, v)
	}
	if o.Query != "" {
		if len(o.Query) > 256 {
			return nil, fmt.Errorf("lantern: a query of %d bytes, above 256", len(o.Query))
		}
		q.Set("q", o.Query)
	}
	if o.PageSize > 0 {
		q.Set("page_size", strconv.Itoa(o.PageSize))
	}
	return q, nil
}

// HomebrewPage reads one page of the homebrew listing: cursor is the page's, "" for the first.
// The entries' manifests are left out of a listing (SPEC.md § 8.5); Homebrew gives them.
func (c *Client) HomebrewPage(ctx context.Context, opts HomebrewOptions, cursor string) (*lantern.HomebrewPage, error) {
	q, err := opts.values()
	if err != nil {
		return nil, err
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	page, err := getJSON[lantern.HomebrewPage](c, ctx, "homebrew", "/homebrew", q)
	if err != nil {
		return nil, err
	}
	return page, checkNext(page.Next, len(page.Items))
}

// Homebrew lists the homebrew, page after page.
func (c *Client) Homebrew(ctx context.Context, opts HomebrewOptions) iter.Seq2[*lantern.Homebrew, error] {
	return pages(ctx, func(cursor string) ([]lantern.Homebrew, *string, error) {
		p, err := c.HomebrewPage(ctx, opts, cursor)
		if err != nil {
			return nil, nil, err
		}
		return p.Items, p.Next, nil
	})
}

// HomebrewEntry reads one entry, with its manifests. The entry must be the one asked for.
func (c *Client) HomebrewEntry(ctx context.Context, id, platform string) (*lantern.Homebrew, error) {
	if !lantern.IsHomebrewID(id) {
		return nil, fmt.Errorf("lantern: %q is not a homebrew id", lantern.Clip(id, 40))
	}
	q := url.Values{}
	if platform != "" {
		q.Set("platform", platform)
	}
	e, err := getJSON[lantern.Homebrew](c, ctx, "homebrew entry", "/homebrew/"+url.PathEscape(id), q)
	if err != nil {
		return nil, err
	}
	if e.ID != id {
		return nil, &lantern.DocumentError{Where: "homebrew entry", Reason: fmt.Sprintf("it is %q, not %q", lantern.Clip(e.ID, 40), id)}
	}
	return e, nil
}

// InstalledHomebrew is a homebrew a device has, by its id and the build it has.
type InstalledHomebrew = lantern.InstalledHomebrew

// HomebrewUpdatesPage reads one page of the entries whose build is above the installed one.
func (c *Client) HomebrewUpdatesPage(ctx context.Context, platform string, installed []InstalledHomebrew, cursor string) (*lantern.HomebrewPage, error) {
	if installed == nil {
		installed = []InstalledHomebrew{}
	}
	for _, h := range installed {
		if !lantern.IsHomebrewID(h.ID) {
			return nil, fmt.Errorf("lantern: %q is not a homebrew id", lantern.Clip(h.ID, 40))
		}
	}
	q := url.Values{}
	if platform != "" {
		if !lantern.IsPlatform(platform) {
			return nil, fmt.Errorf("lantern: %q is not a platform", lantern.Clip(platform, 40))
		}
		q.Set("platform", platform)
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	body := &lantern.HomebrewUpdatesRequest{Schema: 1, Installed: installed}
	resp, err := c.send(ctx, &call{method: http.MethodPost, path: "/homebrew/updates", query: q, body: body, what: "homebrew updates"}, lantern.MaxJSONDocument)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, "homebrew updates", http.StatusOK); err != nil {
		return nil, err
	}
	page, err := read[lantern.HomebrewPage](c, "homebrew updates", resp)
	if err != nil {
		return nil, err
	}
	return page, checkNext(page.Next, len(page.Items))
}

// HomebrewUpdates lists the entries newer than what the device has, page after page.
func (c *Client) HomebrewUpdates(ctx context.Context, platform string, installed []InstalledHomebrew) iter.Seq2[*lantern.Homebrew, error] {
	return pages(ctx, func(cursor string) ([]lantern.Homebrew, *string, error) {
		p, err := c.HomebrewUpdatesPage(ctx, platform, installed, cursor)
		if err != nil {
			return nil, nil, err
		}
		return p.Items, p.Next, nil
	})
}

// DownloadPackage fetches a package of an entry to path, checked as SPEC.md § 8.3 and § 8.4 ask
// before a byte is written: the package must have a profile, a manifest that is within the
// roots and whose digest is manifest_sha256, and a signature that verifies when there is one.
// It returns the plan of the paths the install writes, for the caller to show the user (those
// in Consent need their agreement) and to pin the key (lantern.KeyChanged) before it installs.
// The file is the download of Download: resumed, and kept only when its size and SHA-256 are right.
func (c *Client) DownloadPackage(ctx context.Context, entry *lantern.Homebrew, pkg lantern.Package, path string, progress func(done, total int64)) (*lantern.InstallPlan, error) {
	plan, err := lantern.PlanInstall(entry, pkg)
	if err != nil {
		return nil, err
	}
	if valid, signed := lantern.VerifySignature(entry, pkg); signed && !valid {
		return nil, fmt.Errorf("%w: the signature of %s does not verify", lantern.ErrRefused, entry.ID)
	}
	if err := c.Download(ctx, &lantern.App{File: pkg.File, Size: pkg.Size, SHA256: pkg.SHA256}, path, progress); err != nil {
		return nil, err
	}
	return plan, nil
}
