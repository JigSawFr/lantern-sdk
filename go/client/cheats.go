// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"unicode/utf8"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

// CheatOptions filter the cheat sets (SPEC.md § 10). Every field is optional.
type CheatOptions struct {
	Platform string // "" for the client's
	TitleID  string
	BuildID  string
}

// Cheats lists the cheat sets: a build may have several, from several sources.
func (c *Client) Cheats(ctx context.Context, opts CheatOptions) (*lantern.CheatSets, error) {
	q := url.Values{}
	if opts.Platform != "" {
		if !lantern.IsPlatform(opts.Platform) {
			return nil, fmt.Errorf("lantern: %q is not a platform", lantern.Clip(opts.Platform, 40))
		}
		q.Set("platform", opts.Platform)
	}
	if opts.TitleID != "" {
		if !lantern.CoreIDPattern.MatchString(opts.TitleID) {
			return nil, fmt.Errorf("lantern: %q is not a title id", lantern.Clip(opts.TitleID, 40))
		}
		q.Set("title_id", opts.TitleID)
	}
	if opts.BuildID != "" {
		if !lantern.BuildIDPattern.MatchString(opts.BuildID) {
			return nil, fmt.Errorf("lantern: %q is not a build id", lantern.Clip(opts.BuildID, 70))
		}
		q.Set("build_id", opts.BuildID)
	}
	return getJSON[lantern.CheatSets](c, ctx, "cheats", "/cheats", q)
}

// CheatText is a set's text, read as a file (SPEC.md § 6.6) and checked against its size and
// SHA-256 (1 MiB at most) before it is given back: it is UTF-8 text, in the platform's own
// format, which the caller writes where the profile says (lantern.Profile.Cheats).
func (c *Client) CheatText(ctx context.Context, set *lantern.CheatSet) (string, error) {
	if set.Size < 0 || set.Size > lantern.MaxCheatSet {
		return "", &lantern.DocumentError{Where: "cheat set " + set.ID, Reason: fmt.Sprintf("%d bytes, above %d", set.Size, lantern.MaxCheatSet)}
	}
	if !lantern.CoreIDPattern.MatchString(set.ID) {
		return "", fmt.Errorf("lantern: %q is not a cheat set's id", lantern.Clip(set.ID, 40))
	}
	address, err := c.v1("/cheats/" + url.PathEscape(set.ID))
	if err != nil {
		return "", err
	}
	f, err := c.OpenFile(ctx, &lantern.App{File: address, Size: set.Size, SHA256: set.SHA256}, 0, nil)
	if err != nil {
		return "", err
	}
	defer f.Close()
	text, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(text) {
		return "", &lantern.DocumentError{Where: "cheat set " + set.ID, Reason: "not UTF-8 text"}
	}
	return string(text), nil
}

// CheatWrite is a cheat set to write (scope cheats.write, SPEC.md § 10).
type CheatWrite struct {
	Platform string // "" for the client's
	TitleID  string
	BuildID  string // on platforms whose cheats depend on the build
	Source   string
	Note     string
	Text     string // at most 1 MiB
}

func (w CheatWrite) body(c *Client) (*lantern.CheatWrite, error) {
	platform := w.Platform
	if platform == "" {
		platform = c.platform
	}
	switch {
	case !lantern.IsPlatform(platform):
		return nil, fmt.Errorf("lantern: a cheat set needs a platform")
	case !lantern.CoreIDPattern.MatchString(w.TitleID):
		return nil, fmt.Errorf("lantern: %q is not a title id", lantern.Clip(w.TitleID, 40))
	case w.BuildID != "" && !lantern.BuildIDPattern.MatchString(w.BuildID):
		return nil, fmt.Errorf("lantern: %q is not a build id", lantern.Clip(w.BuildID, 70))
	case len(w.Text) > lantern.MaxCheatSet:
		return nil, fmt.Errorf("lantern: a cheat set of %d bytes, above %d", len(w.Text), lantern.MaxCheatSet)
	case len(w.Note) > lantern.MaxNote:
		return nil, fmt.Errorf("lantern: a note of %d bytes, above %d", len(w.Note), lantern.MaxNote)
	}
	b := &lantern.CheatWrite{Schema: 1, Platform: platform, TitleID: w.TitleID, Text: w.Text}
	for p, v := range map[**string]string{&b.BuildID: w.BuildID, &b.Source: w.Source, &b.Note: w.Note} {
		if v != "" {
			s := v
			*p = &s
		}
	}
	return b, nil
}

// AddCheat writes a new set and gives it as the server lists it. A set that exists already (the
// same platform, title, build and source) is an error that errors.Is(err, lantern.ErrConflict):
// ReplaceCheat replaces it.
func (c *Client) AddCheat(ctx context.Context, w CheatWrite) (*lantern.CheatSet, error) {
	body, err := w.body(c)
	if err != nil {
		return nil, err
	}
	resp, err := c.send(ctx, &call{method: http.MethodPost, path: "/cheats", body: body, what: "cheat set"}, lantern.MaxJSONDocument)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, "cheat set", http.StatusCreated); err != nil {
		return nil, err
	}
	return read[lantern.CheatSet](c, "cheat set", resp)
}

// ReplaceCheat replaces a set.
func (c *Client) ReplaceCheat(ctx context.Context, id string, w CheatWrite) error {
	if !lantern.CoreIDPattern.MatchString(id) {
		return fmt.Errorf("lantern: %q is not a cheat set's id", lantern.Clip(id, 40))
	}
	body, err := w.body(c)
	if err != nil {
		return err
	}
	return c.noContent(ctx, &call{method: http.MethodPut, path: "/cheats/" + url.PathEscape(id), body: body, what: "cheat set"})
}

// DeleteCheat deletes a set.
func (c *Client) DeleteCheat(ctx context.Context, id string) error {
	if !lantern.CoreIDPattern.MatchString(id) {
		return fmt.Errorf("lantern: %q is not a cheat set's id", lantern.Clip(id, 40))
	}
	return c.noContent(ctx, &call{method: http.MethodDelete, path: "/cheats/" + url.PathEscape(id), what: "cheat set"})
}

// noContent sends k and expects 204.
func (c *Client) noContent(ctx context.Context, k *call) error {
	resp, err := c.send(ctx, k, lantern.MaxJSONDocument)
	if err != nil {
		return err
	}
	return c.expect(resp, k.what, http.StatusNoContent)
}
