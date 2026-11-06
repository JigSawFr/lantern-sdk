// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

// Mirrors and peers (SPEC.md § 19) serve the bytes of a file by its hash, and are untrusted: what
// they say decides nothing (L-19.1-1). They get none of the server's credentials (L-19.1-2): a
// request to them carries no token, no signature and no cookie, and a redirect is not followed. A
// peer gets a grant, and nothing else (§ 19.3).

// sourceClients are the HTTP clients of mirrors (their certificates checked as any site's) and of
// peers (HTTPS with a certificate of their own that nobody pins, § 19.4: what they serve is checked
// by its hash). Neither shares the server's transport, whose pin is the server's.
func newSourceClients() (mirror, peer *http.Client) {
	refuse := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	m := &http.Transport{
		Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true, MaxIdleConns: 8,
		IdleConnTimeout: 60 * time.Second, TLSHandshakeTimeout: 15 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	p := &http.Transport{
		MaxIdleConns: 8, IdleConnTimeout: 60 * time.Second, TLSHandshakeTimeout: 15 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, //nolint:gosec // a peer's certificate is its own; the bytes are checked by their hash (SPEC.md § 19.4)
	}
	return &http.Client{Transport: m, CheckRedirect: refuse}, &http.Client{Transport: p, CheckRedirect: refuse}
}

// Grant asks the server for a grant to read a file from a peer (SPEC.md § 19.3), by its SHA-256.
// The grant is checked before it is given: it names this file and its size, it is signed by the
// server's grant key (the handshake's peers.key) for this server's uid, and it lives
// peers.grant_lifetime seconds at most (L-19.3-2). A file the server would not serve is
// lantern.ErrNotFound.
func (c *Client) Grant(ctx context.Context, sha256 string) (*lantern.Grant, error) {
	if !lantern.SHA256Pattern.MatchString(sha256) {
		return nil, errors.New("lantern: sha256 is 64 lower-case hex digits")
	}
	g, err := getJSON[lantern.Grant](c, ctx, "grant", "/grants/sha256/"+sha256, nil)
	if err != nil {
		return nil, err
	}
	hello := c.Hello()
	if hello == nil {
		var err error
		if hello, err = c.Handshake(ctx); err != nil {
			return nil, err
		}
	}
	if hello.Peers == nil {
		return nil, fmt.Errorf("%w: a grant from a server that offers no peers", lantern.ErrUnexpectedResponse)
	}
	bad := func(why string) (*lantern.Grant, error) {
		return nil, fmt.Errorf("%w: grant: %s", lantern.ErrUnexpectedResponse, why)
	}
	now := c.now().Unix()
	payload := lantern.VerifyGrant(g.Grant, map[string]string{hello.UID: hello.Peers.Key}, now)
	switch {
	case payload == nil:
		return bad("it does not verify with the server's grant key")
	case g.SHA256 != sha256 || payload.SHA256 != sha256:
		return bad("it names another file")
	case payload.Size != g.Size:
		return bad("its size is not the document's")
	case hello.Peers.GrantLifetime > lantern.GrantLifetimeLimit || payload.Exp > now+hello.Peers.GrantLifetime+grantSlack:
		return bad("it lives longer than peers.grant_lifetime")
	}
	return g, nil
}

// openSource opens a file at an address that is not the server's: no credential of the server goes,
// a redirect is not followed, and the answer is checked as OpenFile's (see newFile).
func (c *Client) openSource(ctx context.Context, hc *http.Client, target, what string, extra http.Header, size int64, sha string, offset int64, prefix *lantern.Sha256) (*File, error) {
	if offset < 0 || offset > size {
		return nil, fmt.Errorf("lantern: offset %d is outside a file of %d bytes", offset, size)
	}
	if offset > 0 && (prefix == nil || prefix.Size() != offset) {
		return nil, errors.New("lantern: resuming needs the SHA-256 of the bytes before the offset")
	}
	if !lantern.SHA256Pattern.MatchString(sha) {
		return nil, &lantern.DocumentError{Where: what, Reason: "no SHA-256"}
	}
	sctx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(sctx, http.MethodGet, target, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept-Encoding", "identity")
	if offset > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
	}
	for k, v := range extra {
		req.Header[k] = v
	}
	timer := time.AfterFunc(c.timeout, cancel)
	resp, err := hc.Do(req)
	if !timer.Stop() && err == nil {
		resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("%w: no answer in %s", lantern.ErrTransport, c.timeout)
	}
	if err != nil {
		cancel()
		return nil, fmt.Errorf("%w: %w", lantern.ErrTransport, err)
	}
	if resp.StatusCode >= 300 {
		resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("%w: %s: status %d", lantern.ErrUnexpectedResponse, what, resp.StatusCode)
	}
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	return c.newFile(resp, size, sha, offset, prefix, false)
}

// OpenMirror opens a file at one of its mirrors (SPEC.md § 19.2), from byte offset like OpenFile.
// The address must be one a client may read (lantern.MirrorAllowed). The File is checked against
// the size and SHA-256 the server's document gave, whatever the mirror says.
func (c *Client) OpenMirror(ctx context.Context, address string, size int64, sha string, offset int64, prefix *lantern.Sha256) (*File, error) {
	if !lantern.MirrorAllowed(address) {
		return nil, fmt.Errorf("%w: a mirror at %q, which a client does not read (SPEC.md § 19.2)", lantern.ErrUnexpectedResponse, lantern.Clip(address, 100))
	}
	return c.openSource(ctx, c.mirror, address, "mirror", nil, size, sha, offset, prefix)
}

// OpenPeer opens a file on a peer (SPEC.md § 19.4) with the grant the server gave for it (Grant),
// from byte offset like OpenFile. Only the grant goes to the peer.
func (c *Client) OpenPeer(ctx context.Context, peer *lantern.Peer, grant string, size int64, sha string, offset int64, prefix *lantern.Sha256) (*File, error) {
	if peer == nil || peer.URL == "" {
		return nil, errors.New("lantern: no peer")
	}
	target, err := lantern.BlobURL(peer.URL, sha)
	if err != nil {
		return nil, err
	}
	if len(grant) > lantern.GrantLimit {
		return nil, errors.New("lantern: a grant above its limit")
	}
	return c.openSource(ctx, c.peer, target, "peer", http.Header{lantern.GrantHeader: {grant}}, size, sha, offset, prefix)
}

// Sources are where DownloadVia looks for a file before it asks the server.
type Sources struct {
	// Peers are tried first, in order: those that take this server's grants (see
	// discovery.PeersOf). A grant is asked of the server once, for the first.
	Peers []lantern.Peer
	// Mirrors says whether the file's own mirrors (SPEC.md § 19.2) are tried, after the peers.
	Mirrors bool
}

// DownloadVia saves an app's file at path as Download does, from a peer or a mirror when it can, and
// from the server when none gives the file (L-19.1-3): a source that fails, or whose bytes fail the
// check, is passed by. A copy a source left half done is resumed from the next one. It gives the
// source the file came from: "peer", "mirror" or "server".
func (c *Client) DownloadVia(ctx context.Context, app *lantern.App, path string, src Sources, progress func(done, total int64)) (string, error) {
	try := func(open func(offset int64, prefix *lantern.Sha256) (*File, error)) error {
		return download(ctx, app.Size, app.SHA256, path, progress, open)
	}
	if len(src.Peers) > 0 {
		if g, err := c.Grant(ctx, app.SHA256); err == nil && g.Size == app.Size {
			for i := range src.Peers {
				peer := &src.Peers[i]
				err := try(func(offset int64, prefix *lantern.Sha256) (*File, error) {
					return c.OpenPeer(ctx, peer, g.Grant, app.Size, app.SHA256, offset, prefix)
				})
				if err == nil {
					return "peer", nil
				}
				if ctx.Err() != nil {
					return "", ctx.Err()
				}
			}
		} else if ctx.Err() != nil {
			return "", ctx.Err()
		}
	}
	if src.Mirrors {
		for _, address := range lantern.UsableMirrors(app.Mirrors) {
			err := try(func(offset int64, prefix *lantern.Sha256) (*File, error) {
				return c.OpenMirror(ctx, address, app.Size, app.SHA256, offset, prefix)
			})
			if err == nil {
				return "mirror", nil
			}
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
		}
	}
	if err := c.Download(ctx, app, path, progress); err != nil {
		return "", err
	}
	return "server", nil
}

// grantSlack is the seconds a grant may live beyond peers.grant_lifetime before it is refused: the
// clocks of the two sides are not the same to the second.
const grantSlack = 60
