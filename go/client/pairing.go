// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

// Pairing is a pairing under way (SPEC.md § 5.2). Show Code, Verify and Fingerprint (the short
// fingerprint of the key of the server the client talks to: the user compares it with the one the
// server's page shows), and VerifyComplete as a QR code the client draws, the code and the
// fingerprint kept next to it. Then WaitForPairing, or PollPairing every Interval.
type Pairing struct {
	Document *lantern.PairingCode
	// Key is the device key the token will be bound to; nil for a bearer-only pairing.
	Key *lantern.SigningKey
	// SPKI is the fingerprint of the key of the server's connection (hex), "" over plain HTTP.
	SPKI     string
	PollURL  string
	Interval time.Duration
	Started  time.Time
}

// Code is what the user types or compares.
func (p *Pairing) Code() string { return p.Document.Code }

// Verify is the server's approval page.
func (p *Pairing) Verify() string { return p.Document.Verify }

// VerifyComplete is the QR code's text: Verify with the code in its query.
func (p *Pairing) VerifyComplete() string {
	if p.Document.VerifyComplete != "" {
		return p.Document.VerifyComplete
	}
	return p.Document.Verify
}

// Fingerprint is the short fingerprint of the server's key as this client sees it; "" over plain HTTP.
func (p *Pairing) Fingerprint() string {
	if p.SPKI == "" {
		return ""
	}
	s, _ := lantern.ShortFingerprint(p.SPKI)
	return s
}

// Expired reports whether the code has run out.
func (p *Pairing) Expired() bool {
	return time.Since(p.Started) >= time.Duration(p.Document.Expires)*time.Second
}

// PairOptions of Pair.
type PairOptions struct {
	// Key is the device key; a new one is made when nil, unless Bearer is set.
	Key *lantern.SigningKey
	// Bearer asks for a token bound to no key (a server may refuse it).
	Bearer bool
	// Invitation is an invitation's code (SPEC.md § 5.5).
	Invitation string
}

// Pair starts a pairing (SPEC.md § 5.2): the server gives a code, and the user approves it on the
// server's side. Over a connection no CA vouches for (TrustOnFirstUse), the key seen is pinned
// from here on.
func (c *Client) Pair(ctx context.Context, device string, scopes []string, opts PairOptions) (*Pairing, error) {
	if strings.TrimSpace(device) == "" || len(device) > lantern.MaxName {
		return nil, errors.New("device is the device's name, 512 bytes at most")
	}
	if len(scopes) == 0 {
		return nil, errors.New("ask for one scope at least")
	}
	if c.Hello() == nil {
		if _, err := c.Handshake(ctx); err != nil {
			return nil, err
		}
	}
	key := opts.Key
	if key == nil && !opts.Bearer {
		var err error
		if key, err = lantern.GenerateSigningKey(); err != nil {
			return nil, err
		}
	}
	doc := lantern.PairingRequest{Schema: lantern.Schema, Device: device, Scopes: dedupe(scopes)}
	if key != nil {
		doc.Key = key.Document()
	}
	if opts.Invitation != "" {
		doc.Invitation = &opts.Invitation
	}
	resp, err := c.send(ctx, &call{method: http.MethodPost, path: "/pairing", body: doc, anonymous: true, what: "pairing"}, lantern.MaxJSONDocument)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, "pairing", http.StatusOK); err != nil {
		return nil, err
	}
	code, err := read[lantern.PairingCode](c, "pairing", resp)
	if err != nil {
		return nil, err
	}
	if err := lantern.CheckPairingCode(code, c.root); err != nil {
		return nil, err
	}
	spki := c.LastSPKI()
	c.mu.Lock()
	if spki != "" && c.tofu && c.pin == "" {
		c.pin = spki
	}
	c.mu.Unlock()
	poll, err := c.onOrigin(code.Poll, "pairing poll")
	if err != nil {
		return nil, err
	}
	return &Pairing{Document: code, Key: key, SPKI: spki, PollURL: poll, Interval: time.Duration(code.Interval) * time.Second, Started: time.Now()}, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// PollPairing polls once: the token once the user approved (the client then uses it), nil while
// the server waits (202).
func (c *Client) PollPairing(ctx context.Context, p *Pairing) (*lantern.PairingToken, error) {
	resp, err := c.send(ctx, &call{method: http.MethodGet, rawURL: p.PollURL, anonymous: true, signer: p.Key, what: "pairing poll"}, lantern.MaxJSONDocument)
	if err != nil {
		return nil, err
	}
	if resp.status == http.StatusAccepted {
		return nil, nil
	}
	if err := c.expect(resp, "pairing poll", http.StatusOK); err != nil {
		return nil, err
	}
	token, err := read[lantern.PairingToken](c, "pairing poll", resp)
	if err != nil {
		return nil, err
	}
	var key *lantern.SigningKey
	if token.Bound == nil || *token.Bound {
		key = p.Key
	}
	c.SetToken(token.Token, key)
	return token, nil
}

// WaitForPairing polls until the user approves, the code expires (ErrGone) or ctx is done, then
// reads the handshake again (the account is the paired one now) and gives the record to keep; it
// is saved to store when one is given.
func (c *Client) WaitForPairing(ctx context.Context, p *Pairing, store lantern.ServerStore) (*lantern.ServerRecord, error) {
	interval := p.Interval
	for {
		if p.Expired() {
			return nil, &lantern.ProblemError{Status: http.StatusGone, Kind: lantern.ErrGone, Detail: "the pairing code expired"}
		}
		token, err := c.PollPairing(ctx, p)
		var perr *lantern.ProblemError
		if errors.As(err, &perr) && errors.Is(perr, lantern.ErrSlowDown) {
			interval = max(interval+5*time.Second, time.Duration(perr.RetryAfter)*time.Second)
			token, err = nil, nil
		}
		if err != nil {
			return nil, err
		}
		if token != nil {
			if _, err := c.Handshake(ctx); err != nil {
				return nil, err
			}
			record, err := c.record(p, token)
			if err != nil {
				return nil, err
			}
			if store != nil {
				if err := store.Save(record); err != nil {
					return nil, err
				}
			}
			return record, nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// record is what a client keeps of a server once paired (SPEC.md § 5.3): its uid, the key it
// pinned when no CA vouched for it, the token and the device key.
func (c *Client) record(p *Pairing, token *lantern.PairingToken) (*lantern.ServerRecord, error) {
	hello := c.Hello()
	if hello == nil {
		return nil, errors.New("lantern: no handshake yet")
	}
	r := &lantern.ServerRecord{
		UID: hello.UID, URL: c.root + "/", Token: token.Token, Name: hello.Name, SPKI: p.SPKI,
		Scopes: token.Scopes, Paired: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	if p.Key != nil && (token.Bound == nil || *token.Bound) {
		r.Key, r.Bound = p.Key.SeedBase64(), token.Bound != nil && *token.Bound
	}
	if token.RatingCap != nil {
		r.RatingCap, _ = token.RatingCap.MarshalJSON()
	}
	return r, nil
}
