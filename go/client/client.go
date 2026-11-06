// SPDX-License-Identifier: MIT

// Package client talks to a Lantern server (SPEC.md): the handshake, pairing, the token and the
// device key, a server's key pinned by its SHA-256, and requests signed as SPEC.md § 5.4 says.
//
//	c, err := client.New("https://nas.local:8443/", client.Options{TrustOnFirstUse: true})
//	hello, err := c.Handshake(ctx)
//	p, err := c.Pair(ctx, "Living room console", []string{"library"}, client.PairOptions{})
//	// show p.Code(), p.Verify() and p.Fingerprint(); the user approves on the server's page
//	record, err := c.WaitForPairing(ctx, p, store)
//	later, err := client.Paired(record, client.Options{})
//
// A client never follows a redirect (the protocol has none), sends its token and its signatures to
// the server's own origin only, and speaks plain HTTP only to a loopback address (SPEC.md § 2).
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

// UserAgent is the default User-Agent (SPEC.md § 2: <Name>/<version>).
var UserAgent = "LanternGo/" + lantern.Version

const errorBody = 1 << 16

// Options of a client.
type Options struct {
	// HTTPClient sends the requests. Its redirects are never followed, whatever it says. When it is
	// set, the application owns TLS: Pin and TrustOnFirstUse then only check the key afterwards
	// (a request is already sent), so build the client with Pin to have the key checked first.
	HTTPClient *http.Client
	// Token is the bearer token of a paired device; Key signs its requests when it is bound.
	Token string
	Key   *lantern.SigningKey
	// Pin is the SHA-256 (hex) of the server's key: the client talks only over connections that
	// carry it, whatever certificate wraps it (SPEC.md § 5.3). It makes the client skip the CAs.
	Pin string
	// TrustOnFirstUse reads the key of a server no CA vouches for without checking it (before
	// pairing nothing secret is sent), so that Pair can show its fingerprint and pin it.
	TrustOnFirstUse bool
	// RootCAs are the authorities to trust, the system's when nil.
	RootCAs *x509.CertPool
	// Platform is sent as Lantern-Platform; AcceptLanguage as Accept-Language.
	Platform       string
	AcceptLanguage string
	UserAgent      string
	// Base is the path of the API, when the application knows it (the handshake gives it otherwise).
	Base string
	// Timeout of a request, thirty seconds when 0.
	Timeout time.Duration
}

// Deprecation is a route or schema a server said is going away (SPEC.md § 3.4).
type Deprecation struct {
	What   string
	Since  string // Deprecation, a Structured Fields date such as `@1793318400`
	Sunset string // the HTTP date after which it may stop answering
	Link   string // what replaces it
}

// Client is a Lantern client. It is safe for concurrent use.
type Client struct {
	root      string // scheme://host[:port]
	origin    lantern.Origin
	http      *http.Client
	userAgent string
	platform  string
	language  string
	timeout   time.Duration

	mu          sync.Mutex
	base        string
	hello       *lantern.Handshake
	token       string
	key         *lantern.SigningKey
	pin         string
	tofu        bool
	lastSPKI    string
	clockOffset time.Duration
	deprecated  []Deprecation
}

// New is a client of the server at rawURL (HTTPS, or HTTP on a loopback address).
func New(rawURL string, opts Options) (*Client, error) {
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	ok, err := lantern.PlainHTTPAllowed(rawURL)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: %s: plain HTTP is allowed only to a loopback address (SPEC.md § 2)", lantern.ErrInsecureTransport, rawURL)
	}
	origin, _ := lantern.OriginOf(rawURL)
	u, _ := url.Parse(rawURL)
	c := &Client{
		root: u.Scheme + "://" + u.Host, origin: origin, userAgent: opts.UserAgent,
		platform: opts.Platform, language: opts.AcceptLanguage, timeout: opts.Timeout,
		token: opts.Token, key: opts.Key, pin: strings.ToLower(opts.Pin), tofu: opts.TrustOnFirstUse,
	}
	if c.userAgent == "" {
		c.userAgent = UserAgent
	}
	if c.timeout == 0 {
		c.timeout = 30 * time.Second
	}
	if i := strings.IndexByte(c.userAgent, '/'); i < 1 || strings.ContainsRune(c.userAgent[:i], ' ') {
		return nil, errors.New("User-Agent is <Name>/<version> (SPEC.md § 2)")
	}
	if opts.Platform != "" && !lantern.IsPlatform(opts.Platform) {
		return nil, fmt.Errorf("%q is not a platform's name", opts.Platform)
	}
	if c.pin != "" && !lantern.SHA256Pattern.MatchString(c.pin) {
		return nil, errors.New("a pin is a SHA-256 in hex")
	}
	if opts.Base != "" {
		if c.base, err = checkBase(opts.Base); err != nil {
			return nil, err
		}
	}
	if opts.HTTPClient != nil {
		clone := *opts.HTTPClient
		c.http = &clone
	} else {
		tr := &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        16,
			IdleConnTimeout:     60 * time.Second,
			TLSHandshakeTimeout: 15 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12, // SPEC.md § 2, L-2-9, RFC 8996
				RootCAs:            opts.RootCAs,
				InsecureSkipVerify: c.pin != "" || c.tofu, //nolint:gosec // the key is checked by its pin instead
				VerifyConnection:   c.verifyConnection,
			},
		}
		c.http = &http.Client{Transport: tr}
	}
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c, nil
}

// Paired is a client of a server the device paired with.
func Paired(record *lantern.ServerRecord, opts Options) (*Client, error) {
	if record.Key != "" {
		key, err := lantern.SigningKeyFromBase64(record.Key)
		if err != nil {
			return nil, err
		}
		opts.Key = key
	}
	if record.SPKI != "" && opts.HTTPClient == nil {
		opts.Pin = record.SPKI
	}
	opts.Token = record.Token
	return New(record.URL, opts)
}

func checkBase(base string) (string, error) {
	if !strings.HasPrefix(base, "/") || strings.HasPrefix(base, "//") || strings.ContainsAny(base, "?#") {
		return "", &lantern.DocumentError{Where: "base", Reason: fmt.Sprintf("%q is not a path on the server's origin", lantern.Clip(base, 80))}
	}
	return strings.TrimRight(base, "/"), nil
}

// verifyConnection runs on every TLS connection of the built-in transport, before a byte of the
// request is sent: it checks the pin, and remembers the key seen.
func (c *Client) verifyConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("lantern: the server presented no certificate")
	}
	seen := spki(cs.PeerCertificates[0])
	c.mu.Lock()
	pin := c.pin
	c.mu.Unlock()
	if pin != "" && !lantern.CheckPin(seen, pin) {
		return &lantern.PinMismatchError{Seen: seen, Pinned: pin, Where: c.origin.Host}
	}
	return nil
}

func spki(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// SetToken sets the token, and the device key its requests are signed with (nil for a bearer-only
// token); "" removes both.
func (c *Client) SetToken(token string, key *lantern.SigningKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token, c.key = token, key
}

// Hello is the last handshake, or nil before the first.
func (c *Client) Hello() *lantern.Handshake {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hello
}

// LastSPKI is the fingerprint of the key of the last TLS connection, "" over plain HTTP.
func (c *Client) LastSPKI() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastSPKI
}

// Deprecations lists what the server said is going away, each once (also logged, at warning level).
func (c *Client) Deprecations() []Deprecation {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Deprecation(nil), c.deprecated...)
}

// ClockOffset is what the client adds to its clock to read the server's (SPEC.md § 5.4, Annex B.9).
func (c *Client) ClockOffset() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.clockOffset
}

// Offers reports whether the server offers a family at a level this library reads (SPEC.md § 4.2),
// reading the handshake first when needed.
func (c *Client) Offers(ctx context.Context, family string) (bool, error) {
	hello := c.Hello()
	if hello == nil {
		var err error
		if hello, err = c.Handshake(ctx); err != nil {
			return false, err
		}
	}
	level := hello.Features[family]
	return level > 0 && level <= lantern.Schema, nil
}

// RatingCap is the cap on the account (SPEC.md § 5.6), or nil.
func (c *Client) RatingCap() *lantern.RatingCap {
	if h := c.Hello(); h != nil {
		return h.Account.RatingCap
	}
	return nil
}

// A call is one request: below <base>/v1 (path), the handshake (wellKnown), or an address a
// document gave (rawURL).
type call struct {
	method    string
	path      string
	query     url.Values
	body      any
	wellKnown bool
	rawURL    string
	anonymous bool
	signer    *lantern.SigningKey
	headers   http.Header
	raw       []byte // a body that is not JSON: its Content-Type is in headers
	what      string
	timeout   time.Duration // longer than the client's, for a call that waits (a long poll)
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func (c *Client) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.clockOffset)
}

func (c *Client) v1(path string) (string, error) {
	c.mu.Lock()
	base := c.base
	c.mu.Unlock()
	if base == "" {
		return "", errors.New("lantern: no base yet: read the handshake first")
	}
	return c.root + base + "/v1" + path, nil
}

// onOrigin makes an address a document gave absolute: it must be on the server's origin, where
// alone the client's token and signatures go.
func (c *Client) onOrigin(address, what string) (string, error) {
	base, _ := url.Parse(c.root + "/")
	ref, err := url.Parse(address)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %q is not an address", lantern.ErrUnexpectedResponse, what, lantern.Clip(address, 100))
	}
	full := base.ResolveReference(ref).String()
	if o, err := lantern.OriginOf(full); err != nil || o != c.origin {
		return "", fmt.Errorf("%w: %s: %q is not on the server's origin", lantern.ErrUnexpectedResponse, what, lantern.Clip(address, 100))
	}
	return full, nil
}

func (c *Client) build(ctx context.Context, k *call) (*http.Request, error) {
	var target string
	switch {
	case k.rawURL != "":
		target = k.rawURL
	case k.wellKnown:
		target = c.root + "/.well-known/lantern"
	default:
		var err error
		if target, err = c.v1(k.path); err != nil {
			return nil, err
		}
	}
	if len(k.query) > 0 {
		target += "?" + k.query.Encode()
	}
	if ok, err := lantern.PlainHTTPAllowed(target); err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf("%w: %s: plain HTTP is allowed only to a loopback address (SPEC.md § 2)", lantern.ErrInsecureTransport, target)
	}
	body := k.raw
	if k.body != nil {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(k.body); err != nil {
			return nil, err
		}
		body = bytes.TrimRight(buf.Bytes(), "\n")
	}
	req, err := http.NewRequestWithContext(ctx, k.method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body == nil {
		req.Body, req.GetBody, req.ContentLength = http.NoBody, nil, 0
	}
	h := req.Header
	h.Set("User-Agent", c.userAgent)
	h.Set("Accept", "application/json")
	parts := make([]string, len(lantern.Families))
	for i, f := range lantern.Families {
		parts[i] = fmt.Sprintf("%s=%d", f, lantern.Schema)
	}
	h.Set("Accept-Schema", strings.Join(parts, ", "))
	if c.language != "" {
		h.Set("Accept-Language", c.language)
	}
	if c.platform != "" {
		h.Set("Lantern-Platform", c.platform)
	}
	if k.body != nil {
		h.Set("Content-Type", "application/json")
	}
	for name, values := range k.headers {
		h[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
	}
	if o, err := lantern.OriginOf(target); err == nil && o == c.origin {
		c.mu.Lock()
		token, key := c.token, c.key
		c.mu.Unlock()
		if !k.anonymous && token != "" {
			h.Set("Authorization", "Bearer "+token)
		}
		signer := k.signer
		if signer == nil && !k.anonymous {
			signer = key
		}
		if signer != nil {
			if err := lantern.SignRequest(signer, k.method, target, h, body, lantern.SignOptions{Created: c.now().Unix()}); err != nil {
				return nil, err
			}
		}
	}
	return req, nil
}

// send makes a call and reads the whole answer: at most limit bytes of it. A request refused for
// its signature is signed again once (SPEC.md § 5.4, Annex B.2): after signature_expired with the
// server's Date taken, or after signature_replayed with a new nonce.
func (c *Client) send(ctx context.Context, k *call, limit int64) (*response, error) {
	if !k.wellKnown && k.rawURL == "" {
		c.mu.Lock()
		have := c.base != ""
		c.mu.Unlock()
		if !have {
			if _, err := c.Handshake(ctx); err != nil {
				return nil, err
			}
		}
	}
	for attempt := 0; ; attempt++ {
		req, err := c.build(ctx, k)
		if err != nil {
			return nil, err
		}
		resp, err := c.do(ctx, req, limit, k.timeout)
		if err != nil {
			return nil, err
		}
		if resp.status < 400 {
			return resp, nil
		}
		perr := lantern.NewProblemError(resp.status, resp.body, flat(resp.header))
		if attempt == 0 && req.Header.Get("Signature") != "" && c.resign(perr, resp.header) {
			continue
		}
		return resp, perr
	}
}

func (c *Client) resign(err *lantern.ProblemError, h http.Header) bool {
	switch {
	case errors.Is(err, lantern.ErrSignatureExpired):
		return c.adjustClock(h)
	case errors.Is(err, lantern.ErrSignatureReplayed):
		return true
	}
	return false
}

func flat(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

func (c *Client) do(ctx context.Context, req *http.Request, limit int64, longer time.Duration) (*response, error) {
	ctx, cancel := context.WithTimeout(ctx, max(c.timeout, longer))
	defer cancel()
	resp, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		var pin *lantern.PinMismatchError
		if errors.As(err, &pin) {
			return nil, pin
		}
		return nil, fmt.Errorf("%w: %w", lantern.ErrTransport, err)
	}
	defer resp.Body.Close()
	if err := c.checkPin(resp); err != nil {
		return nil, err
	}
	max := limit
	if resp.StatusCode >= 400 {
		max = errorBody
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", lantern.ErrTransport, err)
	}
	if int64(len(body)) > max {
		if resp.StatusCode >= 400 {
			body = body[:max] // an error's body is cut: its status still tells
		} else {
			return nil, &lantern.DocumentError{Where: "response", Reason: fmt.Sprintf("a body above %d bytes", limit)}
		}
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: body}, nil
}

// checkPin remembers the key a connection showed and, for a transport of the application's own
// (which cannot check it before the request), checks it against the pin afterwards.
func (c *Client) checkPin(resp *http.Response) error {
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil
	}
	seen := spki(resp.TLS.PeerCertificates[0])
	c.mu.Lock()
	c.lastSPKI = seen
	pin := c.pin
	c.mu.Unlock()
	if pin != "" && !lantern.CheckPin(seen, pin) {
		return &lantern.PinMismatchError{Seen: seen, Pinned: pin, Where: c.origin.Host}
	}
	return nil
}

func (c *Client) note(what string, h http.Header) {
	since := h.Get("Deprecation")
	if since == "" {
		return
	}
	d := Deprecation{What: what, Since: lantern.Printable(since, 64), Sunset: lantern.Printable(h.Get("Sunset"), 64)}
	for _, l := range strings.Split(h.Get("Link"), ",") {
		if strings.Contains(l, `rel="deprecation"`) {
			d.Link = strings.Trim(strings.TrimSpace(strings.Split(l, ";")[0]), "<>")
			break
		}
	}
	c.mu.Lock()
	for _, e := range c.deprecated {
		if e == d {
			c.mu.Unlock()
			return
		}
	}
	c.deprecated = append(c.deprecated, d)
	c.mu.Unlock()
	slog.Warn("lantern: deprecated", "what", what, "since", d.Since, "sunset", d.Sunset, "link", d.Link)
}

// serverOffset is the offset of the server's Date to this device's clock; false without a Date.
func serverOffset(h http.Header) (time.Duration, bool) {
	t, err := http.ParseTime(h.Get("Date"))
	if err != nil {
		return 0, false
	}
	return time.Until(t), true
}

// adjustClock takes the offset of the server's Date (after a 401 signature_expired, SPEC.md
// § 5.4); false when the answer has no Date to take it from, or it would change nothing.
func (c *Client) adjustClock(h http.Header) bool {
	offset, ok := serverOffset(h)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !ok || (offset-c.clockOffset).Abs() < time.Second {
		return false
	}
	c.clockOffset = offset
	return true
}

// observeClock: after the handshake (Annex B.9), a clock off by half the server's window or more
// is signed with the server's time from then on.
func (c *Client) observeClock(h http.Header, hello *lantern.Handshake) {
	skew := int64(lantern.DefaultSkew)
	if hello.Auth != nil {
		skew = hello.Auth.Skew
	}
	offset, ok := serverOffset(h)
	c.mu.Lock()
	defer c.mu.Unlock()
	if ok && (offset-c.clockOffset).Abs() >= time.Duration(skew)*time.Second/2 {
		c.clockOffset = offset
	}
}

// read is a JSON answer, read by the schema rule.
func read[T any, P interface {
	*T
	json.Unmarshaler
}](c *Client, what string, resp *response) (*T, error) {
	c.note(what, resp.header)
	if mt, _, _ := strings.Cut(resp.header.Get("Content-Type"), ";"); strings.ToLower(strings.TrimSpace(mt)) != "application/json" {
		return nil, fmt.Errorf("%w: %s: Content-Type %q, not JSON", lantern.ErrUnexpectedResponse, what, lantern.Clip(resp.header.Get("Content-Type"), 80))
	}
	return lantern.Parse[T, P](resp.body)
}

// expect is the answer of a call, when its status is one of statuses (an error otherwise).
func (c *Client) expect(resp *response, what string, statuses ...int) error {
	for _, s := range statuses {
		if resp.status == s {
			return nil
		}
	}
	if resp.status >= 300 && resp.status < 400 {
		return fmt.Errorf("%w: %s: a redirect (%d), which Lantern never sends", lantern.ErrUnexpectedResponse, what, resp.status)
	}
	return fmt.Errorf("%w: %s: status %d", lantern.ErrUnexpectedResponse, what, resp.status)
}

// Handshake reads /.well-known/lantern (SPEC.md § 4): who the server is, what it offers, and the
// base of its API. The client needs it before any other call, and reads it on its own when it
// has not.
func (c *Client) Handshake(ctx context.Context) (*lantern.Handshake, error) {
	resp, err := c.send(ctx, &call{method: http.MethodGet, wellKnown: true, what: "handshake"}, lantern.MaxJSONDocument)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, "handshake", http.StatusOK); err != nil {
		return nil, err
	}
	hello, err := read[lantern.Handshake](c, "handshake", resp)
	if err != nil {
		return nil, err
	}
	supported := false
	for _, v := range hello.Versions {
		supported = supported || v == 1
	}
	if !supported {
		return nil, errors.New("lantern: the server does not serve version 1 of the protocol")
	}
	c.mu.Lock()
	if c.base == "" {
		base, err := checkBase(hello.Base)
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		c.base = base
	}
	c.hello = hello
	c.mu.Unlock()
	c.observeClock(resp.header, hello)
	return hello, nil
}
