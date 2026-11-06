// SPDX-License-Identifier: MIT

package client_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/client"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

// shelf is a small Lantern server for the tests: the handshake, pairing and one signed route.
type shelf struct {
	t       *testing.T
	mu      sync.Mutex
	public  ed25519.PublicKey
	polls   int
	seen    []*http.Request
	expire  bool   // answer the first signed request signature_expired, with a Date an hour ahead
	replay  bool   // answer the first signed request signature_replayed
	poll    string // a poll address to give instead of the shelf's own
	tooMany bool   // answer the first poll 429
	url     string
	hello   []byte
}

func newShelf(t *testing.T) *shelf {
	return &shelf{t: t, hello: testutil.Read(t, "examples", "v1", "handshake.json")}
}

func (s *shelf) problem(w http.ResponseWriter, status int, code string, extra map[string]string) {
	for k, v := range extra {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"schema":1,"status":%d,"code":%q,"title":"x"}`, status, code)
}

func (s *shelf) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, r.Clone(r.Context()))
	w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
	json := func(status int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}
	switch {
	case r.URL.Path == "/.well-known/lantern":
		json(200, string(s.hello))
	case r.URL.Path == "/api/lantern/v1/pairing" && r.Method == "POST":
		var req lantern.PairingRequest
		buf := make([]byte, 1<<16)
		n, _ := r.Body.Read(buf)
		if err := req.UnmarshalJSON(buf[:n]); err != nil {
			s.problem(w, 400, "bad_request", nil)
			return
		}
		if req.Key != nil {
			raw, _ := base64.StdEncoding.DecodeString(req.Key.PublicKey)
			s.public = raw
		}
		poll := "/api/lantern/v1/pairing/p_1"
		if s.poll != "" {
			poll = s.poll
		}
		json(200, fmt.Sprintf(`{"schema":1,"code":"KQ4M-7TXD","verify":"%s/pair","verify_complete":"%s/pair?code=KQ4M-7TXD","poll":%q,"interval":1,"expires":60}`, s.url, s.url, poll))
	case r.URL.Path == "/api/lantern/v1/pairing/p_1":
		s.polls++
		switch {
		case s.tooMany && s.polls == 1:
			s.problem(w, 429, "slow_down", map[string]string{"Retry-After": "1"})
		case s.polls < 3:
			w.WriteHeader(202)
		default:
			json(200, `{"schema":1,"token":"et_test","scopes":["library"],"bound":true,"future":[1]}`)
		}
	case r.URL.Path == "/api/lantern/v1/apps":
		switch {
		case s.expire:
			s.expire = false
			s.problem(w, 401, "signature_expired", map[string]string{"Date": time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)})
		case s.replay:
			s.replay = false
			s.problem(w, 401, "signature_replayed", nil)
		default:
			json(200, `{"schema":1,"items":[]}`)
		}
	case r.URL.Path == "/redirect":
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	default:
		s.problem(w, 404, "not_found", nil)
	}
}

// verify checks a request's signature the way SPEC.md § 5.4 says, against the key paired.
func (s *shelf) verify(r *http.Request, wantAuth bool) (created int64, err error) {
	if (r.Header.Get("Authorization") != "") != wantAuth {
		return 0, fmt.Errorf("authorization present: %v", !wantAuth)
	}
	input := strings.TrimPrefix(r.Header.Get("Signature-Input"), "lantern=")
	sig := strings.TrimSuffix(strings.TrimPrefix(r.Header.Get("Signature"), "lantern=:"), ":")
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return 0, err
	}
	uri, err := lantern.ReceivedURI("http", r.Host, r.URL.RequestURI())
	if err != nil {
		return 0, err
	}
	var auth *string
	if v := r.Header.Get("Authorization"); v != "" {
		auth = &v
	}
	base := lantern.SignatureBase(r.Method, uri, auth, nil, input)
	if !ed25519.Verify(s.public, []byte(base), raw) {
		return 0, errors.New("the signature does not verify")
	}
	fmt.Sscanf(input[strings.Index(input, "created=")+8:], "%d", &created)
	return created, nil
}

func serve(t *testing.T, s *shelf, tls bool) *httptest.Server {
	var srv *httptest.Server
	if tls {
		srv = httptest.NewTLSServer(s)
	} else {
		srv = httptest.NewServer(s)
	}
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return srv
}

func TestHandshakeAndErrors(t *testing.T) {
	s := newShelf(t)
	srv := serve(t, s, false)
	c, err := client.New(srv.URL, client.Options{Platform: "switch"})
	if err != nil {
		t.Fatal(err)
	}
	hello, err := c.Handshake(t.Context())
	if err != nil || hello.UID == "" || hello.Base != "/api/lantern" {
		t.Fatalf("%+v %v", hello, err)
	}
	if ok, _ := c.Offers(t.Context(), "library"); !ok {
		t.Error("library is offered")
	}
	if ok, _ := c.Offers(t.Context(), "admin"); ok {
		t.Error("admin is level 0")
	}
	first := s.seen[0]
	for name, want := range map[string]string{"Lantern-Platform": "switch", "Accept": "application/json"} {
		if first.Header.Get(name) != want {
			t.Errorf("%s: %q", name, first.Header.Get(name))
		}
	}
	if !strings.HasPrefix(first.Header.Get("User-Agent"), "LanternGo/") || !strings.Contains(first.Header.Get("Accept-Schema"), "library=1") {
		t.Errorf("headers %v", first.Header)
	}
	if first.Header.Get("Authorization") != "" {
		t.Error("a token that was never given")
	}
}

func TestPlainHTTPIsLoopbackOnly(t *testing.T) {
	if _, err := client.New("http://nas.example.org/", client.Options{}); !errors.Is(err, lantern.ErrInsecureTransport) {
		t.Fatalf("%v", err)
	}
	if _, err := client.New("http://127.0.0.1:1/", client.Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.New("https://h/", client.Options{UserAgent: "nobody"}); err == nil {
		t.Error("a User-Agent without a version")
	}
	if _, err := client.New("https://h/", client.Options{Pin: "xyz"}); err == nil {
		t.Error("a pin that is not a hash")
	}
}

func TestPairingSignsEveryRequest(t *testing.T) {
	s := newShelf(t)
	srv := serve(t, s, false)
	c, _ := client.New(srv.URL, client.Options{})
	ctx := t.Context()
	p, err := c.Pair(ctx, "Lea's Switch", []string{"library", "library"}, client.PairOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Code() != "KQ4M-7TXD" || p.Key == nil || p.Fingerprint() != "" || !strings.HasSuffix(p.PollURL, "/pairing/p_1") {
		t.Fatalf("%+v", p)
	}
	store := &lantern.MemoryServerStore{}
	p.Interval = 10 * time.Millisecond
	record, err := c.WaitForPairing(ctx, p, store)
	if err != nil {
		t.Fatal(err)
	}
	if record.Token != "et_test" || !record.Bound || record.Key != p.Key.SeedBase64() || record.UID == "" || record.URL != srv.URL+"/" {
		t.Fatalf("%+v", record)
	}
	if got, _ := store.Server(record.UID); got != record {
		t.Fatal("not stored")
	}
	// the polls were signed by the device key, without a token; the pairing request itself was anonymous
	polls := 0
	for _, r := range s.seen {
		switch r.URL.Path {
		case "/api/lantern/v1/pairing":
			if r.Header.Get("Authorization") != "" || r.Header.Get("Signature") != "" {
				t.Error("the pairing request carries credentials")
			}
		case "/api/lantern/v1/pairing/p_1":
			polls++
			if _, err := s.verify(r, false); err != nil {
				t.Errorf("poll: %v", err)
			}
		}
	}
	if polls != 3 {
		t.Errorf("%d polls", polls)
	}
	// from now on: the token, and the signature over it
	if _, err := c.Handshake(ctx); err != nil {
		t.Fatal(err)
	}
	later, err := client.Paired(record, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.seen = nil
	if _, err := later.Handshake(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSignatureRetries(t *testing.T) {
	s := newShelf(t)
	srv := serve(t, s, false)
	key, _ := lantern.GenerateSigningKey()
	s.public = key.Public()
	c, _ := client.New(srv.URL, client.Options{Token: "et_x", Key: key})
	ctx := t.Context()
	if _, err := c.Handshake(ctx); err != nil {
		t.Fatal(err)
	}
	s.seen = nil
	s.expire = true
	resp, err := c.GetForTest(ctx, "/apps")
	if err != nil || resp != 200 {
		t.Fatalf("%d %v", resp, err)
	}
	var created []int64
	for _, r := range s.seen {
		n, err := s.verify(r, true)
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, n)
	}
	if len(created) != 2 || created[1]-created[0] < 3500 || c.ClockOffset() < 59*time.Minute {
		t.Fatalf("created %v, offset %v", created, c.ClockOffset())
	}
	// signature_replayed: signed again with a new nonce
	s.seen = nil
	s.replay = true
	if _, err := c.GetForTest(ctx, "/apps"); err != nil {
		t.Fatal(err)
	}
	if len(s.seen) != 2 || s.seen[0].Header.Get("Signature-Input") == s.seen[1].Header.Get("Signature-Input") {
		t.Fatal("the nonce is the same")
	}
	// not found: the status is the kind, the code is the server's
	_, err = c.GetForTest(ctx, "/nowhere")
	var p *lantern.ProblemError
	if !errors.Is(err, lantern.ErrNotFound) || !errors.As(err, &p) || p.Code != "not_found" {
		t.Fatalf("%v", err)
	}
}

func TestSlowDownAndRedirects(t *testing.T) {
	s := newShelf(t)
	s.tooMany = true
	srv := serve(t, s, false)
	c, _ := client.New(srv.URL, client.Options{})
	ctx := t.Context()
	p, err := c.Pair(ctx, "d", []string{"library"}, client.PairOptions{Bearer: true})
	if err != nil || p.Key != nil {
		t.Fatalf("%v %v", p, err)
	}
	p.Interval = time.Millisecond
	start := time.Now()
	if _, err := c.WaitForPairing(ctx, p, nil); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 5*time.Second { // slow_down: the interval grows by 5 s at least
		t.Errorf("only %v", time.Since(start))
	}
}

func TestRedirectIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	c, _ := client.New(srv.URL, client.Options{})
	if _, err := c.Handshake(t.Context()); !errors.Is(err, lantern.ErrUnexpectedResponse) {
		t.Fatalf("%v", err)
	}
}

func TestPinAndTrustOnFirstUse(t *testing.T) {
	s := newShelf(t)
	srv := serve(t, s, true)
	ctx := t.Context()
	// no CA vouches for the test certificate: refused
	plain, _ := client.New(srv.URL, client.Options{})
	if _, err := plain.Handshake(ctx); !errors.Is(err, lantern.ErrTransport) {
		t.Fatalf("an unknown certificate is taken: %v", err)
	}
	// a wrong pin: dropped before anything is sent
	wrong, _ := client.New(srv.URL, client.Options{Pin: strings.Repeat("ab", 32)})
	before := len(s.seen)
	_, err := wrong.Handshake(ctx)
	var pm *lantern.PinMismatchError
	if !errors.Is(err, lantern.ErrPinMismatch) || !errors.As(err, &pm) || pm.Pinned != strings.Repeat("ab", 32) {
		t.Fatalf("%v", err)
	}
	if len(s.seen) != before {
		t.Fatal("a request reached a server whose key is not the pinned one")
	}
	// the first use: the key is read, shown, pinned
	c, _ := client.New(srv.URL, client.Options{TrustOnFirstUse: true})
	p, err := c.Pair(ctx, "d", []string{"library"}, client.PairOptions{})
	if err != nil {
		t.Fatal(err)
	}
	der := srv.Certificate().Raw
	want, _ := lantern.SPKISHA256(der)
	if p.SPKI != want || p.Fingerprint() == "" {
		t.Fatalf("spki %s, want %s", p.SPKI, want)
	}
	p.Interval = time.Millisecond
	record, err := c.WaitForPairing(ctx, p, nil)
	if err != nil || record.SPKI != want {
		t.Fatalf("%+v %v", record, err)
	}
	// later: the pin does it
	later, err := client.Paired(record, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := later.Handshake(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDeprecation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Deprecation", "@1793318400")
		w.Header().Set("Sunset", "Wed, 11 Nov 2026 23:59:59 GMT")
		w.Header().Set("Link", `<https://example.org/new>; rel="deprecation"`)
		_, _ = w.Write(testutil.Read(t, "examples", "v1", "handshake.json"))
	}))
	defer srv.Close()
	c, _ := client.New(srv.URL, client.Options{})
	if _, err := c.Handshake(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Handshake(t.Context())
	d := c.Deprecations()
	if len(d) != 1 || d[0].Since != "@1793318400" || d[0].Link != "https://example.org/new" {
		t.Fatalf("%+v", d)
	}
}

func TestNewerSchemaHandshakeIsAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema":2,"anything":true}`))
	}))
	defer srv.Close()
	c, _ := client.New(srv.URL, client.Options{})
	if _, err := c.Handshake(t.Context()); !errors.Is(err, lantern.ErrNewerSchema) {
		t.Fatalf("%v", err)
	}
	if c.Hello() != nil {
		t.Fatal("a handshake of a newer schema is kept")
	}
}

func TestPollOnAnotherOriginIsRefused(t *testing.T) {
	s := newShelf(t)
	s.poll = "https://evil.example.org/p"
	srv := serve(t, s, false)
	c, _ := client.New(srv.URL, client.Options{})
	if _, err := c.Pair(t.Context(), "d", []string{"library"}, client.PairOptions{}); err == nil {
		t.Fatal("a poll address on another origin is taken")
	}
}
