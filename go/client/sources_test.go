// SPDX-License-Identifier: MIT

package client_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/client"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

// A server that offers grants, with a grant key of its own, and a file.
type granter struct {
	d       *depot
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	uid     string
	file    []byte
	lifeSec int64
	badSize bool
	other   bool // signs with another key
}

func newGranter(t *testing.T) (*granter, *client.Client) {
	d, c := newDepot(t)
	g := &granter{d: d, uid: "6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14", file: bigFile(), lifeSec: 600}
	g.pub, g.priv, _ = ed25519.GenerateKey(nil)
	var hello map[string]any
	json.Unmarshal(testutil.Read(t, "examples", "v1", "handshake.json"), &hello)
	hello["peers"] = map[string]any{"key": base64.StdEncoding.EncodeToString(g.pub), "grant_lifetime": 600}
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/lantern":
			writeJSON(w, 200, hello)
		case strings.HasPrefix(r.URL.Path, "/api/lantern/v1/grants/sha256/"):
			sha := strings.TrimPrefix(r.URL.Path, "/api/lantern/v1/grants/sha256/")
			if sha != sum(g.file) {
				writeJSON(w, 404, map[string]any{"schema": 1, "status": 404, "code": "not_found", "title": "x"})
				return
			}
			key := g.priv
			if g.other {
				_, key, _ = ed25519.GenerateKey(nil)
			}
			exp := time.Now().Unix() + g.lifeSec
			grant, _ := lantern.SignGrant(key, g.uid, sha, int64(len(g.file)), exp)
			size := int64(len(g.file))
			if g.badSize {
				size++
			}
			writeJSON(w, 200, map[string]any{"schema": 1, "sha256": sha, "size": size, "grant": grant, "expires": time.Unix(exp, 0).UTC().Format(time.RFC3339)})
		default:
			http.NotFound(w, r)
		}
	}
	return g, c
}

func TestGrantIsCheckedBeforeItIsGiven(t *testing.T) {
	g, c := newGranter(t)
	ctx := context.Background()
	got, err := c.Grant(ctx, sum(g.file))
	if err != nil || got.Size != int64(len(g.file)) {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := c.Grant(ctx, strings.Repeat("a", 64)); !errors.Is(err, lantern.ErrNotFound) {
		t.Errorf("a file the server does not have: %v", err)
	}
	for name, mend := range map[string]func(){
		"another key":                    func() { g.other = true },
		"a size that is not the grant's": func() { g.other, g.badSize = false, true },
		"too long a life":                func() { g.badSize, g.lifeSec = false, 3600 },
	} {
		mend()
		if _, err := c.Grant(ctx, sum(g.file)); !errors.Is(err, lantern.ErrUnexpectedResponse) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A peer or a mirror: a file server that records what it was sent.
type source struct {
	file     []byte
	grant    string // the grant a peer wants ("" for a mirror)
	wrong    bool
	status   int
	hits     atomic.Int32
	sentAuth atomic.Bool
}

func (s *source) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.hits.Add(1)
	if r.Header.Get("Authorization") != "" || r.Header.Get("Signature") != "" || r.Header.Get("Cookie") != "" {
		s.sentAuth.Store(true)
	}
	if s.status != 0 {
		w.WriteHeader(s.status)
		return
	}
	if s.grant != "" && r.Header.Get(lantern.GrantHeader) != s.grant {
		writeJSON(w, 403, map[string]any{"schema": 1, "status": 403, "code": "forbidden", "title": "x"})
		return
	}
	data := s.file
	if s.wrong {
		data = append([]byte(nil), data...)
		data[len(data)/2] ^= 0xff
	}
	http.ServeContent(w, r, "f", time.Time{}, bytesReader(data))
}

func TestDownloadViaPassesBadSourcesByAndSendsThemNoCredential(t *testing.T) {
	g, c := newGranter(t)
	c.SetToken("secret-token", nil)
	grant, err := c.Grant(context.Background(), sum(g.file))
	if err != nil {
		t.Fatal(err)
	}
	liar := &source{file: g.file, grant: grant.Grant, wrong: true}
	good := &source{file: g.file, grant: grant.Grant}
	mirror := &source{file: g.file}
	app := fileApp(g.file, "/api/lantern/v1/files/f_x")
	g.d.file = g.file
	peerOf := func(s *source) lantern.Peer {
		srv := httptestServer(t, s)
		return lantern.Peer{URL: srv + "/lantern", Name: "p", UID: "p", Slots: 1}
	}
	// the liar's bytes fail the check, the good peer's pass: the mirror is not asked
	app.Mirrors = []lantern.Mirror{{URL: httptestServer(t, mirror) + "/f"}}
	dir := t.TempDir()
	path := filepath.Join(dir, "f.nsp")
	from, err := c.DownloadVia(context.Background(), app, path, client.Sources{Peers: []lantern.Peer{peerOf(liar), peerOf(good)}, Mirrors: true}, nil)
	if err != nil || from != "peer" {
		t.Fatalf("%q %v", from, err)
	}
	if got, _ := os.ReadFile(path); sum(got) != sum(g.file) {
		t.Fatal("the file is not the server's")
	}
	if mirror.hits.Load() != 0 || liar.hits.Load() == 0 {
		t.Errorf("hits: mirror %d, liar %d", mirror.hits.Load(), liar.hits.Load())
	}
	// no peer works (they refuse), the mirror gives the file
	os.Remove(path)
	refusing := &source{file: g.file, status: 503}
	from, err = c.DownloadVia(context.Background(), app, path, client.Sources{Peers: []lantern.Peer{peerOf(refusing)}, Mirrors: true}, nil)
	if err != nil || from != "mirror" {
		t.Fatalf("%q %v", from, err)
	}
	// a mirror that serves other bytes: the server gives the file
	os.Remove(path)
	mirror.wrong = true
	from, err = c.DownloadVia(context.Background(), app, path, client.Sources{Mirrors: true}, nil)
	if err != nil || from != "server" {
		t.Fatalf("%q %v", from, err)
	}
	for name, s := range map[string]*source{"liar": liar, "good": good, "mirror": mirror, "refusing": refusing} {
		if s.sentAuth.Load() {
			t.Errorf("%s was sent a credential of the server", name)
		}
	}
	if _, err := c.OpenMirror(context.Background(), "http://8.8.8.8/f", app.Size, app.SHA256, 0, nil); err == nil {
		t.Error("a mirror over plain HTTP at a public address")
	}
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func httptestServer(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}
