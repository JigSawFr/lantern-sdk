// SPDX-License-Identifier: MIT

package client_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/client"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

// The client against the specification's reference server (spec/server), started by the harness
// of the TypeScript library (typescript/test/fixtures/reference.py) over its fictional library.
// It needs a Python with the `cryptography` package: LANTERN_PYTHON names it, and the tests are
// skipped without it.

type reference struct {
	URL       string `json:"url"`
	SPKI      string `json:"spki"`
	Switch    int    `json:"switch"`
	Served    int    `json:"served"`
	Token     string `json:"token"`
	AdminTok  string `json:"admin_token"`
	AdminSeed string `json:"admin_seed"`
	OldToken  string `json:"old_token"`
}

func startReference(t *testing.T, args ...string) *reference {
	t.Helper()
	python := os.Getenv("LANTERN_PYTHON")
	if python == "" {
		t.Skip("LANTERN_PYTHON is not set: no reference server to start")
	}
	harness := filepath.Join(testutil.SpecDir(t), "..", "typescript", "test", "fixtures", "reference.py")
	cmd := exec.Command(python, append([]string{harness}, args...)...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
		}
	})
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(out).ReadString('\n')
		line <- s
	}()
	var ref reference
	select {
	case s := <-line:
		if err := json.Unmarshal([]byte(s), &ref); err != nil {
			t.Fatalf("the harness said %q: %v\n%s", s, err, stderr.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("the reference server is not ready\n%s", stderr.String())
	}
	return &ref
}

func TestReferencePublicLibrary(t *testing.T) {
	ref := startReference(t, "--public")
	ctx := context.Background()
	c, err := client.New(ref.URL, client.Options{Token: ref.Token})
	if err != nil {
		t.Fatal(err)
	}
	hello, err := c.Handshake(ctx)
	if err != nil || hello.Base != "/api/lantern" {
		t.Fatalf("%v", err)
	}
	for _, family := range []string{"library", "titles", "changes", "homebrew", "cheats", "pairing"} {
		if ok, _ := c.Offers(ctx, family); !ok {
			t.Errorf("%s is not offered", family)
		}
	}
	if ok, _ := c.Offers(ctx, "saves"); ok {
		t.Error("saves are offered")
	}

	t.Run("apps, pages and platforms", func(t *testing.T) {
		ids := map[string]bool{}
		for app, err := range c.Apps(ctx, client.ListOptions{PageSize: 2}) {
			if err != nil {
				t.Fatal(err)
			}
			ids[app.ID] = true
		}
		if len(ids) != ref.Served {
			t.Fatalf("%d apps, the library has %d", len(ids), ref.Served)
		}
		n := 0
		for _, err := range c.Apps(ctx, client.ListOptions{Platform: "switch"}) {
			if err != nil {
				t.Fatal(err)
			}
			n++
		}
		if n != ref.Switch {
			t.Fatalf("%d switch apps, want %d", n, ref.Switch)
		}
		page, err := c.AppsPage(ctx, client.ListOptions{PageSize: 3, Sort: "added"}, "")
		if err != nil || len(page.Items) != 3 || page.Next == nil || page.Total == nil || int(*page.Total) != ref.Served {
			t.Fatalf("%+v %v", page, err)
		}
		if _, err := c.AppsPage(ctx, client.ListOptions{}, "c_never_given"); !errors.Is(err, lantern.ErrBadRequest) && !errors.Is(err, lantern.ErrGone) {
			t.Fatalf("%v", err)
		}
	})

	t.Run("what is missing", func(t *testing.T) {
		var got []string
		for app, err := range c.Missing(ctx, client.MissingOptions{Platform: "switch", Want: []string{"update", "dlc"},
			Installed: []lantern.InstalledApp{{AppID: "0100ABCD00010000", VersionCode: 0}}}) {
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, app.AppID+" "+itoa(app.VersionCode))
		}
		slices.Sort(got)
		if strings.Join(got, ",") != "0100ABCD00010800 196608,0100ABCD00011001 0" {
			t.Fatalf("%v", got)
		}
		var bases []string
		for app, err := range c.Missing(ctx, client.MissingOptions{Platform: "android", Want: []string{"base"}}) {
			if err != nil {
				t.Fatal(err)
			}
			bases = append(bases, app.TitleID)
		}
		if strings.Join(bases, ",") != "org.example.frostlinetales" {
			t.Fatalf("%v", bases)
		}
	})

	t.Run("changes and titles", func(t *testing.T) {
		first, err := c.Changes(ctx, "", "")
		if err != nil || len(first.Added) != 0 || len(first.Removed) != 0 || first.Since == "" {
			t.Fatalf("%+v %v", first, err)
		}
		if next, err := c.Changes(ctx, first.Since, ""); err != nil || next.Since == "" {
			t.Fatalf("%v", err)
		}
		if _, err := c.Changes(ctx, "s_never_given", ""); !errors.Is(err, lantern.ErrBadRequest) && !errors.Is(err, lantern.ErrGone) {
			t.Fatalf("%v", err)
		}
		title, err := c.Title(ctx, "0100ABCD00010000", "switch")
		if err != nil || title.Name != "Frostline Tales" || title.Video == nil || !title.Video.External {
			t.Fatalf("%v", err)
		}
		if g := title.EffectiveGenres(); strings.Join(g, ",") != "adventure,puzzle" {
			t.Fatalf("%v", g)
		}
		titles, unknown, err := c.Titles(ctx, []string{"0100ABCD00010000", "0100EFEF00020000", "0500000000000000"}, "switch")
		if err != nil || len(titles) != 2 || len(unknown) != 1 || unknown[0] != "0500000000000000" {
			t.Fatalf("%d, %v, %v", len(titles), unknown, err)
		}
		if _, err := c.Title(ctx, "0500000000000000", "switch"); !errors.Is(err, lantern.ErrNotFound) {
			t.Fatalf("%v", err)
		}
		if _, err := c.TitleChanges(ctx, "", ""); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("downloads, resumed, and refused when not their document's", func(t *testing.T) {
		var biggest *lantern.App
		for app, err := range c.Apps(ctx, client.ListOptions{Platform: "switch"}) {
			if err != nil {
				t.Fatal(err)
			}
			if biggest == nil || app.Size > biggest.Size {
				biggest = app
			}
		}
		dir := t.TempDir()
		whole := filepath.Join(dir, "game.nsp")
		if err := c.Download(ctx, biggest, whole, nil); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(whole)
		if lantern.SHA256Hex(data) != biggest.SHA256 || int64(len(data)) != biggest.Size {
			t.Fatal("not the app's bytes")
		}
		again := filepath.Join(dir, "again.nsp")
		os.WriteFile(again+".part", data[:len(data)/3], 0o600)
		if err := c.Download(ctx, biggest, again, nil); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(again); !bytes.Equal(got, data) {
			t.Fatal("the resumed file differs")
		}
		wrong := *biggest
		wrong.SHA256 = strings.Repeat("0", 64)
		if err := c.Download(ctx, &wrong, filepath.Join(dir, "wrong.nsp"), nil); !errors.Is(err, lantern.ErrIntegrity) {
			t.Fatalf("%v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "wrong.nsp")); !os.IsNotExist(err) {
			t.Fatal("a refused file was kept")
		}
	})

	t.Run("credentials", func(t *testing.T) {
		bad, _ := client.New(ref.URL, client.Options{Token: "et_not-a-token"})
		if _, err := bad.Handshake(ctx); !errors.Is(err, lantern.ErrUnauthorized) {
			t.Fatalf("%v", err)
		}
		anon, _ := client.New(ref.URL, client.Options{})
		h, err := anon.Handshake(ctx)
		if err != nil || h.Account.State != "anonymous" {
			t.Fatalf("%v", err)
		}
	})
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

// adminDo sends a request signed by the admin's device key to the reference server over its
// self-signed TLS key, for what the Go client does not do (the administration API).
func adminDo(t *testing.T, ref *reference, method, path string, body any) (int, []byte) {
	t.Helper()
	key, err := lantern.SigningKeyFromBase64(ref.AdminSeed)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, ref.URL+strings.TrimPrefix(path, "/"), bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+ref.AdminTok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := lantern.SignRequest(key, method, req.URL.String(), req.Header, raw, lantern.SignOptions{Created: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func TestReferencePairingOverPinnedTLS(t *testing.T) {
	ref := startReference(t, "--tls")
	if ref.SPKI == "" {
		t.Fatal("no key to pin")
	}
	ctx := context.Background()

	// a device that has never met the server reads its key, shows it, and pairs
	c, err := client.New(ref.URL, client.Options{Platform: "switch", TrustOnFirstUse: true})
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Pair(ctx, "Lea's console", []string{"library", "saves"}, client.PairOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p.SPKI != ref.SPKI {
		t.Fatalf("the key seen is %s, the server's is %s", p.SPKI, ref.SPKI)
	}
	// the account's owner approves it, with the admin API, signed
	status, body := adminDo(t, ref, "GET", "/api/lantern/v1/admin/pairings", nil)
	if status != 200 {
		t.Fatalf("admin pairings %d %s", status, body)
	}
	waiting, err := lantern.Parse[lantern.AdminPairings](body)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, w := range waiting.Items {
		if w.Code == p.Code() {
			id = w.ID
			if w.Key == nil || *w.Key != p.Key.Fingerprint() {
				t.Fatalf("the server shows key %v, the device's is %s", w.Key, p.Key.Fingerprint())
			}
		}
	}
	if id == "" {
		t.Fatal("the pairing is not waiting")
	}
	user, one := "lea", int64(1)
	if status, body := adminDo(t, ref, "POST", "/api/lantern/v1/admin/pairings/"+id, lantern.AdminPairingDecision{Schema: &one, Decision: "approve", User: &user}); status != 204 {
		t.Fatalf("approve %d %s", status, body)
	}
	p.Interval = 100 * time.Millisecond
	store := &lantern.MemoryServerStore{}
	record, err := c.WaitForPairing(ctx, p, store)
	if err != nil {
		t.Fatal(err)
	}
	if !record.Bound || record.SPKI != ref.SPKI || record.Token == "" {
		t.Fatalf("%+v", record)
	}

	// the paired device reads with its token, signed, over the pinned key
	paired, err := client.Paired(record, client.Options{Platform: "switch"})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, err := range paired.Apps(ctx, client.ListOptions{}) {
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != ref.Switch {
		t.Fatalf("%d apps", n)
	}
	// the same token without its key is refused: it is bound
	bearerOnly, _ := client.New(ref.URL, client.Options{Token: record.Token, Pin: ref.SPKI})
	_, err = bearerOnly.Handshake(ctx)
	if !errors.Is(err, lantern.ErrSignatureRequired) && !errors.Is(err, lantern.ErrUnauthorized) {
		t.Fatalf("a bound token without its signature: %v", err)
	}
	// another key pinned: refused before a byte is sent
	other := strings.Repeat("ab", 32)
	wrong, _ := client.New(ref.URL, client.Options{Pin: other})
	var pin *lantern.PinMismatchError
	if _, err := wrong.Handshake(ctx); !errors.As(err, &pin) || !errors.Is(err, lantern.ErrPinMismatch) {
		t.Fatalf("%v", err)
	}
}
