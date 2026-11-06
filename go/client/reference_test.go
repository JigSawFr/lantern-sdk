// SPDX-License-Identifier: MIT

package client_test

import (
	"archive/zip"
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

func TestReferenceHomebrew(t *testing.T) {
	ref := startReference(t, "--public")
	ctx := context.Background()
	c, err := client.New(ref.URL, client.Options{Token: ref.Token})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]*lantern.Homebrew{}
	for e, err := range c.Homebrew(ctx, client.HomebrewOptions{PageSize: 1}) {
		if err != nil {
			t.Fatal(err)
		}
		seen[e.Platform+"/"+e.ID] = e
	}
	if len(seen) < 3 {
		t.Fatalf("%d entries listed", len(seen))
	}
	var ports int
	for key, listed := range seen {
		entry, err := c.HomebrewEntry(ctx, listed.ID, listed.Platform)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if entry.Package.ManifestSHA256 != listed.Package.ManifestSHA256 || entry.Package.SHA256 != listed.Package.SHA256 {
			t.Errorf("%s: the entry and the listing differ", key)
		}
		pkg, ok := lantern.PickPackage(entry, "x86_64")
		if !ok {
			pkg, ok = lantern.PickPackage(entry, "aarch64")
		}
		if !ok {
			t.Errorf("%s: no package fits", key)
			continue
		}
		plan, err := lantern.PlanInstall(entry, pkg)
		if err != nil {
			t.Errorf("%s: %v", key, err)
			continue
		}
		if valid, signed := lantern.VerifySignature(entry, pkg); signed && !valid {
			t.Errorf("%s: the signature does not verify", key)
		}
		if entry.Port != nil {
			ports++
			if problems := lantern.PortProblems(entry); len(problems) != 0 {
				t.Errorf("%s: %v", key, problems)
			}
		}
		if problems := lantern.RequiresProblems(entry); len(problems) != 0 {
			t.Errorf("%s: %v", key, problems)
		}
		dest := filepath.Join(t.TempDir(), "package")
		got, err := c.DownloadPackage(ctx, entry, pkg, dest, nil)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if len(got.Free)+len(got.Consent) != len(plan.Free)+len(plan.Consent) {
			t.Errorf("%s: the plans differ", key)
		}
		if st, err := os.Stat(dest); err != nil || st.Size() != pkg.Size {
			t.Errorf("%s: the package is not there whole", key)
		}
	}
	if ports == 0 {
		t.Error("no port among the entries")
	}
	if _, err := c.HomebrewEntry(ctx, "org.example.nothing", ""); err == nil {
		t.Error("an unknown id gave an entry")
	}
	zero := int64(0)
	count := 0
	for _, err := range c.HomebrewUpdates(ctx, "switch", []client.InstalledHomebrew{{ID: "org.example.frostline", Build: zero}}) {
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count == 0 {
		t.Error("an installed build 0 has no update")
	}
}

func TestReferenceCheatsAndRequests(t *testing.T) {
	ref := startReference(t)
	ctx := context.Background()
	key, err := lantern.SigningKeyFromBase64(ref.AdminSeed)
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(ref.URL, client.Options{Token: ref.AdminTok, Key: key, Platform: "switch"})
	if err != nil {
		t.Fatal(err)
	}
	title := "0100ABCD00010000"
	t.Run("cheats", func(t *testing.T) {
		w := client.CheatWrite{TitleID: title, BuildID: "4A1B2C3D4E5F6071", Source: "Test list", Note: "Endless lamp oil", Text: "[Lamp oil]\n04000000 00000000 00000063\n"}
		set, err := c.AddCheat(ctx, w)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.AddCheat(ctx, w); !errors.Is(err, lantern.ErrConflict) {
			t.Errorf("a set that exists: %v", err)
		}
		list, err := c.Cheats(ctx, client.CheatOptions{TitleID: title, BuildID: "4A1B2C3D4E5F6071"})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, other := range list.Cheats {
			found = found || other.ID == set.ID
			if other.BuildID == nil || *other.BuildID != "4A1B2C3D4E5F6071" {
				t.Errorf("the filter kept another build: %+v", other)
			}
		}
		if !found {
			t.Fatalf("the new set is not listed: %+v", list)
		}
		if other, _ := c.Cheats(ctx, client.CheatOptions{TitleID: title, BuildID: "FFFF"}); other == nil || len(other.Cheats) != 0 {
			t.Errorf("the filter kept another build: %+v", other)
		}
		if text, err := c.CheatText(ctx, set); err != nil || text != w.Text {
			t.Errorf("text %q %v", text, err)
		}
		w.Text = "[Lamp oil]\n04000000 00000000 00000064\n"
		if err := c.ReplaceCheat(ctx, set.ID, w); err != nil {
			t.Fatal(err)
		}
		list, _ = c.Cheats(ctx, client.CheatOptions{TitleID: title})
		var mine lantern.CheatSet
		for _, other := range list.Cheats {
			if other.ID == set.ID {
				mine = other
			}
		}
		if text, err := c.CheatText(ctx, &mine); err != nil || text != w.Text {
			t.Errorf("replaced: %q %v", text, err)
		}
		bad := mine
		bad.SHA256 = strings.Repeat("0", 64)
		if _, err := c.CheatText(ctx, &bad); err == nil {
			t.Error("a text that is not the set's was accepted")
		}
		if err := c.DeleteCheat(ctx, set.ID); err != nil {
			t.Fatal(err)
		}
		if err := c.DeleteCheat(ctx, set.ID); !errors.Is(err, lantern.ErrNotFound) {
			t.Errorf("deleted twice: %v", err)
		}
	})
	t.Run("requests", func(t *testing.T) {
		first, created, err := c.RequestTitle(ctx, "0100FEED00020000", "")
		if err != nil || !created || first.Status != "open" {
			t.Fatalf("%+v %v %v", first, created, err)
		}
		again, created, err := c.RequestTitle(ctx, "0100FEED00020000", "")
		if err != nil || created || again.ID != first.ID {
			t.Errorf("asked twice: %+v %v %v", again, created, err)
		}
		list, err := c.Requests(ctx, "")
		if err != nil || len(list.Requests) != 1 {
			t.Fatalf("%+v %v", list, err)
		}
		if err := c.WithdrawRequest(ctx, first.ID); err != nil {
			t.Fatal(err)
		}
		if err := c.WithdrawRequest(ctx, first.ID); !errors.Is(err, lantern.ErrNotFound) {
			t.Errorf("withdrawn twice: %v", err)
		}
	})
}

func TestReferenceAdmin(t *testing.T) {
	ref := startReference(t)
	ctx := context.Background()
	key, err := lantern.SigningKeyFromBase64(ref.AdminSeed)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := client.New(ref.URL, client.Options{Token: ref.AdminTok, Key: key, Platform: "switch"})
	if err != nil {
		t.Fatal(err)
	}
	// Without the scope, the family is refused.
	lea, err := client.New(ref.URL, client.Options{Token: ref.OldToken, Platform: "switch"})
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range lea.AdminUsers(ctx) {
		if !errors.Is(err, lantern.ErrForbidden) {
			t.Errorf("an account without the scope admin: %v", err)
		}
		break
	}

	t.Run("accounts", func(t *testing.T) {
		made, err := admin.AdminCreateUser(ctx, "sam", []string{"library"})
		if err != nil || made.Name != "sam" || made.State != "active" {
			t.Fatalf("%+v %v", made, err)
		}
		if _, err := admin.AdminCreateUser(ctx, "sam", nil); !errors.Is(err, lantern.ErrConflict) {
			t.Errorf("a name taken: %v", err)
		}
		frozen, err := admin.AdminUpdateUser(ctx, "sam", "frozen", nil)
		if err != nil || frozen.State != "frozen" {
			t.Errorf("%+v %v", frozen, err)
		}
		names := map[string]bool{}
		for u, err := range admin.AdminUsers(ctx) {
			if err != nil {
				t.Fatal(err)
			}
			names[u.Name] = true
		}
		if !names["sam"] || !names["lea"] {
			t.Errorf("accounts %v", names)
		}
		if err := admin.AdminDeleteUser(ctx, "sam", "sa"); err == nil {
			t.Error("a deletion whose confirmation is not the name went out")
		}
		if err := admin.AdminDeleteUser(ctx, "sam", "sam"); err != nil {
			t.Fatal(err)
		}
		if err := admin.AdminDeleteUser(ctx, "sam", "sam"); !errors.Is(err, lantern.ErrNotFound) {
			t.Errorf("deleted twice: %v", err)
		}
	})
	t.Run("devices and invitations", func(t *testing.T) {
		var found bool
		for d, err := range admin.AdminDevices(ctx, "lea") {
			if err != nil {
				t.Fatal(err)
			}
			found = found || d.User == "lea"
		}
		if !found {
			t.Error("lea's device is not listed")
		}
		inv, err := admin.AdminCreateInvitation(ctx, lantern.InvitationCreate{User: "lea", Scopes: []string{"library"},
			Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Devices: 1})
		if err != nil || inv.Code == "" {
			t.Fatalf("%+v %v", inv, err)
		}
		listed := false
		for i, err := range admin.AdminInvitations(ctx) {
			if err != nil {
				t.Fatal(err)
			}
			listed = listed || i.ID == inv.ID
		}
		if !listed {
			t.Error("the invitation is not listed")
		}
		if err := admin.AdminRevokeInvitation(ctx, inv.ID); err != nil {
			t.Fatal(err)
		}
		if err := admin.AdminRevokeDevice(ctx, "d_unknown"); !errors.Is(err, lantern.ErrNotFound) {
			t.Errorf("an unknown device: %v", err)
		}
	})
	t.Run("requests", func(t *testing.T) {
		lea, err := client.New(ref.URL, client.Options{Token: ref.AdminTok, Key: key, Platform: "switch"})
		if err != nil {
			t.Fatal(err)
		}
		req, _, err := lea.RequestTitle(ctx, "0100FEED00030000", "")
		if err != nil {
			t.Fatal(err)
		}
		open := 0
		for r, err := range admin.AdminRequests(ctx, client.AdminRequestFilter{Status: "open"}) {
			if err != nil {
				t.Fatal(err)
			}
			if r.Status != "open" || r.User == nil {
				t.Errorf("the filter kept %+v", r)
			}
			open++
		}
		if open == 0 {
			t.Error("the open request is not listed")
		}
		done, err := admin.AdminDeclineRequest(ctx, req.ID, "Only the games this household owns.")
		if err != nil || done.Status != "declined" || done.Reason == nil || *done.Reason != "Only the games this household owns." {
			t.Fatalf("%+v %v", done, err)
		}
		if _, err := admin.AdminCompleteRequest(ctx, req.ID); !errors.Is(err, lantern.ErrConflict) {
			t.Errorf("a request no longer open: %v", err)
		}
	})
}

// failingAt reads from data and fails once past a limit, as a connection that is lost. With
// needArm it fails only after arm() (the first pass that hashes the data goes through).
type failingAt struct {
	data    []byte
	limit   int64
	needArm bool
	armed   bool
}

func (f *failingAt) arm() { f.armed = true }

func (f *failingAt) ReadAt(p []byte, off int64) (int, error) {
	if (!f.needArm || f.armed) && off+int64(len(p)) > f.limit {
		return 0, errors.New("the device went to sleep")
	}
	return copy(p, f.data[off:]), nil
}

func zipOf(t *testing.T, size int) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, err := w.CreateHeader(&zip.FileHeader{Name: "save.dat", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	rnd := make([]byte, size)
	for i := range rnd {
		rnd[i] = byte(i*7 + i>>8)
	}
	f.Write(rnd)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestReferenceSaves(t *testing.T) {
	ref := startReference(t)
	ctx := context.Background()
	key, err := lantern.SigningKeyFromBase64(ref.AdminSeed)
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(ref.URL, client.Options{Token: ref.AdminTok, Key: key, Platform: "switch"})
	if err != nil {
		t.Fatal(err)
	}
	title := "0100ABCD00010000"
	version := int64(196608)
	meta := client.SaveMeta{Kind: "account", GameVersionCode: &version, Profile: "Léa", Note: "Chapter 4"}

	t.Run("one request", func(t *testing.T) {
		archive := zipOf(t, 5000)
		save, err := c.UploadSave(ctx, title, meta, archive)
		if err != nil {
			t.Fatal(err)
		}
		if save.Size != int64(len(archive)) || save.SHA256 != lantern.SHA256Hex(archive) || save.Profile == nil || *save.Profile != "Léa" {
			t.Fatalf("%+v", save)
		}
		list, err := c.Saves(ctx, "", title)
		if err != nil || len(list.Saves) == 0 || list.Saves[0].SaveID != save.SaveID {
			t.Fatalf("the newest is not first: %+v %v", list, err)
		}
		f, err := c.OpenSave(ctx, save)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(f)
		f.Close()
		if err != nil || !bytes.Equal(got, archive) {
			t.Errorf("the archive came back different: %v", err)
		}
		dest := filepath.Join(t.TempDir(), "save.zip")
		if err := c.DownloadSave(ctx, save, dest, nil); err != nil {
			t.Fatal(err)
		}
		if err := c.DeleteSave(ctx, save); err != nil {
			t.Fatal(err)
		}
		if err := c.DeleteSave(ctx, save); !errors.Is(err, lantern.ErrNotFound) {
			t.Errorf("deleted twice: %v", err)
		}
	})
	t.Run("resumable, and resumed", func(t *testing.T) {
		archive := zipOf(t, 3<<20)
		up, err := c.StartSaveUpload(ctx, title, meta, int64(len(archive)), lantern.SHA256Hex(archive))
		if err != nil {
			t.Fatal(err)
		}
		cut := up.ChunkSize + up.ChunkSize/2
		if _, err := c.ContinueSaveUpload(ctx, up.Upload, &failingAt{data: archive, limit: cut}, nil); err == nil {
			t.Fatal("an upload went through a lost connection")
		}
		state, err := c.SaveUploadState(ctx, up.Upload)
		if err != nil || state.Offset == 0 || state.Offset >= state.Length {
			t.Fatalf("where to resume: %+v %v", state, err)
		}
		save, err := c.ContinueSaveUpload(ctx, up.Upload, bytes.NewReader(archive), nil)
		if err != nil || save.SHA256 != lantern.SHA256Hex(archive) {
			t.Fatalf("%+v %v", save, err)
		}
		c.DeleteSave(ctx, save)
	})
	t.Run("an archive that is not the one announced", func(t *testing.T) {
		archive := zipOf(t, 2000)
		up, err := c.StartSaveUpload(ctx, title, meta, int64(len(archive)), strings.Repeat("0", 64))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.ContinueSaveUpload(ctx, up.Upload, bytes.NewReader(archive), nil); err == nil {
			t.Error("an archive of another SHA-256 was kept")
		}
	})
	t.Run("abandoned", func(t *testing.T) {
		archive := zipOf(t, 2000)
		up, err := c.StartSaveUpload(ctx, title, meta, int64(len(archive)), lantern.SHA256Hex(archive))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.AbandonSaveUpload(ctx, up.Upload); err != nil {
			t.Fatal(err)
		}
		if _, err := c.SaveUploadState(ctx, up.Upload); err == nil {
			t.Error("an abandoned upload answers")
		}
	})
}

func TestReferenceEncryptedSaves(t *testing.T) {
	ref := startReference(t)
	ctx := context.Background()
	seed, err := lantern.SigningKeyFromBase64(ref.AdminSeed)
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(ref.URL, client.Options{Token: ref.AdminTok, Key: seed, Platform: "switch"})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.Offers(ctx, "encrypted_saves"); !ok {
		t.Skip("the reference server does not offer encrypted_saves")
	}
	key, err := lantern.GenerateSaveKey()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := lantern.GenerateSaveKey()
	title := "0100ABCD00010000"
	meta := client.SaveMeta{Kind: "account"}
	check := func(t *testing.T, save *lantern.Save, archive []byte) {
		t.Helper()
		id, _ := key.KeyID()
		if save.Encryption == nil || save.Encryption.KeyID != id || save.Encryption.Scheme != lantern.SaveScheme {
			t.Fatalf("encryption %+v", save.Encryption)
		}
		if save.Size != lantern.EncryptedSize(int64(len(archive))) {
			t.Errorf("the server keeps %d bytes", save.Size)
		}
		r, err := c.OpenEncryptedSave(ctx, key, save)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		r.Close()
		if err != nil || !bytes.Equal(got, archive) {
			t.Errorf("the archive came back different: %v", err)
		}
		if _, err := c.OpenEncryptedSave(ctx, other, save); !errors.Is(err, lantern.ErrDecryption) {
			t.Errorf("another key: %v", err)
		}
		dest := filepath.Join(t.TempDir(), "save.zip")
		if err := c.DownloadEncryptedSave(ctx, key, save, dest); err != nil {
			t.Fatal(err)
		}
		if disk, _ := os.ReadFile(dest); !bytes.Equal(disk, archive) {
			t.Error("the saved archive differs")
		}
		c.DeleteSave(ctx, save)
	}
	t.Run("one request", func(t *testing.T) {
		archive := zipOf(t, 70000)
		save, err := c.UploadEncryptedSave(ctx, title, meta, key, archive)
		if err != nil {
			t.Fatal(err)
		}
		check(t, save, archive)
	})
	t.Run("resumable, cut and taken up again", func(t *testing.T) {
		archive := zipOf(t, 3<<20)
		// A reader that fails once partway, as a connection that is lost.
		failing := &failingAt{data: archive, limit: 1 << 20, needArm: true}
		_, err := c.UploadEncryptedSaveResumable(ctx, title, meta, key, failing, int64(len(archive)), func(done, total int64) { failing.arm() })
		var stopped *client.UploadError
		if !errors.As(err, &stopped) || stopped.Backup == nil {
			t.Fatalf("expected an upload that stopped: %v", err)
		}
		defer stopped.Backup.Wipe()
		again := stopped.Backup.EncryptedReaderAt(bytes.NewReader(archive), int64(len(archive)))
		save, err := c.ContinueSaveUpload(ctx, stopped.Upload, again, nil)
		if err != nil {
			t.Fatal(err)
		}
		check(t, save, archive)
	})
}

func TestReferenceEvents(t *testing.T) {
	ref := startReference(t)
	key, err := lantern.SigningKeyFromBase64(ref.AdminSeed)
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(ref.URL, client.Options{Token: ref.AdminTok, Key: key, Platform: "switch"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	next := func(ctx context.Context, s *client.EventStream) *lantern.ServerEvent {
		t.Helper()
		for ev, err := range s.All(ctx) {
			if err != nil {
				t.Fatal(err)
			}
			return ev
		}
		t.Fatal("the stream ended")
		return nil
	}
	first, stop := context.WithCancel(ctx)
	stream := c.Events(client.EventOptions{})
	ready := next(first, stream)
	stop()
	if ready.Event != "ready" || ready.ID == "" {
		t.Fatalf("%+v", ready)
	}
	made, _, err := c.RequestTitle(ctx, "0100FFFF00090000", "switch")
	if err != nil {
		t.Fatal(err)
	}
	// resumed from the first id: ready again, then the request, with its id
	again := c.Events(client.EventOptions{Since: ready.ID})
	var got []*lantern.ServerEvent
	loop, stopLoop := context.WithCancel(ctx)
	for ev, err := range again.All(loop) {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, ev)
		if ev.Event == "request" {
			break
		}
	}
	stopLoop()
	if len(got) < 2 || got[0].ID != ready.ID || got[len(got)-1].Data["id"] != made.ID || got[len(got)-1].Data["status"] != "open" {
		t.Fatalf("%+v", got)
	}
	if again.LastID() != got[len(got)-1].ID {
		t.Errorf("LastID %q", again.LastID())
	}
	// long polling gives the same events, and then the withdrawal
	polled, err := c.PollEvents(ctx, ready.ID, 5*time.Second)
	if err != nil || len(polled.Events) != 1 || polled.Events[0].Event != "request" || polled.Events[0].ID != got[len(got)-1].ID {
		t.Fatalf("%+v %v", polled, err)
	}
	if err := c.WithdrawRequest(ctx, made.ID); err != nil {
		t.Fatal(err)
	}
	gone, err := c.PollEvents(ctx, polled.Since, 5*time.Second)
	if err != nil || len(gone.Events) == 0 {
		t.Fatalf("%+v %v", gone, err)
	}
	if d := gone.Events[0].Data.Extra["deleted"]; string(d) != "true" {
		t.Errorf("%+v", gone.Events[0].Data)
	}
	// a token the server never gave
	for _, err := range c.Events(client.EventOptions{Since: "s_never-given"}).All(ctx) {
		if !errors.Is(err, lantern.ErrBadRequest) && !errors.Is(err, lantern.ErrGone) {
			t.Fatalf("%v", err)
		}
		break
	}
}
