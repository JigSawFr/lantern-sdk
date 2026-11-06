// SPDX-License-Identifier: MIT

package client_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/client"
)

// depot is a small library server: it answers the library routes from what a test sets, and
// serves one file the way SPEC.md § 6.6 says (Range, Repr-Digest), or badly, on request.
type depot struct {
	mu      sync.Mutex
	handler func(w http.ResponseWriter, r *http.Request)
	seen    []*http.Request
	bodies  [][]byte
	file    []byte
	// what a file does wrong
	digest   string // a Repr-Digest to send instead of the right one; "-" for none
	encoding string // a Content-Encoding to send
	noRange  bool   // answer 200 with the whole file to a Range request
	badRange bool   // answer 206 with the wrong Content-Range
	serve    func(http.ResponseWriter, *http.Request, []byte)
}

func (d *depot) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	body, _ := io.ReadAll(r.Body)
	d.seen = append(d.seen, r.Clone(r.Context()))
	d.bodies = append(d.bodies, body)
	h, file := d.handler, d.file
	d.mu.Unlock()
	w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
	if strings.HasPrefix(r.URL.Path, "/api/lantern/v1/files/") {
		d.sendFile(w, r, file)
		return
	}
	if h == nil {
		http.NotFound(w, r)
		return
	}
	h(w, r)
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func (d *depot) sendFile(w http.ResponseWriter, r *http.Request, file []byte) {
	if d.serve != nil {
		d.serve(w, r, file)
		return
	}
	digest, _ := lantern.FormatDigest(sum(file))
	if d.digest != "" {
		digest = d.digest
	}
	if digest != "-" {
		w.Header().Set("Repr-Digest", digest)
	}
	if d.encoding != "" {
		w.Header().Set("Content-Encoding", d.encoding)
	}
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Type", "application/octet-stream")
	if rng := r.Header.Get("Range"); rng != "" && !d.noRange {
		var from int64
		fmt.Sscanf(rng, "bytes=%d-", &from)
		w.Header().Set("Content-Length", strconv.Itoa(len(file)-int(from)))
		cr := fmt.Sprintf("bytes %d-%d/%d", from, len(file)-1, len(file))
		if d.badRange {
			cr = fmt.Sprintf("bytes %d-%d/%d", from+1, len(file)-1, len(file))
		}
		w.Header().Set("Content-Range", cr)
		w.WriteHeader(http.StatusPartialContent)
		w.Write(file[from:])
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(file)))
	w.Write(file)
}

func (d *depot) requests() []*http.Request {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]*http.Request(nil), d.seen...)
}

func newDepot(t *testing.T) (*depot, *client.Client) {
	t.Helper()
	d := &depot{}
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	c, err := client.New(srv.URL, client.Options{Base: "/api/lantern", Platform: "switch"})
	if err != nil {
		t.Fatal(err)
	}
	return d, c
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func appJSON(id string, file []byte, address string) map[string]any {
	return map[string]any{"id": id, "platform": "switch", "title_id": "0100ABCD00010000", "app_id": "0100ABCD00010000",
		"type": "base", "version_code": 0, "size": len(file), "format": "nsp", "sha256": sum(file), "file": address}
}

func TestAppsFollowCursorsAndFilter(t *testing.T) {
	d, c := newDepot(t)
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch q.Get("cursor") {
		case "":
			writeJSON(w, 200, map[string]any{"schema": 1, "items": []any{appJSON("a_1", nil, "/f/1"), appJSON("a_2", nil, "/f/2")}, "next": "c_1", "total": 3})
		case "c_1":
			writeJSON(w, 200, map[string]any{"schema": 1, "items": []any{appJSON("a_3", nil, "/f/3")}, "next": nil})
		default:
			writeJSON(w, 400, map[string]any{"schema": 1, "status": 400, "code": "bad_request", "title": "x"})
		}
	}
	var ids []string
	for app, err := range c.Apps(context.Background(), client.ListOptions{Type: "update", Query: "frost", Sort: "added", PageSize: 2, Format: "nsz", TitleID: "0100ABCD00010000"}) {
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, app.ID)
	}
	if strings.Join(ids, ",") != "a_1,a_2,a_3" {
		t.Fatalf("ids %v", ids)
	}
	first := d.requests()[0]
	want := url.Values{"type": {"update"}, "q": {"frost"}, "sort": {"added"}, "page_size": {"2"}, "format": {"nsz"}, "title_id": {"0100ABCD00010000"}}
	if got := first.URL.Query(); got.Encode() != want.Encode() {
		t.Fatalf("query %v", got)
	}
	if first.Header.Get("Lantern-Platform") != "switch" {
		t.Fatal("no platform header")
	}
	// breaking out of the loop asks for no more pages
	n := len(d.requests())
	for _, err := range c.Apps(context.Background(), client.ListOptions{}) {
		if err != nil {
			t.Fatal(err)
		}
		break
	}
	if got := len(d.requests()) - n; got != 1 {
		t.Fatalf("%d requests for one item", got)
	}
}

func TestAppsRefuseWhatWouldLoop(t *testing.T) {
	d, c := newDepot(t)
	cases := map[string]func(http.ResponseWriter, *http.Request){
		"a cursor given twice": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]any{"schema": 1, "items": []any{appJSON("a_1", nil, "/f")}, "next": "c"})
		},
		"an empty page that goes on": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]any{"schema": 1, "items": []any{}, "next": "c"})
		},
	}
	for name, h := range cases {
		d.handler = h
		var last error
		count := 0
		for _, err := range c.Apps(context.Background(), client.ListOptions{}) {
			count++
			last = err
			if count > 10 {
				t.Fatalf("%s: never stopped", name)
			}
		}
		var doc *lantern.DocumentError
		if !errors.As(last, &doc) {
			t.Fatalf("%s: %v", name, last)
		}
	}
}

func TestExpiredCursorIsGone(t *testing.T) {
	d, c := newDepot(t)
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 410, map[string]any{"schema": 1, "status": 410, "code": "gone", "title": "x"})
	}
	_, err := c.AppsPage(context.Background(), client.ListOptions{}, "c_old")
	if !errors.Is(err, lantern.ErrGone) {
		t.Fatalf("%v", err)
	}
	if _, err := c.AppsPage(context.Background(), client.ListOptions{Query: strings.Repeat("x", 257)}, ""); err == nil {
		t.Fatal("a query of 257 bytes was sent")
	}
}

func TestMissingSendsWhatTheDeviceHas(t *testing.T) {
	d, c := newDepot(t)
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/lantern/v1/apps/missing" || r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, 200, map[string]any{"schema": 1, "items": []any{appJSON("a_u", nil, "/f/u")}, "next": nil})
	}
	opts := client.MissingOptions{Want: []string{"update", "dlc"}, Formats: []string{}, Satisfies: []string{"fs-compression"},
		Installed: []lantern.InstalledApp{{AppID: "0100ABCD00010000", VersionCode: 0}}}
	var got []string
	for app, err := range c.Missing(context.Background(), opts) {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, app.ID)
	}
	if len(got) != 1 || got[0] != "a_u" {
		t.Fatalf("%v", got)
	}
	var sent map[string]json.RawMessage
	if err := json.Unmarshal(d.bodies[0], &sent); err != nil {
		t.Fatal(err)
	}
	if string(sent["formats"]) != "[]" || string(sent["satisfies"]) != `["fs-compression"]` || string(sent["want"]) != `["update","dlc"]` {
		t.Fatalf("body %s", d.bodies[0])
	}
	// nothing installed is an empty list, not an absent one, and a nil formats is not sent
	if _, err := c.MissingPage(context.Background(), client.MissingOptions{Want: []string{"base"}}, ""); err != nil {
		t.Fatal(err)
	}
	if b := string(d.bodies[len(d.bodies)-1]); !strings.Contains(b, `"installed":[]`) || strings.Contains(b, "formats") || strings.Contains(b, "satisfies") {
		t.Fatalf("body %s", b)
	}
	for name, o := range map[string]client.MissingOptions{
		"no want":      {},
		"another want": {Want: []string{"all"}},
		"a bad format": {Want: []string{"base"}, Formats: []string{"NSP"}},
		"a bad token":  {Want: []string{"base"}, Satisfies: []string{"-x"}},
		"too many":     {Want: []string{"base"}, Formats: make([]string, 17)},
	} {
		n := len(d.requests())
		if _, err := c.MissingPage(context.Background(), o, ""); err == nil || len(d.requests()) != n {
			t.Errorf("%s: sent (%v)", name, err)
		}
	}
}

func TestChangesSectionsAndTitles(t *testing.T) {
	d, c := newDepot(t)
	var asked []string
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/lantern/v1/changes":
			if r.URL.Query().Get("since") == "old" {
				writeJSON(w, 410, map[string]any{"schema": 1, "status": 410, "code": "gone", "title": "x"})
				return
			}
			writeJSON(w, 200, map[string]any{"schema": 1, "added": []any{appJSON("a_n", nil, "/f")}, "removed": []string{"a_o"}, "since": "t2"})
		case "/api/lantern/v1/sections":
			writeJSON(w, 200, map[string]any{"schema": 1, "sections": []any{map[string]any{"id": "new", "title": "New", "apps": []string{"a_n"}}}})
		case "/api/lantern/v1/titles":
			ids := strings.Split(r.URL.Query().Get("ids"), ",")
			asked = append(asked, fmt.Sprint(len(ids)))
			titles, unknown := []any{}, []string{}
			for _, id := range ids {
				if id == "none" {
					unknown = append(unknown, id)
					continue
				}
				titles = append(titles, map[string]any{"platform": "switch", "title_id": id, "name": "T " + id})
			}
			writeJSON(w, 200, map[string]any{"schema": 1, "titles": titles, "unknown": unknown})
		case "/api/lantern/v1/titles/changes":
			writeJSON(w, 200, map[string]any{"schema": 1, "titles": []any{}, "removed": []any{map[string]any{"platform": "switch", "title_id": "x"}}, "since": "t9", "more": true})
		case "/api/lantern/v1/titles/0100ABCD00010000":
			writeJSON(w, 200, map[string]any{"schema": 1, "platform": "switch", "title_id": "0100ABCD00010000", "name": "Frostline Tales", "genres": []string{"adventure", "future-genre"}})
		default:
			http.NotFound(w, r)
		}
	}
	ctx := context.Background()
	ch, err := c.Changes(ctx, "t1", "")
	if err != nil || ch.Since != "t2" || len(ch.Added) != 1 || ch.Removed[0] != "a_o" {
		t.Fatalf("%+v %v", ch, err)
	}
	if _, err := c.Changes(ctx, "old", ""); !errors.Is(err, lantern.ErrGone) {
		t.Fatalf("%v", err)
	}
	sec, err := c.Sections(ctx)
	if err != nil || sec.Sections[0].Apps[0] != "a_n" {
		t.Fatalf("%v", err)
	}
	title, err := c.Title(ctx, "0100ABCD00010000", "")
	if err != nil || title.Name != "Frostline Tales" {
		t.Fatalf("%v", err)
	}
	if g := title.EffectiveGenres(); len(g) != 2 || g[1] != "other" {
		t.Fatalf("genres %v", g)
	}
	if _, err := c.Title(ctx, "../x", ""); err == nil {
		t.Fatal("a path was taken for a title id")
	}
	ids := make([]string, 0, 251)
	for i := range 250 {
		ids = append(ids, fmt.Sprintf("T%03d", i))
	}
	ids = append(ids, "T000", "none") // one twice, one the server does not know
	titles, unknown, err := c.Titles(ctx, ids, "")
	if err != nil || len(titles) != 250 || len(unknown) != 1 || strings.Join(asked, ",") != "100,100,51" {
		t.Fatalf("%d titles, %v unknown, asked %v, %v", len(titles), unknown, asked, err)
	}
	tc, err := c.TitleChanges(ctx, "t8", "")
	if err != nil || !tc.More || tc.Since != "t9" || tc.Removed[0].TitleID != "x" {
		t.Fatalf("%+v %v", tc, err)
	}
}

func TestImages(t *testing.T) {
	d, c := newDepot(t)
	png := []byte("\x89PNG not really")
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(png)
	}
	ctx := context.Background()
	good := sum(png)
	got, err := c.Image(ctx, &lantern.Image{URL: "/api/lantern/v1/media/" + good + ".png", SHA256: &good})
	if err != nil || !bytes.Equal(got, png) {
		t.Fatalf("%v", err)
	}
	if h := d.requests()[0].Header.Get("Accept"); h != "image/*" {
		t.Fatalf("Accept %q", h)
	}
	wrong := sum([]byte("other"))
	if _, err := c.Image(ctx, &lantern.Image{URL: "/api/lantern/v1/media/x", SHA256: &wrong}); !errors.Is(err, lantern.ErrIntegrity) {
		t.Fatalf("%v", err)
	}
	yes := true
	n := len(d.requests())
	if _, err := c.Image(ctx, &lantern.Image{URL: "https://cdn.example.org/x.png", External: &yes}); err == nil {
		t.Fatal("an external image was read")
	}
	if _, err := c.Image(ctx, &lantern.Image{URL: "https://cdn.example.org/x.png"}); err == nil {
		t.Fatal("an image of another origin was read")
	}
	if len(d.requests()) != n {
		t.Fatal("a request left for another origin")
	}
}

func fileApp(file []byte, address string) *lantern.App {
	var app lantern.App
	raw, _ := json.Marshal(appJSON("a_f", file, address))
	if err := app.UnmarshalJSON(raw); err != nil {
		panic(err)
	}
	return &app
}

func bigFile() []byte {
	b := make([]byte, 300_000)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

func TestDownloadIsChecked(t *testing.T) {
	d, c := newDepot(t)
	d.file = bigFile()
	app := fileApp(d.file, "/api/lantern/v1/files/f_1")
	path := filepath.Join(t.TempDir(), "game.nsp")
	var last int64
	if err := c.Download(context.Background(), app, path, func(done, total int64) { last = done }); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, d.file) || last != int64(len(d.file)) {
		t.Fatalf("saved %d bytes, progress %d", len(got), last)
	}
	if _, err := os.Stat(path + ".part"); !os.IsNotExist(err) {
		t.Fatal("a .part is left")
	}
	req := d.requests()[0]
	if req.Header.Get("Accept-Encoding") != "identity" || req.Header.Get("Range") != "" {
		t.Fatalf("headers %v", req.Header)
	}
}

func TestDownloadRefusesWhatIsNotTheFile(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		set  func(d *depot, file []byte) *lantern.App
		when string // "open" when refused before a byte is read, "read" after
	}{
		"another Repr-Digest": {func(d *depot, f []byte) *lantern.App {
			d.digest, _ = lantern.FormatDigest(sum([]byte("other")))
			return fileApp(f, "/api/lantern/v1/files/f")
		}, "open"},
		"no Repr-Digest": {func(d *depot, f []byte) *lantern.App { d.digest = "-"; return fileApp(f, "/api/lantern/v1/files/f") }, "open"},
		"a Content-Encoding": {func(d *depot, f []byte) *lantern.App {
			d.encoding = "gzip"
			return fileApp(f, "/api/lantern/v1/files/f")
		}, "open"},
		"bytes that are not the file": {func(d *depot, f []byte) *lantern.App {
			bad := append([]byte(nil), f...)
			bad[1000] ^= 1
			d.file = bad // the headers still name the right file
			d.digest, _ = lantern.FormatDigest(sum(f))
			return fileApp(f, "/api/lantern/v1/files/f")
		}, "read"},
		"a file cut short": {func(d *depot, f []byte) *lantern.App {
			d.serve = func(w http.ResponseWriter, r *http.Request, file []byte) {
				dg, _ := lantern.FormatDigest(sum(file))
				w.Header().Set("Repr-Digest", dg)
				w.Header().Set("Content-Length", strconv.Itoa(len(file)))
				w.Write(file[:len(file)/2]) // the connection then closes on a short body
			}
			return fileApp(f, "/api/lantern/v1/files/f")
		}, "read"},
		"a file too long": {func(d *depot, f []byte) *lantern.App {
			d.serve = func(w http.ResponseWriter, r *http.Request, file []byte) {
				dg, _ := lantern.FormatDigest(sum(file))
				w.Header().Set("Repr-Digest", dg)
				w.Write(append(append([]byte(nil), file...), "extra"...))
			}
			return fileApp(f, "/api/lantern/v1/files/f")
		}, "read"},
		"a file of another origin": {func(d *depot, f []byte) *lantern.App { return fileApp(f, "https://elsewhere.example.org/f") }, "open"},
	} {
		d, c := newDepot(t)
		d.file = bigFile()
		app := tc.set(d, bigFile())
		path := filepath.Join(t.TempDir(), "game.nsp")
		err := c.Download(ctx, app, path, nil)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if name != "a file of another origin" && !errors.Is(err, lantern.ErrIntegrity) && !errors.Is(err, lantern.ErrTransport) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s: a file was left at its path", name)
		}
	}
}

func TestDownloadResumes(t *testing.T) {
	ctx := context.Background()
	file := bigFile()
	for name, setup := range map[string]struct {
		set       func(d *depot)
		wantRange string
	}{
		"a Range request":            {func(d *depot) {}, "bytes=100000-"},
		"a server that sends it all": {func(d *depot) { d.noRange = true }, "bytes=100000-"},
	} {
		d, c := newDepot(t)
		d.file = file
		setup.set(d)
		app := fileApp(file, "/api/lantern/v1/files/f_1")
		path := filepath.Join(t.TempDir(), "game.nsp")
		if err := os.WriteFile(path+".part", file[:100_000], 0o600); err != nil {
			t.Fatal(err)
		}
		if err := c.Download(ctx, app, path, nil); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, _ := os.ReadFile(path); !bytes.Equal(got, file) {
			t.Fatalf("%s: wrong bytes", name)
		}
		if r := d.requests()[0].Header.Get("Range"); r != setup.wantRange {
			t.Fatalf("%s: Range %q", name, r)
		}
	}
	// a partial copy that is not this file's prefix is caught by the SHA-256 and thrown away
	d, c := newDepot(t)
	d.file = file
	app := fileApp(file, "/api/lantern/v1/files/f_1")
	path := filepath.Join(t.TempDir(), "game.nsp")
	wrong := append([]byte(nil), file[:100_000]...)
	wrong[5] ^= 1
	os.WriteFile(path+".part", wrong, 0o600)
	if err := c.Download(ctx, app, path, nil); !errors.Is(err, lantern.ErrIntegrity) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a wrong file was kept")
	}
	if _, err := os.Stat(path + ".part"); !os.IsNotExist(err) {
		t.Fatal("a wrong copy is left to resume")
	}
	// ...and the next call starts from nothing and succeeds
	if err := c.Download(ctx, app, path, nil); err != nil {
		t.Fatal(err)
	}
	// a server that answers a resume with the wrong range is not believed
	d2, c2 := newDepot(t)
	d2.file, d2.badRange = file, true
	path2 := filepath.Join(t.TempDir(), "g")
	os.WriteFile(path2+".part", file[:100_000], 0o600)
	if err := c2.Download(ctx, fileApp(file, "/api/lantern/v1/files/f"), path2, nil); !errors.Is(err, lantern.ErrIntegrity) {
		t.Fatalf("%v", err)
	}
	// a copy that is all there asks for nothing
	d3, c3 := newDepot(t)
	d3.file = file
	path3 := filepath.Join(t.TempDir(), "g")
	os.WriteFile(path3+".part", file, 0o600)
	if err := c3.Download(ctx, fileApp(file, "/api/lantern/v1/files/f"), path3, nil); err != nil || len(d3.requests()) != 0 {
		t.Fatalf("%v, %d requests", err, len(d3.requests()))
	}
}

func TestOpenFileStreamsAndEnds(t *testing.T) {
	d, c := newDepot(t)
	d.file = bigFile()
	f, err := c.OpenFile(context.Background(), fileApp(d.file, "/api/lantern/v1/files/f"), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(got, d.file) {
		t.Fatalf("%d bytes, %v", len(got), err)
	}
	if n, err := f.Read(make([]byte, 8)); n != 0 || err != io.EOF {
		t.Fatalf("after the end: %d, %v", n, err)
	}
	if _, err := c.OpenFile(context.Background(), fileApp(d.file, "/api/lantern/v1/files/f"), 10, nil); err == nil {
		t.Fatal("resumed without the state of the bytes before")
	}
}
