// SPDX-License-Identifier: MIT

package client_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/client"
)

func streamBytes(seed string, size int) []byte {
	out := make([]byte, 0, size+32)
	for i := uint64(0); len(out) < size; i++ {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], i)
		sum := sha256.Sum256(append([]byte(seed), n[:]...))
		out = append(out, sum[:]...)
	}
	return out[:size]
}

// A newer file that shares most of the older one: 777 bytes inserted, 10,000 removed.
func versions() (older, newer []byte) {
	older = streamBytes("older", 900_000)
	newer = append([]byte(nil), older[:300_000]...)
	newer = append(newer, streamBytes("an insertion", 777)...)
	newer = append(newer, older[300_000:600_000]...)
	newer = append(newer, older[610_000:]...)
	return older, newer
}

type deltaServer struct {
	*depot
	index     []byte
	ref       lantern.ChunksRef
	lie       bool   // a range with a byte changed
	crange    string // a Content-Range to send instead of the right one
	rangeHits atomic.Int64
	wholeHits atomic.Int64
	indexHits atomic.Int64
}

// newDelta serves the newer file by ranges and its index.
func newDelta(t *testing.T) (*deltaServer, *client.Client, *lantern.App, []byte) {
	t.Helper()
	d, c := newDepot(t)
	older, newer := versions()
	_, raw, err := lantern.BuildChunkIndex(newer, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	s := &deltaServer{depot: d, index: raw}
	s.ref = lantern.ChunksRefFor("/api/lantern/v1/chunks/sha256/"+sum(newer), raw)
	d.file = newer
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/lantern/v1/chunks/sha256/"+sum(newer) {
			s.indexHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Write(s.index)
			return
		}
		http.NotFound(w, r)
	}
	d.serve = func(w http.ResponseWriter, r *http.Request, file []byte) {
		digest, _ := lantern.FormatDigest(sum(file))
		w.Header().Set("Repr-Digest", digest)
		var from, to int64 = 0, int64(len(file)) - 1
		rng := r.Header.Get("Range")
		if rng == "" {
			s.wholeHits.Add(1)
			w.Header().Set("Content-Length", strconv.Itoa(len(file)))
			w.Write(file)
			return
		}
		if n, _ := fmt.Sscanf(rng, "bytes=%d-%d", &from, &to); n != 2 {
			fmt.Sscanf(rng, "bytes=%d-", &from)
		} else {
			s.rangeHits.Add(1)
		}
		body := append([]byte(nil), file[from:to+1]...)
		if s.lie && len(body) > 10 {
			body[len(body)/2] ^= 0xff
		}
		cr := fmt.Sprintf("bytes %d-%d/%d", from, to, len(file))
		if s.crange != "" {
			cr = s.crange
		}
		w.Header().Set("Content-Range", cr)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(body)
	}
	app := fileApp(newer, "/api/lantern/v1/files/f_2")
	app.Chunks = &s.ref
	return s, c, app, older
}

func TestDownloadWithSeedsReadsOnlyWhatChanged(t *testing.T) {
	s, c, app, older := newDelta(t)
	path := filepath.Join(t.TempDir(), "game.nsp")
	var last int64
	report, err := c.DownloadWithSeeds(context.Background(), app, path, [][]byte{older}, func(done, total int64) { last = done })
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, s.file) || last != int64(len(s.file)) {
		t.Fatalf("saved %d bytes, progress %d", len(got), last)
	}
	if report == nil || report.Reused <= 0 || report.Read <= 0 || report.Reused+report.Read != int64(len(s.file)) || report.Read >= int64(len(s.file)) {
		t.Fatalf("report %+v", report)
	}
	if s.wholeHits.Load() != 0 || s.rangeHits.Load() != int64(report.Ranges) || s.indexHits.Load() != 1 {
		t.Fatalf("whole %d, ranges %d (report %d), index %d", s.wholeHits.Load(), s.rangeHits.Load(), report.Ranges, s.indexHits.Load())
	}
	if _, err := os.Stat(path + ".part"); !os.IsNotExist(err) {
		t.Fatal("a .part is left")
	}
}

func TestDownloadWithSeedsReadsTheWholeFileWhenItCannot(t *testing.T) {
	for name, tc := range map[string]struct {
		set   func(s *deltaServer, app *lantern.App)
		seeds func(older []byte) [][]byte
		index bool // whether the index is read at all
	}{
		"a range with a changed byte":               {func(s *deltaServer, _ *lantern.App) { s.lie = true }, func(o []byte) [][]byte { return [][]byte{o} }, true},
		"a Content-Range that is not the one asked": {func(s *deltaServer, _ *lantern.App) { s.crange = "bytes 0-9/10" }, func(o []byte) [][]byte { return [][]byte{o} }, true},
		"an index that is not the one named": {func(s *deltaServer, _ *lantern.App) {
			s.index = bytes.Replace(s.index, []byte(`"schema":1`), []byte(`"schema":2`), 1)
		}, func(o []byte) [][]byte { return [][]byte{o} }, true},
		"an index of another size":      {func(_ *deltaServer, app *lantern.App) { app.Chunks.Size++ }, func(o []byte) [][]byte { return [][]byte{o} }, true},
		"a seed with nothing in common": {func(*deltaServer, *lantern.App) {}, func([]byte) [][]byte { return [][]byte{streamBytes("elsewhere", 500_000)} }, true},
		"no seed":                       {func(*deltaServer, *lantern.App) {}, func([]byte) [][]byte { return nil }, false},
		"no index":                      {func(_ *deltaServer, app *lantern.App) { app.Chunks = nil }, func(o []byte) [][]byte { return [][]byte{o} }, false},
	} {
		t.Run(name, func(t *testing.T) {
			s, c, app, older := newDelta(t)
			tc.set(s, app)
			path := filepath.Join(t.TempDir(), "game.nsp")
			report, err := c.DownloadWithSeeds(context.Background(), app, path, tc.seeds(older), nil)
			if err != nil {
				t.Fatal(err)
			}
			if report != nil {
				t.Fatalf("a delta report for a file that could not be one: %+v", report)
			}
			if got, _ := os.ReadFile(path); !bytes.Equal(got, s.file) {
				t.Fatalf("saved %d bytes, not the file", len(got))
			}
			if s.wholeHits.Load() != 1 {
				t.Fatalf("the file was read %d times whole", s.wholeHits.Load())
			}
			if (s.indexHits.Load() == 1) != tc.index {
				t.Fatalf("the index was read %d times", s.indexHits.Load())
			}
			if _, err := os.Stat(path + ".part"); !os.IsNotExist(err) {
				t.Fatal("a .part is left")
			}
		})
	}
}

func TestDownloadWithSeedsKeepsToTheServersOrigin(t *testing.T) {
	s, c, app, older := newDelta(t)
	app.Chunks.URL = "https://elsewhere.example.org/chunks/" + sum(s.file)
	path := filepath.Join(t.TempDir(), "game.nsp")
	report, err := c.DownloadWithSeeds(context.Background(), app, path, [][]byte{older}, nil)
	if err != nil || report != nil || s.indexHits.Load() != 0 {
		t.Fatalf("%+v %v, %d", report, err, s.indexHits.Load())
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, s.file) {
		t.Fatal("the file was not saved whole")
	}
}
