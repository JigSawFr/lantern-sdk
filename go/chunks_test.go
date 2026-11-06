// SPDX-License-Identifier: MIT

package lantern_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

// stream is the vectors' bytes: SHA-256(seed ‖ i, i on 8 bytes big-endian) for i = 0, 1, …, cut to size.
func stream(seed string, size int) []byte {
	out := make([]byte, 0, size+32)
	for i := uint64(0); len(out) < size; i++ {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], i)
		sum := sha256.Sum256(append([]byte(seed), n[:]...))
		out = append(out, sum[:]...)
	}
	return out[:size]
}

type chunkCase struct {
	Name string `json:"name"`
	File struct {
		Seed  string `json:"seed"`
		Size  int    `json:"size"`
		Zeros int    `json:"zeros"`
		Edit  string `json:"edit"`
	} `json:"file"`
	FileSHA256 string `json:"file_sha256"`
	FileSize   int64  `json:"file_size"`
	Chunker    struct {
		Size int64 `json:"size"`
	} `json:"chunker"`
	Cuts        []int64             `json:"cuts"`
	Chunks      [][]json.RawMessage `json:"chunks"`
	IndexSize   int                 `json:"index_size"`
	IndexSHA256 string              `json:"index_sha256"`
	Index       string              `json:"index"`
}

type chunkVectors struct {
	Gear struct {
		First  []string `json:"first"`
		Last   string   `json:"last"`
		SHA256 string   `json:"sha256"`
	} `json:"gear"`
	Cases  []chunkCase `json:"cases"`
	Update struct {
		Plan []struct {
			Offset int64  `json:"offset"`
			Size   int64  `json:"size"`
			SHA256 string `json:"sha256"`
			From   string `json:"from"`
		} `json:"plan"`
		Ranges []string `json:"ranges"`
		Read   int64    `json:"read"`
	} `json:"update"`
	Refused []struct {
		Name       string `json:"name"`
		FileSHA256 string `json:"file_sha256"`
		FileSize   int64  `json:"file_size"`
		Chunks     struct {
			URL    string `json:"url"`
			Size   int64  `json:"size"`
			SHA256 string `json:"sha256"`
		} `json:"chunks"`
		Index  string `json:"index"`
		Usable bool   `json:"usable"`
	} `json:"refused"`
}

func loadChunkVectors(t *testing.T) chunkVectors {
	t.Helper()
	var v chunkVectors
	if err := json.Unmarshal(testutil.Read(t, "vectors", "chunks.json"), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// fileOf makes the bytes a vector describes; the newer version is made from the original.
func fileOf(c chunkCase) []byte {
	switch {
	case c.File.Zeros > 0:
		return make([]byte, c.File.Zeros)
	case c.File.Edit != "":
		orig := stream("lantern-cdc-1 vector", 1000000)
		out := append([]byte(nil), orig[:300000]...)
		out = append(out, stream("an insertion", 777)...)
		out = append(out, orig[300000:700000]...)
		return append(out, orig[710000:]...)
	}
	return stream(c.File.Seed, c.File.Size)
}

func TestChunkerGear(t *testing.T) {
	v := loadChunkVectors(t)
	g := lantern.Gear()
	for i, want := range v.Gear.First {
		if got := fmt.Sprintf("%016x", g[i]); got != want {
			t.Errorf("G[%d] = %s, want %s", i, got, want)
		}
	}
	if got := fmt.Sprintf("%016x", g[255]); got != v.Gear.Last {
		t.Errorf("G[255] = %s, want %s", got, v.Gear.Last)
	}
	var all []byte
	for _, x := range g {
		all = binary.BigEndian.AppendUint64(all, x)
	}
	sum := sha256.Sum256(all)
	if hex.EncodeToString(sum[:]) != v.Gear.SHA256 {
		t.Error("the gear table's digest is not the vectors'")
	}
}

func TestChunkerVectors(t *testing.T) {
	v := loadChunkVectors(t)
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			data := fileOf(c)
			cuts, err := lantern.CutFile(data, c.Chunker.Size)
			if err != nil {
				t.Fatal(err)
			}
			var offsets []int64
			for _, x := range cuts {
				offsets = append(offsets, x.Offset)
			}
			if fmt.Sprint(offsets) != fmt.Sprint(append([]int64{}, c.Cuts...)) && !(len(offsets) == 0 && len(c.Cuts) == 0) {
				t.Fatalf("cuts %v, want %v", offsets, c.Cuts)
			}
			list, raw, err := lantern.BuildChunkIndex(data, c.Chunker.Size)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != c.Index {
				t.Errorf("the index's canonical bytes differ:\n%s\n%s", raw, c.Index)
			}
			if len(raw) != c.IndexSize || list.SHA256 != c.FileSHA256 || list.Size != c.FileSize {
				t.Errorf("index of %d bytes for %s (%d)", len(raw), list.SHA256, list.Size)
			}
			sum := sha256.Sum256(raw)
			if hex.EncodeToString(sum[:]) != c.IndexSHA256 {
				t.Error("the index's SHA-256 is not the vectors'")
			}
			ref := lantern.ChunksRefFor("v1/chunks/sha256/"+list.SHA256+".json", raw)
			if _, err := lantern.ReadChunkIndex(raw, &ref, c.FileSHA256, c.FileSize); err != nil {
				t.Errorf("an index a server writes is refused: %v", err)
			}
		})
	}
}

func TestChunkSizeFor(t *testing.T) {
	for length, want := range map[int64]int64{0: 1 << 16, 1000: 1 << 16, 1 << 30: 1 << 16, 1<<30 + 1: 1 << 17, 1 << 40: 0} {
		if got := lantern.ChunkSizeFor(length); got != want {
			t.Errorf("ChunkSizeFor(%d) = %d, want %d", length, got, want)
		}
	}
}

func TestChunkerRefusesASize(t *testing.T) {
	if _, err := lantern.CutFile([]byte("x"), 65535); err == nil {
		t.Error("a chunker of 65,535 bytes was accepted")
	}
}

func TestChunkIndexRefused(t *testing.T) {
	v := loadChunkVectors(t)
	for _, r := range v.Refused {
		t.Run(r.Name, func(t *testing.T) {
			ref := lantern.ChunksRef{URL: r.Chunks.URL, Size: r.Chunks.Size, SHA256: r.Chunks.SHA256}
			_, err := lantern.ReadChunkIndex([]byte(r.Index), &ref, r.FileSHA256, r.FileSize)
			if (err == nil) != r.Usable {
				t.Fatalf("usable = %v, err = %v", r.Usable, err)
			}
			if err != nil && !errors.Is(err, lantern.ErrUnusableIndex) {
				t.Errorf("the error is not ErrUnusableIndex: %v", err)
			}
		})
	}
	if _, err := lantern.ReadChunkIndex(nil, nil, strings.Repeat("0", 64), 0); !errors.Is(err, lantern.ErrUnusableIndex) {
		t.Errorf("no ref: %v", err)
	}
}

func TestDeltaPlanVector(t *testing.T) {
	v := loadChunkVectors(t)
	var older, newer chunkCase
	for _, c := range v.Cases {
		if strings.HasPrefix(c.Name, "1,000,000 bytes, a chunker of 64") {
			older = c
		}
		if strings.HasPrefix(c.Name, "Their newer") {
			newer = c
		}
	}
	seed, file := fileOf(older), fileOf(newer)
	index, _, err := lantern.BuildChunkIndex(file, newer.Chunker.Size)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := lantern.DeltaPlan(index, [][]byte{seed})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != len(v.Update.Plan) {
		t.Fatalf("%d entries, want %d", len(plan), len(v.Update.Plan))
	}
	for i, want := range v.Update.Plan {
		e := plan[i]
		from := "read"
		if e.FromSeed() {
			from = fmt.Sprintf("seed at %d", e.At)
		}
		if e.Offset != want.Offset || e.Length != want.Size || e.SHA256 != want.SHA256 || from != want.From {
			t.Errorf("entry %d = %+v (%s), want %+v", i, e, from, want)
		}
	}
	var ranges []string
	var read int64
	for _, r := range lantern.RangesOf(plan, 0) {
		ranges = append(ranges, fmt.Sprintf("bytes=%d-%d", r.Start, r.End))
		read += r.End - r.Start + 1
	}
	if fmt.Sprint(ranges) != fmt.Sprint(v.Update.Ranges) || read != v.Update.Read {
		t.Errorf("ranges %v (%d bytes), want %v (%d)", ranges, read, v.Update.Ranges, v.Update.Read)
	}

	// The file is put together from the seed and those ranges alone, and checked.
	var out bytes.Buffer
	asked := 0
	err = lantern.Assemble(index, [][]byte{seed}, plan, func(start, end int64) ([]byte, error) {
		asked++
		return file[start : end+1], nil
	}, func(p []byte) error { out.Write(p); return nil }, newer.FileSHA256, newer.FileSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), file) || asked != 2 {
		t.Errorf("assembled %d bytes in %d ranges", out.Len(), asked)
	}

	// A range that lies, a short range, a chunk that is not its own.
	for name, bad := range map[string]ReadRangeFn{
		"a wrong byte": func(s, e int64) ([]byte, error) {
			b := append([]byte(nil), file[s:e+1]...)
			b[len(b)/2] ^= 1
			return b, nil
		},
		"a short range": func(s, e int64) ([]byte, error) { return file[s:e], nil },
	} {
		err := lantern.Assemble(index, [][]byte{seed}, plan, bad, func([]byte) error { return nil }, newer.FileSHA256, newer.FileSize)
		if !errors.Is(err, lantern.ErrChunkRefused) || !errors.Is(err, lantern.ErrIntegrity) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := lantern.Assemble(index, [][]byte{seed}, plan, func(s, e int64) ([]byte, error) { return file[s : e+1], nil }, func([]byte) error { return nil }, strings.Repeat("a", 64), newer.FileSize); !errors.Is(err, lantern.ErrChunkRefused) {
		t.Errorf("another file's SHA-256: %v", err)
	}
}

// ReadRangeFn is lantern.ReadRange, spelled for the table above.
type ReadRangeFn = lantern.ReadRange

func TestRangesOfLimit(t *testing.T) {
	plan := []lantern.PlanEntry{{Offset: 0, Length: 10, Seed: -1}, {Offset: 10, Length: 10, Seed: -1}, {Offset: 20, Length: 10, Seed: 0}, {Offset: 30, Length: 10, Seed: -1}}
	if got := fmt.Sprint(lantern.RangesOf(plan, 0)); got != "[{0 19} {30 39}]" {
		t.Errorf("ranges %s", got)
	}
	if got := fmt.Sprint(lantern.RangesOf(plan, 15)); got != "[{0 9} {10 19} {30 39}]" {
		t.Errorf("limited ranges %s", got)
	}
}

// A hostile index is refused or read within its bounds, never a panic (SPEC.md § 22.3, L-22.3-1).
func FuzzReadChunkIndex(f *testing.F) {
	_, raw, _ := lantern.BuildChunkIndex(stream("fuzz", 200000), 1<<16)
	f.Add(raw)
	f.Add([]byte(`{"schema":1,"sha256":"` + strings.Repeat("0", 64) + `","size":1,"chunker":{"alg":"lantern-cdc-1","size":65536},"chunks":[[1,"` + strings.Repeat("0", 64) + `"]]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		ref := lantern.ChunksRefFor("x", data)
		list, err := lantern.ReadChunkIndex(data, &ref, strings.Repeat("0", 64), 1)
		if err != nil {
			return
		}
		var total int64
		for _, c := range list.Chunks {
			total += c.Size
		}
		if total != list.Size || len(list.Chunks) > lantern.ChunksLimit {
			t.Fatalf("an index read out of its bounds: %d bytes, %d chunks", total, len(list.Chunks))
		}
	})
}
