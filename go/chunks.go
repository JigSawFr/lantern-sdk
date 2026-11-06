// SPDX-License-Identifier: MIT

package lantern

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"sync"
)

// Differential updates (SPEC.md § 22): the chunker lantern-cdc-1 (§ 22.2), a file's chunk index
// (§ 22.1), the check a client makes before it uses one (§ 22.3, L-22.3-1), and the plan of what
// to take from the bytes a client holds (its seeds) and what to read.
//
//	doc, raw, _ := lantern.BuildChunkIndex(file, 0)                // a server's
//	index, _ := lantern.ReadChunkIndex(raw, app.Chunks, app.SHA256, app.Size)   // a client's
//	plan := lantern.DeltaPlan(index, [][]byte{oldFile})

// The limits and names of the family.
const (
	ChunkerAlgorithm = "lantern-cdc-1"
	ChunkIndexSchema = 1
	ChunksLimit      = 100000  // chunks in an index, at most (SPEC.md § 13)
	ChunkIndexLimit  = 8 << 20 // an index's bytes, at most (SPEC.md § 13)
)

// ChunkerSizes are the sizes a chunker may have: the powers of two from 64 KiB to 4 MiB.
var ChunkerSizes = []int64{1 << 16, 1 << 17, 1 << 18, 1 << 19, 1 << 20, 1 << 21, 1 << 22}

// ErrUnusableIndex wraps what makes a chunk index one a client cannot use: it reads the whole file
// instead (SPEC.md § 22.3, L-22.3-4).
var ErrUnusableIndex = errors.New("lantern: a chunk index that cannot be used")

func unusable(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnusableIndex, fmt.Sprintf(format, args...))
}

var (
	gearOnce  sync.Once
	gearTable [256]uint64
)

// Gear is the gear table G of SPEC.md § 22.2: for each byte value, the first 8 bytes, as a
// big-endian integer, of SHA-256(`lantern-cdc-1` ‖ the byte).
func Gear() *[256]uint64 {
	gearOnce.Do(func() {
		input := append([]byte(ChunkerAlgorithm), 0)
		for i := range gearTable {
			input[len(input)-1] = byte(i)
			sum := sha256.Sum256(input)
			gearTable[i] = binary.BigEndian.Uint64(sum[:8])
		}
	})
	return &gearTable
}

func validChunkerSize(size int64) bool {
	for _, s := range ChunkerSizes {
		if s == size {
			return true
		}
	}
	return false
}

// ChunkBounds are a chunker's least and most chunk, and the bits of its mask (SPEC.md § 22.2).
func ChunkBounds(size int64) (min, max int64, maskBits int, err error) {
	if !validChunkerSize(size) {
		return 0, 0, 0, fmt.Errorf("lantern: a chunker's size is a power of two from 65536 to 4194304, not %d", size)
	}
	return size / 4, size * 4, bits.Len64(uint64(size)) - 1, nil
}

// Cut is a chunk of a file: where it starts and how long it is.
type Cut struct {
	Offset, Length int64
}

// CutFile is lantern-cdc-1's chunks of data for a chunker of size (SPEC.md § 22.2): a chunk ends
// at the end of the data, after the first byte from its min-th on whose gear hash has its top bits
// clear, or at its max-th.
func CutFile(data []byte, size int64) ([]Cut, error) {
	min, max, b, err := ChunkBounds(size)
	if err != nil {
		return nil, err
	}
	g := Gear()
	mask := ^uint64(0) << (64 - b)
	var out []Cut
	n := int64(len(data))
	for start := int64(0); start < n; {
		if n-start <= min {
			out = append(out, Cut{start, n - start})
			break
		}
		end := start + max
		if end > n {
			end = n
		}
		at := end
		var h uint64
		for i := start + min; i < end; i++ {
			h = h<<1 + g[data[i]]
			if h&mask == 0 {
				at = i + 1
				break
			}
		}
		out = append(out, Cut{start, at - start})
		start = at
	}
	return out, nil
}

// ChunkSizeFor is the chunker's size a server may choose for a file of length bytes (SPEC.md
// § 22.1): the smallest from 64 KiB whose chunks stay about 16,384 and, whatever the bytes, within
// the limit of 100,000; 0 for a file too large for any.
func ChunkSizeFor(length int64) int64 {
	fits := func(size int64) bool { return length/(size/4+1)+1 <= ChunksLimit }
	for _, size := range ChunkerSizes {
		if fits(size) && length <= size*16384 {
			return size
		}
	}
	if last := ChunkerSizes[len(ChunkerSizes)-1]; fits(last) {
		return last
	}
	return 0
}

// ChunkList is a chunk index whose chunks are typed.
type ChunkList struct {
	Schema    int64
	SHA256    string
	Size      int64
	Alg       string
	ChunkSize int64 // the chunker's size
	Chunks    []ChunkEntry
}

// ChunkEntry is a chunk of an index: its size and the SHA-256 of its bytes.
type ChunkEntry struct {
	Size   int64
	SHA256 string
}

func hexSum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// BuildChunkIndex is a file's chunk index (SPEC.md § 22.1): its document and its canonical bytes
// (§ 2.3), those whose size and SHA-256 the app's or package's `chunks` gives. size is the
// chunker's, ChunkSizeFor's when 0; an error for a file too large for an index.
func BuildChunkIndex(data []byte, size int64) (*ChunkList, []byte, error) {
	if size == 0 {
		size = ChunkSizeFor(int64(len(data)))
	}
	if size == 0 {
		return nil, nil, errors.New("lantern: a file too large for a chunk index")
	}
	cuts, err := CutFile(data, size)
	if err != nil {
		return nil, nil, err
	}
	list := &ChunkList{Schema: ChunkIndexSchema, SHA256: hexSum(data), Size: int64(len(data)), Alg: ChunkerAlgorithm, ChunkSize: size}
	chunks := make([]any, 0, len(cuts))
	for _, c := range cuts {
		sum := hexSum(data[c.Offset : c.Offset+c.Length])
		list.Chunks = append(list.Chunks, ChunkEntry{c.Length, sum})
		chunks = append(chunks, []any{c.Length, sum})
	}
	raw, err := Canonical(map[string]any{
		"schema":  int64(ChunkIndexSchema),
		"sha256":  list.SHA256,
		"size":    list.Size,
		"chunker": map[string]any{"alg": ChunkerAlgorithm, "size": size},
		"chunks":  chunks,
	})
	if err != nil {
		return nil, nil, err
	}
	return list, raw, nil
}

// ChunksRefFor is an app's or package's `chunks`: where the index is, and its size and SHA-256.
func ChunksRefFor(url string, index []byte) ChunksRef {
	return ChunksRef{URL: url, Size: int64(len(index)), SHA256: hexSum(index)}
}

// ReadChunkIndex is the index a client may use for the file of sha and size, from the bytes raw it
// read at ref.URL (SPEC.md § 22.3, L-22.3-1): their size and SHA-256 those of ref, a document of
// schema 1 (above it: absent), naming that file, by a chunker it knows, with chunks of 1 byte to
// the chunker's max whose sizes add up to the file's, 100,000 at most, their SHA-256 in lower
// case. An error that errors.Is(err, ErrUnusableIndex) otherwise.
func ReadChunkIndex(raw []byte, ref *ChunksRef, sha string, size int64) (*ChunkList, error) {
	if ref == nil || !SHA256Pattern.MatchString(ref.SHA256) {
		return nil, unusable("no chunk index to compare it with")
	}
	if int64(len(raw)) != ref.Size || len(raw) > ChunkIndexLimit {
		return nil, unusable("%d bytes, not the %d the document gives (or above %d)", len(raw), ref.Size, ChunkIndexLimit)
	}
	if hexSum(raw) != ref.SHA256 {
		return nil, unusable("its SHA-256 is not the one the document gives")
	}
	doc, err := LoadJSON(raw, LoadOptions{Limit: ChunkIndexLimit, Where: "chunk index"})
	if err != nil {
		return nil, unusable("%v", err)
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil, unusable("not a document")
	}
	schema, err := SchemaOf(obj, "chunk index")
	if err != nil {
		return nil, unusable("not a document")
	}
	if schema != ChunkIndexSchema {
		return nil, unusable("schema %d, which this client does not read", schema)
	}
	chunker, _ := obj["chunker"].(map[string]any)
	alg, _ := chunker["alg"].(string)
	csize, ok := integer(chunker["size"])
	if chunker == nil || alg != ChunkerAlgorithm || !ok || !validChunkerSize(csize) {
		return nil, unusable("a chunker this client does not know")
	}
	gotSize, okSize := integer(obj["size"])
	if got, _ := obj["sha256"].(string); got != sha || !okSize || gotSize != size {
		return nil, unusable("the index of another file")
	}
	chunks, ok := obj["chunks"].([]any)
	if !ok || len(chunks) > ChunksLimit {
		return nil, unusable("chunks: a list of %d at most", ChunksLimit)
	}
	_, max, _, _ := ChunkBounds(csize)
	list := &ChunkList{Schema: schema, SHA256: sha, Size: size, Alg: alg, ChunkSize: csize, Chunks: make([]ChunkEntry, 0, len(chunks))}
	var total int64
	for _, c := range chunks {
		pair, ok := c.([]any)
		if !ok || len(pair) != 2 {
			return nil, unusable("a chunk of another form")
		}
		n, okN := integer(pair[0])
		h, okH := pair[1].(string)
		if !okN || n < 1 || n > max || !okH || !SHA256Pattern.MatchString(h) {
			return nil, unusable("a chunk of another form")
		}
		total += n
		list.Chunks = append(list.Chunks, ChunkEntry{n, h})
	}
	if total != size {
		return nil, unusable("its chunks add up to %d bytes, not the file's %d", total, size)
	}
	return list, nil
}

// integer reads an integer as LoadJSON gives it (a json.Number).
func integer(v any) (int64, bool) {
	n, ok := v.(interface{ Int64() (int64, error) })
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

// PlanEntry is a chunk of the index: where its bytes are in the file, and where to take them from.
type PlanEntry struct {
	Offset, Length int64
	SHA256         string
	// Seed is the seed to take it from and At the offset in it; Seed is -1 for a range of the file to read.
	Seed int
	At   int64
}

// FromSeed says whether the chunk is taken from a seed.
func (p PlanEntry) FromSeed() bool { return p.Seed >= 0 }

// SeedChunks is where each chunk of a seed is: SHA-256 → the first place of those bytes.
func SeedChunks(seed []byte, size int64) (map[string]Cut, error) {
	cuts, err := CutFile(seed, size)
	if err != nil {
		return nil, err
	}
	out := make(map[string]Cut, len(cuts))
	for _, c := range cuts {
		h := hexSum(seed[c.Offset : c.Offset+c.Length])
		if _, ok := out[h]; !ok {
			out[h] = c
		}
	}
	return out, nil
}

// DeltaPlan is what a client takes from where (SPEC.md § 22.3): each chunk of the index, from the
// first seed that has a chunk of the same size and SHA-256 (cut by the index's chunker), or to read.
func DeltaPlan(index *ChunkList, seeds [][]byte) ([]PlanEntry, error) {
	found := make([]map[string]Cut, len(seeds))
	for i, s := range seeds {
		m, err := SeedChunks(s, index.ChunkSize)
		if err != nil {
			return nil, err
		}
		found[i] = m
	}
	plan := make([]PlanEntry, 0, len(index.Chunks))
	var offset int64
	for _, c := range index.Chunks {
		e := PlanEntry{Offset: offset, Length: c.Size, SHA256: c.SHA256, Seed: -1}
		for n, m := range found {
			if hit, ok := m[c.SHA256]; ok && hit.Length == c.Size {
				e.Seed, e.At = n, hit.Offset
				break
			}
		}
		plan = append(plan, e)
		offset += c.Size
	}
	return plan, nil
}

// ByteRange is a range to read: the file's bytes Start to End, inclusive.
type ByteRange struct {
	Start, End int64
}

// RangesOf are the ranges a client asks for: the chunks to read, neighbours that touch joined, a
// range at most limit bytes long (a range is held in memory while it is checked; 0: no limit).
func RangesOf(plan []PlanEntry, limit int64) []ByteRange {
	var out []ByteRange
	for _, p := range plan {
		if p.FromSeed() {
			continue
		}
		if n := len(out); n > 0 && p.Offset == out[n-1].End+1 && (limit == 0 || p.Offset+p.Length-out[n-1].Start <= limit) {
			out[n-1].End = p.Offset + p.Length - 1
			continue
		}
		out = append(out, ByteRange{p.Offset, p.Offset + p.Length - 1})
	}
	return out
}

// ErrChunkRefused is a chunk, or the file put together, that is not what its index says
// (L-22.3-2): what was written is dropped and the file is read whole.
var ErrChunkRefused = fmt.Errorf("%w: a chunk or a file that does not match its index", ErrIntegrity)

// ReadRange reads the file's bytes start to end, inclusive: exactly those.
type ReadRange func(start, end int64) ([]byte, error)

// Assemble gives write the file an index describes, piece by piece in order: each chunk from a seed
// or from a range read gives, its SHA-256 checked as it comes (L-22.3-2); then the whole file's
// size and SHA-256, checked against sha and size. write receives nothing past the file's size
// (L-22.3-3). An error that errors.Is(err, ErrChunkRefused) when a range, a chunk or the file does
// not match: what was written is to be dropped and the file read whole (L-22.3-4). The file is
// trusted only when Assemble returns nil. plan may be nil (DeltaPlan makes it).
func Assemble(index *ChunkList, seeds [][]byte, plan []PlanEntry, read ReadRange, write func(piece []byte) error, sha string, size int64) error {
	if index.Size != size || index.SHA256 != sha {
		return fmt.Errorf("%w: the index of another file", ErrChunkRefused)
	}
	if plan == nil {
		var err error
		if plan, err = DeltaPlan(index, seeds); err != nil {
			return err
		}
	}
	ranges := RangesOf(plan, 8<<20)
	whole := sha256.New()
	var written int64
	var next int
	var heldStart int64
	var held []byte
	for _, e := range plan {
		var piece []byte
		if e.FromSeed() {
			piece = seeds[e.Seed][e.At : e.At+e.Length]
		} else {
			if held == nil || e.Offset >= heldStart+int64(len(held)) {
				r := ranges[next]
				next++
				data, err := read(r.Start, r.End)
				if err != nil {
					return err
				}
				if int64(len(data)) != r.End-r.Start+1 {
					return fmt.Errorf("%w: the range %d-%d gave %d bytes", ErrChunkRefused, r.Start, r.End, len(data))
				}
				held, heldStart = data, r.Start
			}
			piece = held[e.Offset-heldStart : e.Offset-heldStart+e.Length]
		}
		if int64(len(piece)) != e.Length || hexSum(piece) != e.SHA256 {
			return fmt.Errorf("%w: the chunk at %d does not match its SHA-256", ErrChunkRefused, e.Offset)
		}
		if written+int64(len(piece)) > size {
			return fmt.Errorf("%w: more bytes than the file's size", ErrChunkRefused)
		}
		whole.Write(piece)
		if err := write(piece); err != nil {
			return err
		}
		written += int64(len(piece))
	}
	if written != size || !bytes.Equal(whole.Sum(nil), mustHex(sha)) {
		return fmt.Errorf("%w: the file put together does not match its sha256", ErrChunkRefused)
	}
	return nil
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
