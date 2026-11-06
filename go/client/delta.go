// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

// DeltaReport says what a differential download saved (SPEC.md § 22.3).
type DeltaReport struct {
	Reused int64 // bytes taken from the seeds
	Read   int64 // bytes read from the server, in Ranges requests
	Ranges int
	Size   int64 // the file's size
}

// chunkIndex reads the index an app or package names (SPEC.md § 22.1): its bytes, which
// lantern.ReadChunkIndex then checks.
func (c *Client) chunkIndex(ctx context.Context, ref *lantern.ChunksRef) ([]byte, error) {
	target, err := c.onOrigin(ref.URL, "a chunk index")
	if err != nil {
		return nil, err
	}
	resp, err := c.send(ctx, &call{method: http.MethodGet, rawURL: target, what: "chunk index"}, lantern.ChunkIndexLimit)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, "chunk index", http.StatusOK); err != nil {
		return nil, err
	}
	return resp.body, nil
}

// readRange asks for the bytes start to end of a file, inclusive, and gives exactly those: a
// Content-Range that is not the one asked for, or more or fewer bytes, is refused (L-22.3-3).
func (c *Client) readRange(ctx context.Context, target string, size, start, end int64) ([]byte, error) {
	want := end - start + 1
	h := http.Header{"Accept-Encoding": {"identity"}, "Range": {"bytes=" + strconv.FormatInt(start, 10) + "-" + strconv.FormatInt(end, 10)}}
	resp, err := c.stream(ctx, &call{method: http.MethodGet, rawURL: target, headers: h, what: "file"})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bad := func(format string, args ...any) ([]byte, error) {
		return nil, fmt.Errorf("%w: %s", lantern.ErrChunkRefused, fmt.Sprintf(format, args...))
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		return bad("a range served with Content-Encoding %q", lantern.Clip(enc, 40))
	}
	var s, e, total int64
	if resp.StatusCode != http.StatusPartialContent {
		return bad("status %d, not 206, for a range", resp.StatusCode)
	}
	if n, _ := fmt.Sscanf(resp.Header.Get("Content-Range"), "bytes %d-%d/%d", &s, &e, &total); n != 3 || s != start || e != end || total != size {
		return bad("Content-Range %q is not bytes %d-%d/%d", lantern.Clip(resp.Header.Get("Content-Range"), 60), start, end, size)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, want+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", lantern.ErrTransport, err)
	}
	if int64(len(data)) != want {
		return bad("%d bytes for a range of %d", len(data), want)
	}
	return data, nil
}

// DownloadWithSeeds saves an app's file at path as Download does, taking from seeds, the bytes
// the caller holds of older versions, each chunk of the app's index (SPEC.md § 22.3) it finds
// there, and reading the others as ranges of the file. Each chunk, and then the file, is checked
// before it is renamed to path.
//
// It reads the whole file instead (L-22.3-4), and gives a nil report, when it cannot use an index:
// the app has none, the server withdrew the family, the index is not usable, no chunk was found in
// the seeds, or a range or a chunk failed. Nothing of a failed attempt stays.
func (c *Client) DownloadWithSeeds(ctx context.Context, app *lantern.App, path string, seeds [][]byte, progress func(done, total int64)) (*DeltaReport, error) {
	return c.deltaDownload(ctx, app, app.Chunks, path, seeds, progress)
}

// DownloadPackageWithSeeds is DownloadWithSeeds for a homebrew package, with the checks of
// DownloadPackage before a byte is written.
func (c *Client) DownloadPackageWithSeeds(ctx context.Context, entry *lantern.Homebrew, pkg lantern.Package, path string, seeds [][]byte, progress func(done, total int64)) (*lantern.InstallPlan, *DeltaReport, error) {
	plan, err := lantern.PlanInstall(entry, pkg)
	if err != nil {
		return nil, nil, err
	}
	if valid, signed := lantern.VerifySignature(entry, pkg); signed && !valid {
		return nil, nil, fmt.Errorf("%w: the signature of %s does not verify", lantern.ErrRefused, entry.ID)
	}
	report, err := c.deltaDownload(ctx, &lantern.App{File: pkg.File, Size: pkg.Size, SHA256: pkg.SHA256}, pkg.Chunks, path, seeds, progress)
	if err != nil {
		return nil, nil, err
	}
	return plan, report, nil
}

func (c *Client) deltaDownload(ctx context.Context, app *lantern.App, ref *lantern.ChunksRef, path string, seeds [][]byte, progress func(done, total int64)) (*DeltaReport, error) {
	whole := func() (*DeltaReport, error) { return nil, c.Download(ctx, app, path, progress) }
	if ref == nil || len(seeds) == 0 {
		return whole()
	}
	if h := c.Hello(); h != nil && h.Features["deltas"] == 0 {
		if _, there := h.Features["deltas"]; there {
			return whole()
		}
	}
	raw, err := c.chunkIndex(ctx, ref)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return whole()
	}
	index, err := lantern.ReadChunkIndex(raw, ref, app.SHA256, app.Size)
	if err != nil {
		return whole()
	}
	plan, err := lantern.DeltaPlan(index, seeds)
	if err != nil {
		return whole()
	}
	var reused int64
	for _, p := range plan {
		if p.FromSeed() {
			reused += p.Length
		}
	}
	if reused == 0 {
		return whole() // nothing found in the seeds: the file whole
	}
	target, err := c.onOrigin(app.File, "an app's file")
	if err != nil {
		return nil, err
	}

	part := path + ".part"
	out, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	report := &DeltaReport{Reused: reused, Size: app.Size}
	var done int64
	err = lantern.Assemble(index, seeds, plan,
		func(start, end int64) ([]byte, error) {
			data, err := c.readRange(ctx, target, app.Size, start, end)
			if err == nil {
				report.Ranges++
				report.Read += int64(len(data))
			}
			return data, err
		},
		func(piece []byte) error {
			if _, err := out.Write(piece); err != nil {
				return err
			}
			done += int64(len(piece))
			if progress != nil {
				progress(done, app.Size)
			}
			return nil
		}, app.SHA256, app.Size)
	if err == nil {
		if err = out.Sync(); err == nil {
			err = out.Close()
			out = nil
		}
	}
	if out != nil {
		out.Close()
	}
	if err != nil {
		os.Remove(part)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var perr *lantern.ProblemError
		if errors.Is(err, lantern.ErrChunkRefused) || errors.Is(err, lantern.ErrTransport) || errors.As(err, &perr) {
			return whole() // a source or a chunk failed: the file whole (L-22.3-4)
		}
		return nil, err
	}
	if err := os.Rename(part, path); err != nil {
		return nil, err
	}
	return report, nil
}
