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
	"strings"
	"time"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

// stream sends a call and gives the answer's body to read as it arrives, for a file too big to
// hold. The timeout bounds the wait for the answer's headers only; ctx ends the body. A refused
// signature is signed again once, as send does.
func (c *Client) stream(ctx context.Context, k *call) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		req, err := c.build(ctx, k)
		if err != nil {
			return nil, err
		}
		sctx, cancel := context.WithCancel(ctx)
		timer := time.AfterFunc(c.timeout, cancel)
		resp, err := c.http.Do(req.WithContext(sctx))
		if !timer.Stop() && err == nil {
			resp.Body.Close()
			cancel()
			return nil, fmt.Errorf("%w: no answer in %s", lantern.ErrTransport, c.timeout)
		}
		if err != nil {
			cancel()
			var pin *lantern.PinMismatchError
			if errors.As(err, &pin) {
				return nil, pin
			}
			return nil, fmt.Errorf("%w: %w", lantern.ErrTransport, err)
		}
		if err := c.checkPin(resp); err != nil {
			resp.Body.Close()
			cancel()
			return nil, err
		}
		if resp.StatusCode < 400 {
			resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
			return resp, nil
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, errorBody))
		resp.Body.Close()
		cancel()
		perr := lantern.NewProblemError(resp.StatusCode, body, flat(resp.Header))
		if attempt == 0 && req.Header.Get("Signature") != "" && c.resign(perr, resp.Header) {
			continue
		}
		return nil, perr
	}
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// File is a file being downloaded (SPEC.md § 6.6): its bytes are checked as they come, and the
// last Read gives the end only when they are the bytes the document describes (their number and
// their SHA-256); otherwise it gives an error that errors.Is(err, lantern.ErrIntegrity). Close it.
type File struct {
	// Restarted says the server sent the file from its start although a later byte was asked for
	// (the file changed, or it does not resume): the caller starts its copy again.
	Restarted bool
	// Offset is where the bytes this File gives start in the file.
	Offset int64

	body   io.ReadCloser
	size   int64
	sha    string
	hash   *lantern.Sha256
	read   int64
	failed error
}

// OpenFile opens an app's file (SPEC.md § 6.6) from byte offset: 0 for the whole file. To resume,
// give the offset and the SHA-256 state of the bytes before it (prefix, the same *lantern.Sha256
// that read them), or nil to have the file from its start when offset is 0 only.
//
// The headers are checked before a byte is given: the length, the Content-Range of a resumed
// file, no Content-Encoding, and a Repr-Digest that is the app's SHA-256.
func (c *Client) OpenFile(ctx context.Context, app *lantern.App, offset int64, prefix *lantern.Sha256) (*File, error) {
	if offset < 0 || offset > app.Size {
		return nil, fmt.Errorf("lantern: offset %d is outside a file of %d bytes", offset, app.Size)
	}
	if offset > 0 && (prefix == nil || prefix.Size() != offset) {
		return nil, errors.New("lantern: resuming needs the SHA-256 of the bytes before the offset")
	}
	if app.File == "" || !lantern.SHA256Pattern.MatchString(app.SHA256) {
		return nil, &lantern.DocumentError{Where: "app", Reason: "no file address or no SHA-256"}
	}
	target, err := c.onOrigin(app.File, "an app's file")
	if err != nil {
		return nil, err
	}
	h := http.Header{"Accept-Encoding": {"identity"}}
	if offset > 0 {
		h.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
	}
	resp, err := c.stream(ctx, &call{method: http.MethodGet, rawURL: target, headers: h, what: "file"})
	if err != nil {
		return nil, err
	}
	f := &File{body: resp.Body, size: app.Size, sha: app.SHA256, Offset: offset}
	fail := func(format string, args ...any) (*File, error) {
		resp.Body.Close()
		return nil, fmt.Errorf("%w: %s", lantern.ErrIntegrity, fmt.Sprintf(format, args...))
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		return fail("a file served with Content-Encoding %q", lantern.Clip(enc, 40))
	}
	switch resp.StatusCode {
	case http.StatusOK:
		if offset > 0 {
			f.Restarted, f.Offset, prefix = true, 0, nil
		}
		if resp.ContentLength >= 0 && resp.ContentLength != app.Size {
			return fail("%d bytes announced, the app has %d", resp.ContentLength, app.Size)
		}
	case http.StatusPartialContent:
		if offset == 0 {
			return fail("a partial answer to a request for the whole file")
		}
		var start, end, total int64
		if n, _ := fmt.Sscanf(resp.Header.Get("Content-Range"), "bytes %d-%d/%d", &start, &end, &total); n != 3 || start != offset || end != app.Size-1 || total != app.Size {
			return fail("Content-Range %q is not bytes %d-%d/%d", lantern.Clip(resp.Header.Get("Content-Range"), 60), offset, app.Size-1, app.Size)
		}
	default:
		resp.Body.Close()
		return nil, c.expect(&response{status: resp.StatusCode}, "file", http.StatusOK)
	}
	if v := resp.Header.Get("Repr-Digest"); v == "" {
		return fail("no Repr-Digest")
	} else if got := lantern.DigestSHA256(v); got != app.SHA256 {
		return fail("Repr-Digest %q is not the app's SHA-256", lantern.Clip(v, 80))
	}
	if prefix != nil {
		f.hash = prefix
	} else {
		f.hash = lantern.NewSha256()
	}
	f.read = f.hash.Size()
	return f, nil
}

// Read gives the file's bytes; see File.
func (f *File) Read(p []byte) (int, error) {
	if f.failed != nil {
		return 0, f.failed
	}
	if f.read >= f.size {
		// the declared size is read: the next byte, if any, is one too many
		var one [1]byte
		n, err := f.body.Read(one[:])
		if n > 0 {
			f.failed = fmt.Errorf("%w: more than the %d bytes of the app", lantern.ErrIntegrity, f.size)
			return 0, f.failed
		}
		if err != nil && err != io.EOF {
			f.failed = fmt.Errorf("%w: %w", lantern.ErrTransport, err)
			return 0, f.failed
		}
		return 0, f.finish()
	}
	if room := f.size - f.read; int64(len(p)) > room {
		p = p[:room]
	}
	n, err := f.body.Read(p)
	f.hash.Write(p[:n])
	f.read += int64(n)
	switch {
	case err == nil:
		return n, nil
	case err == io.EOF:
		if f.read < f.size {
			f.failed = fmt.Errorf("%w: %d bytes of %d", lantern.ErrIntegrity, f.read, f.size)
			return n, f.failed
		}
		if n > 0 {
			return n, nil
		}
		return 0, f.finish()
	default:
		f.failed = fmt.Errorf("%w: %w", lantern.ErrTransport, err)
		return n, f.failed
	}
}

func (f *File) finish() error {
	if got := f.hash.Hex(); got != f.sha {
		f.failed = fmt.Errorf("%w: SHA-256 %s, the app says %s", lantern.ErrIntegrity, got, f.sha)
		return f.failed
	}
	f.failed = io.EOF
	return io.EOF
}

// Close ends the download.
func (f *File) Close() error { return f.body.Close() }

// Download saves an app's file at path, checked against its SHA-256 (SPEC.md § 6.6, Annex B.4).
// The bytes go to path+".part" first; a copy that a previous call left is resumed with a Range
// request, and starts again when the server sends the whole file. Only a file whose size and
// SHA-256 are the app's is renamed to path: a wrong one is deleted and the error is
// lantern.ErrIntegrity. progress, when set, is told how many bytes of the file are there.
func (c *Client) Download(ctx context.Context, app *lantern.App, path string, progress func(done, total int64)) error {
	part := path + ".part"
	var offset int64
	var prefix *lantern.Sha256
	if st, err := os.Stat(part); err == nil && st.Mode().IsRegular() && st.Size() > 0 && st.Size() <= app.Size {
		if h, err := hashFile(part, st.Size()); err == nil {
			offset, prefix = st.Size(), h
		}
	}
	if offset == app.Size && prefix != nil { // a copy that is all there: nothing to ask
		if prefix.Hex() != app.SHA256 {
			os.Remove(part)
			return fmt.Errorf("%w: SHA-256 %s, the app says %s", lantern.ErrIntegrity, prefix.Hex(), app.SHA256)
		}
		return os.Rename(part, path)
	}
	file, err := c.OpenFile(ctx, app, offset, prefix)
	if err != nil {
		if offset > 0 && errors.Is(err, lantern.ErrBadRequest) { // 416: the copy is not a prefix of this file
			os.Remove(part)
			return c.Download(ctx, app, path, progress)
		}
		return err
	}
	defer file.Close()
	flags := os.O_WRONLY | os.O_CREATE
	if file.Restarted || offset == 0 {
		flags |= os.O_TRUNC
	}
	out, err := os.OpenFile(part, flags, 0o600)
	if err != nil {
		return err
	}
	if !file.Restarted && offset > 0 {
		if _, err := out.Seek(offset, io.SeekStart); err != nil {
			out.Close()
			return err
		}
	}
	done := file.Offset
	buf := make([]byte, 64<<10)
	for {
		n, rerr := file.Read(buf)
		if n > 0 {
			if _, err := out.Write(buf[:n]); err != nil {
				out.Close()
				return err
			}
			done += int64(n)
			if progress != nil {
				progress(done, app.Size)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			out.Close()
			if errors.Is(rerr, lantern.ErrIntegrity) && done >= app.Size {
				os.Remove(part) // all the bytes came and they are wrong: a resume would not mend them
			}
			return rerr
		}
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(part, path)
}

func hashFile(path string, size int64) (*lantern.Sha256, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := lantern.NewSha256()
	n, err := io.Copy(h, io.LimitReader(f, size))
	if err != nil || n != size {
		return nil, errors.New("short")
	}
	return h, nil
}
