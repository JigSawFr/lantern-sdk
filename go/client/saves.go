// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

// The save backups of SPEC.md § 9, for a token with the scope saves. Every route that writes a
// save needs a platform: the client's (Options.Platform) or SaveMeta.Platform.

var (
	saveWord = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	// SaveKinds are the kinds of a save (SPEC.md § 9.1); a reader reads another as other.
	saveKinds = []string{"account", "device", "bcat", "cache", "other"}
)

// SaveMeta is what a backup carries besides its bytes. Every field is optional.
type SaveMeta struct {
	Platform        string // "" for the client's
	Kind            string // account, device, bcat, cache or other
	Slot            string // which of the title's save folders (1 to 64 letters, digits, ., _ and -)
	GameVersionCode *int64 // the game's version_code when it was saved
	Profile         string // the name the user gave the profile, as the device shows it
	Note            string // 120 bytes at most
	// Encryption is set for a backup encrypted on the device (SPEC.md § 9.4): the bytes sent are
	// then the encrypted ones.
	Encryption *lantern.Encryption
}

func (m SaveMeta) check() error {
	switch {
	case m.Platform != "" && !lantern.IsPlatform(m.Platform):
		return fmt.Errorf("lantern: %q is not a platform", lantern.Clip(m.Platform, 40))
	case m.Kind != "" && !contains(saveKinds, m.Kind):
		return fmt.Errorf("lantern: %q is not a save kind", lantern.Clip(m.Kind, 40))
	case m.Slot != "" && !saveWord.MatchString(m.Slot):
		return fmt.Errorf("lantern: %q is not a save slot", lantern.Clip(m.Slot, 70))
	case len(m.Profile) > lantern.MaxProfile:
		return fmt.Errorf("lantern: a profile of %d bytes, above %d", len(m.Profile), lantern.MaxProfile)
	case len(m.Note) > lantern.MaxNote:
		return fmt.Errorf("lantern: a note of %d bytes, above %d", len(m.Note), lantern.MaxNote)
	case m.GameVersionCode != nil && (*m.GameVersionCode < 0 || *m.GameVersionCode > lantern.MaxIJSONInteger):
		return fmt.Errorf("lantern: a game version code outside 0 to 2**53 - 1")
	case m.Encryption != nil && (m.Encryption.Scheme == "" || !keyIDPattern.MatchString(m.Encryption.KeyID)):
		return fmt.Errorf("lantern: an encryption needs a scheme and a key id of 16 hex digits")
	}
	return nil
}

var keyIDPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (m SaveMeta) query() url.Values {
	q := url.Values{}
	if m.Platform != "" {
		q.Set("platform", m.Platform)
	}
	return q
}

func titlePath(prefix, titleID string) (string, error) {
	if !lantern.CoreIDPattern.MatchString(titleID) {
		return "", fmt.Errorf("lantern: %q is not a title id", lantern.Clip(titleID, 40))
	}
	return prefix + url.PathEscape(titleID), nil
}

// Saves lists the account's own backups, newest first per title; titleID and platform narrow it
// ("" for none, the client's platform).
func (c *Client) Saves(ctx context.Context, platform, titleID string) (*lantern.Saves, error) {
	q := url.Values{}
	if platform != "" {
		if !lantern.IsPlatform(platform) {
			return nil, fmt.Errorf("lantern: %q is not a platform", lantern.Clip(platform, 40))
		}
		q.Set("platform", platform)
	}
	if titleID != "" {
		if !lantern.CoreIDPattern.MatchString(titleID) {
			return nil, fmt.Errorf("lantern: %q is not a title id", lantern.Clip(titleID, 40))
		}
		q.Set("title_id", titleID)
	}
	return getJSON[lantern.Saves](c, ctx, "saves", "/saves", q)
}

func (c *Client) saveFile(save *lantern.Save) (*lantern.App, error) {
	if !lantern.CoreIDPattern.MatchString(save.TitleID) || !lantern.CoreIDPattern.MatchString(save.SaveID) {
		return nil, &lantern.DocumentError{Where: "save", Reason: "a title or save id that is not of the form"}
	}
	address, err := c.v1("/saves/" + url.PathEscape(save.TitleID) + "/" + url.PathEscape(save.SaveID))
	if err != nil {
		return nil, err
	}
	return &lantern.App{File: address, Size: save.Size, SHA256: save.SHA256}, nil
}

// OpenSave reads a backup's archive as a file (SPEC.md § 6.6): it ends only when the size and the
// SHA-256 are the save's (lantern.ErrIntegrity otherwise). An encrypted backup gives its encrypted
// bytes, which the caller opens.
func (c *Client) OpenSave(ctx context.Context, save *lantern.Save) (*File, error) {
	app, err := c.saveFile(save)
	if err != nil {
		return nil, err
	}
	return c.OpenFile(ctx, app, 0, nil)
}

// DownloadSave saves a backup's archive to path, as Download does: resumed, and kept only when
// right.
func (c *Client) DownloadSave(ctx context.Context, save *lantern.Save, path string, progress func(done, total int64)) error {
	app, err := c.saveFile(save)
	if err != nil {
		return err
	}
	return c.Download(ctx, app, path, progress)
}

// DeleteSave removes a backup: it then gives 404.
func (c *Client) DeleteSave(ctx context.Context, save *lantern.Save) error {
	if !lantern.CoreIDPattern.MatchString(save.TitleID) || !lantern.CoreIDPattern.MatchString(save.SaveID) {
		return &lantern.DocumentError{Where: "save", Reason: "a title or save id that is not of the form"}
	}
	q := url.Values{}
	if save.Platform != "" {
		q.Set("platform", save.Platform)
	}
	return c.noContent(ctx, &call{method: http.MethodDelete, path: "/saves/" + url.PathEscape(save.TitleID) + "/" + url.PathEscape(save.SaveID), query: q, what: "save"})
}

func contentDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// UploadSave sends a backup in one request (SPEC.md § 9.2), for a save of at most the server's
// limits.save_body bytes (a larger one is refused with 413: UploadSaveResumable has no such
// limit). archive is the zip, or the encrypted bytes when meta.Encryption is set.
func (c *Client) UploadSave(ctx context.Context, titleID string, meta SaveMeta, archive []byte) (*lantern.Save, error) {
	path, err := titlePath("/saves/", titleID)
	if err != nil {
		return nil, err
	}
	if err := meta.check(); err != nil {
		return nil, err
	}
	h := http.Header{"Content-Type": {"application/zip"}, "Content-Digest": {contentDigest(archive)}}
	if meta.Encryption != nil {
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Lantern-Save-Encryption", meta.Encryption.Scheme+"; key_id="+meta.Encryption.KeyID)
	}
	if meta.Kind != "" {
		h.Set("Lantern-Save-Kind", meta.Kind)
	}
	if meta.Slot != "" {
		h.Set("Lantern-Save-Slot", meta.Slot)
	}
	if meta.GameVersionCode != nil {
		h.Set("Lantern-Game-Version", strconv.FormatInt(*meta.GameVersionCode, 10))
	}
	if meta.Profile != "" {
		h.Set("Lantern-Profile", url.PathEscape(meta.Profile))
	}
	if meta.Note != "" {
		h.Set("Lantern-Note", url.PathEscape(meta.Note))
	}
	body := archive
	if body == nil {
		body = []byte{}
	}
	resp, err := c.send(ctx, &call{method: http.MethodPost, path: path, query: meta.query(), raw: body, headers: h, what: "save"}, lantern.MaxJSONDocument)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, "save", http.StatusCreated); err != nil {
		return nil, err
	}
	return read[lantern.Save](c, "save", resp)
}

// StartSaveUpload opens a resumable upload (SPEC.md § 9.3) of size bytes whose SHA-256 is sha256
// (lower-case hex): the session gives where to send the chunks, in what size, and until when.
// A size above the server's limits.save_size is refused with 413.
func (c *Client) StartSaveUpload(ctx context.Context, titleID string, meta SaveMeta, size int64, sha256Hex string) (*lantern.Upload, error) {
	path, err := titlePath("/saves/", titleID)
	if err != nil {
		return nil, err
	}
	if err := meta.check(); err != nil {
		return nil, err
	}
	if size < 0 || size > lantern.MaxIJSONInteger || !lantern.SHA256Pattern.MatchString(sha256Hex) {
		return nil, fmt.Errorf("lantern: an upload needs a size and a SHA-256")
	}
	body := &lantern.UploadRequest{Schema: 1, Size: size, SHA256: sha256Hex, GameVersionCode: meta.GameVersionCode, Encryption: meta.Encryption}
	for p, v := range map[**string]string{&body.Kind: meta.Kind, &body.Slot: meta.Slot, &body.Profile: meta.Profile, &body.Note: meta.Note} {
		if v != "" {
			s := v
			*p = &s
		}
	}
	resp, err := c.send(ctx, &call{method: http.MethodPost, path: path + "/uploads", query: meta.query(), body: body, what: "upload"}, lantern.MaxJSONDocument)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, "upload", http.StatusCreated); err != nil {
		return nil, err
	}
	up, err := read[lantern.Upload](c, "upload", resp)
	if err != nil {
		return nil, err
	}
	if up.ChunkSize < 1 || up.Offset < 0 || up.Offset > size {
		return nil, &lantern.DocumentError{Where: "upload", Reason: "a chunk size or an offset that makes no sense"}
	}
	if _, err := c.onOrigin(up.Upload, "an upload's address"); err != nil {
		return nil, err
	}
	return up, nil
}

// UploadState is where an upload stands.
type UploadState struct {
	Offset    int64 // the bytes the server has
	Length    int64 // the upload's size
	ChunkSize int64 // the chunks to send it in
}

// SaveUploadState asks where to resume after an interruption: it needs only the upload's address.
func (c *Client) SaveUploadState(ctx context.Context, upload string) (*UploadState, error) {
	target, err := c.onOrigin(upload, "an upload's address")
	if err != nil {
		return nil, err
	}
	resp, err := c.send(ctx, &call{method: http.MethodHead, rawURL: target, what: "upload"}, lantern.MaxJSONDocument)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, "upload", http.StatusNoContent); err != nil {
		return nil, err
	}
	st := &UploadState{}
	for h, p := range map[string]*int64{"Upload-Offset": &st.Offset, "Upload-Length": &st.Length, "Lantern-Chunk-Size": &st.ChunkSize} {
		n, err := strconv.ParseInt(resp.header.Get(h), 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%w: upload: no %s", lantern.ErrUnexpectedResponse, h)
		}
		*p = n
	}
	if st.ChunkSize < 1 || st.Offset > st.Length {
		return nil, fmt.Errorf("%w: upload: an offset or a chunk size that makes no sense", lantern.ErrUnexpectedResponse)
	}
	return st, nil
}

// ContinueSaveUpload sends the rest of an upload, from where the server is (the HEAD of the upload
// says) to the end, chunk after chunk, and gives the save once the server has checked the whole
// archive. data is the whole archive (or encrypted bytes), and must be the size and SHA-256 the upload
// was opened with: an upload interrupted can be taken up again with only its address. A chunk the
// server finds at another offset (409) is sent again from the offset it says, a bounded number of
// times; 422 digest_mismatch means the archive is not the one announced, and the server discards it.
func (c *Client) ContinueSaveUpload(ctx context.Context, upload string, data io.ReaderAt, progress func(done, total int64)) (*lantern.Save, error) {
	target, err := c.onOrigin(upload, "an upload's address")
	if err != nil {
		return nil, err
	}
	st, err := c.SaveUploadState(ctx, upload)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, st.ChunkSize)
	realigned := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if progress != nil {
			progress(st.Offset, st.Length)
		}
		n := st.Length - st.Offset
		if n > st.ChunkSize {
			n = st.ChunkSize
		}
		if n == 0 && st.Offset != st.Length {
			return nil, errors.New("lantern: an upload that makes no progress")
		}
		got, rerr := data.ReadAt(buf[:n], st.Offset)
		if int64(got) != n {
			if rerr == nil || errors.Is(rerr, io.EOF) {
				rerr = io.ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("lantern: the data is shorter than the upload: %w", rerr)
		}
		chunk := append([]byte(nil), buf[:n]...)
		h := http.Header{
			"Upload-Offset":  {strconv.FormatInt(st.Offset, 10)},
			"Content-Type":   {"application/offset+octet-stream"},
			"Content-Digest": {contentDigest(chunk)},
		}
		resp, err := c.send(ctx, &call{method: http.MethodPatch, rawURL: target, raw: chunk, headers: h, what: "upload"}, lantern.MaxJSONDocument)
		var perr *lantern.ProblemError
		if errors.As(err, &perr) && perr.Status == http.StatusConflict {
			next, perr2 := strconv.ParseInt(perr.Header("Upload-Offset"), 10, 64)
			if perr2 != nil || next < 0 || next > st.Length || next == st.Offset || realigned >= 8 {
				return nil, err
			}
			realigned++
			st.Offset = next
			continue
		}
		if err != nil {
			return nil, err
		}
		switch resp.status {
		case http.StatusNoContent:
			next, perr := strconv.ParseInt(resp.header.Get("Upload-Offset"), 10, 64)
			if perr != nil || next <= st.Offset || next > st.Length {
				return nil, fmt.Errorf("%w: upload: an Upload-Offset that is not past %d", lantern.ErrUnexpectedResponse, st.Offset)
			}
			st.Offset = next
		case http.StatusCreated:
			if st.Offset+n != st.Length {
				return nil, fmt.Errorf("%w: upload: the server ended the upload before its size", lantern.ErrUnexpectedResponse)
			}
			if progress != nil {
				progress(st.Length, st.Length)
			}
			return read[lantern.Save](c, "save", resp)
		default:
			return nil, c.expect(resp, "upload", http.StatusNoContent, http.StatusCreated)
		}
	}
}

// AbandonSaveUpload abandons an upload.
func (c *Client) AbandonSaveUpload(ctx context.Context, upload string) error {
	target, err := c.onOrigin(upload, "an upload's address")
	if err != nil {
		return err
	}
	return c.noContent(ctx, &call{method: http.MethodDelete, rawURL: target, what: "upload"})
}

// UploadSaveResumable sends a backup of any size up to the server's limits.save_size, in chunks
// that survive a lost connection: it opens the upload and sends it. When it fails after the upload
// was opened, the error says the upload's address (UploadError.Upload) for ContinueSaveUpload.
func (c *Client) UploadSaveResumable(ctx context.Context, titleID string, meta SaveMeta, data io.ReaderAt, size int64, progress func(done, total int64)) (*lantern.Save, error) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(data, 0, size)); err != nil {
		return nil, err
	}
	up, err := c.StartSaveUpload(ctx, titleID, meta, size, fmt.Sprintf("%x", h.Sum(nil)))
	if err != nil {
		return nil, err
	}
	save, err := c.ContinueSaveUpload(ctx, up.Upload, data, progress)
	if err != nil {
		return nil, &UploadError{Upload: up.Upload, Err: err}
	}
	return save, nil
}

// UploadError is a resumable upload that stopped: Upload is its address, to take it up again.
type UploadError struct {
	Upload string
	Err    error
	// Backup is the encrypted backup being sent (UploadEncryptedSaveResumable), nil otherwise: it holds
	// the header and the file key, to encrypt again to the same bytes. Wipe it when done.
	Backup *lantern.SaveBackup
}

func (e *UploadError) Error() string {
	return "lantern: upload " + e.Upload + " stopped: " + e.Err.Error()
}
func (e *UploadError) Unwrap() error { return e.Err }
