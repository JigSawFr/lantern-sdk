// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

// End-to-end encrypted save backups (SPEC.md § 9.4): the archive is encrypted on the device, with a
// key only its user's devices hold; the server keeps the bytes it cannot read, and the key never
// goes to it: of the key, only its id leaves the device (L-9.4-2).

// UploadEncryptedSave encrypts an archive with key and sends it in one request (SPEC.md § 9.2).
// meta.Encryption is set from the key. As the server cannot read the backup, a client SHOULD leave
// the profile and the note out unless its user wants them shown (L-9.4-6).
func (c *Client) UploadEncryptedSave(ctx context.Context, titleID string, meta SaveMeta, key *lantern.SaveKey, archive []byte) (*lantern.Save, error) {
	enc, err := key.Encryption()
	if err != nil {
		return nil, err
	}
	sealed, err := lantern.EncryptBytes(key, archive)
	if err != nil {
		return nil, err
	}
	meta.Encryption = enc
	return c.UploadSave(ctx, titleID, meta, sealed)
}

// UploadEncryptedSaveResumable encrypts an archive that can be read by range (size bytes) and sends
// it in a resumable upload (SPEC.md § 9.3), a new file key and wrap nonce for it (L-9.4-3). The
// encrypted file is kept nowhere: each chunk is encrypted when it is sent. When the upload stops
// after it was opened, the error is an *UploadError whose Backup holds the header made: with the
// upload's address, ContinueSaveUpload takes it up again from Backup.EncryptedReaderAt, to the same
// bytes. The caller wipes the Backup when the upload is done or given up.
func (c *Client) UploadEncryptedSaveResumable(ctx context.Context, titleID string, meta SaveMeta, key *lantern.SaveKey, archive io.ReaderAt, size int64, progress func(done, total int64)) (*lantern.Save, error) {
	backup, err := lantern.NewSaveBackup(key)
	if err != nil {
		return nil, err
	}
	sealed := backup.EncryptedReaderAt(archive, size)
	total := lantern.EncryptedSize(size)
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(sealed, 0, total)); err != nil {
		backup.Wipe()
		return nil, err
	}
	meta.Encryption = backup.Encryption()
	up, err := c.StartSaveUpload(ctx, titleID, meta, total, fmt.Sprintf("%x", h.Sum(nil)))
	if err != nil {
		backup.Wipe()
		return nil, err
	}
	save, err := c.ContinueSaveUpload(ctx, up.Upload, sealed, progress)
	if err != nil {
		return nil, &UploadError{Upload: up.Upload, Err: err, Backup: backup}
	}
	backup.Wipe()
	return save, nil
}

func checkKey(key *lantern.SaveKey, save *lantern.Save) error {
	if save.Encryption == nil {
		return fmt.Errorf("%w: the save is not encrypted", lantern.ErrDecryption)
	}
	id, err := key.KeyID()
	if err != nil {
		return err
	}
	if save.Encryption.Scheme != lantern.SaveScheme || save.Encryption.KeyID != id {
		return fmt.Errorf("%w: the save needs the key %s of %s, not %s", lantern.ErrDecryption, lantern.Clip(save.Encryption.KeyID, 20), lantern.Clip(save.Encryption.Scheme, 40), id)
	}
	return nil
}

type decrypted struct {
	io.Reader
	file *File
}

func (d decrypted) Close() error { return d.file.Close() }

// OpenEncryptedSave reads an encrypted backup and gives its archive. The key must be the one the
// save names. The bytes are opened chunk after chunk, so what is read is authentic as far as it
// goes; but a backup cut, moved or added to is only known at its end, where Read gives
// lantern.ErrDecryption (or lantern.ErrIntegrity for the file itself): restore nothing from an
// archive that did not end with io.EOF (L-9.4-1).
func (c *Client) OpenEncryptedSave(ctx context.Context, key *lantern.SaveKey, save *lantern.Save) (io.ReadCloser, error) {
	if err := checkKey(key, save); err != nil {
		return nil, err
	}
	f, err := c.OpenSave(ctx, save)
	if err != nil {
		return nil, err
	}
	return decrypted{lantern.Decrypt(key, f), f}, nil
}

// DownloadEncryptedSave saves the archive of an encrypted backup to path: written to path.part and
// renamed only when the whole backup opened; nothing is left otherwise.
func (c *Client) DownloadEncryptedSave(ctx context.Context, key *lantern.SaveKey, save *lantern.Save, path string) (err error) {
	r, err := c.OpenEncryptedSave(ctx, key, save)
	if err != nil {
		return err
	}
	defer r.Close()
	part := path + ".part"
	out, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(part)
		}
	}()
	if _, err = io.Copy(out, r); err != nil {
		out.Close()
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	return os.Rename(part, path)
}
