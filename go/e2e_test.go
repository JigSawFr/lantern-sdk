// SPDX-License-Identifier: MIT

package lantern_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type e2eVectors struct {
	Keys []struct {
		SaveKey string `json:"save_key"`
		KeyID   string `json:"key_id"`
		Phrase  string `json:"phrase"`
		QR      string `json:"qr"`
	} `json:"keys"`
	Backups []e2eBackup `json:"backups"`
	Refused []struct {
		Name      string  `json:"name"`
		Backup    *string `json:"backup"`
		Operation string  `json:"operation"`
		SaveKey   string  `json:"save_key"`
		SHA256    string  `json:"sha256"`
		Opens     bool    `json:"opens"`
	} `json:"refused"`
	Phrases []struct {
		Name     string `json:"name"`
		Phrase   string `json:"phrase"`
		Accepted bool   `json:"accepted"`
	} `json:"phrases"`
}

func TestSaveKeysVectors(t *testing.T) {
	var v e2eVectors
	testutil.Vectors(t, "encrypted-saves", &v)
	for _, k := range v.Keys {
		key, err := lantern.NewSaveKey(unhex(t, k.SaveKey))
		if err != nil {
			t.Fatal(err)
		}
		if id, _ := key.KeyID(); id != k.KeyID {
			t.Errorf("key id %s, want %s", id, k.KeyID)
		}
		if key.Phrase() != k.Phrase || key.QR() != k.QR {
			t.Errorf("phrase %s, qr %s", key.Phrase(), key.QR())
		}
		back, err := lantern.SaveKeyFromPhrase(k.Phrase)
		if err != nil || !bytes.Equal(back.Bytes(), key.Bytes()) {
			t.Errorf("the phrase does not give the key back: %v", err)
		}
		if back, err := lantern.SaveKeyFromQR(k.QR); err != nil || !bytes.Equal(back.Bytes(), key.Bytes()) {
			t.Errorf("the QR text does not give the key back: %v", err)
		}
	}
	for _, p := range v.Phrases {
		_, err := lantern.SaveKeyFromPhrase(p.Phrase)
		if (err == nil) != p.Accepted {
			t.Errorf("%s: accepted %v: %v", p.Name, err == nil, err)
		}
		if err != nil && !errors.Is(err, lantern.ErrKeyPhrase) {
			t.Errorf("%s: %v", p.Name, err)
		}
	}
}

type e2eBackup struct {
	Name      string          `json:"name"`
	SaveKey   string          `json:"save_key"`
	FileKey   string          `json:"file_key"`
	WrapNonce string          `json:"wrap_nonce"`
	Archive   json.RawMessage `json:"archive"`
	Header    string          `json:"header"`
	Size      int             `json:"size"`
	SHA256    string          `json:"sha256"`
	Encrypted *string         `json:"encrypted"`
	ChunkTags []string        `json:"chunk_tags"`
}

// archiveOf is the archive in hex, or of the size given, byte i being i % 251.
func archiveOf(t *testing.T, b e2eBackup) []byte {
	var hexed string
	if json.Unmarshal(b.Archive, &hexed) == nil {
		return unhex(t, hexed)
	}
	var gen struct {
		Size int `json:"size"`
	}
	if err := json.Unmarshal(b.Archive, &gen); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, gen.Size)
	for i := range out {
		out[i] = byte(i % 251)
	}
	return out
}

func TestEncryptedBackupsVectors(t *testing.T) {
	var v e2eVectors
	testutil.Vectors(t, "encrypted-saves", &v)
	encrypted := map[string][]byte{}
	for _, b := range v.Backups {
		key, _ := lantern.NewSaveKey(unhex(t, b.SaveKey))
		archive := archiveOf(t, b)
		fixed := bytes.NewReader(append(unhex(t, b.FileKey), unhex(t, b.WrapNonce)...))
		backup, err := lantern.NewSaveBackupFrom(key, fixed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(backup.Header(), unhex(t, b.Header)) {
			t.Errorf("%s: header %x", b.Name, backup.Header())
		}
		got, err := io.ReadAll(backup.Encrypt(bytes.NewReader(archive)))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != b.Size || int64(len(got)) != lantern.EncryptedSize(int64(len(archive))) || lantern.SHA256Hex(got) != b.SHA256 {
			t.Errorf("%s: %d bytes, sha256 %s", b.Name, len(got), lantern.SHA256Hex(got))
		}
		if b.Encrypted != nil && !bytes.Equal(got, unhex(t, *b.Encrypted)) {
			t.Errorf("%s: the bytes differ", b.Name)
		}
		for i, tag := range b.ChunkTags {
			end := lantern.SaveHeader + (i+1)*(lantern.SaveChunk+lantern.SaveTag)
			if end > len(got) {
				end = len(got)
			}
			if hex.EncodeToString(got[end-lantern.SaveTag:end]) != tag {
				t.Errorf("%s: tag of chunk %d", b.Name, i)
			}
		}
		// Random access gives the same bytes.
		at := backup.EncryptedReaderAt(bytes.NewReader(archive), int64(len(archive)))
		for _, off := range []int{0, 50, lantern.SaveHeader, lantern.SaveHeader + 3, len(got) / 2, len(got) - 5} {
			if off >= len(got) {
				continue
			}
			buf := make([]byte, 40000)
			n, _ := at.ReadAt(buf, int64(off))
			if !bytes.Equal(buf[:n], got[off:off+n]) || (off+n != len(got) && n != len(buf)) {
				t.Errorf("%s: ReadAt(%d) gave %d bytes, wrong", b.Name, off, n)
			}
		}
		// And it opens.
		plain, err := lantern.DecryptBytes(key, got)
		if err != nil || !bytes.Equal(plain, archive) {
			t.Errorf("%s: does not open: %v", b.Name, err)
		}
		encrypted[b.Name] = got
	}
	for _, r := range v.Refused {
		key, _ := lantern.NewSaveKey(unhex(t, r.SaveKey))
		var data []byte
		if r.Backup == nil {
			data = []byte("PK\x03\x04 a zip, in clear, long enough to have a header's size and a little more than that, so it is read")
		} else {
			data = append([]byte(nil), encrypted[*r.Backup]...)
		}
		op := r.Operation
		switch {
		case strings.HasPrefix(op, "flip bit 0 of byte "):
			var n int
			for _, c := range strings.TrimPrefix(op, "flip bit 0 of byte ") {
				n = n*10 + int(c-'0')
			}
			data[n] ^= 1
		case op == "flip bit 0 of the last byte":
			data[len(data)-1] ^= 1
		case op == "read with the second key":
			key, _ = lantern.NewSaveKey(unhex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
		case op == "drop the last byte":
			data = data[:len(data)-1]
		case strings.HasPrefix(op, "keep the first 88 + "):
			data = data[:88+65552]
		case op == "append 16 zero bytes":
			data = append(data, make([]byte, 16)...)
		case op == "swap the two chunks":
			first, second := data[88:88+65552], data[88+65552:]
			data = append(append(append([]byte(nil), data[:88]...), second...), first...)
		case op == "a zip in clear":
		default:
			t.Fatalf("%s: operation %q", r.Name, op)
		}
		if r.Backup != nil && r.SHA256 != "" && op != "read with the second key" && lantern.SHA256Hex(data) != r.SHA256 {
			t.Errorf("%s: the refused bytes are not the vector's (%s)", r.Name, op)
		}
		_, err := lantern.DecryptBytes(key, data)
		if (err == nil) != r.Opens || (err != nil && !errors.Is(err, lantern.ErrDecryption)) {
			t.Errorf("%s: opens %v (%v), want %v", r.Name, err == nil, err, r.Opens)
		}
	}
}
