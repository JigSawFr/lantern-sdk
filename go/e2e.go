// SPDX-License-Identifier: MIT

package lantern

import (
	"bufio"
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// End-to-end encrypted save backups, scheme lantern-save-e2e-1 (SPEC.md § 9.4): a save key that
// only the user's devices hold, a file key for each backup wrapped by it, and the archive sealed in
// chunks of 65,536 bytes with XChaCha20-Poly1305. The server keeps bytes it cannot read.
//
// A client MUST NOT send the save key, a file key, the wrapping key or the recovery phrase to any
// server or peer: of the key, only its id leaves the device (L-9.4-2).

// The constants of the scheme.
const (
	SaveScheme     = "lantern-save-e2e-1"
	SaveChunk      = 65536                              // the archive's chunks, the last one shorter
	SaveTag        = 16                                 // a chunk's tag
	SaveHeader     = 88                                 // the header of an encrypted backup
	SaveQRPrefix   = "LANTERN-SAVE-KEY-1:"              // a QR code's text, then the key's 56 symbols
	saveSymbols    = 56                                 // a recovery phrase's symbols
	codeAlphabet   = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ" // the pairing alphabet (SPEC.md § 5.2)
	saveMagic      = "LTNE2E01"
	saveCheckLabel = "lantern-save-key"
)

var (
	// ErrDecryption is a backup that does not open: the key is not its key, the header or a chunk
	// does not open, the last chunk is not marked last, or it goes on after it (L-9.4-1). Restore
	// nothing of it.
	ErrDecryption = errors.New("lantern: the encrypted backup does not open")
	// ErrKeyPhrase is a recovery phrase or a QR text whose form or check does not match (L-9.4-7):
	// say so before anything else.
	ErrKeyPhrase = errors.New("lantern: not a save key's recovery phrase")
)

// SaveKey is the save key: 32 bytes, made once by the first device of the user that encrypts, and
// carried to the others as a recovery phrase or a QR code.
type SaveKey struct {
	key    [32]byte
	wiped  bool
	keyID  string
	wrap   [32]byte
	hasKDF bool
}

// NewSaveKey makes a SaveKey of 32 bytes.
func NewSaveKey(raw []byte) (*SaveKey, error) {
	if len(raw) != 32 {
		return nil, &DocumentError{Where: "save key", Reason: "32 bytes expected"}
	}
	k := &SaveKey{}
	copy(k.key[:], raw)
	return k, nil
}

// GenerateSaveKey makes a new save key from the system's secure random source.
func GenerateSaveKey() (*SaveKey, error) {
	k := &SaveKey{}
	if _, err := io.ReadFull(rand.Reader, k.key[:]); err != nil {
		return nil, err
	}
	return k, nil
}

func (k *SaveKey) derive() error {
	if k.wiped {
		return errors.New("lantern: this save key was wiped")
	}
	if k.hasKDF {
		return nil
	}
	id, err := hkdf.Key(sha256.New, k.key[:], nil, SaveScheme+" key id", 8)
	if err != nil {
		return err
	}
	wrap, err := hkdf.Key(sha256.New, k.key[:], nil, SaveScheme+" wrap", 32)
	if err != nil {
		return err
	}
	k.keyID = fmt.Sprintf("%x", id)
	copy(k.wrap[:], wrap)
	k.hasKDF = true
	return nil
}

// KeyID is the key's id: the first 8 bytes of HKDF-SHA-256 (info "lantern-save-e2e-1 key id"), 16
// lower-case hex digits. It is the one thing of the key that is sent.
func (k *SaveKey) KeyID() (string, error) {
	if err := k.derive(); err != nil {
		return "", err
	}
	return k.keyID, nil
}

// Encryption is the encryption a backup made with this key is sent with.
func (k *SaveKey) Encryption() (*Encryption, error) {
	id, err := k.KeyID()
	if err != nil {
		return nil, err
	}
	return &Encryption{Scheme: SaveScheme, KeyID: id}, nil
}

// Bytes is a copy of the key's 32 bytes, to keep where the system protects keys.
func (k *SaveKey) Bytes() []byte {
	if k.wiped {
		return nil
	}
	return append([]byte(nil), k.key[:]...)
}

// Wipe zeroes the key: it can no longer be used.
func (k *SaveKey) Wipe() {
	k.key, k.wrap, k.wiped, k.hasKDF = [32]byte{}, [32]byte{}, true, false
}

// String does not show the key.
func (k *SaveKey) String() string { return "SaveKey(…)" }

func saveCheck(key []byte) []byte {
	sum := sha256.Sum256(append([]byte(saveCheckLabel), key...))
	return sum[:3]
}

func (k *SaveKey) symbols() string {
	data := append(k.Bytes(), saveCheck(k.key[:])...)
	var out strings.Builder
	acc, bits := 0, 0
	for _, b := range data {
		acc = (acc<<8 | int(b)) & 0xffff
		bits += 8
		for bits >= 5 {
			bits -= 5
			out.WriteByte(codeAlphabet[(acc>>bits)&31])
		}
	}
	if bits > 0 {
		out.WriteByte(codeAlphabet[(acc<<(5-bits))&31])
	}
	return out.String()
}

// Phrase is the recovery phrase: 14 groups of 4 symbols. Show it only when the user asks, on the
// device's own screen (L-9.4-8).
func (k *SaveKey) Phrase() string {
	s := k.symbols()
	groups := make([]string, 0, 14)
	for i := 0; i < len(s); i += 4 {
		groups = append(groups, s[i:i+4])
	}
	return strings.Join(groups, "-")
}

// QR is the QR code's text, in the QR code's alphanumeric mode. Show it only when the user asks
// (L-9.4-8).
func (k *SaveKey) QR() string { return SaveQRPrefix + k.symbols() }

// SaveKeyFromPhrase reads a recovery phrase (case, spaces and dashes ignored); ErrKeyPhrase when
// it is not one or its check does not match.
func SaveKeyFromPhrase(phrase string) (*SaveKey, error) {
	text := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "\t", "", "\n", "").Replace(phrase))
	if len(text) != saveSymbols {
		return nil, fmt.Errorf("%w: %d symbols, not %d", ErrKeyPhrase, len(text), saveSymbols)
	}
	raw := make([]byte, 0, 35)
	acc, bits := 0, 0
	for _, r := range text {
		v := strings.IndexRune(codeAlphabet, r)
		if v < 0 {
			return nil, fmt.Errorf("%w: %q is not a symbol of one", ErrKeyPhrase, r)
		}
		acc = (acc<<5 | v) & 0xfff
		bits += 5
		if bits >= 8 {
			bits -= 8
			raw = append(raw, byte(acc>>bits))
		}
	}
	if subtle.ConstantTimeCompare(saveCheck(raw[:32]), raw[32:35]) != 1 {
		return nil, fmt.Errorf("%w: its check does not match: a symbol is mistyped", ErrKeyPhrase)
	}
	return NewSaveKey(raw[:32])
}

// SaveKeyFromQR reads a QR code's text ("LANTERN-SAVE-KEY-1:" and 56 symbols).
func SaveKeyFromQR(text string) (*SaveKey, error) {
	rest, ok := strings.CutPrefix(text, SaveQRPrefix)
	if !ok {
		return nil, fmt.Errorf("%w: a QR text begins with %s", ErrKeyPhrase, SaveQRPrefix)
	}
	if len(rest) != saveSymbols || strings.ContainsAny(rest, "-  \t\n") || rest != strings.ToUpper(rest) {
		return nil, fmt.Errorf("%w: a QR text is %d upper-case symbols after its prefix", ErrKeyPhrase, saveSymbols)
	}
	return SaveKeyFromPhrase(rest)
}

// EncryptedSize is the length of the encrypted backup of an archive of n bytes: 88 + n + 16 × the
// number of chunks (an empty archive is one empty chunk).
func EncryptedSize(n int64) int64 { return SaveHeader + n + SaveTag*chunkCount(n) }

func chunkCount(n int64) int64 {
	if n == 0 {
		return 1
	}
	return (n + SaveChunk - 1) / SaveChunk
}

func chunkNonce(i int64, last bool) []byte {
	nonce := make([]byte, 24)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(i))
	copy(nonce[16:23], tmp[1:]) // i on 7 bytes, big-endian
	if last {
		nonce[23] = 1
	}
	return nonce
}

// SaveBackup is an encrypted backup in the making: a new file key and a new wrap nonce (L-9.4-3),
// the header made from them, and the means to encrypt the archive to the same bytes again and
// again. A client that resumes an upload (SPEC.md § 9.3) keeps it, and encrypts again, without
// keeping the encrypted file. Wipe it when the upload is done or given up.
type SaveBackup struct {
	header  []byte
	fileKey [32]byte
	enc     *Encryption
}

// NewSaveBackup makes a backup with a new file key and wrap nonce from the secure random source.
func NewSaveBackup(key *SaveKey) (*SaveBackup, error) {
	return newSaveBackup(key, rand.Reader)
}

// NewSaveBackupFrom is NewSaveBackup with the file key (32 bytes) and the wrap nonce (24 bytes)
// read from random, for tests with fixed values: never for a real backup.
func NewSaveBackupFrom(key *SaveKey, random io.Reader) (*SaveBackup, error) {
	return newSaveBackup(key, random)
}

func newSaveBackup(key *SaveKey, random io.Reader) (*SaveBackup, error) {
	if err := key.derive(); err != nil {
		return nil, err
	}
	b := &SaveBackup{}
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(random, b.fileKey[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, err
	}
	id, err := hex.DecodeString(key.keyID)
	if err != nil {
		return nil, err
	}
	head := append([]byte(saveMagic), id...)
	aead, err := chacha20poly1305.NewX(key.wrap[:])
	if err != nil {
		return nil, err
	}
	b.header = append(append(head, nonce...), aead.Seal(nil, nonce, b.fileKey[:], head)...)
	b.enc = &Encryption{Scheme: SaveScheme, KeyID: key.keyID}
	return b, nil
}

// Header is the 88 bytes that begin the encrypted backup.
func (b *SaveBackup) Header() []byte { return append([]byte(nil), b.header...) }

// Encryption is the encryption the backup is sent with.
func (b *SaveBackup) Encryption() *Encryption { e := *b.enc; return &e }

// Wipe zeroes the file key.
func (b *SaveBackup) Wipe() { b.fileKey = [32]byte{} }

func (b *SaveBackup) seal(i int64, last bool, plain []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(b.fileKey[:])
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, chunkNonce(i, last), plain, b.header), nil
}

// Encrypt reads the archive and gives the encrypted backup: the header, then the chunks. The same
// archive gives the same bytes each time.
func (b *SaveBackup) Encrypt(archive io.Reader) io.Reader {
	return &sealer{b: b, in: bufio.NewReaderSize(archive, SaveChunk+1), pending: append([]byte(nil), b.header...)}
}

type sealer struct {
	b       *SaveBackup
	in      *bufio.Reader
	pending []byte
	i       int64
	done    bool
	err     error
}

func (s *sealer) Read(p []byte) (int, error) {
	for len(s.pending) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		if s.done {
			return 0, io.EOF
		}
		buf := make([]byte, SaveChunk)
		n, err := io.ReadFull(s.in, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			s.err = err
			continue
		}
		last := err != nil // a short read: the archive ended
		if !last {
			if _, perr := s.in.Peek(1); perr == io.EOF {
				last = true
			}
		}
		sealed, serr := s.b.seal(s.i, last, buf[:n])
		if serr != nil {
			s.err = serr
			continue
		}
		s.pending, s.i, s.done = sealed, s.i+1, last
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

// EncryptedReaderAt gives random access to the encrypted backup of an archive that can be read by
// range (size bytes): what a resumable upload reads, again and again, to the same bytes, without
// the encrypted file kept anywhere.
func (b *SaveBackup) EncryptedReaderAt(archive io.ReaderAt, size int64) io.ReaderAt {
	return &sealedAt{b: b, src: archive, size: size}
}

type sealedAt struct {
	b    *SaveBackup
	src  io.ReaderAt
	size int64
}

func (s *sealedAt) ReadAt(p []byte, off int64) (int, error) {
	total := EncryptedSize(s.size)
	if off < 0 {
		return 0, errors.New("lantern: negative offset")
	}
	n := 0
	for n < len(p) && off+int64(n) < total {
		at := off + int64(n)
		var piece []byte
		if at < SaveHeader {
			piece = s.b.header[at:]
		} else {
			rel := at - SaveHeader
			i := rel / (SaveChunk + SaveTag)
			start := i * SaveChunk
			length := min(int64(SaveChunk), s.size-start)
			if length < 0 {
				length = 0
			}
			plain := make([]byte, length)
			if length > 0 {
				if got, err := s.src.ReadAt(plain, start); int64(got) != length {
					if err == nil || err == io.EOF {
						err = io.ErrUnexpectedEOF
					}
					return n, err
				}
			}
			sealed, err := s.b.seal(i, i == chunkCount(s.size)-1, plain)
			if err != nil {
				return n, err
			}
			piece = sealed[rel-i*(SaveChunk+SaveTag):]
		}
		n += copy(p[n:], piece)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// EncryptBytes is the encrypted backup of an archive, in one slice.
func EncryptBytes(key *SaveKey, archive []byte) ([]byte, error) {
	b, err := NewSaveBackup(key)
	if err != nil {
		return nil, err
	}
	defer b.Wipe()
	return io.ReadAll(b.Encrypt(bytes.NewReader(archive)))
}

// SaveKeyIDOf is the key id an encrypted backup's header names, or "" when the bytes do not begin
// with one.
func SaveKeyIDOf(header []byte) string {
	if len(header) < 16 || string(header[:8]) != saveMagic {
		return ""
	}
	return fmt.Sprintf("%x", header[8:16])
}

// Decrypt opens an encrypted backup read from r with key, and gives the archive. Each chunk is
// opened before a byte of it is given, so what comes out is authentic as far as it goes; but a
// backup cut, moved, dropped from or added to is only known at its end, where Read gives
// ErrDecryption: restore nothing from an archive that did not end with io.EOF (L-9.4-1).
func Decrypt(key *SaveKey, r io.Reader) io.Reader {
	return &opener{key: key, in: bufio.NewReaderSize(r, SaveChunk+SaveTag+1)}
}

type opener struct {
	key    *SaveKey
	in     *bufio.Reader
	header []byte
	aead   interface {
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
	pending []byte
	i       int64
	done    bool
	err     error
}

func (o *opener) fail(why string) { o.err = fmt.Errorf("%w: %s", ErrDecryption, why) }

func (o *opener) start() {
	if err := o.key.derive(); err != nil {
		o.err = err
		return
	}
	o.header = make([]byte, SaveHeader)
	if _, err := io.ReadFull(o.in, o.header); err != nil {
		o.fail("not even a header")
		return
	}
	if string(o.header[:8]) != saveMagic {
		o.fail("not an encrypted backup")
		return
	}
	if SaveKeyIDOf(o.header) != o.key.keyID {
		o.fail("another key's")
		return
	}
	wrap, err := chacha20poly1305.NewX(o.key.wrap[:])
	if err != nil {
		o.err = err
		return
	}
	fileKey, err := wrap.Open(nil, o.header[16:40], o.header[40:], o.header[:16])
	if err != nil {
		o.fail("the header does not open")
		return
	}
	o.aead, err = chacha20poly1305.NewX(fileKey)
	for i := range fileKey {
		fileKey[i] = 0
	}
	if err != nil {
		o.err = err
	}
}

func (o *opener) Read(p []byte) (int, error) {
	if o.header == nil && o.err == nil {
		o.start()
	}
	for len(o.pending) == 0 {
		if o.err != nil {
			return 0, o.err
		}
		if o.done {
			return 0, io.EOF
		}
		buf := make([]byte, SaveChunk+SaveTag)
		n, err := io.ReadFull(o.in, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			o.err = err
			continue
		}
		last := err != nil
		if !last {
			if _, perr := o.in.Peek(1); perr == io.EOF {
				last = true
			}
		}
		if n < SaveTag {
			o.fail("a chunk shorter than its tag, or none")
			continue
		}
		plain, oerr := o.aead.Open(nil, chunkNonce(o.i, last), buf[:n], o.header)
		if oerr != nil {
			o.fail(fmt.Sprintf("chunk %d does not open (changed, moved, cut, or not the last)", o.i))
			continue
		}
		o.pending, o.i, o.done = plain, o.i+1, last
	}
	n := copy(p, o.pending)
	o.pending = o.pending[n:]
	return n, nil
}

// DecryptBytes opens an encrypted backup held in a slice.
func DecryptBytes(key *SaveKey, backup []byte) ([]byte, error) {
	return io.ReadAll(Decrypt(key, bytes.NewReader(backup)))
}

// EncryptionHeader is the value of the Lantern-Save-Encryption header of a request of SPEC.md § 9.2.
func EncryptionHeader(e *Encryption) string { return e.Scheme + "; key_id=" + e.KeyID }
