// SPDX-License-Identifier: MIT

package lantern

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"regexp"
	"strings"
)

// Sha256 is a SHA-256 fed as bytes arrive, which counts them too.
type Sha256 struct {
	h    hash.Hash
	size int64
}

// NewSha256 starts a SHA-256 over data.
func NewSha256(data ...[]byte) *Sha256 {
	s := &Sha256{h: sha256.New()}
	for _, d := range data {
		_, _ = s.Write(d)
	}
	return s
}

// Write adds bytes; it never fails.
func (s *Sha256) Write(p []byte) (int, error) {
	s.size += int64(len(p))
	return s.h.Write(p)
}

// Size is the number of bytes written.
func (s *Sha256) Size() int64 { return s.size }

// Sum is the digest so far, 32 bytes.
func (s *Sha256) Sum() []byte { return s.h.Sum(nil) }

// Hex is the digest so far, lower-case hex.
func (s *Sha256) Hex() string { return hex.EncodeToString(s.Sum()) }

// SHA256Hex is the SHA-256 of data, lower-case hex.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SHA256Reader reads r to its end and gives its SHA-256 and its size.
func SHA256Reader(r io.Reader) (*Sha256, error) {
	s := NewSha256()
	_, err := io.Copy(s, r)
	return s, err
}

var hexSHA = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// FormatDigest is the field's value for a SHA-256 (64 hex digits): "sha-256=:<base64>:" (RFC 9530).
func FormatDigest(sha256Hex string) (string, error) {
	if !hexSHA.MatchString(sha256Hex) {
		return "", fmt.Errorf("lantern: %q is not a SHA-256 in hex", truncate(sha256Hex, 70))
	}
	raw, _ := hex.DecodeString(sha256Hex)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(raw) + ":", nil
}

var digestKey = regexp.MustCompile(`^[a-z*][a-z0-9_\-.*]*$`)

// ParseDigest reads a Repr-Digest or Content-Digest value (an RFC 8941 dictionary of byte
// sequences): each algorithm and its digest. Members that are not a byte sequence, or not
// base64, are left out; parameters are ignored.
func ParseDigest(value string) map[string][]byte {
	out := map[string][]byte{}
	for _, member := range strings.Split(value, ",") {
		key, rest, found := strings.Cut(strings.TrimSpace(member), "=")
		key = strings.TrimSpace(key)
		item, _, _ := strings.Cut(rest, ";")
		item = strings.TrimSpace(item)
		if !found || !digestKey.MatchString(key) || len(item) < 2 || item[0] != ':' || item[len(item)-1] != ':' {
			continue
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(item[1 : len(item)-1])
		if err != nil {
			continue
		}
		out[key] = raw
	}
	return out
}

// DigestSHA256 is the SHA-256 a digest field gives, lower-case hex; "" without one (or a malformed one).
func DigestSHA256(value string) string {
	raw := ParseDigest(value)["sha-256"]
	if len(raw) != 32 {
		return ""
	}
	return hex.EncodeToString(raw)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
