// SPDX-License-Identifier: MIT

package lantern

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
)

// A server's key fingerprint (SPEC.md § 5.3): the SHA-256 of its certificate's DER
// SubjectPublicKeyInfo. The certificate is read with a small DER reader that goes straight to the
// SubjectPublicKeyInfo, so that a certificate the standard parser is strict about (a self-signed
// one from a NAS) still gives its key. Test vectors: vectors/spki.json.

// ErrCertificate is a certificate this reader cannot find the key of.
var ErrCertificate = errors.New("lantern: a certificate without a readable SubjectPublicKeyInfo")

// element is the tag, the start of the content and the end of the DER element at pos.
func element(data []byte, pos int) (tag byte, start, end int, err error) {
	if pos+2 > len(data) {
		return 0, 0, 0, ErrCertificate
	}
	tag, length := data[pos], int(data[pos+1])
	pos += 2
	if length&0x80 != 0 {
		count := length & 0x7f
		if count == 0 || count > 4 || pos+count > len(data) {
			return 0, 0, 0, ErrCertificate
		}
		length = 0
		for _, b := range data[pos : pos+count] {
			length = length<<8 | int(b)
		}
		pos += count
	}
	end = pos + length
	if length < 0 || end > len(data) || end < pos {
		return 0, 0, 0, ErrCertificate
	}
	return tag, pos, end, nil
}

// SPKIDER is the DER SubjectPublicKeyInfo of a DER certificate (RFC 5280 § 4.1).
func SPKIDER(certificate []byte) ([]byte, error) {
	tag, start, _, err := element(certificate, 0)
	if err != nil || tag != 0x30 {
		return nil, ErrCertificate
	}
	tag, pos, tbsEnd, err := element(certificate, start) // tbsCertificate
	if err != nil || tag != 0x30 {
		return nil, ErrCertificate
	}
	type span struct {
		tag        byte
		begin, end int
	}
	var fields []span
	for pos < tbsEnd && len(fields) < 7 {
		t, _, end, err := element(certificate, pos)
		if err != nil {
			return nil, err
		}
		fields = append(fields, span{t, pos, end})
		pos = end
	}
	if len(fields) > 0 && fields[0].tag == 0xA0 { // [0] version, when present
		fields = fields[1:]
	}
	// serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
	if len(fields) < 6 || fields[5].tag != 0x30 {
		return nil, ErrCertificate
	}
	return certificate[fields[5].begin:fields[5].end], nil
}

// SPKISHA256 is the fingerprint of a DER certificate: lower-case hex.
func SPKISHA256(certificate []byte) (string, error) {
	der, err := SPKIDER(certificate)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// SPKISHA256PEM is the fingerprint of a PEM certificate.
func SPKISHA256PEM(text string) (string, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", ErrCertificate
	}
	return SPKISHA256(block.Bytes)
}

// CheckPin reports whether the key seen is the one pinned (both hex, compared without case).
func CheckPin(seen, pinned string) bool { return strings.EqualFold(seen, pinned) }

// PinMismatchError is a server whose key is not the one pinned: the connection is dropped before
// anything is sent. errors.Is(err, ErrPinMismatch) tells.
type PinMismatchError struct {
	Seen, Pinned, Where string
}

func (e *PinMismatchError) Error() string {
	return "lantern: " + e.Where + ": the server's key " + e.Seen + " is not the one pinned (" + e.Pinned + ")"
}

// Is reports ErrPinMismatch and the kinds it descends from.
func (e *PinMismatchError) Is(target error) bool { return kindIs(ErrPinMismatch, target) }
