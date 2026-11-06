// SPDX-License-Identifier: MIT

package lantern

import (
	"crypto/rand"
	"fmt"
	"regexp"
)

var uidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// IsValidUID reports whether s is a server's uid (SPEC.md § 4.2, L-4.2-9): a random UUID of
// version 4 or 7 (RFC 9562), in lower case. Never a version 1 or 6, which carry a hardware address.
func IsValidUID(s string) bool { return uidPattern.MatchString(s) }

// NewUID is a fresh random uid (a UUID of version 4).
func NewUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("lantern: no randomness: " + err.Error())
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
