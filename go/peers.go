// SPDX-License-Identifier: MIT

package lantern

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Mirrors, grants and peers (SPEC.md § 19): what a client checks of a mirror's address, what a
// grant says and whether it verifies, and the addresses a peer is reached at. A file comes from a
// mirror or a peer only by its hash: whatever they serve is checked by its size and SHA-256 before
// anything is kept (L-19.1-1), and they get no credential of the server (L-19.1-2).

// GrantPurpose is a grant's purpose (SPEC.md § 19.3). GrantLimit is its longest text (§ 13) and
// GrantLifetimeLimit its longest life in seconds (§ 19.3). MirrorsLimit is a file's mirrors at most
// (§ 19.2). GrantHeader is the header a peer reads a grant from (§ 19.4).
const (
	GrantPurpose       = "lantern-grant-1"
	GrantLimit         = 1024
	GrantLifetimeLimit = 900
	MirrorsLimit       = 8
	GrantHeader        = "Lantern-Grant"
)

// GrantPayload is what a grant says (SPEC.md § 19.3).
type GrantPayload struct {
	Exp     int64
	Purpose string
	SHA256  string
	Size    int64
	UID     string
}

// MakeGrantPayload is a grant's payload: the UTF-8 bytes of the object with these keys in this
// order and no space (SPEC.md § 19.3).
func MakeGrantPayload(uid, sha256 string, size, exp int64) ([]byte, error) {
	if !SHA256Pattern.MatchString(sha256) {
		return nil, fmt.Errorf("lantern: sha256 is 64 lower-case hex digits")
	}
	if size < 0 || size > MaxIJSONInteger || exp < 0 || exp > MaxIJSONInteger {
		return nil, fmt.Errorf("lantern: size and exp are integers from 0 to 2^53-1")
	}
	quoted, err := json.Marshal(uid)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`{"exp":%d,"purpose":"%s","sha256":"%s","size":%d,"uid":%s}`, exp, GrantPurpose, sha256, size, quoted)), nil
}

// SignGrant is a grant signed by a server's grant key: "<payload>.<signature>", each in base64url
// without padding.
func SignGrant(key ed25519.PrivateKey, uid, sha256 string, size, exp int64) (string, error) {
	payload, err := MakeGrantPayload(uid, sha256, size, exp)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(ed25519.Sign(key, payload)), nil
}

// GrantContents is a grant's payload as it reads, unverified; nil when it is not of a grant's
// form. Only the canonical bytes are a grant: another spelling of the same object is not.
func GrantContents(grant string) *GrantPayload {
	if len(grant) > GrantLimit {
		return nil
	}
	body, sig, ok := strings.Cut(grant, ".")
	if !ok || len(sig) != 86 || !base64url(body) || !base64url(sig) {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil
	}
	doc, err := LoadJSON(payload, LoadOptions{Limit: GrantLimit, Where: "grant"})
	if err != nil {
		return nil
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil
	}
	exp, okExp := obj["exp"].(json.Number)
	size, okSize := obj["size"].(json.Number)
	purpose, _ := obj["purpose"].(string)
	sha, okSha := obj["sha256"].(string)
	uid, okUID := obj["uid"].(string)
	if !okExp || !okSize || !okSha || !okUID || purpose != GrantPurpose || !SHA256Pattern.MatchString(sha) {
		return nil
	}
	e, err1 := exp.Int64()
	s, err2 := size.Int64()
	if err1 != nil || err2 != nil {
		return nil
	}
	canonical, err := MakeGrantPayload(uid, sha, s, e)
	if err != nil || string(canonical) != string(payload) {
		return nil
	}
	return &GrantPayload{Exp: e, Purpose: purpose, SHA256: sha, Size: s, UID: uid}
}

func base64url(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return s != ""
}

// VerifyGrant is the payload of a grant that verifies (SPEC.md § 19.4): signed by the grant key of
// the server whose uid it names, among keys (uid → its handshake's peers.key, in base64), and not
// expired at now (Unix seconds); nil otherwise. The signature is checked as L-8.4-4 asks.
func VerifyGrant(grant string, keys map[string]string, now int64) *GrantPayload {
	doc := GrantContents(grant)
	if doc == nil {
		return nil
	}
	given, ok := keys[doc.UID]
	if !ok {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(given)
	if err != nil || len(key) != ed25519.PublicKeySize || doc.Exp < now {
		return nil
	}
	body, sig, _ := strings.Cut(grant, ".")
	payload, err1 := base64.RawURLEncoding.DecodeString(body)
	signature, err2 := base64.RawURLEncoding.DecodeString(sig)
	if err1 != nil || err2 != nil || !VerifyEd25519(key, payload, signature) {
		return nil
	}
	return doc
}

// GrantKey is the 32 bytes of a handshake's peers.key, or nil when it is not one.
func GrantKey(peers *HandshakePeers) []byte {
	if peers == nil {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(peers.Key)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil
	}
	return key
}

// IsPrivateAddress is whether host (an address, IPv6 in brackets or not) is of a private network:
// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7 or fe80::/10 (SPEC.md § 19.2). A name is
// not: what it resolves to is not known here.
func IsPrivateAddress(host string) bool {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if i := strings.IndexByte(host, '%'); i >= 0 { // an interface's zone
		host = host[:i]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.IsPrivate()
	}
	b := addr.As16()
	return b[0]&0xfe == 0xfc || b[0] == 0xfe && b[1]&0xc0 == 0x80
}

// PlainHTTPToPeer is whether plain HTTP may go to host: a private network's (SPEC.md § 19.2), or
// loopback (§ 2, for testing).
func PlainHTTPToPeer(host string) bool {
	return IsPrivateAddress(host) || IsLoopback(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
}

// MirrorAllowed is whether a client may read a mirror at address (SPEC.md § 19.2, L-19.2-1):
// absolute, https, or http at an address of a private network (or loopback, as § 2 allows for
// testing); no credentials, no fragment.
func MirrorAllowed(address string) bool {
	if len(address) > 4096 {
		return false
	}
	u, err := url.Parse(address)
	if err != nil || u.User != nil || u.Fragment != "" || strings.Contains(address, "#") || u.Hostname() == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return PlainHTTPToPeer(u.Hostname())
	}
	return false
}

// UsableMirrors are the mirrors of a file a client may read, at most 8 (SPEC.md § 19.2); the
// others are passed by.
func UsableMirrors(mirrors []Mirror) []string {
	var out []string
	for i, m := range mirrors {
		if i >= MirrorsLimit {
			break
		}
		if MirrorAllowed(m.URL) {
			out = append(out, m.URL)
		}
	}
	return out
}

// Peer is a peer found on the LAN (SPEC.md § 19.5): where it serves, and whose grants it takes.
type Peer struct {
	Address string
	Port    int
	Base    string
	TLS     bool
	UID     string
	Name    string
	Slots   int
	Servers []string
	// URL is "<scheme>://<address>:<port><base>": where its route is.
	URL string
}

// PeerURL is a peer's base URL: plain HTTP only at an address of a private network (L-19.4-6).
func PeerURL(address string, port int, base string, tls bool) (string, error) {
	if !tls && !PlainHTTPToPeer(address) {
		return "", fmt.Errorf("lantern: %s: a grant goes over plain HTTP only to a private network (SPEC.md § 19.4)", address)
	}
	scheme := "http"
	if tls {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(address, "["), "]"), strconv.Itoa(port)) + strings.TrimRight(base, "/"), nil
}

// BlobURL is the address of a file on a peer: "<peer base>/v1/blobs/sha256/<hex>".
func BlobURL(peer, sha256 string) (string, error) {
	if !SHA256Pattern.MatchString(sha256) {
		return "", fmt.Errorf("lantern: sha256 is 64 lower-case hex digits")
	}
	return strings.TrimRight(peer, "/") + "/v1/blobs/sha256/" + sha256, nil
}
