// SPDX-License-Identifier: MIT

package lantern

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Signed requests (SPEC.md § 5.4, RFC 9421 HTTP Message Signatures).
//
// A token bound to a device key travels with a signature of the request, by that key, under the
// label "lantern":
//
//   - its components, in this order: "@method", "@target-uri", then "authorization" when the
//     request carries a token, then "content-digest" when it has a body (a poll of a keyed pairing
//     carries no token);
//   - its parameters, in this order: created (Unix seconds), nonce (22 to 64 characters of
//     base64url, 128 random bits at least), keyid (the base64url of the SHA-256 of the key's 32
//     bytes, unpadded) and alg="ed25519";
//   - the signature base: one line per component, then "@signature-params", joined by a line feed,
//     without one at the end.
const (
	// SignatureLabel is the label of the signature in Signature-Input and Signature.
	SignatureLabel = "lantern"
	// SignatureAlg is the only algorithm.
	SignatureAlg = "ed25519"
	// DefaultSkew is auth.skew when a server announces none (SPEC.md § 5.4), in seconds.
	DefaultSkew = 300
	// MaxSignatureHeader bounds Signature-Input and Signature each (SPEC.md § 13).
	MaxSignatureHeader = 1024
)

var nonceForm = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)

// KeyID is a public key's thumbprint, the keyid of its signatures: the base64url of the SHA-256 of
// its 32 bytes, without padding.
func KeyID(public []byte) string {
	sum := sha256.Sum256(public)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ShortFingerprint is the short form of a SHA-256 for people (SPEC.md § 5.3): its first 16 hex
// digits, upper-case, in groups of four (`3F9A 1C07 B2E4 55D0`). hexSum is 64 hex digits.
func ShortFingerprint(hexSum string) (string, error) {
	hexSum = strings.ToLower(hexSum)
	if !SHA256Pattern.MatchString(hexSum) {
		return "", errors.New("a fingerprint is a SHA-256 in hex")
	}
	head := strings.ToUpper(hexSum[:16])
	return head[0:4] + " " + head[4:8] + " " + head[8:12] + " " + head[12:16], nil
}

// NewNonce is a nonce: 128 random bits, base64url, 22 characters.
func NewNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // the system has no randomness: nothing safe is left to do
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// SigningKey is a device's Ed25519 key for one server (SPEC.md § 5.4): made at pairing, kept with
// the token, never sent anywhere. Its secret is not in its String.
type SigningKey struct {
	seed   [32]byte
	public ed25519.PublicKey
	secret ed25519.PrivateKey
}

// NewSigningKey is the key of a 32-byte seed.
func NewSigningKey(seed []byte) (*SigningKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("a device key's seed is 32 bytes")
	}
	k := &SigningKey{secret: ed25519.NewKeyFromSeed(seed)}
	copy(k.seed[:], seed)
	k.public = k.secret.Public().(ed25519.PublicKey)
	return k, nil
}

// GenerateSigningKey is a new key: a device that pairs again makes a new one.
func GenerateSigningKey() (*SigningKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return NewSigningKey(seed)
}

// SigningKeyFromBase64 is the key of a seed in base64.
func SigningKeyFromBase64(seed string) (*SigningKey, error) {
	raw, err := base64.StdEncoding.DecodeString(seed)
	if err != nil {
		return nil, errors.New("a device key is its 32-byte seed, in base64")
	}
	return NewSigningKey(raw)
}

// Public is the key's 32 bytes.
func (k *SigningKey) Public() []byte { return append([]byte(nil), k.public...) }

// Seed is the secret: for the place the device keeps its keys, and nowhere else.
func (k *SigningKey) Seed() []byte { return append([]byte(nil), k.seed[:]...) }

// SeedBase64 is the secret in base64.
func (k *SigningKey) SeedBase64() string { return base64.StdEncoding.EncodeToString(k.seed[:]) }

// PublicBase64 is the public key in base64.
func (k *SigningKey) PublicBase64() string { return base64.StdEncoding.EncodeToString(k.public) }

// KeyID is the key's thumbprint.
func (k *SigningKey) KeyID() string { return KeyID(k.public) }

// Fingerprint is the key's short fingerprint, for people (`21FE 31DF A154 A261`).
func (k *SigningKey) Fingerprint() string {
	sum := sha256.Sum256(k.public)
	s, _ := ShortFingerprint(hex.EncodeToString(sum[:]))
	return s
}

// Document is `key` of a pairing request.
func (k *SigningKey) Document() *DeviceKey {
	return &DeviceKey{Alg: SignatureAlg, PublicKey: k.PublicBase64()}
}

// Sign is the signature of a message.
func (k *SigningKey) Sign(message []byte) []byte { return ed25519.Sign(k.secret, message) }

// String does not show the secret.
func (k *SigningKey) String() string { return "SigningKey(keyid=" + k.KeyID() + ")" }

// TargetURI is `@target-uri` (RFC 9421 § 2.2.2, SPEC.md § 5.4): the scheme, the host in lower
// case, its port only when not the scheme's default, then the path and query exactly as sent
// (their percent-encoding unchanged).
func TargetURI(raw string) (string, error) {
	bad := fmt.Errorf("%q is not an absolute http(s) URL", Clip(raw, 100))
	u, err := url.Parse(raw)
	if err != nil {
		return "", bad
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", bad
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && port != map[string]string{"http": "80", "https": "443"}[scheme] {
		host += ":" + port
	}
	// The path and the query as written: net/url would re-encode them.
	rest := raw[strings.Index(raw, "://")+3:]
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[i:]
	} else {
		rest = ""
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	path, query, hasQuery := strings.Cut(rest, "?")
	if path == "" {
		path = "/"
	}
	out := scheme + "://" + host + path
	if hasQuery && query != "" {
		out += "?" + query
	}
	return out, nil
}

// ReceivedURI is `@target-uri` of a request a server received: its scheme, its Host header and
// its request target (path and query) as sent.
func ReceivedURI(scheme, host, target string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" || strings.ContainsAny(host, "/?#@ \t") {
		return "", errors.New("no Host this server can read")
	}
	if !strings.HasPrefix(target, "/") {
		target = "/" + target
	}
	return TargetURI(scheme + "://" + host + target)
}

// SignedComponents are the components a request covers, in their order.
func SignedComponents(withToken, withBody bool) []string {
	out := []string{"@method", "@target-uri"}
	if withToken {
		out = append(out, "authorization")
	}
	if withBody {
		out = append(out, "content-digest")
	}
	return out
}

// SignatureParams is `@signature-params`: the lantern member's value of Signature-Input.
func SignatureParams(covered []string, created int64, nonce, keyID string) string {
	quoted := make([]string, len(covered))
	for i, c := range covered {
		quoted[i] = `"` + c + `"`
	}
	return fmt.Sprintf(`(%s);created=%d;nonce="%s";keyid="%s";alg="%s"`, strings.Join(quoted, " "), created, nonce, keyID, SignatureAlg)
}

// SignatureBase is the signature base (RFC 9421 § 2.5) of SPEC.md § 5.4's components. A nil
// authorization or digest is a component the request does not cover.
func SignatureBase(method, uri string, authorization, digest *string, params string) string {
	lines := []string{`"@method": ` + method, `"@target-uri": ` + uri}
	if authorization != nil {
		lines = append(lines, `"authorization": `+*authorization)
	}
	if digest != nil {
		lines = append(lines, `"content-digest": `+*digest)
	}
	lines = append(lines, `"@signature-params": `+params)
	return strings.Join(lines, "\n")
}

// SignOptions fix what a signature would take from the clock and the system: tests set them.
type SignOptions struct {
	Created int64  // Unix seconds; the clock's when 0
	Nonce   string // the system's when empty
}

// SignRequest signs a request in place (SPEC.md § 5.4): it adds Content-Digest when the request
// has a body and none, then Signature-Input and Signature. It covers `authorization` when the
// headers have an Authorization.
func SignRequest(key *SigningKey, method, rawURL string, h http.Header, body []byte, opts SignOptions) error {
	method = strings.ToUpper(method)
	var authorization, digest *string
	if v := h.Get("Authorization"); v != "" {
		authorization = &v
	}
	if len(body) > 0 {
		v := h.Get("Content-Digest")
		if v == "" {
			sum := sha256.Sum256(body)
			var err error
			if v, err = FormatDigest(hex.EncodeToString(sum[:])); err != nil {
				return err
			}
			h.Set("Content-Digest", v)
		}
		digest = &v
	}
	nonce := opts.Nonce
	if nonce == "" {
		nonce = NewNonce()
	}
	if !nonceForm.MatchString(nonce) {
		return errors.New("a nonce is 22 to 64 characters of base64url")
	}
	created := opts.Created
	if created == 0 {
		created = time.Now().Unix()
	}
	uri, err := TargetURI(rawURL)
	if err != nil {
		return err
	}
	params := SignatureParams(SignedComponents(authorization != nil, digest != nil), created, nonce, key.KeyID())
	base := SignatureBase(method, uri, authorization, digest, params)
	h.Set("Signature-Input", SignatureLabel+"="+params)
	h.Set("Signature", SignatureLabel+"=:"+base64.StdEncoding.EncodeToString(key.Sign([]byte(base)))+":")
	return nil
}
