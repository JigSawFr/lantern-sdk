// SPDX-License-Identifier: MIT

package lantern_test

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

type signedRequest struct {
	Name          string            `json:"name"`
	Method        string            `json:"method"`
	URI           string            `json:"uri"`
	Body          string            `json:"body"`
	Headers       map[string]string `json:"headers"`
	SignatureBase string            `json:"signature_base"`
}

type signatureVectors struct {
	Key struct {
		Seed             string `json:"seed"`
		PublicKey        string `json:"public_key"`
		KeyID            string `json:"keyid"`
		ShortFingerprint string `json:"short_fingerprint"`
	} `json:"key"`
	ServerTime int64           `json:"server_time"`
	Accepted   []signedRequest `json:"accepted"`
}

func TestSignatureVectors(t *testing.T) {
	var v signatureVectors
	testutil.Vectors(t, "signatures", &v)
	seed, _ := hex.DecodeString(v.Key.Seed)
	key, err := lantern.NewSigningKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if key.PublicBase64() != v.Key.PublicKey || key.KeyID() != v.Key.KeyID || key.Fingerprint() != v.Key.ShortFingerprint {
		t.Fatalf("key: %s %s %s", key.PublicBase64(), key.KeyID(), key.Fingerprint())
	}
	if strings.Contains(key.String(), v.Key.Seed) {
		t.Fatal("the secret is in String")
	}
	for _, a := range v.Accepted {
		t.Run(a.Name, func(t *testing.T) {
			h := http.Header{}
			if auth := a.Headers["Authorization"]; auth != "" {
				h.Set("Authorization", auth)
			}
			// created and the nonce are those of the vector's Signature-Input
			input := a.Headers["Signature-Input"]
			created := between(input, "created=", ";")
			nonce := between(input, `nonce="`, `"`)
			var n int64
			for _, c := range created {
				n = n*10 + int64(c-'0')
			}
			if err := lantern.SignRequest(key, a.Method, a.URI, h, []byte(a.Body), lantern.SignOptions{Created: n, Nonce: nonce}); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"Signature-Input", "Signature", "Content-Digest"} {
				if want, got := a.Headers[name], h.Get(name); want != got {
					t.Errorf("%s:\n got %s\nwant %s", name, got, want)
				}
			}
			uri, err := lantern.TargetURI(a.URI)
			if err != nil || !strings.Contains(a.SignatureBase, uri) {
				t.Errorf("target uri %q (%v)", uri, err)
			}
		})
	}
}

func between(s, from, to string) string {
	i := strings.Index(s, from) + len(from)
	j := strings.Index(s[i:], to)
	return s[i : i+j]
}

func TestTargetURI(t *testing.T) {
	for in, want := range map[string]string{
		"HTTPS://Shelf.Example.org:443/a?x=%2F#frag": "https://shelf.example.org/a?x=%2F",
		"http://[::1]:8080":                          "http://[::1]:8080/",
		"https://h:8443/p%2Fq/?":                     "https://h:8443/p%2Fq/",
	} {
		if got, err := lantern.TargetURI(in); err != nil || got != want {
			t.Errorf("%s: %q, %v (want %q)", in, got, err, want)
		}
	}
	for _, bad := range []string{"ftp://h/", "https://u@h/", "/relative", "https://"} {
		if _, err := lantern.TargetURI(bad); err == nil {
			t.Errorf("%q is taken", bad)
		}
	}
}

func TestSignRequestRefusesBadNonce(t *testing.T) {
	key, _ := lantern.GenerateSigningKey()
	if err := lantern.SignRequest(key, "GET", "https://h/", http.Header{}, nil, lantern.SignOptions{Nonce: "short"}); err == nil {
		t.Fatal("a short nonce is taken")
	}
	if n := lantern.NewNonce(); len(n) != 22 {
		t.Fatalf("nonce %q", n)
	}
}
