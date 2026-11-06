// SPDX-License-Identifier: MIT

package lantern_test

import (
	"encoding/hex"
	"testing"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

func TestEd25519RefusedVectors(t *testing.T) {
	var v struct {
		SmallOrder []string `json:"small_order"`
		Messages   []string `json:"messages"`
		Cases      []struct {
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
			Message   string `json:"message"`
			Signature string `json:"signature"`
			Verifies  bool   `json:"verifies"`
		} `json:"cases"`
	}
	testutil.Vectors(t, "ed25519-refused", &v)
	for _, c := range v.Cases {
		pk, _ := hex.DecodeString(c.PublicKey)
		sig, _ := hex.DecodeString(c.Signature)
		if got := lantern.VerifyEd25519(pk, []byte(c.Message), sig); got != c.Verifies {
			t.Errorf("%s: verifies %v, want %v", c.Name, got, c.Verifies)
		}
	}
	// Every pair of small-order encodings, as the key and as R, with S = 0, is refused.
	for _, k := range v.SmallOrder {
		for _, r := range v.SmallOrder {
			pk, _ := hex.DecodeString(k)
			sig, _ := hex.DecodeString(r + "00000000000000000000000000000000000000000000000000000000000000")
			for _, m := range v.Messages {
				if lantern.VerifyEd25519(pk, []byte(m), sig) {
					t.Fatalf("key %s, R %s, %q: accepted", k, r, m)
				}
			}
		}
	}
}
