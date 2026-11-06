// SPDX-License-Identifier: MIT

package lantern_test

import (
	"encoding/json"
	"testing"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

// FuzzLoadJSON: whatever the bytes, the reader returns a value or a DocumentError, and a value
// it returns has a canonical form that reads back the same.
func FuzzLoadJSON(f *testing.F) {
	for _, seed := range []string{`{}`, `[1,2.5,"x",null,true]`, `{"a":{"b":[{}]}}`, `{"a":"😀"}`, `9007199254740991`, `"\ud800"`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		v, err := lantern.LoadJSON(raw, lantern.LoadOptions{})
		if err != nil {
			if _, ok := err.(*lantern.DocumentError); !ok {
				t.Fatalf("%T is not a DocumentError", err)
			}
			return
		}
		c1, err := lantern.Canonical(v)
		if err != nil {
			t.Fatalf("a loaded value has no canonical form: %v", err)
		}
		again, err := lantern.LoadJSON(c1, lantern.LoadOptions{})
		if err != nil {
			t.Fatalf("the canonical form %s does not load: %v", c1, err)
		}
		if c2, _ := lantern.Canonical(again); string(c1) != string(c2) {
			t.Fatalf("canonical is not stable: %s then %s", c1, c2)
		}
	})
}

// FuzzDocuments: a document that decodes into a model writes back and decodes again, whatever it holds.
func FuzzDocuments(f *testing.F) {
	names := lantern.DocumentNames
	for i, name := range names {
		seed := testutil.Read(f, "examples", "v1", name+".json")
		f.Add(uint8(i), seed)
	}
	f.Fuzz(func(t *testing.T, which uint8, raw []byte) {
		name := names[int(which)%len(names)]
		model := lantern.NewDocument(name)
		if json.Unmarshal(raw, model) != nil {
			return
		}
		back, err := json.Marshal(model)
		if err != nil {
			t.Fatalf("%s: written back with an error: %v", name, err)
		}
		if err := json.Unmarshal(back, lantern.NewDocument(name)); err != nil {
			t.Fatalf("%s: what it wrote does not read: %v\n%s", name, err, back)
		}
	})
}
