// SPDX-License-Identifier: MIT

package lantern_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

func canon(t *testing.T, raw []byte) string {
	t.Helper()
	v, err := lantern.LoadJSON(raw, lantern.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := lantern.Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func stem(path string) string { return strings.TrimSuffix(filepath.Base(path), ".json") }

func TestEveryExampleReadsAndWritesBackUnchanged(t *testing.T) {
	for _, path := range testutil.Glob(t, "examples", "v1", "*.json") {
		t.Run(stem(path), func(t *testing.T) {
			raw := testutil.Read(t, "examples", "v1", filepath.Base(path))
			doc := lantern.NewDocument(stem(path))
			if doc == nil {
				t.Fatalf("no model for %s", stem(path))
			}
			if err := json.Unmarshal(raw, doc); err != nil {
				t.Fatal(err)
			}
			back, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if canon(t, back) != canon(t, raw) {
				t.Errorf("written back differently:\n%s\n%s", canon(t, back), canon(t, raw))
			}
		})
	}
}

func TestUnknownFieldsAreKeptOnARewrite(t *testing.T) {
	for _, path := range testutil.Glob(t, "examples", "v1", "*.json") {
		t.Run(stem(path), func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(testutil.Read(t, "examples", "v1", filepath.Base(path)), &doc); err != nil {
				t.Fatal(err)
			}
			doc["x-example-shelf"] = map[string]any{"kept": []any{1, 2}}
			raw, _ := json.Marshal(doc)
			model := lantern.NewDocument(stem(path))
			if err := json.Unmarshal(raw, model); err != nil {
				t.Fatal(err)
			}
			back, _ := json.Marshal(model)
			if canon(t, back) != canon(t, raw) {
				t.Errorf("a field was lost:\n%s\n%s", canon(t, back), canon(t, raw))
			}
		})
	}
}

func TestNestedUnknownFieldsAreKept(t *testing.T) {
	var doc map[string]any
	_ = json.Unmarshal(testutil.Read(t, "examples", "v1", "homebrew.json"), &doc)
	doc["package"].(map[string]any)["manifest"].([]any)[0].(map[string]any)["x-vendor-mode"] = "0644"
	doc["requires"].(map[string]any)["x-vendor-gpu"] = "anything"
	raw, _ := json.Marshal(doc)
	var h lantern.Homebrew
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	if got := string(h.Package.Manifest[0].Extra["x-vendor-mode"]); got != `"0644"` {
		t.Errorf("x-vendor-mode = %s", got)
	}
	back, _ := json.Marshal(h)
	if canon(t, back) != canon(t, raw) {
		t.Error("a nested field was lost")
	}
}

func TestAMissingRequiredFieldIsRefused(t *testing.T) {
	var doc map[string]any
	_ = json.Unmarshal(testutil.Read(t, "examples", "v1", "apps.json"), &doc)
	delete(doc["items"].([]any)[0].(map[string]any), "sha256")
	raw, _ := json.Marshal(doc)
	var apps lantern.AppsPage
	err := json.Unmarshal(raw, &apps)
	var de *lantern.DocumentError
	if !errors.As(err, &de) || !strings.Contains(err.Error(), "no sha256") {
		t.Fatalf("err = %v", err)
	}
}

func TestAFieldOfTheWrongTypeIsRefused(t *testing.T) {
	for key, value := range map[string]any{"build": "10400", "name": 7, "tags": "journal", "version": nil} {
		var doc map[string]any
		_ = json.Unmarshal(testutil.Read(t, "examples", "v1", "homebrew.json"), &doc)
		doc[key] = value
		raw, _ := json.Marshal(doc)
		var h lantern.Homebrew
		if err := json.Unmarshal(raw, &h); err == nil {
			t.Errorf("%s = %v was taken", key, value)
		}
	}
}

func TestANewerSchemaIsAbsent(t *testing.T) {
	var doc map[string]any
	_ = json.Unmarshal(testutil.Read(t, "examples", "v1", "handshake.json"), &doc)
	raw, _ := json.Marshal(doc)
	if _, err := lantern.Parse[lantern.Handshake](raw); err != nil {
		t.Fatal(err)
	}
	doc["schema"] = 2
	doc["something"] = "this version does not know"
	raw, _ = json.Marshal(doc)
	h, err := lantern.Parse[lantern.Handshake](raw)
	if h != nil || !errors.Is(err, lantern.ErrNewerSchema) {
		t.Fatalf("got %v, %v", h, err)
	}
}

func TestADocumentNeedsAnIntegerSchema(t *testing.T) {
	for _, schema := range []any{nil, "1", 0, true, -1, 1.5} {
		var doc map[string]any
		_ = json.Unmarshal(testutil.Read(t, "examples", "v1", "cheats.json"), &doc)
		doc["schema"] = schema
		raw, _ := json.Marshal(doc)
		if _, err := lantern.Parse[lantern.CheatSets](raw); err == nil || !strings.Contains(err.Error(), "schema") {
			t.Errorf("schema %v: err = %v", schema, err)
		}
	}
}

func TestParseReadsBytesWithinTheLimits(t *testing.T) {
	raw := testutil.Read(t, "examples", "v1", "titles.json")
	if _, err := lantern.Parse[lantern.Titles](raw); err != nil {
		t.Fatal(err)
	}
	if _, err := lantern.Parse[lantern.Titles]([]byte(`{"schema":1,"items":`)); err == nil {
		t.Error("a cut document was taken")
	}
	if _, err := lantern.Parse[lantern.Titles]([]byte(`[]`)); err == nil {
		t.Error("an array was taken")
	}
}

func TestAnExplicitNullIsAbsentForAnOptionalField(t *testing.T) {
	var h lantern.Homebrew
	var doc map[string]any
	_ = json.Unmarshal(testutil.Read(t, "examples", "v1", "homebrew.json"), &doc)
	doc["author"] = nil
	raw, _ := json.Marshal(doc)
	if err := json.Unmarshal(raw, &h); err != nil || h.Author != nil {
		t.Fatalf("author = %v, err = %v", h.Author, err)
	}
}

func TestOpenVocabulariesReadAsTheSpecificationSays(t *testing.T) {
	var h lantern.Homebrew
	_ = json.Unmarshal(testutil.Read(t, "examples", "v1", "homebrew.json"), &h)
	unknown := "hologram"
	h.Kind = &unknown
	h.Genres = []string{"action", "volumetric", "puzzle", "volumetric2"}
	if h.EffectiveKind() != "app" {
		t.Errorf("kind = %s", h.EffectiveKind())
	}
	if got := strings.Join(h.EffectiveGenres(), ","); got != "action,other,puzzle" {
		t.Errorf("genres = %s", got)
	}
	h.Kind = nil
	if h.EffectiveKind() != "app" {
		t.Error("no kind is an app")
	}
}
