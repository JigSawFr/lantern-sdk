// SPDX-License-Identifier: MIT

package schema_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
	"github.com/JigSawFr/lantern-sdk/go/schema"
)

func load(t *testing.T, raw []byte) any {
	t.Helper()
	// Not LoadJSON: a refused example may break the limits LoadJSON refuses first.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestEveryExampleIsValid(t *testing.T) {
	for _, path := range testutil.Glob(t, "examples", "v1", "*.json") {
		name := strings.TrimSuffix(filepath.Base(path), ".json")
		t.Run(name, func(t *testing.T) {
			problems, err := schema.Validate(name, load(t, testutil.Read(t, "examples", "v1", filepath.Base(path))))
			if err != nil || len(problems) > 0 {
				t.Fatalf("%v %v", err, problems)
			}
		})
	}
}

func TestEveryRefusedExampleIsRefused(t *testing.T) {
	for _, path := range testutil.Glob(t, "examples", "v1", "invalid", "*.json") {
		file := filepath.Base(path)
		t.Run(file, func(t *testing.T) {
			name, _, _ := strings.Cut(file, ".")
			problems, err := schema.Validate(name, load(t, testutil.Read(t, "examples", "v1", "invalid", file)))
			if err != nil {
				t.Fatal(err)
			}
			if len(problems) == 0 {
				t.Errorf("%s should be refused", file)
			}
		})
	}
}

func TestNamesAndDefinitions(t *testing.T) {
	names := strings.Join(schema.Names(), " ")
	if !strings.Contains(names, "homebrew") || strings.Contains(names, "common") {
		t.Errorf("names = %s", names)
	}
	ok := func(name string, v any, want bool) {
		t.Helper()
		problems, err := schema.Definition(name, v)
		if err != nil || (len(problems) == 0) != want {
			t.Errorf("%s %v: %v %v", name, v, problems, err)
		}
	}
	ok("sha256", strings.Repeat("0", 64), true)
	ok("sha256", strings.Repeat("0", 63), false)
	if _, err := schema.Validate("nothing", nil); err == nil {
		t.Error("no schema named nothing")
	}
	if _, err := schema.Definition("nothing", nil); err == nil {
		t.Error("no definition named nothing")
	}
}

func TestFormatsAndPathPatterns(t *testing.T) {
	check := func(name string, v any, want bool) {
		t.Helper()
		problems, err := schema.Definition(name, v)
		if err != nil || (len(problems) == 0) != want {
			t.Errorf("%s %q: %v %v", name, v, problems, err)
		}
	}
	check("time", "2026-10-30T09:12:00Z", true)
	check("time", "2026-10-30 09:12:00", false)
	check("time", "2026-13-30T09:12:00Z", false)
	check("device_path", "/switch/app/app.nro", true)
	check("device_path", "/switch/../app.nro", false)
	check("device_path", "switch/app.nro", false)
	check("data_path", "data/a.bin", true)
	check("data_path", "/data/a.bin", false)
	check("data_path", "data/./a.bin", false)
}
