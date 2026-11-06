// SPDX-License-Identifier: MIT

// Package testutil finds the specification's folder (the submodule at the repository's root) for
// the tests, and skips them when it is not checked out.
package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// SpecDir is the specification's folder.
func SpecDir(t testing.TB) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "..", "..", "..", "spec")
	if _, err := os.Stat(filepath.Join(dir, "SPEC.md")); err != nil {
		t.Skip("the specification is not checked out (git submodule update --init)")
	}
	return dir
}

// Read is the bytes of a file under the specification's folder.
func Read(t testing.TB, elem ...string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{SpecDir(t)}, elem...)...))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Glob lists files under the specification's folder.
func Glob(t testing.TB, elem ...string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(append([]string{SpecDir(t)}, elem...)...))
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

// Vectors reads a vectors file of the specification into v.
func Vectors(t testing.TB, name string, v any) {
	t.Helper()
	if err := json.Unmarshal(Read(t, "vectors", name+".json"), v); err != nil {
		t.Fatal(err)
	}
}
