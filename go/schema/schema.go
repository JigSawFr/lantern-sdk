// SPDX-License-Identifier: MIT

// Package schema checks documents against the specification's JSON Schemas, without a dependency:
// the subset of JSON Schema 2020-12 that spec/schemas/v1 uses ($ref, allOf, anyOf, oneOf, not,
// if/then/else, properties, required, additionalProperties, propertyNames, items, enum, const,
// pattern, lengths, bounds, prefixItems, uniqueItems, and the formats date-time, date and uuid).
//
//	problems, err := schema.Validate("homebrew", document) // none when valid
//
// A server validates what it is about to serve; a client may validate what it reads. A reader
// stays lenient where the specification says so (an unknown kind or genre, SPEC.md § 8.1,
// § 7.1): this is the writer's check, the strict one, which every example of the specification
// passes and every refused one fails.
//
// The schemas are a copy of spec/schemas/v1, made by go generate.
package schema

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/JigSawFr/lantern-sdk/go"
)

//go:embed v1/*.json
var files embed.FS

var (
	loadOnce sync.Once
	all      map[string]any
)

func schemas() map[string]any {
	loadOnce.Do(func() {
		all = map[string]any{}
		entries, _ := files.ReadDir("v1")
		for _, e := range entries {
			raw, _ := files.ReadFile(path.Join("v1", e.Name()))
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			var v any
			if err := dec.Decode(&v); err != nil {
				panic("schema: " + e.Name() + ": " + err.Error())
			}
			all[strings.TrimSuffix(e.Name(), ".json")] = v
		}
	})
	return all
}

// Names are the documents the schemas describe (homebrew, apps…), common.json aside, sorted.
func Names() []string {
	var out []string
	for n := range schemas() {
		if n != "common" {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// Raw is the schema of a document (or "common"), as published, or nil.
func Raw(name string) []byte {
	raw, err := files.ReadFile(path.Join("v1", name+".json"))
	if err != nil {
		return nil
	}
	return raw
}

var (
	dateTime = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$`)
	dateOnly = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	uuidForm = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

type object = map[string]any

// Validate is every way document breaks schemas/v1/<name>.json (homebrew, apps, problem…), as
// "$.path: what"; none when it is valid. document is what lantern.LoadJSON gives. An error when
// there is no such schema.
func Validate(name string, document any) ([]string, error) {
	s := schemas()
	node, ok := s[name]
	if !ok || name == "common" {
		return nil, fmt.Errorf("schema: no schema named %q", name)
	}
	return (&validator{}).errors(document, node, "$", name), nil
}

// IsValid reports whether document is valid against schemas/v1/<name>.json.
func IsValid(name string, document any) (bool, error) {
	p, err := Validate(name, document)
	return len(p) == 0, err
}

// Definition is every way value breaks common.json's definition name (app, homebrew, package…).
func Definition(name string, value any) ([]string, error) {
	defs := schemas()["common"].(object)["$defs"].(object)
	if _, ok := defs[name]; !ok {
		return nil, fmt.Errorf("schema: no definition named %q", name)
	}
	return (&validator{}).errors(value, object{"$ref": "common.json#/$defs/" + name}, "$", "common"), nil
}

type validator struct{}

func (v *validator) resolve(ref, base string) (any, string) {
	target, pointer, _ := strings.Cut(ref, "#")
	doc := base
	if target != "" {
		doc = strings.TrimSuffix(target, ".json")
	}
	node := schemas()[doc]
	for _, part := range strings.Split(pointer, "/") {
		if part == "" {
			continue
		}
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		node = node.(object)[part]
	}
	return node, doc
}

func canon(x any) string {
	b, err := lantern.Canonical(x)
	if err != nil {
		return fmt.Sprint(x)
	}
	return string(b)
}

func isType(value any, kind string) bool {
	switch kind {
	case "object":
		_, ok := value.(object)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "null":
		return value == nil
	case "integer":
		n, ok := value.(json.Number)
		return ok && !strings.ContainsAny(string(n), ".eE")
	case "number":
		_, ok := value.(json.Number)
		return ok
	}
	return false
}

func float(n json.Number) float64 {
	f, _ := strconv.ParseFloat(string(n), 64)
	return f
}

func (v *validator) errors(value, schema any, p, base string) []string {
	switch s := schema.(type) {
	case bool:
		if s {
			return nil
		}
		return []string{p + ": not allowed"}
	case object:
		return v.object(value, s, p, base)
	}
	return nil
}

func (v *validator) object(value any, s object, p, base string) []string {
	var out []string
	if ref, ok := s["$ref"].(string); ok {
		target, doc := v.resolve(ref, base)
		out = append(out, v.errors(value, target, p, doc)...)
	}
	if all, ok := s["allOf"].([]any); ok {
		for _, part := range all {
			out = append(out, v.errors(value, part, p, base)...)
		}
	}
	if any_, ok := s["anyOf"].([]any); ok {
		match := false
		for _, sub := range any_ {
			if len(v.errors(value, sub, p, base)) == 0 {
				match = true
				break
			}
		}
		if !match {
			out = append(out, p+": matches none of anyOf")
		}
	}
	if one, ok := s["oneOf"].([]any); ok {
		n := 0
		for _, sub := range one {
			if len(v.errors(value, sub, p, base)) == 0 {
				n++
			}
		}
		if n != 1 {
			out = append(out, fmt.Sprintf("%s: matches %d of oneOf, not exactly one", p, n))
		}
	}
	if not, ok := s["not"]; ok && len(v.errors(value, not, p, base)) == 0 {
		out = append(out, p+": matches what is forbidden here")
	}
	if cond, ok := s["if"]; ok {
		branch := "else"
		if len(v.errors(value, cond, p, base)) == 0 {
			branch = "then"
		}
		if sub, ok := s[branch]; ok {
			out = append(out, v.errors(value, sub, p, base)...)
		}
	}
	if t, ok := s["type"]; ok {
		var kinds []string
		switch x := t.(type) {
		case string:
			kinds = []string{x}
		case []any:
			for _, k := range x {
				kinds = append(kinds, k.(string))
			}
		}
		match := false
		for _, k := range kinds {
			match = match || isType(value, k)
		}
		if !match {
			return append(out, fmt.Sprintf("%s: not of type %s", p, strings.Join(kinds, "/")))
		}
	}
	if c, ok := s["const"]; ok && canon(value) != canon(c) {
		out = append(out, fmt.Sprintf("%s: not %s", p, canon(c)))
	}
	if e, ok := s["enum"].([]any); ok {
		found := false
		var shown []string
		for _, x := range e {
			found = found || canon(value) == canon(x)
			shown = append(shown, fmt.Sprint(x))
		}
		if !found {
			out = append(out, fmt.Sprintf("%s: %s is not one of %s", p, clip(canon(value), 60), clip(strings.Join(shown, ", "), 200)))
		}
	}
	switch x := value.(type) {
	case string:
		out = append(out, v.str(x, s, p)...)
	case json.Number:
		f := float(x)
		if m, ok := s["minimum"].(json.Number); ok && f < float(m) {
			out = append(out, fmt.Sprintf("%s: below %s", p, m))
		}
		if m, ok := s["maximum"].(json.Number); ok && f > float(m) {
			out = append(out, fmt.Sprintf("%s: above %s", p, m))
		}
	case []any:
		out = append(out, v.array(x, s, p, base)...)
	case object:
		out = append(out, v.members(x, s, p, base)...)
	}
	return out
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return lantern.Clip(s, n)
}

func intOf(x any) (int, bool) {
	n, ok := x.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return int(i), err == nil
}

func (v *validator) str(value string, s object, p string) []string {
	var out []string
	length := utf8.RuneCountInString(value)
	if m, ok := intOf(s["minLength"]); ok && length < m {
		out = append(out, fmt.Sprintf("%s: shorter than %d", p, m))
	}
	if m, ok := intOf(s["maxLength"]); ok && length > m {
		out = append(out, fmt.Sprintf("%s: longer than %d", p, m))
	}
	if pat, ok := s["pattern"].(string); ok && !matcher(pat).match(value) {
		out = append(out, fmt.Sprintf("%s: %q does not match %s", p, clip(value, 60), pat))
	}
	if f, ok := s["format"].(string); ok && !formatOK(value, f) {
		out = append(out, fmt.Sprintf("%s: %q is not a %s", p, clip(value, 60), f))
	}
	return out
}

func formatOK(value, format string) bool {
	switch format {
	case "date-time":
		if !dateTime.MatchString(value) {
			return false
		}
		v := strings.ToUpper(value)
		for _, layout := range []string{time.RFC3339, time.RFC3339Nano} {
			if _, err := time.Parse(layout, v); err == nil {
				return true
			}
		}
		return false
	case "date":
		if !dateOnly.MatchString(value) {
			return false
		}
		_, err := time.Parse("2006-01-02", value)
		return err == nil
	case "uuid":
		return uuidForm.MatchString(value)
	}
	return true
}

func (v *validator) array(value []any, s object, p, base string) []string {
	var out []string
	if m, ok := intOf(s["minItems"]); ok && len(value) < m {
		out = append(out, fmt.Sprintf("%s: fewer than %d items", p, m))
	}
	if m, ok := intOf(s["maxItems"]); ok && len(value) > m {
		out = append(out, fmt.Sprintf("%s: more than %d items", p, m))
	}
	if u, _ := s["uniqueItems"].(bool); u {
		seen := map[string]bool{}
		for _, e := range value {
			c := canon(e)
			if seen[c] {
				out = append(out, p+": an item twice")
				break
			}
			seen[c] = true
		}
	}
	prefix, _ := s["prefixItems"].([]any)
	for i, sub := range prefix {
		if i < len(value) {
			out = append(out, v.errors(value[i], sub, fmt.Sprintf("%s[%d]", p, i), base)...)
		}
	}
	if items, ok := s["items"]; ok {
		for i := len(prefix); i < len(value); i++ {
			out = append(out, v.errors(value[i], items, fmt.Sprintf("%s[%d]", p, i), base)...)
		}
	}
	return out
}

func (v *validator) members(value object, s object, p, base string) []string {
	var out []string
	if req, ok := s["required"].([]any); ok {
		for _, k := range req {
			if _, has := value[k.(string)]; !has {
				out = append(out, fmt.Sprintf("%s: no %s", p, k))
			}
		}
	}
	props, _ := s["properties"].(object)
	keys := make([]string, 0, len(value))
	for k := range value {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		item := value[k]
		if sub, ok := props[k]; ok {
			out = append(out, v.errors(item, sub, p+"."+k, base)...)
		} else if add, ok := s["additionalProperties"]; ok {
			out = append(out, v.errors(item, add, p+"."+k, base)...)
		}
		if names, ok := s["propertyNames"]; ok {
			for _, e := range v.errors(k, names, p+"."+k, base) {
				out = append(out, strings.Replace(e, p+"."+k+":", fmt.Sprintf("%s: the key %q:", p, k), 1))
			}
		}
	}
	return out
}
