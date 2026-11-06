// SPDX-License-Identifier: MIT

package lantern

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The limits of SPEC.md § 13, which a client bounds what it reads with and a server stays within.
const (
	MaxJSONDocument  = 32 << 20 // a JSON document, in bytes
	MaxDepth         = 16       // a JSON document's nesting
	MaxString        = 4096     // a string field, in UTF-8 bytes
	MaxName          = 512      // name
	MaxNote          = 120      // note
	MaxProfile       = 64       // profile
	MaxPageItems     = 1000     // the items of a page
	MaxTitlesAtOnce  = 100      // the titles read at once (SPEC.md § 7.2)
	MaxManifestFiles = 4096     // the files of a manifest
	MaxPath          = 1024     // a manifest's path, in bytes
	MaxPathPart      = 255      // a part of a path, in bytes
	MaxPackages      = 16       // a homebrew's packages
	MaxTags          = 32       // the tags of a title or a homebrew
	MaxTag           = 64       // a tag, in bytes
	MaxRequiredData  = 256      // the files of a port's requires_data, alternatives included
	MaxAccept        = 32       // the accepted versions of a port's data file
	MaxRequires      = 8        // the tokens of an app's requires (SPEC.md § 6.1)
	MaxIncludes      = 16       // the versions an app includes (SPEC.md § 6.1)
	MaxWords         = 16       // the words of a missing request's formats and of its satisfies (SPEC.md § 6.3)
	MaxCheatSet      = 1 << 20  // a cheat set's text, in bytes
	MaxDatagram      = 1200     // a discovery datagram, in bytes
	// MaxIJSONInteger is the largest integer an I-JSON document holds (SPEC.md § 2.3).
	MaxIJSONInteger = 1<<53 - 1
)

// StringCaps are the bounds of the string fields whose bound is not MaxString, by name.
var StringCaps = map[string]int{"name": MaxName, "note": MaxNote, "profile": MaxProfile}

// Problems says every way document goes beyond SPEC.md § 13 (none when it does not): its depth,
// its strings (by their key's bound), and the lists the section bounds (a page's items, a manifest,
// packages, tags, a port's data). document is a value as LoadJSON gives it.
func Problems(document any, caps map[string]int) []string {
	if caps == nil {
		caps = StringCaps
	}
	var out []string
	var walk func(v any, depth int, key, path string)
	walk = func(v any, depth int, key, path string) {
		switch x := v.(type) {
		case map[string]any:
			if depth > MaxDepth {
				out = append(out, fmt.Sprintf("%s: nested deeper than %d", path, MaxDepth))
				return
			}
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(x[k], depth+1, k, path+"."+k)
			}
			if data, ok := x["requires_data"].([]any); ok && key == "port" {
				count := 0
				for _, d := range data {
					if group, ok := d.(map[string]any)["one_of"].([]any); ok {
						for _, g := range group {
							if l, ok := g.([]any); ok {
								count += len(l)
							}
						}
					} else {
						count++
					}
				}
				if count > MaxRequiredData {
					out = append(out, fmt.Sprintf("%s.requires_data: %d files, above %d", path, count, MaxRequiredData))
				}
			}
		case []any:
			if depth > MaxDepth {
				out = append(out, fmt.Sprintf("%s: nested deeper than %d", path, MaxDepth))
				return
			}
			bound := map[string]int{"items": MaxPageItems, "manifest": MaxManifestFiles, "packages": MaxPackages, "tags": MaxTags, "accept": MaxAccept}[key]
			if bound > 0 && len(x) > bound {
				out = append(out, fmt.Sprintf("%s: %d items, above %d", path, len(x), bound))
			}
			item := key
			if key == "tags" {
				item = "tag"
			}
			for i, e := range x {
				walk(e, depth+1, item, fmt.Sprintf("%s[%d]", path, i))
			}
		case string:
			limit := MaxString
			if key == "tag" {
				limit = MaxTag
			} else if c, ok := caps[key]; ok {
				limit = c
			}
			if len(x) > limit {
				out = append(out, fmt.Sprintf("%s: %d bytes, above %d", path, len(x), limit))
			}
		}
	}
	walk(document, 1, "", "$")
	return out
}

// LoadOptions tune LoadJSON. The zero value is SPEC.md § 13's.
type LoadOptions struct {
	Limit int            // at most this many bytes (MaxJSONDocument when 0)
	Caps  map[string]int // string bounds by key (StringCaps when nil)
	Where string         // the document's name, for errors
}

// LoadJSON reads a JSON document within SPEC.md § 13: at most Limit bytes, UTF-8, nested 16 deep
// at most, I-JSON (no integer beyond 2^53-1, no member name twice, no lone surrogate), its strings
// within their bounds. It gives maps, slices, strings, booleans, nil and json.Number (a number
// keeps its text); a *DocumentError otherwise.
func LoadJSON(raw []byte, opts LoadOptions) (any, error) {
	where := opts.Where
	if where == "" {
		where = "document"
	}
	limit := opts.Limit
	if limit == 0 {
		limit = MaxJSONDocument
	}
	if len(raw) > limit {
		return nil, &DocumentError{Where: where, Reason: fmt.Sprintf("%d bytes, above %d", len(raw), limit)}
	}
	if !utf8.Valid(raw) {
		return nil, &DocumentError{Where: where, Reason: "not JSON (not UTF-8)"}
	}
	if hasLoneSurrogate(raw) {
		return nil, &DocumentError{Where: where, Reason: "not JSON (a lone surrogate)"}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := readValue(dec, 1)
	if err == nil {
		if _, more := dec.Token(); more != io.EOF {
			err = fmt.Errorf("data after the document")
		}
	}
	if err != nil {
		if e, ok := err.(*DocumentError); ok {
			e.Where = where
			return nil, e
		}
		return nil, &DocumentError{Where: where, Reason: fmt.Sprintf("not JSON (%v)", err)}
	}
	if found := Problems(value, opts.Caps); len(found) > 0 {
		if len(found) > 3 {
			found = found[:3]
		}
		return nil, &DocumentError{Where: where, Reason: "beyond SPEC.md § 13: " + strings.Join(found, "; ")}
	}
	return value, nil
}

func readValue(dec *json.Decoder, depth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Number:
		return t, checkNumber(t)
	case json.Delim:
		if depth > MaxDepth {
			return nil, &DocumentError{Reason: fmt.Sprintf("nested deeper than %d", MaxDepth)}
		}
		if t == '[' {
			list := []any{}
			for dec.More() {
				v, err := readValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				list = append(list, v)
			}
			_, err := dec.Token()
			return list, err
		}
		object := map[string]any{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key := k.(string)
			if _, dup := object[key]; dup {
				return nil, fmt.Errorf("a member name is given twice")
			}
			v, err := readValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = v
		}
		_, err = dec.Token()
		return object, err
	}
	return tok, nil
}

func checkNumber(n json.Number) error {
	s := string(n)
	if !strings.ContainsAny(s, ".eE") {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil || v > MaxIJSONInteger || v < -MaxIJSONInteger {
			return fmt.Errorf("the integer %s is beyond 2**53 - 1", truncate(s, 20))
		}
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(f, 0) {
		return fmt.Errorf("the number %s is beyond a double's range", truncate(s, 20))
	}
	return nil
}

// hasLoneSurrogate reports whether raw escapes a UTF-16 surrogate that has no partner (RFC 7493 § 2.1).
func hasLoneSurrogate(raw []byte) bool {
	for i := 0; i+1 < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		if raw[i+1] != 'u' {
			i++ // an escaped character: skip it, so that \\u is not a \u
			continue
		}
		unit, ok := hex4(raw, i+2)
		if !ok {
			continue
		}
		switch {
		case unit >= 0xD800 && unit < 0xDC00:
			if i+11 < len(raw) && raw[i+6] == '\\' && raw[i+7] == 'u' {
				if low, ok := hex4(raw, i+8); ok && low >= 0xDC00 && low < 0xE000 {
					i += 11
					continue
				}
			}
			return true
		case unit >= 0xDC00 && unit < 0xE000:
			return true
		}
		i += 5
	}
	return false
}

func hex4(raw []byte, at int) (int, bool) {
	if at+4 > len(raw) {
		return 0, false
	}
	v, err := strconv.ParseUint(string(raw[at:at+4]), 16, 16)
	return int(v), err == nil
}

// Clip cuts text to limit UTF-8 bytes, on a character's boundary.
func Clip(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}

// Printable is text without control characters, within limit bytes: what a client shows of a
// server's detail or motd (SPEC.md § 12).
func Printable(text string, limit int) string {
	var b strings.Builder
	for _, c := range text {
		if c == '\n' || (c >= 32 && !(c >= 127 && c < 160)) {
			b.WriteRune(c)
		}
	}
	return Clip(b.String(), limit)
}
