// SPDX-License-Identifier: MIT

package lantern

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Canonical is value's canonical JSON, in UTF-8 (SPEC.md § 2.3): RFC 8785's JSON Canonicalization
// Scheme. What sync's merge rule compares (§ 20.4) and what a chunk index is written in (§ 22.1)
// are canonical bytes. No space; an object's members sorted by their names as UTF-16 code units;
// strings with only what JSON must escape escaped; numbers as ECMAScript writes them (1.0 is 1,
// -0.0 is 0, 1e21 is 1e+21).
//
// value is what LoadJSON gives (maps, slices, strings, booleans, nil, json.Number), or Go's own
// numbers. An error for what JSON does not have: NaN, an infinity, a type that is not JSON.
func Canonical(value any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeCanonical(&b, value); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		writeString(b, x)
	case json.Number:
		return writeNumberText(b, string(x))
	case int:
		return writeInt(b, int64(x))
	case int64:
		return writeInt(b, x)
	case float64:
		s, err := Number(x)
		b.WriteString(s)
		return err
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("lantern: not JSON: %T", v)
	}
	return nil
}

func writeInt(b *bytes.Buffer, n int64) error {
	if n > MaxIJSONInteger || n < -MaxIJSONInteger {
		s, err := Number(float64(n))
		b.WriteString(s)
		return err
	}
	b.WriteString(strconv.FormatInt(n, 10))
	return nil
}

func writeNumberText(b *bytes.Buffer, text string) error {
	if !strings.ContainsAny(text, ".eE") {
		if n, err := strconv.ParseInt(text, 10, 64); err == nil {
			return writeInt(b, n)
		}
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return fmt.Errorf("lantern: a number beyond a double's range is not I-JSON: %s", truncate(text, 20))
	}
	s, err := Number(f)
	b.WriteString(s)
	return err
}

func lessUTF16(a, c string) bool {
	ua, uc := utf16.Encode([]rune(a)), utf16.Encode([]rune(c))
	for i := 0; i < len(ua) && i < len(uc); i++ {
		if ua[i] != uc[i] {
			return ua[i] < uc[i]
		}
	}
	return len(ua) < len(uc)
}

func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// Number is a JSON number as ECMAScript writes it (RFC 8785 § 3.2.2.3): an integer without a
// fraction or an exponent, the others in their shortest form that reads back the same. An error
// for NaN and an infinity, which I-JSON does not have.
func Number(x float64) (string, error) {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return "", fmt.Errorf("lantern: JSON has no NaN nor infinity")
	}
	if x == 0 {
		return "0", nil
	}
	sign := ""
	if x < 0 {
		sign, x = "-", -x
	}
	// The shortest digits that read back the same, as "d.ddde+XX".
	e := strconv.FormatFloat(x, 'e', -1, 64)
	mantissa, exp, _ := strings.Cut(e, "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	exponent, _ := strconv.Atoi(exp)
	k, n := len(digits), exponent+1 // the value is 0.<digits> x 10^n
	var body string
	switch {
	case k <= n && n <= 21:
		body = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		body = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		body = "0." + strings.Repeat("0", -n) + digits
	default:
		body = digits[:1]
		if k > 1 {
			body += "." + digits[1:]
		}
		sgn := "-"
		if n > 0 {
			sgn = "+"
		}
		body += "e" + sgn + strconv.Itoa(abs(n-1))
	}
	return sign + body, nil
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
