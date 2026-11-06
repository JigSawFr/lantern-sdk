// SPDX-License-Identifier: MIT

package lantern_test

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

func TestCanonicalVectors(t *testing.T) {
	var vectors struct {
		Cases []struct {
			Name      string `json:"name"`
			JSON      string `json:"json"`
			Canonical string `json:"canonical"`
			SHA256    string `json:"sha256"`
		} `json:"cases"`
	}
	testutil.Vectors(t, "canonical-json", &vectors)
	if len(vectors.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			v, err := lantern.LoadJSON([]byte(c.JSON), lantern.LoadOptions{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := lantern.Canonical(v)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.Canonical {
				t.Errorf("canonical = %s, want %s", got, c.Canonical)
			}
			if lantern.SHA256Hex(got) != c.SHA256 {
				t.Errorf("sha256 = %s, want %s", lantern.SHA256Hex(got), c.SHA256)
			}
		})
	}
}

func TestNumbersAsECMAScriptWritesThem(t *testing.T) {
	for want, x := range map[string]float64{
		"0": 0, "1": 1, "-1": -1, "0.5": 0.5, "100": 100, "1e+21": 1e21, "1e-7": 1e-7, "0.000001": 1e-6,
		"123456789012345680000": 123456789012345678901, "1.5e+300": 1.5e300, "5e-324": 5e-324,
		"4.5": 4.5, "-0.1": -0.1, "1.7976931348623157e+308": math.MaxFloat64, "100000000000000000000": 1e20,
	} {
		if got, err := lantern.Number(x); err != nil || got != want {
			t.Errorf("Number(%v) = %s, %v, want %s", x, got, err, want)
		}
	}
	for _, x := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := lantern.Number(x); err == nil {
			t.Errorf("Number(%v) was taken", x)
		}
	}
}

func TestCanonicalRefusesWhatIsNotJSON(t *testing.T) {
	if _, err := lantern.Canonical(map[string]any{"a": make(chan int)}); err == nil {
		t.Error("a channel was taken")
	}
	if _, err := lantern.Canonical(math.NaN()); err == nil {
		t.Error("NaN was taken")
	}
}

func TestLoadJSONKeepsToTheLimits(t *testing.T) {
	deep := strings.Repeat("[", 17) + strings.Repeat("]", 17)
	cases := map[string]string{
		"nested too deep":       deep,
		"integer beyond I-JSON": `{"a": 9007199254740992}`,
		"a name twice":          `{"a": 1, "a": 2}`,
		"a lone surrogate":      `{"a": "\ud800"}`,
		"a lone low surrogate":  `{"a": "\udc00x"}`,
		"a cut document":        `{"a": `,
		"data after":            `{} {}`,
		"NaN":                   `{"a": NaN}`,
		"a string too long":     `{"x": "` + strings.Repeat("a", 4097) + `"}`,
		"a name too long":       `{"name": "` + strings.Repeat("a", 513) + `"}`,
		"too many items":        `{"items": [` + strings.Repeat("0,", 1000) + `0]}`,
		"bad UTF-8":             "{\"a\": \"\xff\"}",
	}
	for name, raw := range cases {
		_, err := lantern.LoadJSON([]byte(raw), lantern.LoadOptions{})
		var de *lantern.DocumentError
		if !errors.As(err, &de) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for name, raw := range map[string]string{
		"16 deep":          strings.Repeat("[", 16) + strings.Repeat("]", 16),
		"a pair":           `{"a": "😀"}`,
		"an escaped slash": `{"a": "\\ud800"}`,
		"2^53-1":           `{"a": 9007199254740991, "b": -9007199254740991, "c": 1.5e300}`,
		"1000 items":       `{"items": [` + strings.Repeat("0,", 999) + `0]}`,
	} {
		if _, err := lantern.LoadJSON([]byte(raw), lantern.LoadOptions{}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := lantern.LoadJSON([]byte(`{"a": 1}`), lantern.LoadOptions{Limit: 3}); err == nil {
		t.Error("the byte limit was not kept")
	}
}

func TestPrintableAndClip(t *testing.T) {
	if got := lantern.Printable("a\x00b\x1b[31mc\u0085\nd\x7f", 100); got != "ab[31mc\nd" {
		t.Errorf("printable = %q", got)
	}
	if got := lantern.Clip("héllo", 2); got != "h" {
		t.Errorf("clip = %q", got)
	}
	if got := lantern.Clip("héllo", 3); got != "hé" {
		t.Errorf("clip = %q", got)
	}
}

func TestDigests(t *testing.T) {
	sum := lantern.SHA256Hex([]byte("abc"))
	if sum != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal(sum)
	}
	field, err := lantern.FormatDigest(sum)
	if err != nil || field != "sha-256=:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=:" {
		t.Fatalf("%q %v", field, err)
	}
	if got := lantern.DigestSHA256(field); got != sum {
		t.Errorf("round trip = %s", got)
	}
	if got := lantern.DigestSHA256("sha-512=:AAAA:, " + field + ";x=1"); got != sum {
		t.Errorf("among others = %s", got)
	}
	for _, bad := range []string{"", "sha-256=:AAAA:", "sha-256=ungWv48Bz", "sha-256=:!!!!:", "SHA-256=:AAAA:"} {
		if got := lantern.DigestSHA256(bad); got != "" {
			t.Errorf("%q gave %q", bad, got)
		}
	}
	if _, err := lantern.FormatDigest("zz"); err == nil {
		t.Error("not hex was taken")
	}
	s := lantern.NewSha256([]byte("a"))
	_, _ = s.Write([]byte("bc"))
	if s.Hex() != sum || s.Size() != 3 {
		t.Errorf("streamed = %s, %d", s.Hex(), s.Size())
	}
	r, err := lantern.SHA256Reader(strings.NewReader("abc"))
	if err != nil || r.Hex() != sum {
		t.Errorf("reader = %v, %v", r, err)
	}
}

func TestUID(t *testing.T) {
	for i := 0; i < 50; i++ {
		if u := lantern.NewUID(); !lantern.IsValidUID(u) {
			t.Fatalf("%s is not valid", u)
		}
	}
	for _, bad := range []string{"", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", "6BA7B810-9DAD-41D1-80B4-00C04FD430C8", "x"} {
		if lantern.IsValidUID(bad) {
			t.Errorf("%q is valid", bad)
		}
	}
	if !lantern.IsValidUID("018f3b6e-2f4a-7c3b-9d1e-0a1b2c3d4e5f") {
		t.Error("a version 7 uid is refused")
	}
}

func TestProblemErrorsAreOfTheKindOfTheirStatus(t *testing.T) {
	cases := []struct {
		status int
		body   string
		kinds  []error
		not    []error
		code   string
	}{
		{404, `{"schema":1,"status":404,"code":"not_found","detail":"no such title"}`, []error{lantern.ErrNotFound}, []error{lantern.ErrGone}, "not_found"},
		{410, `{"schema":1,"status":410,"code":"cursor_expired"}`, []error{lantern.ErrGone}, nil, ""},
		{403, `{"schema":1,"status":403,"code":"account_frozen"}`, []error{lantern.ErrAccountFrozen, lantern.ErrForbidden}, nil, "account_frozen"},
		{401, `{"schema":1,"status":401,"code":"signature_expired"}`, []error{lantern.ErrSignatureExpired, lantern.ErrSignatureRefused, lantern.ErrUnauthorized}, []error{lantern.ErrSignatureInvalid}, "signature_expired"},
		{503, `not json`, []error{lantern.ErrUnavailable, lantern.ErrServer}, nil, ""},
		{502, ``, []error{lantern.ErrServer}, []error{lantern.ErrUnavailable}, ""},
		{405, `{}`, []error{lantern.ErrBadRequest}, nil, ""},
		{416, `{}`, []error{lantern.ErrBadRequest}, nil, ""},
		{418, `{}`, nil, []error{lantern.ErrServer, lantern.ErrBadRequest}, ""},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint(c.status, c.code), func(t *testing.T) {
			var err error = lantern.NewProblemError(c.status, []byte(c.body), map[string]string{"retry-after": "7"})
			for _, k := range c.kinds {
				if !errors.Is(err, k) {
					t.Errorf("not %v", k)
				}
			}
			for _, k := range c.not {
				if errors.Is(err, k) {
					t.Errorf("is %v", k)
				}
			}
			var p *lantern.ProblemError
			if !errors.As(err, &p) || p.Status != c.status || p.Code != c.code || p.RetryAfter != 7 {
				t.Errorf("problem = %+v", p)
			}
		})
	}
}

func TestProblemDetailIsBoundedAndPrintable(t *testing.T) {
	body := `{"schema":1,"status":500,"code":"internal","detail":"` + strings.Repeat("é", 600) + `\u001b[0m"}`
	p := lantern.NewProblemError(500, []byte(body), nil)
	if len(p.Detail) > lantern.DetailLimit || strings.ContainsRune(p.Detail, 0x1b) {
		t.Errorf("detail = %q", p.Detail)
	}
	p = lantern.NewProblemError(429, []byte(`{}`), map[string]string{"Retry-After": "-3"})
	if p.RetryAfter != 0 {
		t.Error("a negative Retry-After was taken")
	}
	if got := lantern.NewProblemError(404, nil, nil).Error(); got != "404 error" {
		t.Errorf("error = %q", got)
	}
}

func TestAnUnknownCodeIsReadByItsStatus(t *testing.T) {
	p := lantern.NewProblemError(404, []byte(`{"schema":1,"status":404,"code":"a_later_code"}`), nil)
	if p.Code != "" || !errors.Is(p, lantern.ErrNotFound) || p.Problem == nil || p.Problem.Code != "a_later_code" {
		t.Errorf("problem = %+v", p)
	}
}
