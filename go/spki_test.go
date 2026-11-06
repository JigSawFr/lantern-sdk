// SPDX-License-Identifier: MIT

package lantern_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

func TestSPKIVectors(t *testing.T) {
	var v struct {
		Certificates []struct {
			Name   string `json:"name"`
			PEM    string `json:"pem"`
			SHA256 string `json:"spki_sha256"`
			Short  string `json:"short"`
		} `json:"certificates"`
	}
	testutil.Vectors(t, "spki", &v)
	if len(v.Certificates) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range v.Certificates {
		got, err := lantern.SPKISHA256PEM(c.PEM)
		if err != nil || got != c.SHA256 {
			t.Errorf("%s: %s, %v", c.Name, got, err)
		}
		if short, err := lantern.ShortFingerprint(got); err != nil || short != c.Short {
			t.Errorf("%s short: %s, %v", c.Name, short, err)
		}
		if !lantern.CheckPin(got, c.SHA256) {
			t.Errorf("%s pin", c.Name)
		}
	}
	if _, err := lantern.ShortFingerprint("abc"); err == nil {
		t.Error("a short fingerprint of a non-hash")
	}
	for _, bad := range [][]byte{nil, {0x30}, {0x30, 0x03, 0x30, 0x01}, {0x31, 0x00}} {
		if _, err := lantern.SPKIDER(bad); err == nil {
			t.Errorf("%x is a certificate", bad)
		}
	}
}

func TestFileServerStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "servers.json")
	s := &lantern.FileServerStore{Path: path}
	if r, err := s.Server("u"); r != nil || err != nil {
		t.Fatalf("empty: %v %v", r, err)
	}
	rec := &lantern.ServerRecord{UID: "u", URL: "https://h/", Token: "t", Scopes: []string{"library"}, Extra: map[string]json.RawMessage{"future": []byte(`{"a":1}`)}}
	if err := s.Save(rec); err != nil {
		t.Fatal(err)
	}
	got, err := s.Server("u")
	if err != nil || got == nil || got.Token != "t" || string(got.Extra["future"]) != `{"a":1}` {
		t.Fatalf("%+v %v", got, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm()&0o077 != 0 && filepath.Separator == '/' {
		t.Errorf("mode %v", info.Mode())
	}
	if all, _ := s.Servers(); len(all) != 1 {
		t.Fatalf("%d servers", len(all))
	}
	if err := s.Forget("u"); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Server("u"); r != nil {
		t.Fatal("forgotten and kept")
	}
	// a newer schema is read as absent, and never written over
	if err := os.WriteFile(path, []byte(`{"schema":2,"servers":{"u":{"uid":"u","url":"x","token":"t"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(rec); err == nil {
		t.Fatal("a newer file is written over")
	}
	if raw, _ := os.ReadFile(path); string(raw) != `{"schema":2,"servers":{"u":{"uid":"u","url":"x","token":"t"}}}` {
		t.Fatalf("changed: %s", raw)
	}
}

func TestInvitationLink(t *testing.T) {
	sum := "79315e024cf7f6e0f2553884fd098ac59df2e2a72f139d8e03b6ee62a2d13fd0"
	l, err := lantern.ParseInvitationLink("https://nas.example.org:8443/x?invitation=abcd-efgh-ijkl-mnop&spki=" + sum)
	if err != nil || l.URL != "https://nas.example.org:8443/" || l.Code != "ABCD-EFGH-IJKL-MNOP" || l.SPKI != sum {
		t.Fatalf("%+v %v", l, err)
	}
	for _, bad := range []string{
		"http://nas.example.org/?invitation=ABCD-EFGH-IJKL-MNOP",
		"https://h/?invitation=A&invitation=B",
		"https://h/?invitation=SHORT",
		"https://h/?invitation=ABCD-EFGH-IJKL-MNOP&spki=zz",
		"https://h/",
	} {
		if _, err := lantern.ParseInvitationLink(bad); err == nil {
			t.Errorf("%q is taken", bad)
		}
	}
}

func TestCheckPairingCode(t *testing.T) {
	good := func() *lantern.PairingCode {
		return &lantern.PairingCode{Code: "ABCD-1234", Verify: "https://h/pair", VerifyComplete: "https://h/pair?code=ABCD-1234", Poll: "/api/v1/pairing/p_1", Interval: 5, Expires: 300}
	}
	if err := lantern.CheckPairingCode(good(), "https://h"); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*lantern.PairingCode){
		"plain http":   func(p *lantern.PairingCode) { p.Verify = "http://h/pair" },
		"other origin": func(p *lantern.PairingCode) { p.VerifyComplete = "https://evil/pair?code=ABCD-1234" },
		"no code":      func(p *lantern.PairingCode) { p.VerifyComplete = "https://h/pair?code=XXXX" },
		"foreign poll": func(p *lantern.PairingCode) { p.Poll = "https://evil/p" },
		"expires":      func(p *lantern.PairingCode) { p.Expires = 601 },
		"interval":     func(p *lantern.PairingCode) { p.Interval = 0 },
	} {
		p := good()
		mut(p)
		if err := lantern.CheckPairingCode(p, "https://h"); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}
