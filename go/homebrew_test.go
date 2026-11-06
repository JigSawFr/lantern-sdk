// SPDX-License-Identifier: MIT

package lantern_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

func TestHomebrewPathVectors(t *testing.T) {
	var v struct {
		Paths []struct {
			Path     string `json:"path"`
			Accepted bool   `json:"accepted"`
			Why      string `json:"why"`
		} `json:"paths"`
		Manifests []struct {
			Manifest []lantern.ManifestEntry `json:"manifest"`
			Accepted bool                    `json:"accepted"`
			Why      string                  `json:"why"`
		} `json:"manifests"`
	}
	testutil.Vectors(t, "paths", &v)
	for _, c := range v.Paths {
		if got := lantern.PathProblem(c.Path) == ""; got != c.Accepted {
			t.Errorf("%q (%s): accepted %v", c.Path, c.Why, got)
		}
	}
	for _, c := range v.Manifests {
		if got := len(lantern.ManifestProblems(c.Manifest)) == 0; got != c.Accepted {
			t.Errorf("manifest (%s): accepted %v", c.Why, got)
		}
	}
}

func TestHomebrewSignatureVectors(t *testing.T) {
	var v struct {
		Manifests []struct {
			Manifest       []lantern.ManifestEntry `json:"manifest"`
			Canonical      string                  `json:"canonical"`
			ManifestSHA256 string                  `json:"manifest_sha256"`
		} `json:"manifests"`
		Signed []struct {
			Entry struct {
				ID       string `json:"id"`
				Platform string `json:"platform"`
				Build    int64  `json:"build"`
				Package  struct {
					SHA256         string `json:"sha256"`
					ManifestSHA256 string `json:"manifest_sha256"`
				} `json:"package"`
			} `json:"entry"`
			SignedBytes string            `json:"signed_bytes"`
			Signature   lantern.Signature `json:"signature"`
			Fingerprint string            `json:"key_short_fingerprint"`
			Verifies    bool              `json:"verifies"`
		} `json:"signed"`
	}
	testutil.Vectors(t, "homebrew-signatures", &v)
	for i, m := range v.Manifests {
		if got := lantern.ManifestCanonical(m.Manifest); got != m.Canonical {
			t.Errorf("manifest %d: canonical %s", i, got)
		}
		if got := lantern.ManifestSHA256(m.Manifest); got != m.ManifestSHA256 {
			t.Errorf("manifest %d: digest %s", i, got)
		}
	}
	for i, s := range v.Signed {
		entry := &lantern.Homebrew{ID: s.Entry.ID, Platform: s.Entry.Platform, Build: s.Entry.Build, Signature: &s.Signature,
			Package: lantern.Package{SHA256: s.Entry.Package.SHA256, ManifestSHA256: s.Entry.Package.ManifestSHA256}}
		if got := string(lantern.SignedMessage(entry, entry.Package)); got != s.SignedBytes {
			t.Errorf("signed %d: bytes %s", i, got)
		}
		if valid, signed := lantern.VerifySignature(entry, entry.Package); !signed || valid != s.Verifies {
			t.Errorf("signed %d: valid %v signed %v", i, valid, signed)
		}
		if got, err := lantern.KeyFingerprint(s.Signature.PublicKey); err != nil || got != s.Fingerprint {
			t.Errorf("signed %d: fingerprint %q %v", i, got, err)
		}
	}
}

func TestHomebrewRequiresVectors(t *testing.T) {
	var v struct {
		Cases []struct {
			Name       string           `json:"name"`
			Requires   lantern.Requires `json:"requires"`
			Device     map[string]any   `json:"device"`
			Decision   string           `json:"decision"`
			Conditions int              `json:"conditions"`
		} `json:"cases"`
	}
	testutil.Vectors(t, "requires", &v)
	for _, c := range v.Cases {
		entry := &lantern.Homebrew{Requires: &c.Requires}
		decision, reasons := lantern.Offer(entry, c.Device)
		if string(decision) != c.Decision || len(reasons) != c.Conditions {
			t.Errorf("%s: %s %v, want %s and %d conditions", c.Name, decision, reasons, c.Decision, c.Conditions)
		}
	}
}

func hb(t *testing.T, platform string, p lantern.Package) *lantern.Homebrew {
	t.Helper()
	return &lantern.Homebrew{ID: "org.example.frostline", Platform: platform, Build: 1, Package: p}
}

func archive(manifest ...lantern.ManifestEntry) lantern.Package {
	return lantern.Package{Format: "zip", Manifest: manifest, ManifestSHA256: lantern.ManifestSHA256(manifest)}
}

func file(path string) lantern.ManifestEntry {
	return lantern.ManifestEntry{Path: path, Size: 1, SHA256: strings.Repeat("1", 64)}
}

func TestPlanInstallKeepsToTheProfilesRoots(t *testing.T) {
	good := archive(file("/switch/org.example.frostline/a.nro"), file("/config/org.example.frostline/s.ini"), file("/atmosphere/x"))
	plan, err := lantern.PlanInstall(hb(t, "switch", good), good)
	if err != nil || len(plan.Free) != 2 || len(plan.Consent) != 1 {
		t.Fatalf("plan %+v %v", plan, err)
	}
	for name, p := range map[string]lantern.Package{
		"outside the roots": archive(file("/switch/other/a.nro")),
		"a bad path":        archive(file("/switch/org.example.frostline/../x")),
		"a wrong digest": func() lantern.Package {
			p := archive(file("/switch/org.example.frostline/a"))
			p.ManifestSHA256 = strings.Repeat("0", 64)
			return p
		}(),
		"no manifest":        {Format: "zip", ManifestSHA256: strings.Repeat("0", 64)},
		"a format not known": {Format: "exe"},
	} {
		if _, err := lantern.PlanInstall(hb(t, "switch", p), p); err == nil {
			t.Errorf("%s: installed", name)
		}
	}
	if _, err := lantern.PlanInstall(hb(t, "ios", good), good); err == nil {
		t.Error("a platform without a profile: installed")
	}
	system := lantern.Package{Format: "vpk", Manifest: []lantern.ManifestEntry{}, ManifestSHA256: lantern.ManifestSHA256(nil)}
	if plan, err := lantern.PlanInstall(hb(t, "vita", system), system); err != nil || len(plan.Free)+len(plan.Consent) != 0 {
		t.Errorf("the platform's installer: %+v %v", plan, err)
	}
}

func TestPickPackageByArchitecture(t *testing.T) {
	e := hb(t, "linux", lantern.Package{Format: "zip", File: "any"})
	e.Packages = []lantern.Package{{File: "arm", Arch: []string{"aarch64"}}, {File: "x64", Arch: []string{"x86_64"}}}
	if p, ok := lantern.PickPackage(e, "x86_64"); !ok || p.File != "x64" {
		t.Errorf("x86_64: %v %v", p.File, ok)
	}
	if p, ok := lantern.PickPackage(e, "riscv64"); !ok || p.File != "any" {
		t.Errorf("riscv64 falls to the package without arch: %v %v", p.File, ok)
	}
	e.Package.Arch = []string{"x86"}
	if _, ok := lantern.PickPackage(e, "riscv64"); ok {
		t.Error("nothing fits, and one was picked")
	}
	if lantern.ArchOK(lantern.Package{Arch: []string{"aarch64"}}, "switch", "") {
		t.Error("arch on a platform of one architecture")
	}
}

func TestPortDataIsChecked(t *testing.T) {
	raw := `{"id":"org.example.harbor","platform":"linux","kind":"port","name":"H","version":"1","build":1,
	 "package":{"format":"zip","file":"f","size":1,"sha256":"` + strings.Repeat("a", 64) + `","manifest_sha256":"` + strings.Repeat("b", 64) + `","manifest":[]},
	 "port":{"original":{"name":"Harbor"},"engine":{"name":"Lighthouse"},"data_root":"/harbor/","assets":"user_owned",
	  "requires_data":[{"path":"data/HARBOR.PAK","hint":"in the game folder","accept":[{"sha256":"` + strings.Repeat("c", 64) + `","label":"1.0"}]},
	   {"one_of":[[{"path":"music/THEME.OGG","hint":"soundtrack"}],[{"path":"data/MUSIC.PAK","hint":"next to it"}]],"optional":true}]}}`
	var e lantern.Homebrew
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatal(err)
	}
	if problems := lantern.PortProblems(&e); len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	check := lantern.CheckLaunch(&e, nil)
	if check.OK || len(check.Missing) != 1 || check.Missing[0] != "data/HARBOR.PAK" || len(check.AbsentOptional) == 0 {
		t.Errorf("nothing there: %+v", check)
	}
	have := map[string]lantern.FileHashes{"data/HARBOR.PAK": {"sha256": strings.Repeat("c", 64)}}
	if check := lantern.CheckLaunch(&e, have); !check.OK {
		t.Errorf("the right file: %+v", check)
	}
	have["data/HARBOR.PAK"] = lantern.FileHashes{"sha256": strings.Repeat("d", 64)}
	if check := lantern.CheckLaunch(&e, have); check.OK || len(check.Wrong) != 1 {
		t.Errorf("another version: %+v", check)
	}
	e.Port.DataRoot = "/harbor"
	if len(lantern.PortProblems(&e)) == 0 {
		t.Error("a data_root without its slash")
	}
	e.Port.DataRoot = "/harbor/"
	e.Package.Manifest = []lantern.ManifestEntry{file("/harbor/data/HARBOR.PAK")}
	if len(lantern.PortProblems(&e)) == 0 {
		t.Error("the package ships the user's data")
	}
}

func TestKeyPinning(t *testing.T) {
	pinned := "A"
	e := &lantern.Homebrew{Signature: &lantern.Signature{PublicKey: "A"}}
	empty := ""
	if lantern.KeyChanged(nil, e) != lantern.KeyPin || lantern.KeyChanged(&pinned, e) != lantern.KeySame {
		t.Error("first install, same key")
	}
	e.Signature.PublicKey = "B"
	if lantern.KeyChanged(&pinned, e) != lantern.KeyDiffers {
		t.Error("another key")
	}
	e.Signature = nil
	if lantern.KeyChanged(&pinned, e) != lantern.KeyDiffers || lantern.KeyChanged(&empty, e) != lantern.KeySame {
		t.Error("unsigned after a signed one, unsigned again")
	}
	_ = base64.StdEncoding
}
