// SPDX-License-Identifier: MIT

package lantern_test

import (
	"encoding/json"
	"errors"
	"testing"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

func TestSyncMergeVectors(t *testing.T) {
	var v struct {
		ServerTime string `json:"server_time"`
		Skew       int64  `json:"skew"`
		Cases      []struct {
			Name      string            `json:"name"`
			Have      *vectorItem       `json:"have"`
			Sent      vectorItem        `json:"sent"`
			Replaced  bool              `json:"replaced"`
			Kept      vectorItem        `json:"kept"`
			Canonical map[string]string `json:"canonical"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(testutil.Read(t, "vectors", "sync-merge.json"), &v); err != nil {
		t.Fatal(err)
	}
	now, ok := lantern.ParseSyncTime(v.ServerTime)
	if !ok {
		t.Fatal("the server's time")
	}
	for _, c := range v.Cases {
		kept, replaced, err := lantern.SyncMerge(c.Have.item(), *c.Sent.item(), now, v.Skew)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		if replaced != c.Replaced || kept.Updated != c.Kept.Updated || kept.IsDeleted() != c.Kept.Deleted {
			t.Errorf("%s: replaced %v kept %+v, want %v %+v", c.Name, replaced, kept, c.Replaced, c.Kept)
			continue
		}
		got, _ := lantern.Canonical(kept.Value)
		want, _ := lantern.Canonical(c.Kept.Value)
		if string(got) != string(want) {
			t.Errorf("%s: kept %s, want %s", c.Name, got, want)
		}
		if c.Canonical != nil && !c.Sent.Deleted {
			if s, _ := lantern.Canonical(c.Sent.Value); string(s) != c.Canonical["sent"] {
				t.Errorf("%s: canonical sent %s, want %s", c.Name, s, c.Canonical["sent"])
			}
		}
	}
}

// Two devices that change the same items end with the same result, whatever the order their
// changes arrive in (SPEC.md § 20.4).
func TestSyncMergeConverges(t *testing.T) {
	a := lantern.SyncValue("switch/0100", map[string]any{"note": "a"}, 1_000)
	b := lantern.SyncValue("switch/0100", map[string]any{"note": "b"}, 1_000)
	gone := lantern.SyncDeletion("switch/0100", 1_000)
	later := lantern.SyncValue("switch/0100", map[string]any{"note": "c"}, 2_000)
	now := int64(10_000)
	for _, order := range [][]lantern.SyncItem{{a, b, gone, later}, {later, gone, b, a}, {gone, a, later, b}, {b, later, a, gone}} {
		var have *lantern.SyncItem
		for _, sent := range order {
			kept, _, err := lantern.SyncMerge(have, sent, now, 300)
			if err != nil {
				t.Fatal(err)
			}
			have = &kept
		}
		if have.Updated != lantern.FormatSyncTime(2_000) || have.IsDeleted() {
			t.Fatalf("%+v", have)
		}
	}
	// the same time: a deletion beats both values, and the greater value beats the smaller
	for _, order := range [][]lantern.SyncItem{{a, b, gone}, {gone, b, a}, {b, gone, a}} {
		var have *lantern.SyncItem
		for _, sent := range order {
			kept, _, _ := lantern.SyncMerge(have, sent, now, 300)
			have = &kept
		}
		if !have.IsDeleted() {
			t.Fatalf("%+v", have)
		}
	}
}

func TestSyncTimes(t *testing.T) {
	for text, want := range map[string]int64{"1970-01-01T00:00:00Z": 0, "1970-01-01T00:00:01.5Z": 1500, "2026-10-30T09:12:03.250Z": 1793351523250} {
		if got, ok := lantern.ParseSyncTime(text); !ok || got != want {
			t.Errorf("%s: %d %v", text, got, ok)
		}
		if lantern.FormatSyncTime(want) == "" {
			t.Error("format")
		}
	}
	if lantern.FormatSyncTime(1793351523250) != "2026-10-30T09:12:03.250Z" {
		t.Error(lantern.FormatSyncTime(1793351523250))
	}
	for _, bad := range []string{"", "2026-10-30", "2026-10-30T09:12:03+01:00", "2026-10-30T09:12:03.2501Z", "2026-02-30T09:12:03Z", "2026-10-30T24:00:00Z", "2026-10-30T09:60:00Z", "2026-10-30T09:12:60Z", "2026-10-30 09:12:03Z"} {
		if _, ok := lantern.ParseSyncTime(bad); ok {
			t.Errorf("%q was read", bad)
		}
	}
	if _, _, err := lantern.SyncMerge(nil, lantern.SyncItem{Key: "k", Updated: "soon"}, 0, 300); err == nil {
		t.Error("an updated that is not a time")
	}
}

func TestSyncStateSchemaRule(t *testing.T) {
	s := lantern.SyncOff("6f1c", "lea")
	s.Agree("wishes")
	s.Agree("wishes")
	if !s.Allows("wishes") || s.Allows("installed") || len(s.Consent) != 1 {
		t.Fatalf("%+v", s)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	back := lantern.ReadSyncState(raw)
	if back == nil || back.Server != "6f1c" || !back.Allows("wishes") {
		t.Fatalf("%s", raw)
	}
	// a field it does not know is kept when the state is written back
	withExtra := lantern.ReadSyncState([]byte(`{"schema":1,"server":"s","profile":"p","consent":[],"revs":{},"x-note":"kept"}`))
	out, _ := json.Marshal(withExtra)
	if !json.Valid(out) || !contains(string(out), `"x-note":"kept"`) {
		t.Errorf("%s", out)
	}
	for _, bad := range []string{``, `{"schema":2,"server":"s","profile":"p","consent":[],"revs":{}}`, `{"schema":1}`, `[]`, `{"schema":1,"server":"s","profile":"p","consent":"all","revs":{}}`} {
		if lantern.ReadSyncState([]byte(bad)) != nil {
			t.Errorf("%q was read", bad)
		}
	}
	s.Off()
	if s.Allows("wishes") || len(s.Revs) != 0 || s.Generation != nil {
		t.Errorf("%+v", s)
	}
	if lantern.IfMatch("g_4Rz1", 42) != `"g_4Rz1-42"` || lantern.WishKey("switch", "0100ABCD00010000") != "switch/0100ABCD00010000" {
		t.Error("If-Match and wish key")
	}
	if !errors.Is(&lantern.GenerationChangedError{Kept: "a", Now: "b"}, lantern.ErrGenerationChanged) {
		t.Error("errors.Is")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// vectorItem is an item of the vectors: they carry no key.
type vectorItem struct {
	Value   any    `json:"value"`
	Deleted bool   `json:"deleted"`
	Updated string `json:"updated"`
}

func (v *vectorItem) item() *lantern.SyncItem {
	if v == nil {
		return nil
	}
	it := &lantern.SyncItem{Key: "k", Value: v.Value, Updated: v.Updated}
	if v.Deleted {
		it.Deleted = &v.Deleted
	}
	return it
}
