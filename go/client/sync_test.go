// SPDX-License-Identifier: MIT

package client_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/client"
)

func syncPage(generation string, rev int, next any, items ...map[string]any) map[string]any {
	if items == nil {
		items = []map[string]any{}
	}
	return map[string]any{"schema": 1, "collection": "wishes", "generation": generation, "rev": rev, "items": items, "next": next}
}

func TestSyncPullReadsAgainWholeWhenDeletionsAreGone(t *testing.T) {
	d, c := newDepot(t)
	var sinces atomic.Int32
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Get("since") != "":
			sinces.Add(1)
			writeJSON(w, 410, map[string]any{"schema": 1, "status": 410, "code": "gone", "title": "x"})
		case q.Get("cursor") == "":
			writeJSON(w, 200, syncPage("g_1", 9, "2", map[string]any{"key": "switch/A", "value": map[string]any{"n": 1}, "updated": "2026-10-30T09:00:00.000Z", "rev": 8},
				map[string]any{"key": "switch/B", "deleted": true, "updated": "2026-10-30T09:00:00.000Z", "rev": 9}))
		default:
			writeJSON(w, 200, syncPage("g_1", 9, nil, map[string]any{"key": "switch/C", "value": map[string]any{"n": 3}, "updated": "2026-10-30T09:00:00.000Z", "rev": 7}))
		}
	}
	state := lantern.SyncOff("u", "lea")
	state.Agree("wishes")
	g, rev := "g_1", int64(3)
	state.Generation, state.Revs["wishes"] = &g, rev
	got, err := c.Syncer(state).Pull(context.Background(), "wishes")
	if err != nil || sinces.Load() != 1 || !got.Whole || got.Rev != 9 {
		t.Fatalf("%+v %v (%d reads since)", got, err, sinces.Load())
	}
	// a whole read carries no deletion, across its pages
	if len(got.Items) != 2 || got.Items[0].Key != "switch/A" || got.Items[1].Key != "switch/C" {
		t.Fatalf("%+v", got.Items)
	}
	if state.Revs["wishes"] != 9 {
		t.Errorf("%v", state.Revs)
	}
}

func TestSyncPullTurnsSyncOffWhenTheGenerationChanged(t *testing.T) {
	d, c := newDepot(t)
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, syncPage("g_2", 1, nil))
	}
	state := lantern.SyncOff("u", "lea")
	state.Agree("wishes")
	state.Agree("installed")
	g := "g_1"
	state.Generation, state.Revs["wishes"] = &g, 4
	_, err := c.Syncer(state).Pull(context.Background(), "wishes")
	var changed *lantern.GenerationChangedError
	if !errors.As(err, &changed) || changed.Kept != "g_1" || changed.Now != "g_2" {
		t.Fatalf("%v", err)
	}
	if state.Allows("wishes") || state.Allows("installed") || state.Generation != nil || len(state.Revs) != 0 {
		t.Errorf("sync is on: %+v", state)
	}
}

func TestSyncPushIsCheckedBeforeItIsSent(t *testing.T) {
	d, c := newDepot(t)
	var hits atomic.Int32
	d.handler = func(w http.ResponseWriter, r *http.Request) { hits.Add(1); http.NotFound(w, r) }
	state := lantern.SyncOff("u", "lea")
	state.Agree("wishes")
	g := "g_1"
	state.Generation, state.Revs["wishes"] = &g, 1
	s := c.Syncer(state)
	ctx := context.Background()
	good := lantern.SyncValue("switch/A", map[string]any{"n": 1}, 1_000)
	deletedWithValue := good
	t1 := true
	deletedWithValue.Deleted = &t1
	late := good
	late.Updated = "tomorrow"
	nokey := good
	nokey.Key = ""
	for name, items := range map[string][]lantern.SyncItem{"a deletion with a value": {deletedWithValue}, "a time that is none": {late}, "no key": {nokey}} {
		if _, err := s.Push(ctx, "wishes", items, client.PushOptions{}); err == nil {
			t.Errorf("%s was sent", name)
		}
	}
	if _, err := s.Push(ctx, "installed", []lantern.SyncItem{good}, client.PushOptions{}); !errors.Is(err, lantern.ErrConsentRequired) {
		t.Errorf("a collection not agreed to: %v", err)
	}
	many := make([]lantern.SyncItem, lantern.SyncWriteLimit+1)
	for i := range many {
		many[i] = good
	}
	if _, err := s.Push(ctx, "wishes", many, client.PushOptions{Whole: true}); err == nil {
		t.Error("an all-or-nothing write above the limit")
	}
	if hits.Load() != 0 {
		t.Errorf("%d requests went out", hits.Load())
	}
}
