// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

// Syncer syncs one profile with one server (SPEC.md § 20): the collections its user agreed to, and
// nothing else. It holds the profile's SyncState, which the application keeps (a file) and writes
// back after each call, and which it changes: the generation and revisions last read, and the
// consent, taken back when the server's generation is no longer the one kept.
//
//	state := lantern.SyncOff(hello.UID, "lea")
//	state.Agree("wishes") // after asking the user: which collections, to which server
//	s := c.Syncer(state)
//	pull, err := s.Pull(ctx, "wishes")
type Syncer struct {
	c     *Client
	state *lantern.SyncState
}

// Syncer is the syncing of a profile's state with this server.
func (c *Client) Syncer(state *lantern.SyncState) *Syncer { return &Syncer{c: c, state: state} }

// State is the profile's state, as the Syncer changed it: keep it after each call.
func (s *Syncer) State() *lantern.SyncState { return s.state }

// consent checks the user agreed to sync a collection, by name (L-20.1-1, L-20.1-2): nothing of
// /v1/sync is read or written before.
func (s *Syncer) consent(collection string) error {
	if !s.state.Allows(collection) {
		return fmt.Errorf("%w: %q was not agreed to", lantern.ErrConsentRequired, collection)
	}
	return nil
}

// generation notes the generation a read gave. It is the one kept, or the first; another is
// L-20.3-2: the state is dropped and sync turned off, and the error says so.
func (s *Syncer) generation(now string) error {
	if s.state.Generation != nil && *s.state.Generation != now {
		kept := *s.state.Generation
		s.state.Off()
		return &lantern.GenerationChangedError{Kept: kept, Now: now}
	}
	s.state.Generation = &now
	return nil
}

// Info reads what the account keeps (SPEC.md § 20.3): the generation, the caller's device key in
// `installed`, and each collection's revision and count. The user must have agreed to a collection.
func (s *Syncer) Info(ctx context.Context) (*lantern.Sync, error) {
	if len(s.state.Consent) == 0 {
		return nil, fmt.Errorf("%w: sync is off", lantern.ErrConsentRequired)
	}
	info, err := getJSON[lantern.Sync](s.c, ctx, "sync", "/sync", nil)
	if err != nil {
		return nil, err
	}
	if err := s.generation(info.Generation); err != nil {
		return nil, err
	}
	return info, nil
}

// SyncPull is a collection as read (SPEC.md § 20.3): its generation and revision, and its items.
type SyncPull struct {
	Collection string
	Generation string
	Rev        int64
	Items      []lantern.SyncItem
	// Whole says the items are the whole collection (deletions left out), not the changes since a
	// revision: the first read, or after the server no longer kept the deletions that far back.
	Whole bool
}

// Pull reads a collection (SPEC.md § 20.3): its changes since the revision last read, deletions
// included, or all of it (without deletions) when none was read, or when the server answers
// `410 gone` because it no longer keeps the deletions that far back. The state takes the
// generation and the revision. A generation other than the one kept turns sync off
// (lantern.ErrGenerationChanged): ask the user again.
func (s *Syncer) Pull(ctx context.Context, collection string) (*SyncPull, error) {
	if err := s.consent(collection); err != nil {
		return nil, err
	}
	if !validCollection(collection) {
		return nil, fmt.Errorf("lantern: %q is not a collection name", collection)
	}
	rev, haveRev := s.state.Revs[collection]
	if s.state.Generation == nil {
		haveRev = false
	}
	out, err := s.readPages(ctx, collection, rev, haveRev)
	if errors.Is(err, lantern.ErrGone) && haveRev {
		out, err = s.readPages(ctx, collection, 0, false)
	}
	if err != nil {
		return nil, err
	}
	if err := s.generation(out.Generation); err != nil {
		return nil, err
	}
	s.state.Revs[collection] = out.Rev
	return out, nil
}

func (s *Syncer) readPages(ctx context.Context, collection string, since int64, withSince bool) (*SyncPull, error) {
	out := &SyncPull{Collection: collection, Whole: !withSince}
	cursor, seen := "", map[string]bool{}
	for first := true; ; first = false {
		q := url.Values{}
		if withSince {
			q.Set("since", strconv.FormatInt(since, 10))
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		page, err := getJSON[lantern.SyncCollection](s.c, ctx, "sync", "/sync/"+collection, q)
		if err != nil {
			return nil, err
		}
		if page.Collection != collection {
			return nil, &lantern.DocumentError{Where: "sync", Reason: fmt.Sprintf("the collection %q, not %q", page.Collection, collection)}
		}
		if err := checkNext(page.Next, len(page.Items)); err != nil {
			return nil, err
		}
		switch {
		case first: // rev is the collection's when its first page was read
			out.Generation, out.Rev = page.Generation, page.Rev
		case page.Generation != out.Generation:
			return nil, &lantern.DocumentError{Where: "sync", Reason: "the generation changed while a collection was read"}
		}
		for _, it := range page.Items {
			if !withSince && it.IsDeleted() {
				continue // a whole read carries none
			}
			out.Items = append(out.Items, it)
		}
		if page.Next == nil {
			return out, nil
		}
		if seen[*page.Next] {
			return nil, &lantern.DocumentError{Where: "next", Reason: "a cursor given twice"}
		}
		seen[*page.Next] = true
		cursor = *page.Next
	}
}

// PushOptions tune Push.
type PushOptions struct {
	// Whole says the items were made from the whole collection as the last Pull read it: the write
	// is then all or nothing (`If-Match`, L-20.4-3), and lantern.ErrPreconditionFailed means it
	// changed since, so pull again. It takes at most lantern.SyncWriteLimit items. Without it the
	// merge rule of § 20.4 settles each item and the items are sent as many as a write takes.
	Whole bool
}

// Push writes items to a collection (SPEC.md § 20.4) and gives each as the server keeps it, with
// its rev. The state must have read the collection first (it needs the generation). A write of
// another generation (`409`) is the data deleted since: sync is turned off as for a read, when the
// server's generation is read to be another.
func (s *Syncer) Push(ctx context.Context, collection string, items []lantern.SyncItem, opts PushOptions) ([]lantern.SyncItem, error) {
	if err := s.consent(collection); err != nil {
		return nil, err
	}
	if !validCollection(collection) {
		return nil, fmt.Errorf("lantern: %q is not a collection name", collection)
	}
	if s.state.Generation == nil {
		return nil, errors.New("lantern: pull the collection before writing to it: the generation is not known")
	}
	if opts.Whole && len(items) > lantern.SyncWriteLimit {
		return nil, fmt.Errorf("lantern: a write that is all or nothing takes %d items at most", lantern.SyncWriteLimit)
	}
	if opts.Whole {
		if _, ok := s.state.Revs[collection]; !ok {
			return nil, errors.New("lantern: pull the collection before writing it whole: its revision is not known")
		}
	}
	for _, it := range items {
		if it.Key == "" || (it.IsDeleted() && it.Value != nil) {
			return nil, fmt.Errorf("lantern: an item has a key, and a value or a deletion: %q", it.Key)
		}
		if _, ok := lantern.ParseSyncTime(it.Updated); !ok {
			return nil, fmt.Errorf("lantern: %q: updated is not a UTC time to the millisecond", it.Key)
		}
	}
	var kept []lantern.SyncItem
	for chunk := range slices.Chunk(items, lantern.SyncWriteLimit) {
		body := lantern.SyncWrite{Schema: lantern.Schema, Generation: *s.state.Generation, Items: sent(chunk)}
		k := &call{method: http.MethodPatch, path: "/sync/" + collection, body: body, what: "sync"}
		if opts.Whole {
			k.headers = http.Header{"If-Match": {lantern.IfMatch(*s.state.Generation, s.state.Revs[collection])}}
		}
		resp, err := s.c.send(ctx, k, lantern.MaxJSONDocument)
		if err != nil {
			if errors.Is(err, lantern.ErrConflict) {
				return kept, s.conflict(ctx, err)
			}
			return kept, err
		}
		if err := s.c.expect(resp, "sync", http.StatusOK); err != nil {
			return kept, err
		}
		page, err := read[lantern.SyncCollection](s.c, "sync", resp)
		if err != nil {
			return kept, err
		}
		if page.Generation != *s.state.Generation {
			return kept, s.generation(page.Generation)
		}
		kept = append(kept, page.Items...)
	}
	return kept, nil
}

// sent are items as they go: a key, a value or a deletion, and a time; a rev the server gave is not sent.
func sent(items []lantern.SyncItem) []lantern.SyncItem {
	out := make([]lantern.SyncItem, len(items))
	for i, it := range items {
		out[i] = lantern.SyncItem{Key: it.Key, Value: it.Value, Deleted: it.Deleted, Updated: it.Updated}
	}
	return out
}

// conflict is a write the server refused with `409`: the data was deleted since (L-20.4-4). The
// generation is read again to be sure; another one turns sync off.
func (s *Syncer) conflict(ctx context.Context, refused error) error {
	info, err := getJSON[lantern.Sync](s.c, ctx, "sync", "/sync", nil)
	if err != nil {
		return refused
	}
	if g := s.generation(info.Generation); g != nil {
		return g
	}
	return refused
}

// Delete erases the items the server keeps of a collection, or of every one when collection is "",
// and gives the account a new generation (SPEC.md § 20.5). It needs no consent: it is what the user
// asks when they turn sync off (L-20.1-3). The state forgets the generation and the revisions: read the collections again.
func (s *Syncer) Delete(ctx context.Context, collection string) error {
	path := "/sync"
	if collection != "" {
		if !validCollection(collection) {
			return fmt.Errorf("lantern: %q is not a collection name", collection)
		}
		path += "/" + collection
	}
	if err := s.c.noContent(ctx, &call{method: http.MethodDelete, path: path, what: "sync"}); err != nil {
		return err
	}
	// the account has a new generation: what was read of every collection is gone with it
	s.state.Generation, s.state.Revs = nil, map[string]int64{}
	return nil
}

func validCollection(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
