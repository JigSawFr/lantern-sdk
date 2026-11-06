// SPDX-License-Identifier: MIT

package lantern

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/JigSawFr/lantern-sdk/go/internal/model"
)

// Sync (SPEC.md § 20): a user's wishes, and what each of their devices has installed, kept by their
// server. This file is what a client and a server share: the times, the merge rule, the revision
// a write is made against, and the state a client keeps for one profile and one server.

// SyncCollections are the collections of this version (SPEC.md § 20.2); a later version may add
// others, which a reader skips.
var SyncCollections = []string{"wishes", "installed"}

// SyncWriteLimit is the items in one write at most (SPEC.md § 13). SyncTombstoneDays is how long a
// server keeps a deletion at least (§ 20.5).
const (
	SyncWriteLimit    = 1000
	SyncTombstoneDays = 30
)

var syncTime = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,3})?Z$`)

// ParseSyncTime is an item's time in milliseconds since the epoch: UTC, to the millisecond at most
// (SPEC.md § 20.2). It is false when text is not one, or not a date that exists.
func ParseSyncTime(text string) (int64, bool) {
	m := syncTime.FindStringSubmatch(text)
	if m == nil {
		return 0, false
	}
	n := func(i int) int { v, _ := strconv.Atoi(m[i]); return v }
	ms := 0
	if m[7] != "" {
		frac := (m[7][1:] + "00")[:3]
		ms, _ = strconv.Atoi(frac)
	}
	if n(4) > 23 || n(5) > 59 || n(6) > 59 {
		return 0, false
	}
	t := time.Date(n(1), time.Month(n(2)), n(3), n(4), n(5), n(6), 0, time.UTC)
	if t.Year() != n(1) || int(t.Month()) != n(2) || t.Day() != n(3) {
		return 0, false
	}
	return t.UnixMilli() + int64(ms), true
}

// FormatSyncTime is a time as items carry it: "2026-10-30T09:12:03.250Z".
func FormatSyncTime(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
}

// SyncReplaces is whether the item sent replaces the item a server has (SPEC.md § 20.4), their
// `updated` read by ParseSyncTime; have is nil when nothing is kept. The later `updated` wins; on
// the same one a deletion wins, and between two values the greater canonical JSON (§ 2.3); the same
// item again changes nothing.
func SyncReplaces(have *SyncItem, sent SyncItem) (bool, error) {
	t, ok := ParseSyncTime(sent.Updated)
	if !ok {
		return false, &DocumentError{Where: "updated", Reason: "not a UTC time to the millisecond"}
	}
	if have == nil {
		return true, nil
	}
	u, ok := ParseSyncTime(have.Updated)
	if !ok {
		return true, nil
	}
	if t != u {
		return t > u, nil
	}
	sentDeleted, haveDeleted := sent.IsDeleted(), have.IsDeleted()
	if sentDeleted || haveDeleted {
		return sentDeleted && !haveDeleted, nil
	}
	a, err := Canonical(sent.Value)
	if err != nil {
		return false, err
	}
	b, err := Canonical(have.Value)
	if err != nil {
		return false, err
	}
	return bytes.Compare(a, b) > 0, nil
}

// SyncMerge is the item a server keeps of have and sent (SPEC.md § 20.4), at its time now (in
// milliseconds) with its skew (seconds, auth.skew): sent with its `updated` normalized (to the
// millisecond, and to the server's time when it is more than skew ahead) when it replaces have;
// have otherwise. A kept item that is sent takes the collection's next rev: that is the caller's.
func SyncMerge(have *SyncItem, sent SyncItem, now int64, skew int64) (kept SyncItem, replaced bool, err error) {
	t, ok := ParseSyncTime(sent.Updated)
	if !ok {
		return SyncItem{}, false, &DocumentError{Where: "updated", Reason: "not a UTC time to the millisecond"}
	}
	if t > now+skew*1000 {
		t = now
	}
	sent.Updated = FormatSyncTime(t)
	replaced, err = SyncReplaces(have, sent)
	if err != nil {
		return SyncItem{}, false, err
	}
	if replaced {
		return sent, true, nil
	}
	return *have, false, nil
}

// IsDeleted is whether the item is a deletion.
func (i SyncItem) IsDeleted() bool { return i.Deleted != nil && *i.Deleted }

// SyncValue is an item to send: a value at `updated` (a time in milliseconds, the device's corrected
// by its offset to the server's Date, Annex B.9).
func SyncValue(key string, value any, updated int64) SyncItem {
	return SyncItem{Key: key, Value: value, Updated: FormatSyncTime(updated)}
}

// SyncDeletion is an item to send that deletes its key at `updated`.
func SyncDeletion(key string, updated int64) SyncItem {
	deleted := true
	return SyncItem{Key: key, Deleted: &deleted, Updated: FormatSyncTime(updated)}
}

// IfMatch is the If-Match of a write made from the whole collection: `"<generation>-<rev>"`
// (SPEC.md § 20.4).
func IfMatch(generation string, rev int64) string {
	return `"` + generation + "-" + strconv.FormatInt(rev, 10) + `"`
}

// WishKey is a wish's key: "<platform>/<title_id>" (SPEC.md § 20.2).
func WishKey(platform, titleID string) string { return platform + "/" + titleID }

// ErrConsentRequired is sync without its user's consent (SPEC.md § 20.1): a client reads and
// writes nothing of it, and asks first. Agreeing to one collection does not cover another
// (L-20.1-2): what a device has installed leaves it only with a consent given for it by name.
var ErrConsentRequired = errors.New("lantern: sync without the user's consent")

// GenerationChangedError is the generation a client kept being no longer the server's (SPEC.md
// § 20.3, L-20.3-2): the user's sync data was deleted. The client dropped its copy of the state and
// turned sync off: ask the user again before it syncs.
type GenerationChangedError struct{ Kept, Now string }

func (e *GenerationChangedError) Error() string {
	return fmt.Sprintf("lantern: the sync data was deleted on the server (generation %s is now %s): sync is off until asked again", e.Kept, e.Now)
}

// ErrGenerationChanged is what a *GenerationChangedError is, for errors.Is.
var ErrGenerationChanged = errors.New("lantern: the sync generation changed")

// Is makes errors.Is(err, ErrGenerationChanged) true.
func (e *GenerationChangedError) Is(target error) bool { return target == ErrGenerationChanged }

// SyncState is what one console profile agreed to sync with one server (SPEC.md § 20.1), and what it
// last read: the collections by name, each given on its own, the generation and the revisions. An
// application asks its user, then calls Consent; nothing of sync goes before. It is a document of
// its own schema, kept by the application (a file): read it with ReadSyncState, which keeps what it
// does not know, so that a state written back loses nothing.
type SyncState struct {
	Schema     int64            `json:"schema" lantern:"required"`
	Server     string           `json:"server" lantern:"required"`
	Profile    string           `json:"profile" lantern:"required"`
	Consent    []string         `json:"consent" lantern:"required"`
	Generation *string          `json:"generation"`
	Revs       map[string]int64 `json:"revs" lantern:"required"`
	// Extra holds the fields this version does not know, as they were read.
	Extra map[string]json.RawMessage `json:"-"`
}

// UnmarshalJSON reads SyncState, keeping the fields it does not know.
func (s *SyncState) UnmarshalJSON(data []byte) error { return model.Decode(data, s) }

// MarshalJSON writes SyncState with the fields it kept.
func (s SyncState) MarshalJSON() ([]byte, error) { return model.Encode(s) }

// SyncOff is a state of no consent: sync off, for a server (its uid) and a profile.
func SyncOff(server, profile string) *SyncState {
	return &SyncState{Schema: 1, Server: server, Profile: profile, Consent: []string{}, Revs: map[string]int64{}}
}

// ReadSyncState reads a state as kept, by the schema rule (SPEC.md § 3.2): nil when the bytes are
// absent, of a newer schema, or not a state, so that the application asks its user again; the
// stored bytes are never written over.
func ReadSyncState(raw []byte) *SyncState {
	s, err := Parse[SyncState](raw)
	if err != nil {
		return nil
	}
	if s.Revs == nil {
		s.Revs = map[string]int64{}
	}
	return s
}

// Allows is whether the user agreed to sync a collection, by name.
func (s *SyncState) Allows(collection string) bool { return slices.Contains(s.Consent, collection) }

// Agree records the user's consent to sync a collection (SPEC.md § 20.1).
func (s *SyncState) Agree(collection string) {
	if !s.Allows(collection) {
		s.Consent = append(s.Consent, collection)
	}
}

// Off turns sync off (L-20.1-3): no consent, nothing read. Whether to delete what the server keeps
// is the user's to say (Syncer.Delete).
func (s *SyncState) Off() {
	s.Consent, s.Generation, s.Revs = []string{}, nil, map[string]int64{}
}
