// SPDX-License-Identifier: MIT

package lantern

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// ErrNewerOnDisk is a file of a newer schema than this library reads: it is read as absent and
// never written over (SPEC.md § 3.2).
var ErrNewerOnDisk = errors.New("lantern: the file is of a newer schema: not written over")

// ServerRecord is what a client keeps of a server it paired with, by its uid (SPEC.md § 5.2 to
// § 5.4): where it is, the fingerprint of the key it pinned (SPKI, SHA-256 hex, "" when a CA
// vouches for its certificate), its token, the device key the token is bound to (Key: its secret
// seed, base64; "" for a bearer-only token), the scopes and rating cap the token carries, and when
// it paired. The fields this library does not know are kept in Extra and written back. The token
// and the key are secrets: the store keeps them where the system protects them.
type ServerRecord struct {
	UID       string
	URL       string
	Token     string
	Name      string
	SPKI      string
	Key       string
	Scopes    []string
	Bound     bool
	RatingCap json.RawMessage // the token's rating cap as the server sent it, or nil
	Paired    string          // RFC 3339, UTC
	Extra     map[string]json.RawMessage
}

var recordKeys = map[string]bool{
	"uid": true, "url": true, "token": true, "name": true, "spki": true, "key": true,
	"scopes": true, "bound": true, "rating_cap": true, "paired": true,
}

// String does not show the token or the key.
func (r *ServerRecord) String() string {
	return fmt.Sprintf("ServerRecord(uid=%s url=%s spki=%s bound=%t)", r.UID, r.URL, r.SPKI, r.Bound)
}

// MarshalJSON writes the record with the fields it kept.
func (r ServerRecord) MarshalJSON() ([]byte, error) {
	out := map[string]json.RawMessage{}
	for k, v := range r.Extra {
		if !recordKeys[k] {
			out[k] = v
		}
	}
	put := func(k string, v any) {
		b, _ := json.Marshal(v)
		out[k] = b
	}
	put("uid", r.UID)
	put("url", r.URL)
	put("token", r.Token)
	put("name", r.Name)
	if r.SPKI != "" {
		put("spki", r.SPKI)
	}
	if r.Key != "" {
		put("key", r.Key)
	}
	scopes := r.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	put("scopes", scopes)
	put("bound", r.Bound)
	put("paired", r.Paired)
	if len(r.RatingCap) > 0 {
		out["rating_cap"] = r.RatingCap
	}
	return json.Marshal(out)
}

// UnmarshalJSON reads a record; an error when it lacks uid, url or token.
func (r *ServerRecord) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	str := func(k string) (string, bool) {
		var s string
		if v, ok := raw[k]; ok && json.Unmarshal(v, &s) == nil {
			return s, true
		}
		return "", false
	}
	var ok1, ok2, ok3 bool
	*r = ServerRecord{}
	r.UID, ok1 = str("uid")
	r.URL, ok2 = str("url")
	r.Token, ok3 = str("token")
	if !ok1 || !ok2 || !ok3 {
		return errors.New("a server record has a uid, a url and a token")
	}
	r.Name, _ = str("name")
	r.SPKI, _ = str("spki")
	r.Key, _ = str("key")
	r.Paired, _ = str("paired")
	_ = json.Unmarshal(raw["scopes"], &r.Scopes)
	var bound bool
	if json.Unmarshal(raw["bound"], &bound) == nil {
		r.Bound = bound
	}
	if v, ok := raw["rating_cap"]; ok && len(v) > 0 && v[0] == '{' {
		r.RatingCap = v
	}
	for k, v := range raw {
		if !recordKeys[k] {
			if r.Extra == nil {
				r.Extra = map[string]json.RawMessage{}
			}
			r.Extra[k] = v
		}
	}
	return nil
}

// ServerStore is where a client keeps the servers it paired with: their tokens and device keys are
// secrets, kept where the system protects them when it has such a place (SPEC.md § 5.4).
type ServerStore interface {
	// Server is the record of a uid, or nil.
	Server(uid string) (*ServerRecord, error)
	// Servers lists the records.
	Servers() ([]*ServerRecord, error)
	// Save keeps a record (a new pairing replaces the server's former one).
	Save(record *ServerRecord) error
	// Forget removes a record.
	Forget(uid string) error
}

// MemoryServerStore keeps servers in memory.
type MemoryServerStore struct {
	mu      sync.Mutex
	servers map[string]*ServerRecord
}

// Server implements ServerStore.
func (s *MemoryServerStore) Server(uid string) (*ServerRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.servers[uid], nil
}

// Servers implements ServerStore.
func (s *MemoryServerStore) Servers() ([]*ServerRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*ServerRecord, 0, len(s.servers))
	for _, r := range s.servers {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out, nil
}

// Save implements ServerStore.
func (s *MemoryServerStore) Save(record *ServerRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.servers == nil {
		s.servers = map[string]*ServerRecord{}
	}
	s.servers[record.UID] = record
	return nil
}

// Forget implements ServerStore.
func (s *MemoryServerStore) Forget(uid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.servers, uid)
	return nil
}

// FileServerStore keeps servers in a JSON file, readable by its owner alone:
// {"schema": 1, "servers": {"<uid>": {…}}}. A file of a newer schema is read as absent and never
// written over (Save gives ErrNewerOnDisk); the keys this library does not know, the file's and
// each record's, are kept.
type FileServerStore struct {
	Path string
	mu   sync.Mutex
}

// readFile is the file's top level, and false when its schema is newer than this library's.
func readFile(path string) (map[string]json.RawMessage, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]json.RawMessage{}, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, false, fmt.Errorf("%s: %w", path, err)
	}
	var schema int64
	if json.Unmarshal(doc["schema"], &schema) != nil || schema < 1 {
		return nil, false, fmt.Errorf("%s: no integer schema", path)
	}
	return doc, schema <= Schema, nil
}

func (s *FileServerStore) records() (map[string]json.RawMessage, bool, map[string]json.RawMessage, error) {
	doc, ok, err := readFile(s.Path)
	if err != nil || !ok {
		return nil, ok, nil, err
	}
	servers := map[string]json.RawMessage{}
	if v, has := doc["servers"]; has {
		_ = json.Unmarshal(v, &servers)
	}
	return servers, true, doc, nil
}

// Server implements ServerStore.
func (s *FileServerStore) Server(uid string) (*ServerRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	servers, _, _, err := s.records()
	if err != nil {
		return nil, err
	}
	var r ServerRecord
	if v, ok := servers[uid]; ok && json.Unmarshal(v, &r) == nil {
		return &r, nil
	}
	return nil, nil
}

// Servers implements ServerStore.
func (s *FileServerStore) Servers() ([]*ServerRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	servers, _, _, err := s.records()
	if err != nil {
		return nil, err
	}
	var out []*ServerRecord
	for _, v := range servers {
		var r ServerRecord
		if json.Unmarshal(v, &r) == nil {
			out = append(out, &r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out, nil
}

func (s *FileServerStore) update(uid string, record *ServerRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	servers, ok, doc, err := s.records()
	if err != nil {
		return err
	}
	if !ok {
		return ErrNewerOnDisk
	}
	if record == nil {
		delete(servers, uid)
	} else {
		b, err := json.Marshal(record)
		if err != nil {
			return err
		}
		servers[uid] = b
	}
	doc["schema"] = json.RawMessage("1")
	doc["servers"], _ = json.Marshal(servers)
	out, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return writeAtomic(s.Path, out)
}

// Save implements ServerStore.
func (s *FileServerStore) Save(record *ServerRecord) error { return s.update(record.UID, record) }

// Forget implements ServerStore.
func (s *FileServerStore) Forget(uid string) error { return s.update(uid, nil) }

// writeAtomic writes a file through a temporary one, readable by its owner alone.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".lantern-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // after a rename, there is nothing left to remove
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, os.ErrInvalid) {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// InvitationLink is what an invitation's link carries (SPEC.md § 5.5): the server's origin, the
// invitation's code, and the fingerprint of its key (SHA-256 hex) when no CA vouches for its
// certificate: a client pins that one, without asking the user to compare.
type InvitationLink struct {
	URL  string
	Code string
	SPKI string // "" when the link names none
}

// ParseInvitationLink reads an invitation's link.
func ParseInvitationLink(link string) (*InvitationLink, error) {
	ok, err := PlainHTTPAllowed(link)
	if err != nil || !ok {
		return nil, errors.New("an invitation's link is an HTTPS address")
	}
	u, _ := url.Parse(link)
	query := u.Query()
	codes, spkis := query["invitation"], query["spki"]
	if len(codes) != 1 || len(spkis) > 1 {
		return nil, errors.New("an invitation's link carries one invitation code")
	}
	code := strings.ToUpper(strings.TrimSpace(codes[0]))
	if n := len(strings.ReplaceAll(code, "-", "")); n < 16 || n > 32 {
		return nil, errors.New("an invitation's code is 16 to 32 symbols")
	}
	out := &InvitationLink{URL: u.Scheme + "://" + u.Host + "/", Code: code}
	if len(spkis) == 1 {
		out.SPKI = strings.ToLower(spkis[0])
		if !SHA256Pattern.MatchString(out.SPKI) {
			return nil, errors.New("spki is the server key's SHA-256, hex")
		}
	}
	return out, nil
}

// CheckPairingCode makes the checks a client makes on a pairing code before it shows anything
// (SPEC.md § 5.2): verify is an address it may open (HTTPS, or HTTP on loopback); verify_complete
// is on verify's origin with the code in its query; the poll address is on the server's origin
// (root).
func CheckPairingCode(doc *PairingCode, root string) error {
	bad := func(reason string) error { return &DocumentError{Where: "pairing code", Reason: reason} }
	if ok, err := PlainHTTPAllowed(doc.Verify); err != nil || !ok {
		return bad(fmt.Sprintf("verify %q is not an HTTPS address", Clip(doc.Verify, 100)))
	}
	if doc.VerifyComplete != "" {
		a, err1 := OriginOf(doc.VerifyComplete)
		b, err2 := OriginOf(doc.Verify)
		alnum := func(s string) string {
			var sb strings.Builder
			for _, c := range strings.ToUpper(s) {
				if c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' {
					sb.WriteRune(c)
				}
			}
			return sb.String()
		}
		u, _ := url.Parse(doc.VerifyComplete)
		query := ""
		if u != nil {
			query = alnum(u.RawQuery)
		}
		if err1 != nil || err2 != nil || a != b || !strings.Contains(query, alnum(doc.Code)) {
			return bad("verify_complete is not verify's address with the code in it")
		}
	}
	if p, err := url.Parse(doc.Poll); err != nil {
		return bad("the poll address is not an address")
	} else if p.Scheme != "" || p.Host != "" {
		a, err1 := OriginOf(doc.Poll)
		b, err2 := OriginOf(root)
		if err1 != nil || err2 != nil || a != b {
			return bad("the poll address is not on the server's origin")
		}
	}
	if doc.Expires < 1 || doc.Expires > 600 || doc.Interval < 1 {
		return bad("expires is 1 to 600 seconds, interval 1 or more")
	}
	return nil
}
