// SPDX-License-Identifier: Apache-2.0

package lantern

import (
	"bytes"
	"fmt"
	"math"
	"math/rand/v2"
	"strconv"
	"strings"
	"unicode/utf8"
)

// EventDataLimit is the most an event's data may hold, in bytes (SPEC.md § 13). EventLineLimit is the
// longest line of a stream a reader keeps: the data and a field's name, with room.
const (
	EventDataLimit = 4096
	EventLineLimit = EventDataLimit + 1024
)

// EventTypes are the events of this version (SPEC.md § 18.2); a reader ignores the others.
var EventTypes = []string{"ready", "library", "request", "pairing", "save", "sync", "shutdown"}

// SSEBlock is what a stream gave between two empty lines: an event's fields, or retry alone.
// A field that was not given is its zero value, and Has… says whether it was.
type SSEBlock struct {
	ID       string
	Event    string
	Data     string
	Retry    int // milliseconds
	HasID    bool
	HasEvent bool
	HasData  bool
	HasRetry bool
}

// ServerEvent is an event a client reads (SPEC.md § 18.2): its id (a token of /v1/changes), its
// type and its document, as LoadJSON gives it (maps, slices, strings, json.Number…).
type ServerEvent struct {
	ID    string
	Event string
	Data  map[string]any
}

// SSEParser is a bounded Server-Sent Events parser, as the WHATWG HTML standard parses: lines
// ended by CR, LF or CRLF, "field: value", data lines joined by LF, a comment begins with ":",
// an empty line dispatches the event. A line above LineLimit bytes, or an event whose data is
// above DataLimit, is a *DocumentError as soon as the bound is passed, without holding the rest.
type SSEParser struct {
	LineLimit int // EventLineLimit when 0
	DataLimit int // EventDataLimit when 0
	// LastEventID is the last id the stream set, as the standard keeps it.
	LastEventID string
	// Comments counts the comments read (heartbeats).
	Comments int

	line    []byte
	afterCR bool
	started bool
	block   sseOpen
}

type sseOpen struct {
	id, event string
	data      []string
	dataBytes int
	retry     int
	hasID     bool
	hasEvent  bool
	hasRetry  bool
	any       bool
}

func (p *SSEParser) lineLimit() int {
	if p.LineLimit > 0 {
		return p.LineLimit
	}
	return EventLineLimit
}

func (p *SSEParser) dataLimit() int {
	if p.DataLimit > 0 {
		return p.DataLimit
	}
	return EventDataLimit
}

// Push feeds the parser a chunk of the stream and gives the blocks it completed. When a bound is
// passed it gives the blocks completed before it, and the error.
func (p *SSEParser) Push(chunk []byte) ([]SSEBlock, error) {
	var out []SSEBlock
	for _, b := range chunk {
		if p.afterCR {
			p.afterCR = false
			if b == '\n' {
				continue
			}
		}
		if b == '\n' || b == '\r' {
			p.afterCR = b == '\r'
			block, ok, err := p.endLine()
			if err != nil {
				return out, err
			}
			if ok {
				out = append(out, block)
			}
			continue
		}
		if len(p.line) >= p.lineLimit() {
			return out, &DocumentError{Where: "events", Reason: fmt.Sprintf("an event stream's line above %d bytes", p.lineLimit())}
		}
		p.line = append(p.line, b)
	}
	return out, nil
}

func (p *SSEParser) endLine() (SSEBlock, bool, error) {
	raw := p.line
	p.line = p.line[:0]
	text := string(bytes.ToValidUTF8(raw, []byte("�")))
	if !p.started {
		p.started = true
		text = strings.TrimPrefix(text, "\uFEFF")
	}
	if text == "" {
		block, ok := p.dispatch()
		return block, ok, nil
	}
	if text[0] == ':' {
		p.Comments++
		return SSEBlock{}, false, nil
	}
	field, value, found := strings.Cut(text, ":")
	if found {
		value = strings.TrimPrefix(value, " ")
	}
	b := &p.block
	switch field {
	case "data":
		b.dataBytes += len(value)
		if len(b.data) > 0 {
			b.dataBytes++
		}
		if b.dataBytes > p.dataLimit() {
			return SSEBlock{}, false, &DocumentError{Where: "events", Reason: fmt.Sprintf("an event's data above %d bytes (SPEC.md § 13)", p.dataLimit())}
		}
		b.data = append(b.data, value)
		b.any = true
	case "event":
		b.event, b.hasEvent, b.any = value, true, true
	case "id":
		if !strings.Contains(value, "\x00") {
			b.id, b.hasID = value, true
			p.LastEventID = value
		}
		b.any = true
	case "retry":
		if n, ok := digits(value, 9); ok {
			b.retry, b.hasRetry, b.any = n, true, true
		}
	}
	return SSEBlock{}, false, nil
}

func digits(s string, most int) (int, bool) {
	if s == "" || len(s) > most {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

func (p *SSEParser) dispatch() (SSEBlock, bool) {
	b := p.block
	p.block = sseOpen{}
	if !b.any {
		return SSEBlock{}, false
	}
	out := SSEBlock{ID: b.id, Event: b.event, Retry: b.retry, HasID: b.hasID, HasEvent: b.hasEvent, HasRetry: b.hasRetry}
	if len(b.data) > 0 {
		out.Data, out.HasData = strings.Join(b.data, "\n"), true
	}
	return out, true
}

// ReadEvent is the event a block carries, or nil when a reader ignores it (SPEC.md § 18.1,
// L-18.1-5): no data, no id, a type this version does not know, a document of a newer schema.
// A data that is not a JSON object with an integer schema is a *DocumentError.
func ReadEvent(block SSEBlock) (*ServerEvent, error) {
	if !block.HasData || !block.HasEvent || !contains(EventTypes, block.Event) {
		return nil, nil
	}
	where := "event " + block.Event
	doc, err := LoadJSON([]byte(block.Data), LoadOptions{Limit: EventDataLimit, Where: where})
	if err != nil {
		return nil, err
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil, &DocumentError{Where: where, Reason: "an event's data is a JSON object"}
	}
	schema, err := SchemaOf(obj, where)
	if err != nil {
		return nil, err
	}
	if schema > Schema || !block.HasID || block.ID == "" || !utf8.ValidString(block.ID) {
		return nil, nil
	}
	return &ServerEvent{ID: block.ID, Event: block.Event, Data: obj}, nil
}

// Backoff is the seconds to wait after the attempt-th failure in a row (Annex B.2): a random time,
// with full jitter, between 0 and min(60, 2^attempt), and at least floor.
func Backoff(attempt int, floor float64) float64 {
	ceiling := math.Min(60, math.Pow(2, math.Min(float64(attempt), 6)))
	return math.Max(floor, rand.Float64()*ceiling)
}
