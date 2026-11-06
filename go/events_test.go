// SPDX-License-Identifier: MIT

package lantern_test

import (
	"errors"
	"strings"
	"testing"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

func parse(t *testing.T, p *lantern.SSEParser, chunks ...string) []lantern.SSEBlock {
	t.Helper()
	var out []lantern.SSEBlock
	for _, c := range chunks {
		b, err := p.Push([]byte(c))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b...)
	}
	return out
}

func TestSSEParserFollowsTheStandard(t *testing.T) {
	p := &lantern.SSEParser{}
	// CR, LF and CRLF all end a line, whatever the chunks cut; a BOM, a comment and an unknown field are skipped.
	blocks := parse(t, p, "\ufeffretry: 1500\r\n\r", "\n: heartbeat\nid: e_1\r", "event: ready\ndata: {\"a\":\ndata: 1}\nx-other: y\n\n")
	if len(blocks) != 2 || !blocks[0].HasRetry || blocks[0].Retry != 1500 || blocks[0].HasData {
		t.Fatalf("%+v", blocks)
	}
	if b := blocks[1]; b.ID != "e_1" || b.Event != "ready" || b.Data != "{\"a\":\n1}" {
		t.Fatalf("%+v", b)
	}
	if p.LastEventID != "e_1" || p.Comments != 1 {
		t.Fatalf("%q %d", p.LastEventID, p.Comments)
	}
}

func TestSSEParserBounds(t *testing.T) {
	p := &lantern.SSEParser{}
	good := "id: e_1\nevent: ready\ndata: {\"schema\":1}\n\n"
	blocks, err := p.Push([]byte(good + "data: " + strings.Repeat("x", lantern.EventDataLimit+1) + "\n"))
	var de *lantern.DocumentError
	if !errors.As(err, &de) || len(blocks) != 1 {
		t.Fatalf("%v %d", err, len(blocks))
	}
	q := &lantern.SSEParser{}
	if _, err := q.Push([]byte(strings.Repeat("y", lantern.EventLineLimit+1))); !errors.As(err, &de) {
		t.Fatalf("a line above its bound: %v", err)
	}
}

func TestReadEventIgnoresWhatItShould(t *testing.T) {
	cases := map[string]struct {
		block lantern.SSEBlock
		want  bool
	}{
		"known":        {lantern.SSEBlock{ID: "e_1", Event: "library", Data: `{"schema":1}`, HasID: true, HasEvent: true, HasData: true}, true},
		"unknown type": {lantern.SSEBlock{ID: "e_1", Event: "weather", Data: `{"schema":1}`, HasID: true, HasEvent: true, HasData: true}, false},
		"newer schema": {lantern.SSEBlock{ID: "e_1", Event: "library", Data: `{"schema":99}`, HasID: true, HasEvent: true, HasData: true}, false},
		"no id":        {lantern.SSEBlock{Event: "library", Data: `{"schema":1}`, HasEvent: true, HasData: true}, false},
		"no data":      {lantern.SSEBlock{ID: "e_1", Event: "library", HasID: true, HasEvent: true}, false},
	}
	for name, c := range cases {
		ev, err := lantern.ReadEvent(c.block)
		if err != nil || (ev != nil) != c.want {
			t.Errorf("%s: %v %v", name, ev, err)
		}
	}
	for _, data := range []string{`[1]`, `{"x":1}`, `{"schema":1.5}`, `nope`} {
		b := lantern.SSEBlock{ID: "e_1", Event: "library", Data: data, HasID: true, HasEvent: true, HasData: true}
		if _, err := lantern.ReadEvent(b); err == nil {
			t.Errorf("%s was accepted", data)
		}
	}
}

func TestBackoffStaysWithinItsBounds(t *testing.T) {
	for attempt := 0; attempt < 12; attempt++ {
		for range 50 {
			if v := lantern.Backoff(attempt, 2); v < 2 || v > 60 && v > 2 {
				t.Fatalf("attempt %d: %v", attempt, v)
			}
		}
	}
}
