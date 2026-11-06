// SPDX-License-Identifier: MIT

package client_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/client"
)

func stream(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(200)
	w.Write([]byte(text))
	w.(http.Flusher).Flush()
}

func TestEventsResumeWithTheLastIDAfterRetry(t *testing.T) {
	d, c := newDepot(t)
	var n atomic.Int32
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1:
			if r.Header.Get("Last-Event-ID") != "" || r.Header.Get("Accept") != "text/event-stream" {
				t.Errorf("first: %v", r.Header)
			}
			stream(w, "retry: 50\n\nid: e_1\nevent: ready\ndata: {\"schema\":1}\n\nid: e_2\nevent: weather\ndata: {\"schema\":1}\n\nid: e_3\nevent: library\ndata: {\"schema\":1,\"families\":[\"apps\"]}\n\n")
		default:
			if got := r.Header.Get("Last-Event-ID"); got != "e_3" {
				t.Errorf("Last-Event-ID %q", got)
			}
			stream(w, "id: e_4\nevent: shutdown\ndata: {\"schema\":1,\"retry\":1}\n\n")
		}
	}
	s := c.Events(client.EventOptions{})
	var got []string
	started := time.Now()
	for ev, err := range s.All(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, ev.ID+":"+ev.Event)
		if ev.Event == "shutdown" {
			break
		}
	}
	if strings.Join(got, " ") != "e_1:ready e_3:library e_4:shutdown" {
		t.Fatalf("%v", got)
	}
	if s.LastID() != "e_4" || !s.ServerStopping() || time.Since(started) < 50*time.Millisecond {
		t.Fatalf("%q %v %v", s.LastID(), s.ServerStopping(), time.Since(started))
	}
	if s.Retry() != time.Second {
		t.Fatalf("shutdown's retry: %v", s.Retry())
	}
}

func TestEventsGiveUpOnAnIDTooOld(t *testing.T) {
	d, c := newDepot(t)
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 410, map[string]any{"schema": 1, "status": 410, "code": "gone", "title": "x"})
	}
	for _, err := range c.Events(client.EventOptions{Since: "s_old"}).All(context.Background()) {
		if !errors.Is(err, lantern.ErrGone) {
			t.Fatalf("%v", err)
		}
		return
	}
	t.Fatal("no error")
}

func TestEventsRefuseAnOversizedEventAfterGivingWhatCameBefore(t *testing.T) {
	d, c := newDepot(t)
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		stream(w, "retry: 10\n\nid: e_1\nevent: ready\ndata: {\"schema\":1}\n\nid: e_2\nevent: library\ndata: {\"schema\":1,\"x\":\""+strings.Repeat("x", 64<<10)+"\"}\n\n")
	}
	var events int
	var failure error
	for ev, err := range c.Events(client.EventOptions{}).All(context.Background()) {
		if err != nil {
			failure = err
			break
		}
		events += 1 - 0*len(ev.ID)
	}
	var de *lantern.DocumentError
	if events != 1 || !errors.As(failure, &de) {
		t.Fatalf("%d %v", events, failure)
	}
}

func TestEventsGiveUpAfterFailuresInARow(t *testing.T) {
	d, c := newDepot(t)
	var n atomic.Int32
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			stream(w, "retry: 1\n\nid: e_1\nevent: ready\ndata: {\"schema\":1}\n\n") // sets a short retry, then ends
			return
		}
		writeJSON(w, 503, map[string]any{"schema": 1, "status": 503, "code": "unavailable", "title": "x"})
	}
	waits := 0
	s := c.Events(client.EventOptions{Tries: 2, OnReconnect: func(error, time.Duration) { waits++ }})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var failure error
	for ev, err := range s.All(ctx) {
		if err != nil {
			failure = err
			break
		}
		_ = ev
	}
	if !errors.Is(failure, lantern.ErrUnavailable) || n.Load() != 3 || waits != 2 {
		t.Fatalf("%v, %d connections, %d waits", failure, n.Load(), waits)
	}
}

func TestEventsEndWithTheContext(t *testing.T) {
	d, c := newDepot(t)
	d.handler = func(w http.ResponseWriter, r *http.Request) {
		stream(w, "retry: 10\n\nid: e_1\nevent: ready\ndata: {\"schema\":1}\n\n")
		<-r.Context().Done()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var failure error
	for ev, err := range c.Events(client.EventOptions{}).All(ctx) {
		if err != nil {
			failure = err
			break
		}
		if ev.Event == "ready" {
			cancel()
		}
	}
	if !errors.Is(failure, context.Canceled) {
		t.Fatalf("%v", failure)
	}
}
