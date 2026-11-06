// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

// An open stream (SPEC.md § 18.1) is read over the client's own transport, for a server needs
// the token and the signature, which a browser's EventSource cannot send (§ 5.4).

// open makes a call and gives the answer as it comes, its body unread: a 200 whose
// Content-Type is `want`. A request refused for its signature is signed again once, as send does.
// The caller closes the body.
func (c *Client) open(ctx context.Context, k *call, want string) (*http.Response, error) {
	c.mu.Lock()
	have := c.base != ""
	c.mu.Unlock()
	if !have {
		if _, err := c.Handshake(ctx); err != nil {
			return nil, err
		}
	}
	for attempt := 0; ; attempt++ {
		req, err := c.build(ctx, k)
		if err != nil {
			return nil, err
		}
		resp, err := c.http.Do(req)
		if err != nil {
			var pin *lantern.PinMismatchError
			if errors.As(err, &pin) {
				return nil, pin
			}
			return nil, fmt.Errorf("%w: %w", lantern.ErrTransport, err)
		}
		if err := c.checkPin(resp); err != nil {
			resp.Body.Close()
			return nil, err
		}
		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, errorBody))
			resp.Body.Close()
			perr := lantern.NewProblemError(resp.StatusCode, body, flat(resp.Header))
			if attempt == 0 && req.Header.Get("Signature") != "" && c.resign(perr, resp.Header) {
				continue
			}
			return nil, perr
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("%w: %s: status %d", lantern.ErrUnexpectedResponse, k.what, resp.StatusCode)
		}
		if mt, _, _ := strings.Cut(resp.Header.Get("Content-Type"), ";"); strings.ToLower(strings.TrimSpace(mt)) != want {
			resp.Body.Close()
			return nil, fmt.Errorf("%w: %s: Content-Type %q, not %s", lantern.ErrUnexpectedResponse, k.what, lantern.Clip(resp.Header.Get("Content-Type"), 80), want)
		}
		c.note(k.what, resp.Header)
		return resp, nil
	}
}

// EventOptions tune an event stream.
type EventOptions struct {
	// Since is the token to resume from: an id read before, kept across a restart (Annex B.10).
	Since string
	// Tries is the connections that fail in a row before giving up (Annex B.2: 5 when 0).
	Tries int
	// OnReconnect is called each time the stream is opened again, with the error that ended the
	// last connection (nil when it ended as the server meant) and the time waited first.
	OnReconnect func(err error, wait time.Duration)
}

// EventStream is the events of a server (SPEC.md § 18.1), read for as long as the loop over All
// runs: opened again as the text says when it ends or fails, after retry at least (L-18.1-9) with
// Last-Event-ID set to the last id read, backing off as Annex B.2 says while connecting fails,
// and when nothing came for twice limits.heartbeat.
//
// It gives up on what it cannot go on from, as the error of the loop: a stream that breaks the
// limits of § 13 (*lantern.DocumentError), a token the server no longer takes, an id too old
// (lantern.ErrGone: read the library again, then open a stream without a token), or Tries
// failures in a row.
//
//	for ev, err := range c.Events(client.EventOptions{}).All(ctx) { ... }
type EventStream struct {
	c    *Client
	opts EventOptions

	mu       sync.Mutex
	lastID   string
	retry    time.Duration
	stopping bool
}

// Events is a stream of the server's events (feature `events`). Nothing is opened until All is
// ranged over. A client holds one stream per server (L-18.4-3).
func (c *Client) Events(opts EventOptions) *EventStream {
	if opts.Tries <= 0 {
		opts.Tries = 5
	}
	return &EventStream{c: c, opts: opts, lastID: opts.Since, retry: 5 * time.Second}
}

// LastID is the last event id read: where the stream goes on from, and what to keep across a restart.
func (s *EventStream) LastID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastID
}

// Retry is the time to wait before connecting again, as the server last said.
func (s *EventStream) Retry() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retry
}

// ServerStopping is whether the server said it is stopping (`shutdown`), until the stream is open again.
func (s *EventStream) ServerStopping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopping
}

func transient(err error) bool {
	return errors.Is(err, lantern.ErrTransport) || errors.Is(err, lantern.ErrSlowDown) ||
		errors.Is(err, lantern.ErrServer) || errors.Is(err, lantern.ErrUnavailable)
}

// All is the stream's events, as they come. The loop ends when the context does (the error is
// then the context's), when the loop breaks, or with an error the stream cannot go on from.
func (s *EventStream) All(ctx context.Context) iter.Seq2[*lantern.ServerEvent, error] {
	return func(yield func(*lantern.ServerEvent, error) bool) {
		failures := 0
		var wait time.Duration
		for {
			if wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					timer.Stop()
					yield(nil, ctx.Err())
					return
				case <-timer.C:
				}
			}
			ended, stop := s.once(ctx, yield, &failures)
			if stop {
				return
			}
			if ended != nil {
				if ctx.Err() != nil {
					yield(nil, ctx.Err())
					return
				}
				if !transient(ended) {
					yield(nil, ended)
					return
				}
				failures++
				if failures >= s.opts.Tries {
					yield(nil, ended)
					return
				}
			}
			// The stream ended (or failed): wait retry at least, and back off while connecting fails.
			var floor time.Duration
			var perr *lantern.ProblemError
			if errors.As(ended, &perr) && errors.Is(ended, lantern.ErrSlowDown) {
				floor = time.Duration(perr.RetryAfter) * time.Second
			}
			wait = max(s.Retry(), floor)
			if failures > 0 {
				wait = max(wait, time.Duration(lantern.Backoff(failures, 0)*float64(time.Second)))
			}
			if s.opts.OnReconnect != nil {
				s.opts.OnReconnect(ended, wait)
			}
		}
	}
}

// once reads one connection: its error (nil when it ended cleanly), and whether the loop is over.
func (s *EventStream) once(ctx context.Context, yield func(*lantern.ServerEvent, error) bool, failures *int) (ended error, stop bool) {
	headers := http.Header{"Accept": {"text/event-stream"}, "Accept-Encoding": {"identity"}}
	if id := s.LastID(); id != "" {
		headers.Set("Last-Event-ID", id)
	}
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	resp, err := s.c.open(connCtx, &call{method: http.MethodGet, path: "/events", headers: headers, what: "events"}, "text/event-stream")
	if err != nil {
		return err, false
	}
	defer resp.Body.Close()
	*failures = 0
	s.mu.Lock()
	s.stopping = false
	s.mu.Unlock()

	idle := 60 * time.Second // twice the default heartbeat
	if h := s.c.Hello(); h != nil && h.Limits != nil && h.Limits.Heartbeat != nil && *h.Limits.Heartbeat > 0 {
		idle = time.Duration(*h.Limits.Heartbeat) * 2 * time.Second
	}
	watchdog := time.AfterFunc(idle, cancel)
	defer watchdog.Stop()

	parser := &lantern.SSEParser{}
	buf := make([]byte, 8<<10)
	for {
		n, readErr := resp.Body.Read(buf)
		watchdog.Reset(idle)
		var refused error
		var blocks []lantern.SSEBlock
		if n > 0 {
			// What came before a bound passed is given; then the stream is refused.
			blocks, refused = parser.Push(buf[:n])
		}
		for _, block := range blocks {
			if block.HasRetry {
				s.mu.Lock()
				s.retry = time.Duration(block.Retry) * time.Millisecond
				s.mu.Unlock()
			}
			ev, err := lantern.ReadEvent(block)
			if err != nil {
				return err, false
			}
			if id := parser.LastEventID; id != "" {
				s.mu.Lock()
				s.lastID = id
				s.mu.Unlock()
			}
			if ev == nil {
				continue
			}
			if ev.Event == "shutdown" {
				s.mu.Lock()
				s.stopping = true
				if secs, ok := ev.Data["retry"].(interface{ Float64() (float64, error) }); ok {
					if f, err := secs.Float64(); err == nil && f > 0 {
						s.retry = max(s.retry, time.Duration(f*float64(time.Second)))
					}
				}
				s.mu.Unlock()
			}
			if !yield(ev, nil) {
				return nil, true
			}
			if ctx.Err() != nil {
				yield(nil, ctx.Err())
				return nil, true
			}
			if s.ServerStopping() {
				return nil, false
			}
		}
		if refused != nil {
			return refused, false
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil, false
			}
			if ctx.Err() == nil && connCtx.Err() != nil {
				readErr = errors.New("nothing came for twice limits.heartbeat")
			}
			return fmt.Errorf("%w: events: %w", lantern.ErrTransport, readErr), false
		}
	}
}

// PollEvents is long polling (SPEC.md § 18.3), for a client that cannot keep a stream open: the
// events after a token (Changes.Events, `ready` and `shutdown` excepted), answered as soon as one
// the caller may see comes, or once wait has passed (a wait above limits.wait is lowered by the
// server). Changes.Since resumes after the last of them: ask again at once with it, and wait
// (Annex B.2) only after an error. An id too old is lantern.ErrGone, as for Changes.
func (c *Client) PollEvents(ctx context.Context, since string, wait time.Duration) (*lantern.Changes, error) {
	if since == "" {
		return nil, errors.New("lantern: a long poll resumes from a token: read Changes first")
	}
	if wait < 0 {
		return nil, errors.New("lantern: a wait is not negative")
	}
	secs := int(wait / time.Second)
	q := url.Values{"since": {since}, "wait": {strconv.Itoa(secs)}}
	k := &call{method: http.MethodGet, path: "/changes", query: q, what: "events", timeout: wait + c.timeout}
	resp, err := c.send(ctx, k, lantern.MaxJSONDocument)
	if err != nil {
		return nil, err
	}
	if err := c.expect(resp, "events", http.StatusOK); err != nil {
		return nil, err
	}
	return read[lantern.Changes](c, "events", resp)
}
