// SPDX-License-Identifier: MIT

package client_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/client"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

// hostile is a scenario of python/tools/hostile_server.py: a server that breaks one rule a
// client relies on. The tests of this file say what the client must do about it.
type hostile struct {
	URL    string `json:"url"`
	Token  string `json:"token"`
	Expect string `json:"expect"`
}

func startHostile(t *testing.T, scenario string) *hostile {
	t.Helper()
	python := os.Getenv("LANTERN_PYTHON")
	if python == "" {
		t.Skip("LANTERN_PYTHON is not set: no hostile server to start")
	}
	tool := filepath.Join(testutil.SpecDir(t), "..", "python", "tools", "hostile_server.py")
	cmd := exec.Command(python, tool, scenario)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(out).ReadString('\n')
		line <- s
	}()
	var h hostile
	select {
	case s := <-line:
		if err := json.Unmarshal([]byte(s), &h); err != nil {
			t.Fatalf("the hostile server said %q: %v", s, err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the hostile server is not ready")
	}
	return &h
}

func TestReferenceHostileEvents(t *testing.T) {
	h := startHostile(t, "oversized-event")
	c, err := client.New(h.URL, client.Options{Token: h.Token, Base: "/api/lantern", Platform: "switch"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var events int
	var failure error
	for _, err := range c.Events(client.EventOptions{}).All(ctx) {
		if err != nil {
			failure = err
			break
		}
		events++
	}
	var de *lantern.DocumentError
	if events != 1 || !errors.As(failure, &de) {
		t.Fatalf("%d events, then %v: %s", events, failure, h.Expect)
	}
}
