// SPDX-License-Identifier: MIT

package discovery_test

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/JigSawFr/lantern-sdk/go/discovery"
)

const peerReply = `{"schema":1,"lantern":"peer","uid":"p1","name":"Lea's Switch","port":47116,"base":"/lantern","tls":false,"slots":2,"servers":["s1","s2"]}`

func TestReadPeerReply(t *testing.T) {
	p := discovery.ReadPeerReply([]byte(peerReply), "192.168.1.30")
	if p == nil || p.URL != "http://192.168.1.30:47116/lantern" || p.Slots != 2 || len(p.Servers) != 2 || p.Name != "Lea's Switch" {
		t.Fatalf("%+v", p)
	}
	bad := map[string]string{
		"a server's":        strings.Replace(peerReply, `"peer"`, `"server"`, 1),
		"newer schema":      strings.Replace(peerReply, `"schema":1`, `"schema":2`, 1),
		"no slots":          strings.Replace(peerReply, `"slots":2`, `"slots":0`, 1),
		"nine slots":        strings.Replace(peerReply, `"slots":2`, `"slots":9`, 1),
		"port 0":            strings.Replace(peerReply, `47116`, `0`, 1),
		"a base with ?":     strings.Replace(peerReply, `/lantern`, `/l?x`, 1),
		"servers not text":  strings.Replace(peerReply, `["s1","s2"]`, `[1]`, 1),
		"tls not a boolean": strings.Replace(peerReply, `"tls":false`, `"tls":"no"`, 1),
		"not JSON":          "peer",
		"too long":          peerReply[:len(peerReply)-1] + strings.Repeat(" ", 1300) + "}",
	}
	for name, doc := range bad {
		if discovery.ReadPeerReply([]byte(doc), "192.168.1.30") != nil {
			t.Errorf("%s was read", name)
		}
	}
	// plain HTTP from a public address: a grant never goes there (L-19.4-6)
	if discovery.ReadPeerReply([]byte(peerReply), "8.8.8.8") != nil {
		t.Error("a peer at a public address over plain HTTP")
	}
	if discovery.ReadPeerReply([]byte(strings.Replace(peerReply, `"tls":false`, `"tls":true`, 1)), "8.8.8.8") == nil {
		t.Error("a peer over HTTPS")
	}
}

func TestPeerFromTXT(t *testing.T) {
	p := discovery.PeerFromTXT("10.0.0.7", 47116, map[string]string{"servers": "s1,s2", "path": "/lantern", "v": "1", "tls": "0"}, "Console")
	if p == nil || p.URL != "http://10.0.0.7:47116/lantern" || len(p.Servers) != 2 || p.TLS {
		t.Fatalf("%+v", p)
	}
	for _, txt := range []map[string]string{
		{"servers": "s1", "path": "/lantern", "v": "1"},
		{"servers": "s1", "path": "/lantern", "v": "x", "tls": "0"},
		{"servers": "s1", "path": "lantern", "v": "1", "tls": "0"},
	} {
		if discovery.PeerFromTXT("10.0.0.7", 47116, txt, "n") != nil {
			t.Errorf("%v", txt)
		}
	}
}

func TestDiscoverPeersAsksForPeersAndKeepsTheOnesOfAServer(t *testing.T) {
	responder, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("no UDP on loopback")
	}
	defer responder.Close()
	port := responder.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 2048)
		n, from, err := responder.ReadFrom(buf)
		if err != nil || string(buf[:n]) != string(discovery.PeersRequest) {
			return
		}
		other := strings.Replace(strings.Replace(peerReply, `"p1"`, `"p2"`, 1), `["s1","s2"]`, `["s9"]`, 1)
		for _, r := range []string{`{"schema":1,"lantern":"server","uid":"u","name":"n","base":"/api","port":8443,"versions":[1]}`, peerReply, peerReply, other} {
			_, _ = responder.WriteTo([]byte(r), from)
		}
	}()
	peers, err := discovery.DiscoverPeers(t.Context(), []string{"127.0.0.1"}, discovery.Options{Port: port, Timeout: 500 * time.Millisecond})
	if err != nil || len(peers) != 2 {
		t.Fatalf("%+v %v", peers, err)
	}
	if got := discovery.PeersOf(peers, "s1"); len(got) != 1 || got[0].UID != "p1" {
		t.Fatalf("%+v", got)
	}
}

func FuzzReadPeerReply(f *testing.F) {
	f.Add([]byte(peerReply))
	f.Fuzz(func(t *testing.T, data []byte) {
		if p := discovery.ReadPeerReply(data, "10.0.0.1"); p != nil && (p.Port < 1 || p.Port > 65535 || p.Slots < 1 || p.Slots > 8 || !strings.HasPrefix(p.URL, "http")) {
			t.Fatalf("%+v", p)
		}
	})
}
