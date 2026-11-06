// SPDX-License-Identifier: MIT

package discovery_test

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/JigSawFr/lantern-sdk/go/discovery"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

func TestReadReply(t *testing.T) {
	f := discovery.ReadReply(testutil.Read(t, "examples", "v1", "discovery.json"), "192.168.1.20")
	if f == nil || f.Address != "192.168.1.20" || f.Port == 0 || f.UID == "" || f.Name == "" || f.Base == "" || len(f.Versions) == 0 {
		t.Fatalf("%+v", f)
	}
	if got := f.URL(); !strings.HasPrefix(got, "https://192.168.1.20") {
		t.Errorf("url %s", got)
	}
	v6 := discovery.Found{Address: "fe80::1", Port: 443}
	if v6.URL() != "https://[fe80::1]/" {
		t.Errorf("url %s", v6.URL())
	}
}

func TestReadReplyRefuses(t *testing.T) {
	ok := `{"schema":1,"lantern":"server","uid":"u","name":"n","base":"/api","port":8443,"versions":[1]}`
	if discovery.ReadReply([]byte(ok), "10.0.0.1") == nil {
		t.Fatal("a good reply is refused")
	}
	for name, bad := range map[string]string{
		"newer schema": strings.Replace(ok, `"schema":1`, `"schema":2`, 1),
		"not a server": strings.Replace(ok, `"server"`, `"peer"`, 1),
		"no uid":       strings.Replace(ok, `"uid":"u",`, ``, 1),
		"port 0":       strings.Replace(ok, `8443`, `0`, 1),
		"port float":   strings.Replace(ok, `8443`, `8443.0`, 1),
		"base //":      strings.Replace(ok, `"/api"`, `"//evil"`, 1),
		"base space":   strings.Replace(ok, `"/api"`, `"/a b"`, 1),
		"no versions":  strings.Replace(ok, `[1]`, `[]`, 1),
		"version 0":    strings.Replace(ok, `[1]`, `[0]`, 1),
		"not json":     `{`,
		"array":        `[]`,
		"too long":     strings.Replace(ok, `"n"`, `"`+strings.Repeat("x", 1300)+`"`, 1),
		"dup key":      strings.Replace(ok, `"port"`, `"uid":"v","port"`, 1),
	} {
		if discovery.ReadReply([]byte(bad), "10.0.0.1") != nil {
			t.Errorf("%s: taken", name)
		}
	}
	// a field a later version adds is skipped
	if discovery.ReadReply([]byte(strings.Replace(ok, `"port"`, `"extra":{"a":1},"port"`, 1)), "10.0.0.1") == nil {
		t.Error("an unknown field is refused")
	}
}

func TestFromTXT(t *testing.T) {
	f := discovery.FromTXT("10.0.0.2", 8443, map[string]string{"uid": "u", "path": "/api/lantern", "v": "1,2"}, "Shelf")
	if f == nil || f.Base != "/api/lantern" || len(f.Versions) != 2 || f.Name != "Shelf" {
		t.Fatalf("%+v", f)
	}
	for _, txt := range []map[string]string{
		{"path": "/a", "v": "1"}, {"uid": "u", "path": "a", "v": "1"}, {"uid": "u", "path": "/a", "v": "x"}, {"uid": "u", "path": "/a", "v": "0"}, {"uid": "u", "path": "/a"},
	} {
		if discovery.FromTXT("10.0.0.2", 8443, txt, "n") != nil {
			t.Errorf("%v is taken", txt)
		}
	}
	if discovery.FromTXT("10.0.0.2", 0, map[string]string{"uid": "u", "path": "/a", "v": "1"}, "n") != nil {
		t.Error("port 0")
	}
}

func TestDirectedBroadcast(t *testing.T) {
	if got, err := discovery.DirectedBroadcast("192.168.1.20", 24); err != nil || got != "192.168.1.255" {
		t.Fatalf("%s %v", got, err)
	}
	if got, _ := discovery.DirectedBroadcast("10.1.2.3", 16); got != "10.1.255.255" {
		t.Fatal(got)
	}
	if _, err := discovery.DirectedBroadcast("nope", 24); err == nil {
		t.Fatal("not an address")
	}
}

func TestDiscover(t *testing.T) {
	responder, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("no UDP on loopback")
	}
	defer responder.Close()
	port := responder.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 2048)
		n, from, err := responder.ReadFrom(buf)
		if err != nil || string(buf[:n]) != string(discovery.Request) {
			return
		}
		reply := `{"schema":1,"lantern":"server","uid":"u","name":"Shelf","base":"/api","port":8443,"versions":[1]}`
		_, _ = responder.WriteTo([]byte("garbage"), from)
		_, _ = responder.WriteTo([]byte(reply), from)
		_, _ = responder.WriteTo([]byte(reply), from) // twice: found once
	}()
	found, err := discovery.Discover(t.Context(), []string{"127.0.0.1"}, discovery.Options{Port: port, Timeout: 500 * time.Millisecond})
	if err != nil || len(found) != 1 || found[0].Name != "Shelf" || found[0].Address != "127.0.0.1" {
		t.Fatalf("%+v %v", found, err)
	}
	if a := discovery.Addresses(append(found, found...)); len(a) != 1 {
		t.Fatalf("%v", a)
	}
}

func FuzzReadReply(f *testing.F) {
	f.Add([]byte(`{"schema":1,"lantern":"server","uid":"u","name":"n","base":"/api","port":8443,"versions":[1]}`))
	f.Add([]byte(`{"schema":1,"port":1e3}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if found := discovery.ReadReply(data, "10.0.0.1"); found != nil && (found.Port < 1 || found.Port > 65535 || len(found.Versions) == 0 || strings.ContainsAny(found.Base, "?# ")) {
			t.Fatalf("%+v", found)
		}
	})
}
