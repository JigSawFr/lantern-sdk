// SPDX-License-Identifier: MIT

package lantern_test

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	lantern "github.com/JigSawFr/lantern-sdk/go"
	"github.com/JigSawFr/lantern-sdk/go/internal/testutil"
)

func TestGrantVectors(t *testing.T) {
	var v struct {
		Key struct {
			Seed      string `json:"seed"`
			PublicKey string `json:"public_key"`
		} `json:"key"`
		Payload string `json:"payload"`
		Grant   string `json:"grant"`
		Cases   []struct {
			Name       string            `json:"name"`
			Grant      string            `json:"grant"`
			PathSHA256 string            `json:"path_sha256"`
			PeerTime   int64             `json:"peer_time"`
			Servers    map[string]string `json:"servers"`
			Serves     bool              `json:"serves"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(testutil.Read(t, "vectors", "grants.json"), &v); err != nil {
		t.Fatal(err)
	}
	// the grant is the payload signed by the key, byte for byte
	c := lantern.GrantContents(v.Grant)
	if c == nil {
		t.Fatal("the grant of the vectors is not read")
	}
	signed, err := lantern.SignGrant(ed25519.NewKeyFromSeed(unhex(t, v.Key.Seed)), c.UID, c.SHA256, c.Size, c.Exp)
	if err != nil || signed != v.Grant {
		t.Fatalf("%v\n%s\n%s", err, signed, v.Grant)
	}
	if p, _ := lantern.MakeGrantPayload(c.UID, c.SHA256, c.Size, c.Exp); string(p) != v.Payload {
		t.Fatalf("%s", p)
	}
	for _, k := range v.Cases {
		// what a peer decides (SPEC.md § 19.4): it verifies, and names the file of the path
		got := lantern.VerifyGrant(k.Grant, k.Servers, k.PeerTime)
		serves := got != nil && got.SHA256 == k.PathSHA256
		if serves != k.Serves {
			t.Errorf("%s: serves %v, want %v", k.Name, serves, k.Serves)
		}
	}
}

func TestPrivateAddressesAndMirrors(t *testing.T) {
	private := []string{"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.20", "fc00::1", "fd12::1", "fe80::1", "[fe80::1]", "fe80::1%eth0", "::ffff:192.168.1.2"}
	public := []string{"8.8.8.8", "172.32.0.1", "172.15.0.1", "192.169.0.1", "11.0.0.1", "2001:db8::1", "fec0::1", "example.org", "", "127.0.0.1"}
	for _, h := range private {
		if !lantern.IsPrivateAddress(h) {
			t.Errorf("%q is private", h)
		}
	}
	for _, h := range public {
		if lantern.IsPrivateAddress(h) {
			t.Errorf("%q is not private", h)
		}
	}
	if !lantern.PlainHTTPToPeer("127.0.0.1") || !lantern.PlainHTTPToPeer("::1") || lantern.PlainHTTPToPeer("8.8.8.8") {
		t.Error("plain HTTP goes to private networks and loopback only")
	}
	ok := []string{"https://mirror.example.org/f.nsz", "http://192.168.1.5:8080/f", "http://127.0.0.1/f", "http://[fd00::1]/f"}
	bad := []string{"http://mirror.example.org/f", "http://8.8.8.8/f", "ftp://192.168.1.5/f", "https://user:pw@mirror.example.org/f", "https://mirror.example.org/f#x", "/relative", "https:///f"}
	for _, u := range ok {
		if !lantern.MirrorAllowed(u) {
			t.Errorf("%q is allowed", u)
		}
	}
	for _, u := range bad {
		if lantern.MirrorAllowed(u) {
			t.Errorf("%q is refused", u)
		}
	}
	var many []lantern.Mirror
	for i := 0; i < 12; i++ {
		many = append(many, lantern.Mirror{URL: "https://m.example.org/f"})
	}
	many[1].URL = "http://8.8.8.8/f"
	if got := lantern.UsableMirrors(many); len(got) != 7 {
		t.Errorf("%d mirrors usable of the first 8", len(got))
	}
}

func TestPeerAddresses(t *testing.T) {
	u, err := lantern.PeerURL("192.168.1.9", 47116, "/lantern/", false)
	if err != nil || u != "http://192.168.1.9:47116/lantern" {
		t.Fatalf("%q %v", u, err)
	}
	if u, _ := lantern.PeerURL("fe80::1", 1, "/l", true); u != "https://[fe80::1]:1/l" {
		t.Errorf("%q", u)
	}
	if _, err := lantern.PeerURL("8.8.8.8", 1, "/l", false); err == nil {
		t.Error("a grant went over plain HTTP to a public address")
	}
	sha := "3a7bd3e2b4c1f0a9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a392817"
	if b, err := lantern.BlobURL(u+"/", sha); err != nil || b != u+"/v1/blobs/sha256/"+sha {
		t.Errorf("%q %v", b, err)
	}
	if _, err := lantern.BlobURL(u, "ABC"); err == nil {
		t.Error("a short hash")
	}
}
