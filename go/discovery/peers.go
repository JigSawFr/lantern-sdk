// SPDX-License-Identifier: MIT

package discovery

import (
	"context"
	"strconv"
	"strings"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

// PeersRequest is the datagram that also asks the peers of the network (SPEC.md § 19.5). A peer
// answers only such a datagram, unicast. A client looks for peers at most once a minute and reads
// a file from at most 2 peers at once (L-19.5-2).
var PeersRequest = []byte(`{"schema":1,"lantern":"discover","peers":true}`)

// PeerServiceType is the DNS-SD service type of peers (SPEC.md § 19.5).
const PeerServiceType = "_lantern-peer._tcp"

// ReadPeerReply reads a peer's reply (SPEC.md § 19.5), or nil when it is not one this library
// reads: above 1200 bytes, not UTF-8 JSON, of a newer schema, not a peer's, with a field not of
// its form, or plain HTTP from an address outside a private network (a grant never goes there,
// L-19.4-6). A hint, as any reply.
func ReadPeerReply(data []byte, address string) *lantern.Peer {
	if len(data) > lantern.MaxDatagram {
		return nil
	}
	doc, err := lantern.LoadJSON(data, lantern.LoadOptions{Limit: lantern.MaxDatagram, Where: "peer reply"})
	if err != nil {
		return nil
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil
	}
	schema, ok := integer(obj["schema"])
	if !ok || schema < 1 || schema > lantern.Schema {
		return nil
	}
	uid, okUID := obj["uid"].(string)
	name, okName := obj["name"].(string)
	base, _ := obj["base"].(string)
	tls, okTLS := obj["tls"].(bool)
	port, okPort := integer(obj["port"])
	slots, okSlots := integer(obj["slots"])
	list, okList := obj["servers"].([]any)
	if obj["lantern"] != "peer" || !okUID || len(uid) < 1 || len(uid) > 64 || !okName || !baseOK(base) || !okTLS ||
		!okPort || port < 1 || port > 65535 || !okSlots || slots < 1 || slots > 8 || !okList || len(list) > 16 {
		return nil
	}
	servers := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok || len(s) > 64 {
			return nil
		}
		servers = append(servers, s)
	}
	return peer(address, int(port), base, tls, uid, name, int(slots), servers)
}

func peer(address string, port int, base string, tls bool, uid, name string, slots int, servers []string) *lantern.Peer {
	url, err := lantern.PeerURL(address, port, base, tls)
	if err != nil {
		return nil
	}
	return &lantern.Peer{
		Address: address, Port: port, Base: base, TLS: tls, UID: uid, Slots: slots, Servers: servers, URL: url,
		Name: strings.ReplaceAll(lantern.Printable(name, lantern.MaxName), "\n", " "),
	}
}

// PeerFromTXT reads a peer's DNS-SD advertisement (SPEC.md § 19.5: `servers=`, `path=`, `v=1`,
// `tls=0|1`), or nil when it is not one this library reads. A peer's slots are not advertised: one
// is assumed. txt maps the record's keys to their values; name is the instance's.
func PeerFromTXT(address string, port int, txt map[string]string, name string) *lantern.Peer {
	servers, path := txt["servers"], txt["path"]
	if v, err := strconv.Atoi(txt["v"]); err != nil || v < 1 || !baseOK(path) || port < 1 || port > 65535 {
		return nil
	}
	if txt["tls"] != "0" && txt["tls"] != "1" {
		return nil
	}
	var list []string
	for _, s := range strings.Split(servers, ",") {
		if s != "" {
			if len(s) > 64 || len(list) == 16 {
				return nil
			}
			list = append(list, s)
		}
	}
	return peer(address, port, path, txt["tls"] == "1", "", name, 1, list)
}

// DiscoverPeers sends the datagram that asks for peers to each of addresses and gathers their
// replies for Timeout; each peer once, by uid and address. Keep the peers whose Servers hold the
// uid of the server the files come from.
func DiscoverPeers(ctx context.Context, addresses []string, opts Options) ([]lantern.Peer, error) {
	return gather(ctx, addresses, opts, PeersRequest, ReadPeerReply, func(p lantern.Peer) [2]string { return [2]string{p.UID, p.Address} })
}

// PeersOf are the peers that take a server's grants (SPEC.md § 19.5): those whose servers hold uid.
func PeersOf(peers []lantern.Peer, uid string) []lantern.Peer {
	var out []lantern.Peer
	for _, p := range peers {
		for _, s := range p.Servers {
			if s == uid {
				out = append(out, p)
				break
			}
		}
	}
	return out
}
