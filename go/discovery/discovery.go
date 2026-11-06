// SPDX-License-Identifier: MIT

// Package discovery finds Lantern servers on the local network (SPEC.md § 4.1): the datagram a
// client sends on UDP 47115 and the replies it reads, and the TXT record of a DNS-SD
// (`_lantern._tcp`) advertisement, which the application's own mDNS library browses.
//
//	found, err := discovery.Discover(ctx, []string{"192.168.1.255"}, discovery.Options{})
//	for _, f := range found { fmt.Println(f.Name, f.URL()) } // then the handshake, over TLS
//
// Discovery is a hint: it gives an address and a name, nothing more. A reply proves nothing; the
// client trusts a server only through TLS and pairing (SPEC.md § 5, L-4.1-5). A reply is read by
// the schema rule: one of a newer schema is absent, and a reply this library cannot read is left
// out.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	lantern "github.com/JigSawFr/lantern-sdk/go"
)

// Port is the UDP port of discovery.
const Port = 47115

// Request is the datagram a client sends (SPEC.md § 4.1).
var Request = []byte(`{"schema":1,"lantern":"discover"}`)

// ServiceType is the DNS-SD service type of servers (RFC 6763).
const ServiceType = "_lantern._tcp"

// Found is a server that answered: the reply's source Address, its HTTPS Port, its UID, Name, Base
// and Versions (the handshake's, unchecked until the client reads it).
type Found struct {
	Address  string
	Port     int
	UID      string
	Name     string
	Base     string
	Versions []int
}

// URL is the server's origin, to hand to the client.
func (f Found) URL() string {
	host := f.Address
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if f.Port == 443 {
		return "https://" + host + "/"
	}
	return "https://" + host + ":" + strconv.Itoa(f.Port) + "/"
}

// DirectedBroadcast is the broadcast address of address's network (`192.168.1.255` for
// `192.168.1.20`/24): where a client sends the datagram, since some consoles drop 255.255.255.255.
func DirectedBroadcast(address string, prefix int) (string, error) {
	ip := net.ParseIP(address).To4()
	if ip == nil || prefix < 0 || prefix > 32 {
		return "", fmt.Errorf("%q/%d is not an IPv4 network", address, prefix)
	}
	mask := net.CIDRMask(prefix, 32)
	out := make(net.IP, 4)
	for i := range ip {
		out[i] = ip[i] | ^mask[i]
	}
	return out.String(), nil
}

func baseOK(base string) bool {
	if !strings.HasPrefix(base, "/") || strings.HasPrefix(base, "//") || len(base) > 256 || strings.ContainsAny(base, "?#\\ ") {
		return false
	}
	for _, c := range []byte(base) {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	return true
}

func integer(v any) (int64, bool) {
	n, ok := v.(interface{ Int64() (int64, error) })
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil {
		return 0, false
	}
	if s, ok := v.(fmt.Stringer); ok && strings.ContainsAny(s.String(), ".eE") {
		return 0, false
	}
	return i, true
}

// ReadReply reads a server's reply (SPEC.md § 4.1), or nil when it is not one this library reads:
// above 1200 bytes, not UTF-8 JSON, of a newer schema, not a server's, or with a field not of its
// form.
func ReadReply(data []byte, address string) *Found {
	if len(data) > lantern.MaxDatagram {
		return nil
	}
	doc, err := lantern.LoadJSON(data, lantern.LoadOptions{Limit: lantern.MaxDatagram, Where: "discovery reply"})
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
	uid, _ := obj["uid"].(string)
	name, okName := obj["name"].(string)
	base, _ := obj["base"].(string)
	port, okPort := integer(obj["port"])
	versions, okVersions := obj["versions"].([]any)
	if obj["lantern"] != "server" || len(uid) < 1 || len(uid) > 64 || !okName || !baseOK(base) ||
		!okPort || port < 1 || port > 65535 || !okVersions || len(versions) == 0 {
		return nil
	}
	found := &Found{
		Address: address, Port: int(port), UID: uid, Base: base,
		Name: strings.ReplaceAll(lantern.Printable(name, lantern.MaxName), "\n", " "),
	}
	for _, v := range versions {
		n, ok := integer(v)
		if !ok || n < 1 {
			return nil
		}
		found.Versions = append(found.Versions, int(n))
	}
	return found
}

// FromTXT reads a DNS-SD advertisement (SPEC.md § 4.1: `uid=`, `path=`, `v=`), or nil when it is
// not one this library reads. txt maps the record's keys to their values; name is the instance's.
func FromTXT(address string, port int, txt map[string]string, name string) *Found {
	uid, path, versions := txt["uid"], txt["path"], txt["v"]
	if uid == "" || !baseOK(path) || versions == "" || port < 1 || port > 65535 {
		return nil
	}
	found := &Found{
		Address: address, Port: port, UID: uid, Base: path,
		Name: strings.ReplaceAll(lantern.Printable(name, lantern.MaxName), "\n", " "),
	}
	for _, v := range strings.Split(versions, ",") {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return nil
		}
		found.Versions = append(found.Versions, n)
	}
	return found
}

// Options of Discover.
type Options struct {
	Port    int           // Port when 0
	Timeout time.Duration // how long it listens: two seconds when 0
	// Conn is the socket to use, when the application brings its own (for a given interface, or a
	// test); Discover makes one otherwise, and closes only that one.
	Conn net.PacketConn
}

// Discover sends the discovery datagram to each of addresses (directed broadcasts, or a server's
// own address) and gathers the replies for Timeout; each server once, by uid and address.
func Discover(ctx context.Context, addresses []string, opts Options) ([]Found, error) {
	return gather(ctx, addresses, opts, Request, ReadReply, func(f Found) [2]string { return [2]string{f.UID, f.Address} })
}

// gather sends a datagram to each address and reads the replies for the time asked, with read:
// each answerer once, by key.
func gather[T any](ctx context.Context, addresses []string, opts Options, request []byte,
	read func(data []byte, address string) *T, key func(T) [2]string) ([]T, error) {
	if opts.Port == 0 {
		opts.Port = Port
	}
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Second
	}
	conn := opts.Conn
	if conn == nil {
		var err error
		if conn, err = net.ListenPacket("udp4", ":0"); err != nil {
			return nil, err
		}
		defer conn.Close()
	}
	for _, a := range addresses {
		dest, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(a, strconv.Itoa(opts.Port)))
		if err != nil {
			return nil, err
		}
		if _, err := conn.WriteTo(request, dest); err != nil {
			return nil, err
		}
	}
	deadline := time.Now().Add(opts.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	_ = conn.SetReadDeadline(deadline)

	var found []T
	seen := map[[2]string]bool{}
	buf := make([]byte, lantern.MaxDatagram+1)
	for {
		n, source, err := conn.ReadFrom(buf)
		if err != nil {
			var timeout interface{ Timeout() bool }
			if errors.As(err, &timeout) && timeout.Timeout() || errors.Is(err, net.ErrClosed) {
				break
			}
			return found, err
		}
		host, _, _ := net.SplitHostPort(source.String())
		if f := read(buf[:n], host); f != nil && !seen[key(*f)] {
			seen[key(*f)] = true
			found = append(found, *f)
		}
	}
	return found, ctx.Err()
}

// Addresses lists the addresses of the servers found, each once, in order.
func Addresses(found []Found) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range found {
		if !seen[f.Address] {
			seen[f.Address] = true
			out = append(out, f.Address)
		}
	}
	return out
}
