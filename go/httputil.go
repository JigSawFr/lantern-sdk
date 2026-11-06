// SPDX-License-Identifier: MIT

package lantern

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Origin is an absolute http(s) URL's scheme, host (lower case) and port, the port made explicit.
type Origin struct {
	Scheme, Host string
	Port         int
}

// OriginOf is the origin of an absolute http(s) URL.
func OriginOf(raw string) (Origin, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Origin{}, fmt.Errorf("%q is not an absolute http(s) URL", Clip(raw, 100))
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Hostname() == "" {
		return Origin{}, fmt.Errorf("%q is not an absolute http(s) URL", Clip(raw, 100))
	}
	port := 80
	if scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Origin{}, fmt.Errorf("%q is not an absolute http(s) URL", Clip(raw, 100))
		}
		port = n
	}
	return Origin{scheme, strings.ToLower(u.Hostname()), port}, nil
}

// IsLoopback reports whether host is 127.0.0.0/8, ::1 or localhost: where plain HTTP is allowed,
// for testing (SPEC.md § 2).
func IsLoopback(host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// PlainHTTPAllowed reports whether raw may be spoken to: HTTPS, or plain HTTP to a loopback
// address. An error when it is not an absolute http(s) URL.
func PlainHTTPAllowed(raw string) (bool, error) {
	o, err := OriginOf(raw)
	if err != nil {
		return false, err
	}
	return o.Scheme == "https" || IsLoopback(o.Host), nil
}
