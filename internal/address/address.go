// Package address parses where to reach a peer: host, port and optionally the
// peer ID that must answer there.
package address

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/samaasi/lazy-chat/internal/identity"
)

// DefaultPort is the TCP port assumed when an address names none.
const DefaultPort = 8080

// Target is where to connect when discovery cannot help: an address, and
// optionally the peer ID that must answer there.
type Target struct {
	ID   string // empty: accept whoever proves a valid identity
	Host string
	Port int
}

// String renders the target as accepted by Parse.
func (t Target) String() string {
	hp := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	if t.ID != "" {
		return t.ID + "@" + hp
	}
	return hp
}

// Parse reads "host", "host:port", "[v6]:port" or any of those prefixed
// with "<peer id>@". A missing port means DefaultPort.
func Parse(s string) (Target, error) {
	var t Target
	s = strings.TrimSpace(s)
	if s == "" {
		return t, errors.New("empty address")
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return t, errors.New("an address cannot contain spaces or control characters")
		}
	}
	if id, rest, ok := strings.Cut(s, "@"); ok {
		id = strings.ToLower(id)
		if !identity.ValidID(id) {
			return t, fmt.Errorf("%q is not a valid peer ID (32 hex characters)", id)
		}
		t.ID, s = id, rest
	}

	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		// No port (or a bare IPv6 address): use the default one.
		host, portStr = strings.Trim(s, "[]"), strconv.Itoa(DefaultPort)
	}
	if host == "" {
		return t, errors.New("missing host")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return t, fmt.Errorf("invalid port %q", portStr)
	}
	if ip := net.ParseIP(host); ip == nil && !validHostname(host) {
		return t, fmt.Errorf("invalid host %q", host)
	}
	t.Host, t.Port = host, port
	return t, nil
}

func validHostname(h string) bool {
	if len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// LooksLikeAddress reports whether s is more likely an address than a peer
// name or ID prefix: it has an "@" or ":" or is an IP address or dotted host name.
func LooksLikeAddress(s string) bool {
	s = strings.TrimSpace(s)
	return strings.ContainsAny(s, "@:") || net.ParseIP(s) != nil || strings.Contains(s, ".")
}
