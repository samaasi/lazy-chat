package address

import (
	"strings"
	"testing"
)

const someID = "0123456789abcdef0123456789abcdef"

func TestParse(t *testing.T) {
	good := map[string]Target{
		"192.168.1.20":                    {Host: "192.168.1.20", Port: DefaultPort},
		"192.168.1.20:9000":               {Host: "192.168.1.20", Port: 9000},
		"bob-laptop":                      {Host: "bob-laptop", Port: DefaultPort},
		"bob-laptop.local:8081":           {Host: "bob-laptop.local", Port: 8081},
		"[::1]:8080":                      {Host: "::1", Port: 8080},
		"::1":                             {Host: "::1", Port: DefaultPort},
		"[fe80::1]":                       {Host: "fe80::1", Port: DefaultPort},
		someID + "@10.0.0.5:7000":         {ID: someID, Host: "10.0.0.5", Port: 7000},
		strings.ToUpper(someID) + "@host": {ID: someID, Host: "host", Port: DefaultPort},
		"  10.0.0.5:1  ":                  {Host: "10.0.0.5", Port: 1},
		"10.0.0.5:65535":                  {Host: "10.0.0.5", Port: 65535},
	}
	for in, want := range good {
		got, err := Parse(in)
		if err != nil || got != want {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", in, got, err, want)
		}
		// Round trip.
		if again, err := Parse(got.String()); err != nil || again != got {
			t.Errorf("round trip of %q: %+v %v", in, again, err)
		}
	}
	bad := []string{
		"", "   ", "@host", "nothex@host", someID + "@", ":8080", "host:0", "host:65536", "host:-1", "host:abc",
		"host name", "host\x1b[2J", "bad_host!", "-bad.example", "a..b", strings.Repeat("a", 64) + ".example",
		"host:8080:9", someID + "@" + someID + "@host",
	}
	for _, in := range bad {
		if got, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) accepted: %+v", in, got)
		}
	}
}

func TestLooksLikeAddress(t *testing.T) {
	for in, want := range map[string]bool{
		"bob": false, "d033": false, "Alice Smith": false, someID: false,
		"192.168.1.5": true, "host:8080": true, someID + "@host": true, "bob.local": true, "::1": true, "[::1]:80": true,
	} {
		if got := LooksLikeAddress(in); got != want {
			t.Errorf("LooksLikeAddress(%q) = %v", in, got)
		}
	}
}
