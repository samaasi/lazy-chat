package utils

import (
	"strings"
	"testing"
	"time"
)

func TestSanitizeTextStripsTerminalControl(t *testing.T) {
	cases := map[string]string{
		"plain":                     "plain",
		"line1\nline2\r\nline3":     "line1 line2  line3",
		"tab\there":                 "tab here",
		"\x1b[2J\x1b[31mred\x1b[0m": "[2J[31mred[0m", // ESC removed, text kept but inert
		"\x07bell\x00nul":           "bellnul",
		"rtl\u202Eevil":             "rtlevil",
		"iso\u2066late\u2069d":      "isolated",
		"bad\xffutf8":               "bad\uFFFDutf8",
		"emoji 👩‍👩‍👧 ok":            "emoji 👩‍👩‍👧 ok",
		"sep\u2028arator":           "sep arator",
		"":                          "",
	}
	for in, want := range cases {
		if got := SanitizeText(in, 0); got != want {
			t.Errorf("SanitizeText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeTextTruncatesOnRuneBoundary(t *testing.T) {
	got := SanitizeText(strings.Repeat("é", 10), 4)
	if got != "éééé…" {
		t.Fatalf("got %q", got)
	}
	if SanitizeText("short", 10) != "short" {
		t.Fatal("short strings must be untouched")
	}
}

func TestSafeFileName(t *testing.T) {
	good := map[string]string{
		"report.pdf":           "report.pdf",
		"../../.bashrc":        ".bashrc",
		`..\..\evil.exe`:       "evil.exe",
		"/etc/passwd":          "passwd",
		"C:\\Windows\\sys.ini": "sys.ini",
		"na\x00me.txt":         "name.txt",
		"we<ir>d:na|me?.txt":   "we_ir_d_na_me_.txt",
		"  spaced.txt. ":       "spaced.txt",
		"CON":                  "_CON",
		"nul.txt":              "_nul.txt",
		"com1.log":             "_com1.log",
		"contest.txt":          "contest.txt",
	}
	for in, want := range good {
		got, err := SafeFileName(in)
		if err != nil || got != want {
			t.Errorf("SafeFileName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", ".", "..", "...", "/", "../", "\x01\x02", " . "} {
		if got, err := SafeFileName(bad); err == nil {
			t.Errorf("SafeFileName(%q) = %q, want error", bad, got)
		}
	}
}

func TestSafeFileNameLengthKeepsExtension(t *testing.T) {
	long := strings.Repeat("a", 500) + ".tar.gz"
	got, err := SafeFileName(long)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > maxFileNameBytes || !strings.HasSuffix(got, ".gz") {
		t.Fatalf("bad truncation: len=%d %q", len(got), got[len(got)-10:])
	}
	multi, _ := SafeFileName(strings.Repeat("é", 300) + ".txt")
	if len(multi) > maxFileNameBytes || !strings.HasSuffix(multi, ".txt") {
		t.Fatalf("multi-byte truncation broke: len=%d", len(multi))
	}
}

func TestLimiter(t *testing.T) {
	clock := time.Unix(0, 0)
	l := newLimiter(2, 3, func() time.Time { return clock })
	for i := range 3 {
		if !l.Allow() {
			t.Fatalf("burst token %d denied", i)
		}
	}
	if l.Allow() {
		t.Fatal("burst exceeded but allowed")
	}
	clock = clock.Add(500 * time.Millisecond) // +1 token at 2/s
	if !l.Allow() || l.Allow() {
		t.Fatal("expected exactly one refilled token")
	}
}

func TestKeyedLimiterIsolatesAndBoundsKeys(t *testing.T) {
	k := NewKeyedLimiter(0, 1, 2)
	if !k.Allow("a") || k.Allow("a") {
		t.Fatal("key a should get exactly one token")
	}
	if !k.Allow("b") {
		t.Fatal("key b must be independent of a")
	}
	if k.Allow("c") {
		t.Fatal("new keys beyond maxKeys must be refused while others are fresh")
	}
}
