package logger

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l, _ := New(Options{Level: WarnLevel, Output: &buf})
	l.Info("hidden")
	l.Warn("shown")
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), "shown") {
		t.Fatalf("unexpected output: %q", buf.String())
	}
	l.SetLevel(DebugLevel)
	l.Debug("now visible")
	if !strings.Contains(buf.String(), "now visible") {
		t.Fatal("SetLevel did not take effect")
	}
}

func TestUntrustedValuesCannotForgeLines(t *testing.T) {
	var buf bytes.Buffer
	l, _ := New(Options{Level: InfoLevel, Output: &buf})
	l.Info("received", "from", "evil\n2026-01-01 level=ERROR msg=forged")
	if lines := strings.Count(strings.TrimSpace(buf.String()), "\n"); lines != 0 {
		t.Fatalf("value injected an extra log line: %q", buf.String())
	}
}

func TestRotationAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "app.log")
	w, err := newRotatingFile(path, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for range 10 {
		if _, err := w.Write(bytes.Repeat([]byte("x"), 40)); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{path, path + ".1", path + ".2"} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s: %v", p, err)
		}
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Fatal("kept more backups than configured")
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]Level{"debug": DebugLevel, "INFO": InfoLevel, " Warning ": WarnLevel, "error": ErrorLevel} {
		if got, err := ParseLevel(in); err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseLevel("loud"); err == nil {
		t.Error("expected error for unknown level")
	}
}
