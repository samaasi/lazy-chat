package notification

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
)

const hostile = `"; Start-Process calc; $(6*7) ` + "`" + `n "@ ' -- --help <b>x</b> & \" \\`

func TestHostileTextNeverReachesScriptSource(t *testing.T) {
	for _, goos := range []string{"windows", "darwin", "linux"} {
		cmd, err := buildCommand(goos, "title "+hostile, "body "+hostile)
		if err != nil {
			t.Fatal(err)
		}
		switch goos {
		case "windows":
			// Script is constant; the payload is only in the environment.
			script := decodePowerShell(t, cmd.Args[len(cmd.Args)-1])
			if script != windowsScript {
				t.Error("windows script must be the constant template")
			}
			if strings.Contains(strings.Join(cmd.Args, " "), "Start-Process") {
				t.Error("payload leaked into the command line")
			}
			if len(cmd.Env) != 2 || !strings.Contains(cmd.Env[1], hostile) {
				t.Errorf("payload should travel via env, got %v", cmd.Env)
			}
		case "darwin":
			// Script lines (-e) must not contain the payload; it is the final argv.
			for i, a := range cmd.Args {
				if i > 0 && cmd.Args[i-1] == "-e" && strings.Contains(a, "Start-Process") {
					t.Error("payload leaked into AppleScript source")
				}
			}
			if cmd.Args[len(cmd.Args)-3] != "--" {
				t.Error("argv payload must follow a -- terminator")
			}
		case "linux":
			if cmd.Args[1] != "--" {
				t.Error("notify-send arguments must follow --")
			}
			if strings.Contains(cmd.Args[len(cmd.Args)-1], "<b>") {
				t.Error("markup should be escaped")
			}
		}
	}
}

func decodePowerShell(t *testing.T, enc string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

// Real PowerShell: run the same transport (-EncodedCommand + env) with a
// script that echoes the escaped value, and check `$(6*7)` stays literal.
func TestWindowsTransportKeepsPayloadInert(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		t.Skip("powershell not available")
	}
	script := `[Console]::Out.Write([System.Security.SecurityElement]::Escape($env:` + envBody + `))`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(script))
	cmd.Env = append(os.Environ(), envBody+"=from mallory: $(6*7) \"@ `n <x>")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if strings.Contains(got, "42") || !strings.Contains(got, "$(6*7)") {
		t.Fatalf("payload was evaluated: %q", got)
	}
	if !strings.Contains(got, "&lt;x&gt;") {
		t.Fatalf("XML not escaped: %q", got)
	}
}

func TestSanitisedAndTruncated(t *testing.T) {
	var mu sync.Mutex
	var got []command
	nm := NewNotificationManager(true, nil)
	nm.goos = "linux"
	nm.run = func(_ context.Context, c command) error {
		mu.Lock()
		got = append(got, c)
		mu.Unlock()
		return nil
	}
	_ = nm.NotifyMessageReceived("evil\x1b[31m", strings.Repeat("é", 1000)+"\nline2")
	nm.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("got %d notifications", len(got))
	}
	body := got[0].Args[len(got[0].Args)-1]
	if strings.ContainsAny(body, "\x1b\n") {
		t.Errorf("control characters survived: %q", body)
	}
	if n := len([]rune(body)); n > maxBodyRunes+1 {
		t.Errorf("body not truncated by runes: %d", n)
	}
}

func TestDisabledAndClosed(t *testing.T) {
	calls := 0
	nm := NewNotificationManager(false, nil)
	nm.run = func(context.Context, command) error { calls++; return nil }
	_ = nm.NotifyPeerConnected("a")
	nm.SetEnabled(true)
	if !nm.IsEnabled() {
		t.Fatal("SetEnabled had no effect")
	}
	nm.Close()
	nm.Close() // idempotent
	if err := nm.NotifyPeerConnected("late"); err != nil {
		t.Fatalf("notify after Close must not fail or panic: %v", err)
	}
	if calls != 0 {
		t.Fatalf("unexpected calls: %d", calls)
	}
}

func TestSlowHelperDoesNotBlockCaller(t *testing.T) {
	release := make(chan struct{})
	nm := NewNotificationManager(true, nil)
	nm.goos = "linux"
	nm.run = func(context.Context, command) error { <-release; return nil }

	done := make(chan struct{})
	go func() {
		for range queueSize * 4 { // far more than the queue holds
			_ = nm.NotifyMessageReceived("a", "b")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("notify blocked on a slow helper")
	}
	close(release)
	nm.Close()
}

func TestUnsupportedOS(t *testing.T) {
	if _, err := buildCommand("plan9", "t", "b"); err == nil {
		t.Fatal("expected error")
	}
}
