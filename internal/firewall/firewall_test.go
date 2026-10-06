package firewall

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"
)

var bg = context.Background()

// fake builds a Guard for goos whose commands and files are scripted.
func fake(goos string, files map[string]string, run runner) *Guard {
	g := New("/opt/lazy chat/it's/lazy-chat", 8080, 9999, 10)
	g.goos = goos
	g.file = func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, errors.New("no such file")
	}
	if run == nil {
		run = func(context.Context, string, ...string) ([]byte, int, error) { return nil, -1, errors.New("not found") }
	}
	g.run = run
	return g
}

func TestInterpretWindows(t *testing.T) {
	cases := []struct {
		name string
		st   windowsState
		want Status
	}{
		{"firewall off", windowsState{Enabled: false}, Open},
		{"allowed", windowsState{Enabled: true, Allow: true}, Open},
		{"no rule", windowsState{Enabled: true}, Blocked},
		{"a block rule wins over an allow rule", windowsState{Enabled: true, Allow: true, Block: true}, Blocked},
		{"blocked only", windowsState{Enabled: true, Block: true}, Blocked},
	}
	for _, c := range cases {
		r := interpretWindows(c.st, "ADVICE")
		if r.Status != c.want {
			t.Errorf("%s: %v, want %v", c.name, r.Status, c.want)
		}
		if (r.Advice != "") != (c.want == Blocked) {
			t.Errorf("%s: advice %q", c.name, r.Advice)
		}
	}
	r := interpretWindows(windowsState{Enabled: true, Allow: true, Public: true}, "ADVICE")
	if !r.PublicNetwork || !strings.Contains(r.Advice, "set it to Private") {
		t.Fatalf("a Public network must be pointed out even when allowed: %+v", r)
	}
}

func TestLastJSON(t *testing.T) {
	out := []byte("WARNING: something\r\n{\"enabled\":true,\"allow\":false}\r\n")
	if got := string(lastJSON(out)); got != `{"enabled":true,"allow":false}` {
		t.Fatalf("got %q", got)
	}
	if lastJSON([]byte("no json here")) != nil {
		t.Fatal("found JSON in plain text")
	}
}

func TestLinuxAdvice(t *testing.T) {
	ufw := fake("linux", map[string]string{"/etc/ufw/ufw.conf": "# comment\nENABLED=yes\nLOGLEVEL=low\n"}, nil)
	r := ufw.Check(bg)
	if r.Status != Blocked || !strings.Contains(r.Advice, "sudo ufw allow 8080/tcp && sudo ufw allow 9999:10008/udp") {
		t.Fatalf("ufw: %+v", r)
	}
	off := fake("linux", map[string]string{"/etc/ufw/ufw.conf": "ENABLED=no\n"}, nil)
	if r := off.Check(bg); r.Status != Open || r.Advice != "" {
		t.Fatalf("ufw off: %+v", r)
	}
	fwd := fake("linux", nil, func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		if name == "firewall-cmd" {
			return []byte("running\n"), 0, nil
		}
		return nil, -1, errors.New("not found")
	})
	r = fwd.Check(bg)
	if r.Status != Blocked || !strings.Contains(r.Advice, "--add-port=8080/tcp --add-port=9999-10008/udp") {
		t.Fatalf("firewalld: %+v", r)
	}
	if r := fake("linux", nil, nil).Check(bg); r.Status != Open {
		t.Fatalf("no firewall: %+v", r)
	}
	if err := fake("linux", nil, nil).Allow(bg); !errors.Is(err, ErrManual) {
		t.Fatalf("Allow on Linux: %v", err)
	}
}

func TestMacAdvice(t *testing.T) {
	on := fake("darwin", nil, func(context.Context, string, ...string) ([]byte, int, error) {
		return []byte("Firewall is enabled. (State = 1)\n"), 0, nil
	})
	r := on.Check(bg)
	if !strings.Contains(r.Advice, "--unblockapp '/opt/lazy chat/it'\\''s/lazy-chat'") {
		t.Fatalf("advice must quote the path safely: %q", r.Advice)
	}
	off := fake("darwin", nil, func(context.Context, string, ...string) ([]byte, int, error) {
		return []byte("Firewall is disabled. (State = 0)\n"), 0, nil
	})
	if r := off.Check(bg); r.Status != Open {
		t.Fatalf("off: %+v", r)
	}
}

func TestElevationOutcomes(t *testing.T) {
	for code, want := range map[int]error{0: nil, 1223: ErrDeclined} {
		g := fake("windows", nil, func(_ context.Context, name string, _ ...string) ([]byte, int, error) { return nil, code, nil })
		if err := g.Allow(bg); !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Errorf("exit %d: %v", code, err)
		}
	}
	g := fake("windows", nil, func(context.Context, string, ...string) ([]byte, int, error) { return nil, 5, nil })
	if err := g.Allow(bg); err == nil {
		t.Fatal("a failure was reported as success")
	}
}

// The scripts are only ever run on Windows, so check them there with the
// real PowerShell parser, using a path that would break naive quoting.
func TestScriptsParseAndQuotePathsSafely(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		t.Skip("no powershell")
	}
	path := `C:\Users\O'Brien\$(Start-Process calc)\lazy-chat.exe`
	g := &Guard{run: execRun}
	for name, script := range map[string]string{
		"check":  checkScript(path),
		"allow":  allowScript(path),
		"remove": removeScript(),
	} {
		parse := `$errs = $null; [void][System.Management.Automation.Language.Parser]::ParseInput([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('` +
			encodePS(script) + `')), [ref]$null, [ref]$errs); if ($errs.Count) { $errs | ForEach-Object { $_.Message }; exit 1 }; exit 0`
		out, code, err := g.powershell(bg, parse)
		if err != nil || code != 0 {
			t.Errorf("%s script does not parse: %v %s", name, err, out)
		}
	}
	// The path is taken literally: nothing in it is executed or expanded.
	out, code, err := g.powershell(bg, "$exe = "+psQuote(path)+"\n[Console]::Out.Write($exe)")
	if err != nil || code != 0 || string(out) != path {
		t.Fatalf("quoted path came out as %q (%d %v)", out, code, err)
	}
}

// Reading the firewall needs no administrator rights, so the real check can
// run here: a program with no rules must not be reported open (unless the
// firewall is off altogether).
func TestRealWindowsCheck(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	if testing.Short() {
		t.Skip("slow: queries Windows Firewall")
	}
	g := New(`C:\nowhere\lazy-chat-test-`+strings.Repeat("x", 8)+`.exe`, 8080, 9999, 10)
	r := g.Check(bg)
	t.Logf("status=%v public=%v", r.Status, r.PublicNetwork)
	if r.Status == Unknown {
		t.Fatalf("could not read the firewall state: %+v", r)
	}
}

func blockedWindows(t *testing.T, allowCode int, calls *[]string) *Guard {
	t.Helper()
	g := fake("windows", nil, func(_ context.Context, _ string, args ...string) ([]byte, int, error) {
		script := decodePS(args[len(args)-1])
		switch {
		case strings.Contains(script, "Start-Process"):
			*calls = append(*calls, "allow")
			return nil, allowCode, nil
		default:
			*calls = append(*calls, "check")
			return []byte(`{"enabled":true,"allow":false,"block":false,"public":false}`), 0, nil
		}
	})
	g.Exe = `C:\Apps\lazy-chat.exe`
	return g
}

func decodePS(b64 string) string {
	raw, _ := base64.StdEncoding.DecodeString(b64)
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

func TestFirstRunAsksOnceAndAllows(t *testing.T) {
	dir := t.TempDir()
	var calls []string
	g := blockedWindows(t, 0, &calls)
	in := strings.NewReader("\nnext line for the chat\n")
	var out strings.Builder
	FirstRun(bg, g, dir, in, &out)
	if !strings.Contains(out.String(), "[Y/n]") || !strings.Contains(out.String(), "Done") {
		t.Fatalf("output:\n%s", out.String())
	}
	if strings.Join(calls, ",") != "check,allow" {
		t.Fatalf("calls %v", calls)
	}
	// Only the answer was consumed; the chat gets the rest.
	rest, _ := io.ReadAll(in)
	if string(rest) != "next line for the chat\n" {
		t.Fatalf("FirstRun read past its line: %q", rest)
	}
	// Never asked again for the same program.
	calls = nil
	FirstRun(bg, g, dir, strings.NewReader(""), &out)
	if len(calls) != 0 {
		t.Fatalf("asked again: %v", calls)
	}
	// A different program path (moved or reinstalled) is asked about again.
	g.Exe = `D:\Elsewhere\lazy-chat.exe`
	FirstRun(bg, g, dir, strings.NewReader("y\n"), &out)
	if strings.Join(calls, ",") != "check,allow" {
		t.Fatalf("calls %v", calls)
	}
}

func TestFirstRunRespectsNo(t *testing.T) {
	dir := t.TempDir()
	var calls []string
	g := blockedWindows(t, 0, &calls)
	var out strings.Builder
	FirstRun(bg, g, dir, strings.NewReader("n\n"), &out)
	if strings.Join(calls, ",") != "check" || !strings.Contains(out.String(), "/firewall") {
		t.Fatalf("calls %v, output:\n%s", calls, out.String())
	}
	if !loadAsked(dir).Declined {
		t.Fatal("a refusal was not remembered")
	}
}

func TestFirstRunDeclinedPromptAndSkips(t *testing.T) {
	var calls []string
	var out strings.Builder
	FirstRun(bg, blockedWindows(t, 1223, &calls), t.TempDir(), strings.NewReader("y\n"), &out)
	if !strings.Contains(out.String(), "declined") {
		t.Fatalf("output:\n%s", out.String())
	}
	// Not asked: other systems, and throw-away "go run" builds.
	calls = nil
	FirstRun(bg, fake("linux", nil, nil), t.TempDir(), strings.NewReader("y\n"), &out)
	g := blockedWindows(t, 0, &calls)
	g.Exe = `C:\Users\me\AppData\Local\Temp\go-build123\b001\exe\lazy-chat.exe`
	FirstRun(bg, g, t.TempDir(), strings.NewReader("y\n"), &out)
	if len(calls) != 0 {
		t.Fatalf("asked when it should not: %v", calls)
	}
}
