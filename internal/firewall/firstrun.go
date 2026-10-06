package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// stateFile remembers that the user was asked, per executable path.
const stateFile = "firewall.json"

type askedState struct {
	Exe      string    `json:"exe"`
	Declined bool      `json:"declined"`
	At       time.Time `json:"at"`
}

// Ephemeral reports whether exe is a throw-away build (go run), for which a
// rule would be useless: the next run has another path.
func Ephemeral(exe string) bool {
	// Both separators, whatever this system's own is.
	p := strings.ReplaceAll(strings.ToLower(exe), `\`, "/")
	return strings.Contains(p, "/go-build")
}

func loadAsked(dataDir string) askedState {
	var st askedState
	if b, err := os.ReadFile(filepath.Join(dataDir, stateFile)); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func saveAsked(dataDir string, st askedState) {
	if b, err := json.Marshal(st); err == nil {
		_ = os.MkdirAll(dataDir, 0o700)
		_ = os.WriteFile(filepath.Join(dataDir, stateFile), b, 0o600)
	}
}

// AlreadyAsked reports whether the user has been asked about this executable.
func AlreadyAsked(dataDir, exe string) bool {
	return strings.EqualFold(loadAsked(dataDir).Exe, exe)
}

// FirstRun asks, once per executable path, whether to open Windows Firewall,
// and does so on yes. It reads a single line from in without buffering ahead,
// so the chat's own input reader is unaffected. Other systems are not asked:
// macOS prompts by itself, and on Linux only a command can be suggested,
// which the start-up notice does.
func FirstRun(ctx context.Context, g *Guard, dataDir string, in io.Reader, out io.Writer) {
	if g.goos != "windows" || Ephemeral(g.Exe) || AlreadyAsked(dataDir, g.Exe) {
		return
	}
	fmt.Fprintln(out, "Checking whether Windows Firewall lets other peers reach you...")
	r := g.Check(ctx)
	if r.Status != Blocked {
		saveAsked(dataDir, askedState{Exe: g.Exe, At: time.Now()})
		if r.PublicNetwork {
			fmt.Fprintln(out, r.Advice)
		}
		return
	}

	fmt.Fprintln(out, "Windows Firewall is blocking lazy-chat, so other computers on your network cannot find or reach you.")
	fmt.Fprint(out, "Allow lazy-chat on private networks? You will see one administrator prompt. [Y/n] ")
	answer := strings.ToLower(strings.TrimSpace(readLine(in)))
	st := askedState{Exe: g.Exe, At: time.Now()}
	if answer != "" && answer != "y" && answer != "yes" {
		st.Declined = true
		saveAsked(dataDir, st)
		fmt.Fprintln(out, "Not changed. You can do it later with /firewall in the app, or \"lazy-chat firewall\".")
		return
	}
	switch err := g.Allow(ctx); {
	case err == nil:
		fmt.Fprintln(out, "Done: lazy-chat is allowed on private networks.")
	case errors.Is(err, ErrDeclined):
		st.Declined = true
		fmt.Fprintln(out, "The administrator prompt was declined; nothing was changed. You can do it later with /firewall.")
	default:
		fmt.Fprintln(out, "Could not change the firewall:", err)
	}
	if r.PublicNetwork {
		fmt.Fprintln(out, r.Advice)
	}
	saveAsked(dataDir, st)
}

// readLine reads up to a newline one byte at a time, so nothing after it is
// consumed.
func readLine(in io.Reader) string {
	var b strings.Builder
	buf := make([]byte, 1)
	for b.Len() < 256 {
		n, err := in.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				break
			}
			b.WriteByte(buf[0])
		}
		if err != nil {
			break
		}
	}
	return b.String()
}
