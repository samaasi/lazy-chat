// Package firewall checks whether the operating system's firewall lets other
// peers reach lazy-chat, and, on Windows, adds the rule that allows it.
//
// Every firewall drops unsolicited inbound packets by default, which is what
// both discovery announcements and incoming chat connections are. No program
// can or should get around that by itself, so this package asks once: on
// Windows it adds a rule for this executable on private networks only, with a
// single administrator (UAC) prompt; elsewhere it prints the exact command.
package firewall

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
)

// Status is what the firewall does to lazy-chat's inbound traffic.
type Status int

const (
	// Unknown means the state could not be determined.
	Unknown Status = iota
	// Open means peers can reach us: an allow rule exists or no firewall is active.
	Open
	// Blocked means unsolicited inbound traffic is dropped.
	Blocked
)

func (s Status) String() string {
	switch s {
	case Open:
		return "open"
	case Blocked:
		return "blocked"
	}
	return "unknown"
}

// RuleName is the display name and group of the rule this package creates.
const RuleName = "lazy-chat"

// ErrManual means this system's firewall must be opened by the user, with the
// command in Report.Advice.
var ErrManual = errors.New("this firewall has to be opened by hand")

// ErrDeclined means the user refused the administrator prompt.
var ErrDeclined = errors.New("the administrator prompt was declined")

// Report is the result of a check.
type Report struct {
	Status Status
	// PublicNetwork is set on Windows when a connected network is classified
	// as Public, where a private-only rule has no effect.
	PublicNetwork bool
	// Advice tells the user what to do, or is empty when nothing is needed.
	Advice string
}

// Guard checks and opens the firewall for one executable and its ports.
type Guard struct {
	Exe       string // absolute path of the program
	TCPPort   int
	DiscBase  int // first discovery UDP port
	DiscRange int // number of discovery ports

	goos string
	run  runner
	file func(string) ([]byte, error)
}

// runner runs a program and returns its standard output and exit code.
type runner func(ctx context.Context, name string, args ...string) (out []byte, code int, err error)

// New returns a Guard for this system.
func New(exe string, tcpPort, discBase, discRange int) *Guard {
	return &Guard{Exe: exe, TCPPort: tcpPort, DiscBase: discBase, DiscRange: discRange,
		goos: runtime.GOOS, run: execRun, file: os.ReadFile}
}

func execRun(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out, ee.ExitCode(), nil
	}
	if err != nil {
		return out, -1, err
	}
	return out, 0, nil
}

func (g *Guard) udpRange() string {
	return fmt.Sprintf("%d-%d", g.DiscBase, g.DiscBase+g.DiscRange-1)
}

// Check reports whether peers can reach this program.
func (g *Guard) Check(ctx context.Context) Report {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	switch g.goos {
	case "windows":
		return g.checkWindows(ctx)
	case "linux":
		return g.checkLinux(ctx)
	case "darwin":
		return g.checkMac(ctx)
	}
	return Report{Status: Unknown}
}

// Allow opens the firewall for this program. On Windows it shows one
// administrator prompt; elsewhere it returns ErrManual and the caller should
// show Check's advice.
func (g *Guard) Allow(ctx context.Context) error {
	if g.goos != "windows" {
		return ErrManual
	}
	return g.elevated(ctx, allowScript(g.Exe))
}

// Remove deletes the rules this package created.
func (g *Guard) Remove(ctx context.Context) error {
	if g.goos != "windows" {
		return ErrManual
	}
	return g.elevated(ctx, removeScript())
}

// ---- Windows -------------------------------------------------------------------

// psQuote makes s a single-quoted PowerShell string literal, in which nothing
// is interpreted except a doubled quote.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// encodePS encodes a script for powershell -EncodedCommand (UTF-16LE, base64),
// so it never passes through command-line quoting.
func encodePS(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

func (g *Guard) powershell(ctx context.Context, script string) ([]byte, int, error) {
	return g.run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePS(script))
}

// checkScript prints a JSON summary of the rules that apply to the program.
// Reading rules needs no administrator rights.
func checkScript(exe string) string {
	return `$ErrorActionPreference = 'Stop'
$exe = ` + psQuote(exe) + `
$r = @{ enabled = $false; allow = $false; block = $false; public = $false }
$r.enabled = [bool]((Get-NetFirewallProfile -Name Private).Enabled -eq 'True')
$rules = @()
$rules += Get-NetFirewallApplicationFilter -Program $exe -ErrorAction SilentlyContinue | Get-NetFirewallRule
$rules += Get-NetFirewallRule -Group '` + RuleName + `' -ErrorAction SilentlyContinue
$rules += Get-NetFirewallRule -DisplayName '` + RuleName + `*' -ErrorAction SilentlyContinue
foreach ($x in $rules) {
  if (-not $x -or $x.Enabled.ToString() -ne 'True' -or $x.Direction.ToString() -ne 'Inbound') { continue }
  $p = $x.Profile.ToString()
  if ($p -notmatch 'Private|Any') { continue }
  if ($x.Action.ToString() -eq 'Block') { $r.block = $true } elseif ($x.Action.ToString() -eq 'Allow') { $r.allow = $true }
}
foreach ($c in @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)) {
  if ($c.NetworkCategory.ToString() -eq 'Public') { $r.public = $true }
}
$r | ConvertTo-Json -Compress`
}

type windowsState struct {
	Enabled bool `json:"enabled"`
	Allow   bool `json:"allow"`
	Block   bool `json:"block"`
	Public  bool `json:"public"`
}

func (g *Guard) checkWindows(ctx context.Context) Report {
	out, code, err := g.powershell(ctx, checkScript(g.Exe))
	if err != nil || code != 0 {
		return Report{Status: Unknown, Advice: g.windowsAdvice()}
	}
	var st windowsState
	if json.Unmarshal(lastJSON(out), &st) != nil {
		return Report{Status: Unknown, Advice: g.windowsAdvice()}
	}
	return interpretWindows(st, g.windowsAdvice())
}

func interpretWindows(st windowsState, advice string) Report {
	r := Report{PublicNetwork: st.Public}
	switch {
	case !st.Enabled:
		r.Status = Open // the private-network firewall is off
	case st.Allow && !st.Block: // a block rule beats an allow rule in Windows
		r.Status = Open
	default:
		r.Status = Blocked
		r.Advice = advice
	}
	if st.Public {
		r.Advice = strings.TrimSpace(r.Advice + "\nYour network is set to Public, where lazy-chat is not allowed. If it is a network you trust (home, office), " +
			"set it to Private: Settings > Network & internet > (your connection) > Properties > Private network.")
	}
	return r
}

// lastJSON returns the last line of out that looks like a JSON object, since
// PowerShell may print warnings before it.
func lastJSON(out []byte) []byte {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); strings.HasPrefix(l, "{") {
			return []byte(l)
		}
	}
	return nil
}

func (g *Guard) windowsAdvice() string {
	return "Windows Firewall is blocking lazy-chat, so other computers cannot find or reach you. " +
		"Run \"lazy-chat firewall\" (or /firewall in the app) to allow it on private networks; it shows one administrator prompt."
}

// allowScript runs elevated. It removes block rules for the program (left by a
// dismissed "Allow access?" prompt, and stronger than any allow rule) and our
// own earlier rule, then adds one rule for the program on private networks.
func allowScript(exe string) string {
	return `$ErrorActionPreference = 'Stop'
$exe = ` + psQuote(exe) + `
Get-NetFirewallApplicationFilter -Program $exe -ErrorAction SilentlyContinue | Get-NetFirewallRule |
  Where-Object { $_.Direction.ToString() -eq 'Inbound' -and $_.Action.ToString() -eq 'Block' } | Remove-NetFirewallRule
Get-NetFirewallRule -Group '` + RuleName + `' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName '` + RuleName + `' -Group '` + RuleName + `' -Direction Inbound -Action Allow -Program $exe -Profile Private ` +
		`-Description 'Lets other lazy-chat peers on private networks discover and connect to this computer.' | Out-Null
exit 0`
}

func removeScript() string {
	return `$ErrorActionPreference = 'Stop'
Get-NetFirewallRule -Group '` + RuleName + `' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
exit 0`
}

// elevated runs script as administrator through a UAC prompt and waits for it.
func (g *Guard) elevated(ctx context.Context, script string) error {
	launcher := `try {
  $p = Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru ` +
		`-ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','` + encodePS(script) + `'
  exit $p.ExitCode
} catch { exit 1223 }`
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute) // the user has to read and answer the prompt
	defer cancel()
	_, code, err := g.powershell(ctx, launcher)
	switch {
	case err != nil:
		return err
	case code == 1223: // ERROR_CANCELLED
		return ErrDeclined
	case code != 0:
		return fmt.Errorf("adding the firewall rule failed (exit code %d)", code)
	}
	return nil
}

// ---- Linux -----------------------------------------------------------------------

func (g *Guard) checkLinux(ctx context.Context) Report {
	if b, err := g.file("/etc/ufw/ufw.conf"); err == nil && ufwEnabled(string(b)) {
		return Report{Status: Blocked, Advice: fmt.Sprintf(
			"The ufw firewall is on. To let peers find and reach you, run:\n  sudo ufw allow %d/tcp && sudo ufw allow %s/udp",
			g.TCPPort, strings.Replace(g.udpRange(), "-", ":", 1))}
	}
	if out, code, err := g.run(ctx, "firewall-cmd", "--state"); err == nil && code == 0 && strings.TrimSpace(string(out)) == "running" {
		return Report{Status: Blocked, Advice: fmt.Sprintf(
			"The firewalld firewall is on. To let peers find and reach you, run:\n  sudo firewall-cmd --permanent --add-port=%d/tcp --add-port=%s/udp && sudo firewall-cmd --reload",
			g.TCPPort, g.udpRange())}
	}
	// No firewall we know of is active. (Hand-written iptables/nftables rules
	// cannot be read without root; the README covers them.)
	return Report{Status: Open}
}

func ufwEnabled(conf string) bool {
	for _, l := range strings.Split(conf, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "ENABLED=") {
			v := strings.Trim(strings.TrimPrefix(l, "ENABLED="), `"' `)
			return strings.EqualFold(v, "yes")
		}
	}
	return false
}

// ---- macOS -----------------------------------------------------------------------

func (g *Guard) checkMac(ctx context.Context) Report {
	out, code, err := g.run(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	if err != nil || code != 0 {
		return Report{Status: Unknown}
	}
	if !strings.Contains(strings.ToLower(string(out)), "enabled") || strings.Contains(strings.ToLower(string(out)), "disabled") {
		return Report{Status: Open}
	}
	// macOS asks "accept incoming network connections?" by itself the first
	// time; this is for when that was answered with Deny.
	return Report{Status: Unknown, Advice: "The macOS firewall is on. If you were asked whether lazy-chat may accept incoming connections, choose Allow. " +
		"If you denied it, run:\n  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add " + shellQuote(g.Exe) +
		" && sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp " + shellQuote(g.Exe)}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
