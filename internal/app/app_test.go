package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/config"
	"github.com/samaasi/lazy-chat/internal/identity"
)

// ---- Harness ---------------------------------------------------------------

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type instance struct {
	t    *testing.T
	name string
	app  *App
	in   *io.PipeWriter
	out  *syncBuf
	dir  string
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func newInstance(t *testing.T, name string, discBase int, mod ...func(*config.Config)) *instance {
	t.Helper()
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Encryption = "off" // tests must never prompt for a passphrase or touch DPAPI
	cfg.Username = name
	cfg.TCPPort = freeTCPPort(t)
	cfg.ListenAddr = "127.0.0.1"
	cfg.DiscoveryPort, cfg.DiscoveryRange = discBase, 4
	cfg.BroadcastAddr = "127.0.0.1"
	cfg.BroadcastInterval = 1
	cfg.LogLevel = "error"
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.DownloadDir = filepath.Join(dir, "downloads")
	cfg.Database.Path = filepath.Join(cfg.DataDir, "chat.db")
	for _, f := range mod {
		f(cfg)
	}

	pr, pw := io.Pipe()
	out := &syncBuf{}
	a, err := New(cfg, WithIO(pr, out))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go a.CLI().Start(ctx)
	t.Cleanup(func() {
		cancel()
		pw.Close()
		a.Stop()
	})
	return &instance{t: t, name: name, app: a, in: pw, out: out, dir: dir}
}

func (i *instance) say(format string, args ...any) {
	i.t.Helper()
	if _, err := fmt.Fprintf(i.in, format+"\n", args...); err != nil {
		i.t.Fatal(err)
	}
}

// waitOut waits until the instance's output contains every fragment.
func (i *instance) waitOut(fragments ...string) {
	i.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		out := i.out.String()
		missing := ""
		for _, f := range fragments {
			if !strings.Contains(out, f) {
				missing = f
				break
			}
		}
		if missing == "" {
			return
		}
		if time.Now().After(deadline) {
			i.t.Fatalf("%s: timed out waiting for %q\n--- %s's output ---\n%s", i.name, missing, i.name, out)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (i *instance) neverOut(fragment string, wait time.Duration) {
	i.t.Helper()
	time.Sleep(wait)
	if strings.Contains(i.out.String(), fragment) {
		i.t.Fatalf("%s: output unexpectedly contains %q\n%s", i.name, fragment, i.out.String())
	}
}

// randomBase picks a base UDP port such that base..base+7 can all be bound
// right now. Random ports can fall into OS-reserved ranges (Windows excludes
// some for Hyper-V/WSL), which would make tests flaky.
func randomBase() int {
	for range 200 {
		base := 20000 + rand.IntN(30000)
		var conns []*net.UDPConn
		ok := true
		for p := base; p < base+8; p++ {
			c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: p})
			if err != nil {
				ok = false
				break
			}
			conns = append(conns, c)
		}
		for _, c := range conns {
			c.Close()
		}
		if ok {
			return base
		}
	}
	panic("no usable UDP port range found")
}

func pair(t *testing.T, mods ...func(*config.Config)) (alice, bob *instance) {
	t.Helper()
	base := randomBase()
	alice = newInstance(t, "alice", base, mods...)
	bob = newInstance(t, "bob", base, mods...)
	// Discovery must find both ways before anything else is attempted.
	waitPeers := func(me *instance, other string) {
		deadline := time.Now().Add(15 * time.Second)
		for {
			for _, p := range me.app.Peers().Peers() {
				if p.Username == other {
					return
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s never discovered %s", me.name, other)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitPeers(alice, "bob")
	waitPeers(bob, "alice")
	return
}

// ---- End-to-end ------------------------------------------------------------

func TestChatEndToEnd(t *testing.T) {
	alice, bob := pair(t)

	alice.say("/send bob hello bob")
	bob.waitOut("alice (" + alice.app.ID()[:8] + "): hello bob")
	bob.waitOut("* alice (" + alice.app.ID()[:8] + ") connected")

	// Bob can answer on the connection Alice opened.
	bob.say("/send alice hi   back")
	alice.waitOut("bob (" + bob.app.ID()[:8] + "): hi   back") // whitespace is preserved

	// Delivery receipts: nothing is flagged as undelivered.
	alice.say("/history bob")
	alice.waitOut("Conversation with bob", "you: hello bob")
	time.Sleep(200 * time.Millisecond)
	if strings.Contains(alice.out.String(), "(not delivered)") {
		t.Fatalf("message not acknowledged:\n%s", alice.out.String())
	}

	// Both are connected, and the CLI says so.
	alice.say("/connections")
	alice.waitOut("Active connections (1)")
	alice.say("/whoami")
	alice.waitOut(alice.app.ID())
}

func TestGroupJourney(t *testing.T) {
	alice, bob := pair(t)

	alice.say("/creategroup Crew | the crew")
	alice.waitOut(`Created group "Crew"`)
	alice.say("/invite Crew bob")
	bob.waitOut(`invited you to group "Crew"`)

	bob.say("/invites")
	bob.waitOut("Crew")
	bob.say("/accept Crew")
	bob.waitOut(`Joined group "Crew"`)
	alice.waitOut(`bob (` + bob.app.ID()[:8] + `) joined group "Crew"`)

	alice.say("/groupmsg Crew team talk")
	bob.waitOut("[Crew] alice (" + alice.app.ID()[:8] + "): team talk")
	bob.say("/groupmsg Crew roger that")
	alice.waitOut("[Crew] bob (" + bob.app.ID()[:8] + "): roger that")

	alice.say("/members Crew")
	alice.waitOut("alice", "bob", "admin")

	// Only the creator may invite; a member cannot.
	bob.say("/invite Crew alice")
	bob.waitOut("only the group creator")

	// Bob leaves: Alice is told and his later messages are not accepted.
	bob.say("/leavegroup Crew")
	bob.waitOut(`Left group "Crew"`)
	alice.waitOut("bob left")
	alice.say("/groupmsg Crew anyone still here?")
	bob.neverOut("anyone still here?", 500*time.Millisecond)

	// Alice removes nobody she cannot; removing a former member fails cleanly.
	alice.say("/kick Crew bob")
	alice.waitOut("no member matches")
}

func TestRemovedMemberIsCutOff(t *testing.T) {
	alice, bob := pair(t)
	defer func() {
		if t.Failed() {
			t.Logf("bob's output:\n%s", bob.out.String())
		}
	}()
	alice.say("/creategroup Crew")
	alice.waitOut("Created group")
	alice.say("/invite Crew bob")
	bob.waitOut("invited you")
	bob.say("/accept Crew")
	alice.waitOut("joined group")

	alice.say("/kick Crew bob")
	alice.waitOut(`Removed bob`)
	bob.waitOut("you were removed")

	bob.say("/groupmsg Crew let me back in")
	bob.waitOut("Error")
	alice.neverOut("let me back in", 300*time.Millisecond)
	bob.say("/groups")
	bob.waitOut("not a member of any groups")
}

func TestFileTransferEndToEnd(t *testing.T) {
	alice, bob := pair(t)
	data := bytes.Repeat([]byte("0123456789abcdef"), 70_000) // ~1.1 MB, several chunks
	src := filepath.Join(alice.dir, "report final.txt")      // note the space
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}

	alice.say(`/sendfile bob %s`, src)
	bob.waitOut("wants to send you \"report final.txt\"", "/getfile ")

	// Nothing is stored until Bob agrees.
	if entries, _ := os.ReadDir(bob.app.config.DownloadDir); len(entries) != 0 {
		t.Fatalf("data written before acceptance: %v", entries)
	}

	// The CLI prints the short transfer ID in the offer line.
	line := ""
	for _, l := range strings.Split(bob.out.String(), "\n") {
		if strings.Contains(l, "/getfile ") {
			line = l
		}
	}
	id := strings.Fields(line[strings.Index(line, "/getfile ")+len("/getfile "):])[0]
	bob.say("/getfile %s", id)

	bob.waitOut("Received \"report final.txt\"")
	alice.waitOut("received \"report final.txt\" intact")

	got, err := os.ReadFile(filepath.Join(bob.app.config.DownloadDir, "report final.txt"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("received file mismatch (err=%v, %d bytes)", err, len(got))
	}
	alice.say("/transfers")
	alice.waitOut("completed")
}

func TestUnsafeInputIsNeutralisedEndToEnd(t *testing.T) {
	alice, bob := pair(t)
	alice.say("/send bob \x1b[2J\x1b]0;pwned\x07 clear-screen attempt ‮fdp.exe")
	bob.waitOut("clear-screen attempt")
	out := bob.out.String()
	if strings.ContainsAny(out, "\x1b\x07‮") {
		t.Fatalf("terminal control sequences reached bob's screen: %q", out)
	}
}

func TestOfflinePeerKeepsUndeliveredMessage(t *testing.T) {
	alice, bob := pair(t)
	bobID := bob.app.ID()
	bob.app.Stop()

	// Alice still has Bob in her table, but nobody is listening any more.
	alice.say("/send %s are you there", bobID)
	alice.waitOut("saved but not delivered")
	alice.say("/history %s", bobID)
	alice.waitOut("are you there", "(not delivered)")
}

func TestUnknownCommandsAndBadInputAreHandled(t *testing.T) {
	alice, _ := pair(t)
	alice.say("/nonsense")
	alice.waitOut("Unknown command: /nonsense")
	alice.say("hello without a slash")
	alice.waitOut("Messages are sent with /send")
	alice.say("/send")
	alice.waitOut("Usage: /send <peer> <message>")
	alice.say("/send nobody-by-that-name hi")
	alice.waitOut("no peer matches")
	alice.say("/history bob 0")
	alice.waitOut("not a positive number")
	alice.say("/help")
	alice.waitOut("/creategroup", "/sendfile", "/export")
}

func TestExportNeverOverwrites(t *testing.T) {
	alice, bob := pair(t)
	alice.say("/send bob one")
	bob.waitOut("one")
	out := filepath.Join(alice.dir, "export.json")
	alice.say("/export bob %s json", out)
	alice.waitOut("Exported to")
	data, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(data), `"message":"one"`) {
		t.Fatalf("export: %v %q", err, data)
	}
	alice.say("/export bob %s json", out)
	alice.waitOut("cannot create")
}

// ---- Lifecycle -------------------------------------------------------------

func TestQuitCommandEndsRun(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Encryption = "off" // tests must never prompt for a passphrase or touch DPAPI
	dir := t.TempDir()
	cfg.TCPPort = freeTCPPort(t)
	cfg.ListenAddr = "127.0.0.1"
	cfg.DiscoveryPort, cfg.DiscoveryRange = randomBase(), 2
	cfg.BroadcastAddr = "127.0.0.1"
	cfg.LogLevel = "error"
	cfg.DataDir, cfg.DownloadDir = filepath.Join(dir, "d"), filepath.Join(dir, "dl")
	cfg.Database.Path = filepath.Join(cfg.DataDir, "db")

	for _, ending := range []string{"quit", "eof"} {
		pr, pw := io.Pipe()
		a, err := New(cfg, WithIO(pr, &syncBuf{}))
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- a.Run() }()
		time.Sleep(100 * time.Millisecond)
		if ending == "quit" {
			fmt.Fprintln(pw, "/quit")
		} else {
			pw.Close()
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s: Run returned %v", ending, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: Run did not return: the program would hang", ending)
		}
		pw.Close()
	}
}

func TestStopIsIdempotentAndReleasesPorts(t *testing.T) {
	alice, _ := pair(t)
	port := alice.app.Port()
	if err := alice.app.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := alice.app.Stop(); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("port %d still in use after Stop: %v", port, err)
	}
	l.Close()
	if err := alice.app.Start(); err == nil {
		t.Fatal("a stopped app must not restart")
	}
}

func TestIdentityIsStableAcrossRestarts(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Encryption = "off" // tests must never prompt for a passphrase or touch DPAPI
	dir := t.TempDir()
	cfg.TCPPort = freeTCPPort(t)
	cfg.ListenAddr = "127.0.0.1"
	cfg.DiscoveryPort, cfg.DiscoveryRange = randomBase(), 2
	cfg.BroadcastAddr = "127.0.0.1"
	cfg.LogLevel = "error"
	cfg.DataDir, cfg.DownloadDir = filepath.Join(dir, "d"), filepath.Join(dir, "dl")
	cfg.Database.Path = filepath.Join(cfg.DataDir, "db")

	var ids [2]string
	for i := range ids {
		a, err := New(cfg, WithIO(strings.NewReader(""), &syncBuf{}))
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = a.ID()
		a.Stop()
	}
	if ids[0] != ids[1] {
		t.Fatalf("peer ID changed across restarts: %s -> %s", ids[0], ids[1])
	}
}

func TestNewFailsCleanlyOnBadConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Encryption = "off" // tests must never prompt for a passphrase or touch DPAPI
	cfg.Username = ""
	if _, err := New(cfg); err == nil {
		t.Fatal("invalid config accepted")
	}

	// A database path that cannot be created releases everything else.
	cfg = config.DefaultConfig()
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.DownloadDir = filepath.Join(dir, "dl")
	cfg.Database.Path = filepath.Join(blocker, "sub", "db") // parent is a file
	cfg.LogLevel = "error"
	if _, err := New(cfg, WithIO(strings.NewReader(""), &syncBuf{})); err == nil {
		t.Fatal("unusable database path accepted")
	}
}

func TestSafetyNumbersMatchAndVerificationSticks(t *testing.T) {
	alice, bob := pair(t)
	groups := strings.Fields(identity.SafetyNumber(alice.app.ID(), bob.app.ID()))
	line1, line2 := strings.Join(groups[:6], "  "), strings.Join(groups[6:], "  ")

	// Each side shows the identical number.
	alice.say("/safety bob")
	alice.waitOut(line1, line2, "NOT verified")
	bob.say("/safety alice")
	bob.waitOut(line1, line2, "NOT verified")

	alice.say("/list")
	alice.waitOut("unverified")

	alice.say("/verify bob")
	alice.waitOut("now marked verified")
	alice.say("/safety bob")
	alice.waitOut("(verified)")
	alice.say("/connections")
	alice.say("/send bob hello") // connect, so /connections has a row
	bob.waitOut("hello")
	alice.say("/connections")
	alice.waitOut("verified")

	// It is Alice's local judgement: Bob has not verified Alice.
	bob.say("/list")
	bob.waitOut("unverified")

	alice.say("/unverify bob")
	alice.waitOut("no longer marked verified")
	alice.say("/safety bob")
	time.Sleep(100 * time.Millisecond)
	if strings.Count(alice.out.String(), "NOT verified") < 2 {
		t.Fatalf("unverify did not take effect:\n%s", alice.out.String())
	}
}
