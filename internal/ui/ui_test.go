package ui

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConsoleScrubsTerminalEscapes(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsole(&buf)
	c.Printf("from %s: %s", "evil\x1b[2J\x1b[H", "\x1b]0;pwned\x07 hi ‮elif.exe")
	out := buf.String()
	if strings.ContainsAny(out, "\x1b\x07‮") {
		t.Fatalf("control characters reached the terminal: %q", out)
	}
	if !strings.Contains(out, "hi") {
		t.Fatalf("legitimate text lost: %q", out)
	}
}

func TestConsoleRedrawsPromptAfterAsyncOutput(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsole(&buf)
	c.SetPrompt("> ")
	c.ShowPrompt()
	c.Println("incoming")
	got := buf.String()
	if got != "> \rincoming\n> " {
		t.Fatalf("got %q", got)
	}
	buf.Reset()
	c.InputDone()
	c.Println("command output")
	if buf.String() != "command output\n" {
		t.Fatalf("no prompt expected while a command runs: %q", buf.String())
	}
}

func TestConsoleConcurrentWritersDoNotInterleave(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsole(&buf)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				c.Printf("line-%02d-%s", i, strings.Repeat("x", 40))
			}
		}()
	}
	wg.Wait()
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if len(line) != len("line-00-")+40 {
			t.Fatalf("interleaved output: %q", line)
		}
	}
}

func TestStatusLineIsReplacedByNextOutput(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsole(&buf)
	c.Status("progress 50%")
	c.Println("message")
	if buf.String() != "\rprogress 50%\rmessage\n" {
		t.Fatalf("got %q", buf.String())
	}
	buf.Reset()
	c.Status("x")
	c.EndStatus()
	c.EndStatus()
	if buf.String() != "\rx\n" {
		t.Fatalf("got %q", buf.String())
	}
}

type fakeDisplay struct {
	mu    sync.Mutex
	lines []string
	ended int
}

func (f *fakeDisplay) Status(l string) { f.mu.Lock(); f.lines = append(f.lines, l); f.mu.Unlock() }
func (f *fakeDisplay) EndStatus()      { f.mu.Lock(); f.ended++; f.mu.Unlock() }

func TestProgressBarRenderingAndEdgeCases(t *testing.T) {
	d := &fakeDisplay{}
	clock := time.Unix(1000, 0)
	pb := NewProgressBar(d, "file.bin", 1000)
	pb.now = func() time.Time { return clock }
	pb.startTime = clock

	clock = clock.Add(time.Second)
	pb.Update(500)
	if len(d.lines) != 1 || !strings.Contains(d.lines[0], " 50.0%") || !strings.Contains(d.lines[0], "ETA 0:01") {
		t.Fatalf("render: %v", d.lines)
	}

	pb.Update(600) // within the redraw interval: no flicker
	if len(d.lines) != 1 {
		t.Fatal("redrew too often")
	}

	pb.Finish()
	pb.Finish()
	pb.Update(1)
	if d.ended != 1 || !strings.Contains(d.lines[len(d.lines)-1], "100.0%") {
		t.Fatalf("finish: ended=%d last=%q", d.ended, d.lines[len(d.lines)-1])
	}

	// Zero-sized and overshooting inputs must not panic or print NaN.
	for _, total := range []int64{0, 10} {
		z := NewProgressBar(&fakeDisplay{}, "z", total)
		z.Update(99999)
		z.Finish()
		if strings.Contains(z.render(time.Now()), "NaN") {
			t.Fatal("NaN in progress line")
		}
	}
}

func TestAbortedBarDoesNotLeaveAStatusLine(t *testing.T) {
	d := &fakeDisplay{}
	pb := NewProgressBar(d, "x", 10)
	pb.Abort()
	if d.ended != 0 {
		t.Fatal("abort before any drawing should not emit a newline")
	}
}

func TestMultiProgressManager(t *testing.T) {
	d := &fakeDisplay{}
	m := NewMultiProgressManager(d)
	m.AddProgress("a", "A", 10)
	m.UpdateProgress("a", 5)
	m.UpdateProgress("missing", 1)
	m.FinishProgress("a")
	m.FinishProgress("a")
	m.AddProgress("b", "B", 10)
	m.RemoveProgress("b")
	m.RemoveProgress("b")
	if d.ended != 1 {
		t.Fatalf("ended = %d", d.ended)
	}
}

func TestFormatBytes(t *testing.T) {
	cases := map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 20: "5.0 MiB", 3 << 30: "3.0 GiB"}
	for in, want := range cases {
		if got := FormatBytes(in); got != want {
			t.Errorf("FormatBytes(%d) = %q, want %q", in, got, want)
		}
	}
	if got := FormatBytes(1<<62 + 5); got == "" {
		t.Error("huge value produced nothing")
	}
}

func TestEndStatusRestoresPrompt(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsole(&buf)
	c.SetPrompt("> ")
	c.ShowPrompt()
	buf.Reset()
	c.Status("50%")
	c.EndStatus()
	if want := "\r50%\n> "; buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
}
