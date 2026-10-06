package filetransfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/logger"
	"github.com/samaasi/lazy-chat/internal/protocol"
)

// ---- In-process network between two managers -------------------------------

type frame struct {
	kind protocol.Kind
	body []byte
}

// pipeNet is one end of a loopback link. Frames sent on one end are delivered,
// in order, to the handlers of the other.
type pipeNet struct {
	id        string
	peer      *pipeNet
	mu        sync.Mutex
	handlers  map[protocol.Kind]interfaces.FrameHandler
	listeners []interfaces.PeerListener
	inbox     chan frame
	down      bool
	disc      int

	// Test hooks, applied to frames this end sends.
	tamper func(kind protocol.Kind, body []byte) []byte // return nil to drop
	gate   chan struct{}                                // when set, chunk sends wait on it
	wg     sync.WaitGroup
}

func newPipe(idA, idB string) (*pipeNet, *pipeNet) {
	a := &pipeNet{id: idA, handlers: map[protocol.Kind]interfaces.FrameHandler{}, inbox: make(chan frame, 64)}
	b := &pipeNet{id: idB, handlers: map[protocol.Kind]interfaces.FrameHandler{}, inbox: make(chan frame, 64)}
	a.peer, b.peer = b, a
	for _, n := range []*pipeNet{a, b} {
		n.wg.Add(1)
		go n.deliver()
	}
	return a, b
}

func (p *pipeNet) deliver() {
	defer p.wg.Done()
	for f := range p.inbox {
		p.mu.Lock()
		h := p.handlers[f.kind]
		p.mu.Unlock()
		if h != nil {
			h(p.peer.id, f.body)
		}
	}
}

func (p *pipeNet) stop() { close(p.inbox); p.wg.Wait() }

func (p *pipeNet) Start(context.Context) error { return nil }
func (p *pipeNet) Stop() error                 { return nil }
func (p *pipeNet) ConnectToPeer(context.Context, string) error {
	return nil
}
func (p *pipeNet) IsConnected(string) bool        { return !p.down }
func (p *pipeNet) ConnectedPeers() []string       { return nil }
func (p *pipeNet) PeerName(string) (string, bool) { return "", false }
func (p *pipeNet) Handle(k protocol.Kind, h interfaces.FrameHandler) {
	p.mu.Lock()
	p.handlers[k] = h
	p.mu.Unlock()
}
func (p *pipeNet) AddListener(l interfaces.PeerListener) {
	p.mu.Lock()
	p.listeners = append(p.listeners, l)
	p.mu.Unlock()
}
func (p *pipeNet) Disconnect(string) {
	p.mu.Lock()
	p.disc++
	p.mu.Unlock()
	p.drop()
}

// drop simulates the connection dying on both ends.
func (p *pipeNet) drop() {
	for _, n := range []*pipeNet{p, p.peer} {
		n.mu.Lock()
		n.down = true
		ls := append([]interfaces.PeerListener(nil), n.listeners...)
		n.mu.Unlock()
		for _, l := range ls {
			l.PeerDisconnected(n.peer.id)
		}
	}
}

func (p *pipeNet) Send(ctx context.Context, to string, kind protocol.Kind, body []byte) error {
	p.mu.Lock()
	down, tamper, gate := p.down, p.tamper, p.gate
	p.mu.Unlock()
	if to != p.peer.id {
		return errors.New("unknown peer")
	}
	if down {
		return errors.New("connection closed")
	}
	if gate != nil && kind == protocol.KindFileChunk {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	body = bytes.Clone(body)
	if tamper != nil {
		if body = tamper(kind, body); body == nil {
			return nil
		}
	}
	select {
	case p.peer.inbox <- frame{kind, body}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *pipeNet) SendJSON(ctx context.Context, to string, kind protocol.Kind, v any) error {
	b, err := protocol.Marshal(v)
	if err != nil {
		return err
	}
	return p.Send(ctx, to, kind, b)
}

// ---- Harness ---------------------------------------------------------------

type lines struct {
	mu sync.Mutex
	s  []string
}

func (l *lines) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.s = append(l.s, fmt.Sprintf(format, args...))
}
func (l *lines) text() string { l.mu.Lock(); defer l.mu.Unlock(); return strings.Join(l.s, "\n") }

const (
	idA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	idB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type side struct {
	m    *Manager
	net  *pipeNet
	out  *lines
	dir  string
	note *notifier
}

type notifier struct {
	mu    sync.Mutex
	files []string
}

func (n *notifier) received() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.files...)
}

func (n *notifier) NotifyMessageReceived(string, string) error { return nil }
func (n *notifier) NotifyFileReceived(s, f string) error {
	n.mu.Lock()
	n.files = append(n.files, f)
	n.mu.Unlock()
	return nil
}
func (n *notifier) NotifyPeerConnected(string) error    { return nil }
func (n *notifier) NotifyPeerDisconnected(string) error { return nil }
func (n *notifier) SetEnabled(bool)                     {}
func (n *notifier) IsEnabled() bool                     { return true }

func newPair(t *testing.T, mod ...func(*Options)) (sender, receiver *side) {
	t.Helper()
	na, nb := newPipe(idA, idB)
	mk := func(n *pipeNet, name string, opts ...func(*Options)) *side {
		s := &side{net: n, out: &lines{}, dir: filepath.Join(t.TempDir(), "downloads"), note: &notifier{}}
		o := Options{DownloadDir: s.dir, MaxFileSize: 64 << 20, AcceptTimeout: 5 * time.Second, ResultTimeout: 5 * time.Second}
		for _, f := range opts {
			f(&o)
		}
		s.m = NewManager(o, Deps{Logger: logger.Discard(), Net: n, Out: s.out, Notifier: s.note, Names: func(string) string { return name }})
		s.m.Register()
		return s
	}
	sender, receiver = mk(na, "sender"), mk(nb, "receiver", mod...)
	t.Cleanup(func() {
		sender.m.Close()
		receiver.m.Close()
		na.stop()
		nb.stop()
	})
	return
}

func writeTemp(t *testing.T, size int) (string, []byte) {
	t.Helper()
	data := make([]byte, size)
	_, _ = rand.Read(data)
	p := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p, data
}

func waitState(t *testing.T, s *side, id string, want Status) TransferState {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, st := range s.m.List() {
			if st.TransferID == id && st.Status == want {
				return st
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s to reach %q; have %+v\noutput:\n%s", id[:8], want, s.m.List(), s.out.text())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitOffer waits for an incoming offer on the receiver and returns its ID.
func waitOffer(t *testing.T, r *side) TransferState {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, st := range r.m.GetActiveTransfers() {
			if st.Direction == Receiving && st.Status == StatusOffered {
				return st
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no offer arrived; output:\n%s", r.out.text())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func noPartFiles(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), partSuffix) {
			t.Fatalf("leftover partial file %s", e.Name())
		}
	}
}

func rawOffer(id, name string, size int64, data []byte) protocol.FileOffer {
	sum := sha256.Sum256(data)
	return protocol.FileOffer{TransferID: id, Name: name, Size: size, SHA256: hex.EncodeToString(sum[:])}
}

const tid = "0123456789abcdef0123456789abcdef"

// ---- Tests -----------------------------------------------------------------

func TestTransferEndToEnd(t *testing.T) {
	s, r := newPair(t)
	path, data := writeTemp(t, 3*1024*1024+123) // not a multiple of the chunk size

	id, err := s.m.SendFile(bg, idB, path)
	if err != nil {
		t.Fatal(err)
	}
	offer := waitOffer(t, r)
	if offer.TransferID != id || offer.FileName != "payload.bin" || offer.FileSize != int64(len(data)) {
		t.Fatalf("offer: %+v", offer)
	}
	// The offer is registered before the user is told about it (so that an
	// immediate /getfile always finds it); the hint follows a moment later.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(r.out.text(), "/getfile "+id[:8]) {
		if time.Now().After(deadline) {
			t.Fatalf("receiver was not told how to accept:\n%s", r.out.text())
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Nothing touches the disk before the user agrees.
	if entries, _ := os.ReadDir(r.dir); len(entries) != 0 {
		t.Fatalf("files created before acceptance: %v", entries)
	}

	if _, err := r.m.Accept(id[:8]); err != nil {
		t.Fatal(err)
	}
	rs := waitState(t, r, id, StatusCompleted)
	ss := waitState(t, s, id, StatusCompleted)

	got, err := os.ReadFile(rs.Path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("received file differs (err=%v, %d bytes)", err, len(got))
	}
	if rs.BytesTransferred != int64(len(data)) || ss.BytesTransferred != int64(len(data)) {
		t.Fatalf("byte counts: recv=%d send=%d", rs.BytesTransferred, ss.BytesTransferred)
	}
	if filepath.Dir(rs.Path) != r.dir {
		t.Fatalf("file saved outside the download dir: %s", rs.Path)
	}
	noPartFiles(t, r.dir)
	if got := r.note.received(); len(got) != 1 {
		t.Fatalf("file notifications: %v", got)
	}
	if !strings.Contains(s.out.text(), "received \"payload.bin\" intact") {
		t.Fatalf("sender output:\n%s", s.out.text())
	}
}

func TestAutoAcceptAndEmptyFile(t *testing.T) {
	s, r := newPair(t, func(o *Options) { o.AutoAccept = true })
	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := s.m.SendFile(bg, idB, empty)
	if err != nil {
		t.Fatal(err)
	}
	rs := waitState(t, r, id, StatusCompleted)
	waitState(t, s, id, StatusCompleted)
	if st, err := os.Stat(rs.Path); err != nil || st.Size() != 0 {
		t.Fatalf("empty file: %v %v", st, err)
	}
}

func TestExistingFilesAreNeverOverwritten(t *testing.T) {
	s, r := newPair(t, func(o *Options) { o.AutoAccept = true })
	path, data := writeTemp(t, 1000)
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	precious := filepath.Join(r.dir, "payload.bin")
	if err := os.WriteFile(precious, []byte("precious"), 0o644); err != nil {
		t.Fatal(err)
	}

	id, _ := s.m.SendFile(bg, idB, path)
	rs := waitState(t, r, id, StatusCompleted)
	if got, _ := os.ReadFile(precious); string(got) != "precious" {
		t.Fatal("an existing file was overwritten")
	}
	if filepath.Base(rs.Path) != "payload (1).bin" {
		t.Fatalf("saved as %s", rs.Path)
	}
	if got, _ := os.ReadFile(rs.Path); !bytes.Equal(got, data) {
		t.Fatal("content mismatch")
	}
}

func TestRejectedOffer(t *testing.T) {
	s, r := newPair(t)
	path, _ := writeTemp(t, 100)
	id, _ := s.m.SendFile(bg, idB, path)
	offer := waitOffer(t, r)
	if _, err := r.m.Reject(offer.TransferID[:6]); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, s, id, StatusRejected)
	if st.Reason != "declined" {
		t.Fatalf("reason %q", st.Reason)
	}
	if _, err := r.m.Accept(id); err == nil {
		t.Fatal("accepted a rejected offer")
	}
	if entries, _ := os.ReadDir(r.dir); len(entries) != 0 {
		t.Fatalf("files left behind: %v", entries)
	}
}

func TestSenderGivesUpWhenNobodyAnswers(t *testing.T) {
	s, r := newPair(t, func(o *Options) { o.OfferTTL = time.Hour })
	s.m.opts.AcceptTimeout = 100 * time.Millisecond
	path, _ := writeTemp(t, 100)
	id, _ := s.m.SendFile(bg, idB, path)
	waitOffer(t, r)
	st := waitState(t, s, id, StatusFailed)
	if st.Reason != "no answer from peer" {
		t.Fatalf("reason %q", st.Reason)
	}
	// The abort reaches the receiver, so the stale offer disappears.
	waitState(t, r, id, StatusCancelled)
}

func TestUnansweredOffersExpire(t *testing.T) {
	s, r := newPair(t, func(o *Options) { o.OfferTTL = time.Minute })
	path, _ := writeTemp(t, 100)
	id, _ := s.m.SendFile(bg, idB, path)
	offer := waitOffer(t, r)

	r.m.reap(time.Now().Add(30 * time.Second)) // not yet
	if len(r.m.GetActiveTransfers()) != 1 {
		t.Fatal("offer expired early")
	}
	r.m.reap(time.Now().Add(2 * time.Minute))
	waitState(t, r, offer.TransferID, StatusCancelled)
	waitState(t, s, id, StatusRejected) // the sender is told it expired
}

func TestHostileFileNamesStayInsideTheDownloadDir(t *testing.T) {
	_, r := newPair(t, func(o *Options) { o.AutoAccept = true })
	cases := map[string]string{
		"../../escape.txt":     "escape.txt",
		`..\..\win-escape.txt`: "win-escape.txt",
		"/etc/cron.d/evil":     "evil",
		"CON":                  "_CON",
		"nul.txt":              "_nul.txt",
		"report\x00.pdf.exe":   "report.pdf.exe",
		"we<ird>:name|.txt":    "we_ird__name_.txt",
		"trailing dots...":     "trailing dots",
		"‮fdp.exe":             "fdp.exe",
	}
	i := 0
	for name, want := range cases {
		data := []byte("data-" + name)
		id := fmt.Sprintf("%032x", i+1)
		i++
		_ = r.net.peer.SendJSON(bg, idB, protocol.KindFileOffer, rawOffer(id, name, int64(len(data)), data))
		waitState(t, r, id, StatusActive)
		chunk, _ := protocol.EncodeChunk(id, data)
		_ = r.net.peer.Send(bg, idB, protocol.KindFileChunk, chunk)
		_ = r.net.peer.SendJSON(bg, idB, protocol.KindFileDone, protocol.FileDone{TransferID: id})
		st := waitState(t, r, id, StatusCompleted)
		if filepath.Base(st.Path) != want || filepath.Dir(st.Path) != r.dir {
			t.Errorf("%q saved as %q, want %q in %s", name, st.Path, want, r.dir)
		}
	}
	// And nothing escaped.
	parent := filepath.Dir(r.dir)
	for _, bad := range []string{"escape.txt", "win-escape.txt", "evil"} {
		if _, err := os.Stat(filepath.Join(parent, bad)); err == nil {
			t.Errorf("%s escaped to the parent directory", bad)
		}
	}
}

func TestBadOffersAreRefusedWithAReason(t *testing.T) {
	_, r := newPair(t, func(o *Options) { o.MaxFileSize = 1000 })
	good := rawOffer(tid, "ok.txt", 10, []byte("0123456789"))

	cases := map[string]protocol.FileOffer{
		"too large":        {TransferID: tid, Name: "big.bin", Size: 1001, SHA256: good.SHA256},
		"negative size":    {TransferID: tid, Name: "neg.bin", Size: -1, SHA256: good.SHA256},
		"empty name":       {TransferID: tid, Name: "", Size: 1, SHA256: good.SHA256},
		"dots only":        {TransferID: tid, Name: "..", Size: 1, SHA256: good.SHA256},
		"short checksum":   {TransferID: tid, Name: "a", Size: 1, SHA256: "abcd"},
		"non-hex checksum": {TransferID: tid, Name: "a", Size: 1, SHA256: strings.Repeat("zz", 32)},
	}
	var replies []protocol.FileAccept
	var mu sync.Mutex
	r.net.peer.Handle(protocol.KindFileAccept, func(_ string, body []byte) {
		var a protocol.FileAccept
		_ = protocol.Unmarshal(body, &a)
		mu.Lock()
		replies = append(replies, a)
		mu.Unlock()
	})
	for _, o := range cases {
		_ = r.net.peer.SendJSON(bg, idB, protocol.KindFileOffer, o)
	}
	// Offers with an unusable transfer ID are dropped without a reply.
	_ = r.net.peer.SendJSON(bg, idB, protocol.KindFileOffer, protocol.FileOffer{TransferID: "short", Name: "a", Size: 1, SHA256: good.SHA256})
	_ = r.net.peer.SendJSON(bg, idB, protocol.KindFileOffer, protocol.FileOffer{TransferID: strings.ToUpper(tid), Name: "a", Size: 1, SHA256: good.SHA256})

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(replies)
		mu.Unlock()
		if n == len(cases) || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(replies) != len(cases) {
		t.Fatalf("got %d refusals for %d bad offers", len(replies), len(cases))
	}
	for _, a := range replies {
		if a.Accepted || a.Reason == "" {
			t.Errorf("bad offer not refused with a reason: %+v", a)
		}
	}
	if len(r.m.List()) != 0 {
		t.Fatalf("bad offers created transfers: %+v", r.m.List())
	}
}

func TestOfferFloodIsLimited(t *testing.T) {
	_, r := newPair(t, func(o *Options) { o.MaxPendingPerPeer = 3; o.MaxActive = 5 })
	refused := make(chan protocol.FileAccept, 64)
	r.net.peer.Handle(protocol.KindFileAccept, func(_ string, body []byte) {
		var a protocol.FileAccept
		_ = protocol.Unmarshal(body, &a)
		refused <- a
	})
	for i := range 10 {
		o := rawOffer(fmt.Sprintf("%032x", i+1), fmt.Sprintf("f%d", i), 1, []byte("x"))
		_ = r.net.peer.SendJSON(bg, idB, protocol.KindFileOffer, o)
	}
	for range 7 {
		select {
		case a := <-refused:
			if a.Accepted {
				t.Fatal("refusal expected")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("expected refusals for the offers over the limit")
		}
	}
	if n := len(r.m.GetActiveTransfers()); n != 3 {
		t.Fatalf("%d pending offers kept, limit is 3", n)
	}
}

func TestDataBeforeAcceptanceIsIgnoredAndPeerIsEventuallyCut(t *testing.T) {
	_, r := newPair(t)
	data := []byte("unsolicited")
	_ = r.net.peer.SendJSON(bg, idB, protocol.KindFileOffer, rawOffer(tid, "x.txt", int64(len(data)), data))
	waitOffer(t, r)

	chunk, _ := protocol.EncodeChunk(tid, data)
	for range maxStrikes + 5 {
		_ = r.net.peer.Send(bg, idB, protocol.KindFileChunk, chunk)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.net.mu.Lock()
		cut := r.net.disc
		r.net.mu.Unlock()
		if cut > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("peer streaming unsolicited data was never disconnected")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if entries, _ := os.ReadDir(r.dir); len(entries) != 0 {
		t.Fatalf("unsolicited data reached the disk: %v", entries)
	}
}

func TestTooMuchDataAbortsTransfer(t *testing.T) {
	_, r := newPair(t, func(o *Options) { o.AutoAccept = true })
	data := []byte("short")
	_ = r.net.peer.SendJSON(bg, idB, protocol.KindFileOffer, rawOffer(tid, "x.txt", int64(len(data)), data))
	waitState(t, r, tid, StatusActive)
	chunk, _ := protocol.EncodeChunk(tid, []byte("this is longer than five bytes"))
	_ = r.net.peer.Send(bg, idB, protocol.KindFileChunk, chunk)
	st := waitState(t, r, tid, StatusFailed)
	if !strings.Contains(st.Reason, "more data") {
		t.Fatalf("reason %q", st.Reason)
	}
	noPartFiles(t, r.dir)
}

func TestCorruptedDataIsDetected(t *testing.T) {
	s, r := newPair(t, func(o *Options) { o.AutoAccept = true })
	path, _ := writeTemp(t, 200_000)
	s.net.mu.Lock()
	s.net.tamper = func(kind protocol.Kind, body []byte) []byte {
		if kind == protocol.KindFileChunk {
			body[len(body)-1] ^= 0xFF // flip bits in every chunk's last byte
		}
		return body
	}
	s.net.mu.Unlock()

	id, _ := s.m.SendFile(bg, idB, path)
	rs := waitState(t, r, id, StatusFailed)
	if rs.Reason != "checksum mismatch" {
		t.Fatalf("reason %q", rs.Reason)
	}
	ss := waitState(t, s, id, StatusFailed)
	if !strings.Contains(ss.Reason, "checksum mismatch") {
		t.Fatalf("sender was told: %q", ss.Reason)
	}
	noPartFiles(t, r.dir)
	entries, _ := os.ReadDir(r.dir)
	if len(entries) != 0 {
		t.Fatalf("a corrupted file was kept: %v", entries)
	}
}

func TestTruncatedTransferIsDetected(t *testing.T) {
	s, r := newPair(t, func(o *Options) { o.AutoAccept = true })
	path, _ := writeTemp(t, 5*protocol.MaxChunkSize)
	n := 0
	s.net.mu.Lock()
	s.net.tamper = func(kind protocol.Kind, body []byte) []byte {
		if kind == protocol.KindFileChunk {
			n++
			if n == 3 {
				return nil // a chunk is lost
			}
		}
		return body
	}
	s.net.mu.Unlock()
	id, _ := s.m.SendFile(bg, idB, path)
	rs := waitState(t, r, id, StatusFailed)
	if !strings.Contains(rs.Reason, "incomplete") {
		t.Fatalf("reason %q", rs.Reason)
	}
	noPartFiles(t, r.dir)
}

func TestStalledTransferIsReaped(t *testing.T) {
	s, r := newPair(t, func(o *Options) { o.AutoAccept = true; o.IdleTimeout = time.Minute })
	path, _ := writeTemp(t, 10*protocol.MaxChunkSize)
	gate := make(chan struct{})
	s.net.mu.Lock()
	s.net.gate = gate
	s.net.mu.Unlock()

	id, _ := s.m.SendFile(bg, idB, path)
	waitState(t, r, id, StatusActive)
	r.m.reap(time.Now().Add(30 * time.Second))
	if len(r.m.GetActiveTransfers()) != 1 {
		t.Fatal("reaped too early")
	}
	r.m.reap(time.Now().Add(2 * time.Minute))
	st := waitState(t, r, id, StatusFailed)
	if st.Reason != "stalled" {
		t.Fatalf("reason %q", st.Reason)
	}
	noPartFiles(t, r.dir)
	close(gate)
	waitState(t, s, id, StatusCancelled) // the abort reaches the sender
}

func TestPeerDisconnectMidTransferCleansUp(t *testing.T) {
	s, r := newPair(t, func(o *Options) { o.AutoAccept = true })
	path, _ := writeTemp(t, 10*protocol.MaxChunkSize)
	gate := make(chan struct{})
	s.net.mu.Lock()
	s.net.gate = gate
	s.net.mu.Unlock()
	id, _ := s.m.SendFile(bg, idB, path)
	waitState(t, r, id, StatusActive)

	s.net.drop()
	st := waitState(t, r, id, StatusFailed)
	if st.Reason != "peer disconnected" {
		t.Fatalf("reason %q", st.Reason)
	}
	waitState(t, s, id, StatusFailed)
	noPartFiles(t, r.dir)
}

func TestCancelFromEitherSide(t *testing.T) {
	for _, bySender := range []bool{true, false} {
		s, r := newPair(t, func(o *Options) { o.AutoAccept = true })
		path, _ := writeTemp(t, 20*protocol.MaxChunkSize)
		gate := make(chan struct{})
		s.net.mu.Lock()
		s.net.gate = gate
		s.net.mu.Unlock()
		id, _ := s.m.SendFile(bg, idB, path)
		waitState(t, r, id, StatusActive)

		canceller := r
		if bySender {
			canceller = s
		}
		if _, err := canceller.m.Cancel(id[:8]); err != nil {
			t.Fatal(err)
		}
		waitState(t, s, id, StatusCancelled)
		waitState(t, r, id, StatusCancelled)
		noPartFiles(t, r.dir)
		close(gate)
		if _, err := canceller.m.Cancel(id); err == nil {
			t.Fatal("cancelled a finished transfer")
		}
	}
}

func TestOnlyTheOwningPeerCanDriveATransfer(t *testing.T) {
	_, r := newPair(t, func(o *Options) { o.AutoAccept = true })
	data := []byte("legit data")
	_ = r.net.peer.SendJSON(bg, idB, protocol.KindFileOffer, rawOffer(tid, "legit.txt", int64(len(data)), data))
	waitState(t, r, tid, StatusActive)

	// A different authenticated peer tries to feed, finish, abort and
	// answer someone else's transfer.
	const mallory = "cccccccccccccccccccccccccccccccc"
	chunk, _ := protocol.EncodeChunk(tid, []byte("evil data!"))
	r.m.onChunk(mallory, chunk)
	r.m.onDone(mallory, mustJSON(protocol.FileDone{TransferID: tid}))
	r.m.onAbort(mallory, mustJSON(protocol.FileAbort{TransferID: tid}))
	r.m.onAccept(mallory, mustJSON(protocol.FileAccept{TransferID: tid, Accepted: true}))
	r.m.onResult(mallory, mustJSON(protocol.FileResult{TransferID: tid, OK: true}))

	if st := r.m.GetActiveTransfers(); len(st) != 1 || st[0].Status != StatusActive || st[0].BytesTransferred != 0 {
		t.Fatalf("transfer was disturbed: %+v", st)
	}

	// The real owner can still finish it.
	good, _ := protocol.EncodeChunk(tid, data)
	_ = r.net.peer.Send(bg, idB, protocol.KindFileChunk, good)
	_ = r.net.peer.SendJSON(bg, idB, protocol.KindFileDone, protocol.FileDone{TransferID: tid})
	st := waitState(t, r, tid, StatusCompleted)
	if got, _ := os.ReadFile(st.Path); !bytes.Equal(got, data) {
		t.Fatalf("content %q", got)
	}
}

func mustJSON(v any) []byte { b, _ := protocol.Marshal(v); return b }

func TestSendFileValidation(t *testing.T) {
	s, _ := newPair(t)
	if _, err := s.m.SendFile(bg, idB, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
	if _, err := s.m.SendFile(bg, idB, t.TempDir()); err == nil {
		t.Fatal("directory accepted")
	}
}

func TestSendToUnreachablePeerFailsCleanly(t *testing.T) {
	s, _ := newPair(t)
	s.net.mu.Lock()
	s.net.down = true
	s.net.mu.Unlock()
	path, _ := writeTemp(t, 100)
	id, err := s.m.SendFile(bg, idB, path)
	if err != nil {
		t.Fatal(err)
	}
	st := waitState(t, s, id, StatusFailed)
	if !strings.Contains(st.Reason, "could not reach peer") {
		t.Fatalf("reason %q", st.Reason)
	}
}

func TestSeveralTransfersAtOnce(t *testing.T) {
	s, r := newPair(t, func(o *Options) { o.AutoAccept = true })
	type job struct {
		id   string
		data []byte
	}
	var jobs []job
	for i := range 5 {
		path, data := writeTemp(t, 200_000+i*7919)
		id, err := s.m.SendFile(bg, idB, path)
		if err != nil {
			t.Fatal(err)
		}
		jobs = append(jobs, job{id, data})
	}
	for _, j := range jobs {
		st := waitState(t, r, j.id, StatusCompleted)
		if got, _ := os.ReadFile(st.Path); !bytes.Equal(got, j.data) {
			t.Fatalf("transfer %s corrupted", j.id[:8])
		}
	}
	noPartFiles(t, r.dir)
}

func TestResolveAndListing(t *testing.T) {
	s, r := newPair(t)
	path, _ := writeTemp(t, 10)
	id, _ := s.m.SendFile(bg, idB, path)
	waitOffer(t, r)

	if _, err := r.m.Resolve("abc"); err == nil {
		t.Fatal("3-character prefixes must be refused")
	}
	if _, err := r.m.Resolve("ffffffff"); err == nil {
		t.Fatal("unknown prefix resolved")
	}
	if st, err := r.m.Resolve(strings.ToUpper(id[:6])); err != nil || st.TransferID != id {
		t.Fatalf("resolve: %v %v", st, err)
	}
	if _, err := s.m.Accept(id[:8]); err == nil {
		t.Fatal("the sender cannot accept its own outgoing offer")
	}
	if _, err := r.m.Accept(id[:8]); err != nil {
		t.Fatal(err)
	}
	waitState(t, r, id, StatusCompleted)
	list := r.m.List()
	if len(list) != 1 || list[0].Status != StatusCompleted {
		t.Fatalf("list: %+v", list)
	}
}

func TestFinishedHistoryIsBounded(t *testing.T) {
	_, r := newPair(t)
	for i := range maxFinished + 20 {
		tr := &transfer{state: TransferState{TransferID: fmt.Sprintf("%032x", i), PeerID: idA, Status: StatusActive}}
		r.m.mu.Lock()
		r.m.active[key(idA, tr.state.TransferID)] = tr
		r.m.mu.Unlock()
		r.m.finish(tr, StatusCancelled, "x", false)
	}
	if n := len(r.m.List()); n != maxFinished {
		t.Fatalf("history has %d entries, want %d", n, maxFinished)
	}
}

func TestCloseCleansUpEverything(t *testing.T) {
	s, r := newPair(t, func(o *Options) { o.AutoAccept = true })
	path, _ := writeTemp(t, 10*protocol.MaxChunkSize)
	gate := make(chan struct{})
	s.net.mu.Lock()
	s.net.gate = gate
	s.net.mu.Unlock()
	id, _ := s.m.SendFile(bg, idB, path)
	waitState(t, r, id, StatusActive)

	done := make(chan struct{})
	go func() { r.m.Close(); s.m.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung with a transfer in flight")
	}
	noPartFiles(t, r.dir)
	if _, err := s.m.SendFile(bg, idB, path); err == nil {
		t.Fatal("SendFile after Close")
	}
	close(gate)
}

var bg = context.Background()
