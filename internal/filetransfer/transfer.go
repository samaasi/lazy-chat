// Package filetransfer sends and receives files over the authenticated peer
// connection.
//
// The protocol is offer / accept / stream / verify:
//
//	sender                         receiver
//	  FileOffer (name,size,sha256) ->
//	                               <- FileAccept (after the user agrees)
//	  FileChunk x N (raw bytes)    ->
//	  FileDone                     ->
//	                               <- FileResult (size and SHA-256 checked)
//
// Nothing is written to disk before the receiver accepts (unless auto-accept
// is configured). The receiver never trusts the sender's file name or size:
// the name is reduced to a safe single path element, the size is capped, data
// goes to an exclusively-created temporary file, and the file only appears
// under its final name after the checksum matches. Files are streamed in
// 32 KiB chunks, so memory use is constant whatever the file size.
package filetransfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/protocol"
	"github.com/samaasi/lazy-chat/internal/ui"
	"github.com/samaasi/lazy-chat/internal/utils"
)

// Status is the lifecycle state of a transfer.
type Status string

const (
	StatusOffered   Status = "offered"   // waiting for the receiver's decision
	StatusActive    Status = "active"    // data is flowing
	StatusCompleted Status = "completed" // done and verified
	StatusFailed    Status = "failed"
	StatusRejected  Status = "rejected"
	StatusCancelled Status = "cancelled"
)

func (s Status) finished() bool { return s != StatusOffered && s != StatusActive }

// Direction says which side of a transfer we are.
type Direction string

const (
	Sending   Direction = "send"
	Receiving Direction = "receive"
)

// TransferState is an immutable snapshot of a transfer.
type TransferState struct {
	TransferID       string
	Direction        Direction
	PeerID           string
	FileName         string
	FileSize         int64
	BytesTransferred int64
	Status           Status
	Reason           string // why a transfer failed or was refused
	StartedAt        time.Time
	CompletedAt      time.Time
	Path             string // final location of a received file
}

// Options configures a Manager. Zero values select the defaults.
type Options struct {
	DownloadDir string
	MaxFileSize int64         // largest file we accept
	AutoAccept  bool          // accept offers without asking
	OfferTTL    time.Duration // how long an unanswered incoming offer is kept
	// AcceptTimeout is how long a sender waits for the receiver's decision.
	AcceptTimeout time.Duration
	// ResultTimeout is how long a sender waits for the final verification.
	ResultTimeout time.Duration
	// IdleTimeout aborts an active transfer that makes no progress.
	IdleTimeout time.Duration

	MaxActive         int // simultaneous incoming transfers (offered + active)
	MaxPendingPerPeer int // unanswered offers from one peer
}

func (o *Options) applyDefaults() {
	if o.MaxFileSize <= 0 {
		o.MaxFileSize = 256 << 20
	}
	if o.OfferTTL <= 0 {
		o.OfferTTL = 5 * time.Minute
	}
	if o.AcceptTimeout <= 0 {
		o.AcceptTimeout = 5 * time.Minute
	}
	if o.ResultTimeout <= 0 {
		o.ResultTimeout = 60 * time.Second
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 60 * time.Second
	}
	if o.MaxActive <= 0 {
		o.MaxActive = 8
	}
	if o.MaxPendingPerPeer <= 0 {
		o.MaxPendingPerPeer = 4
	}
}

// Printer receives lines meant for the user.
type Printer interface {
	Printf(format string, args ...any)
}

// Deps are the collaborators of a Manager.
type Deps struct {
	Logger   interfaces.Logger
	Net      interfaces.NetworkManager
	Out      Printer
	Display  ui.Display // progress bars; may be nil
	Notifier interfaces.NotificationManager
	Names    func(peerID string) string // display name for a peer
}

const (
	// maxFinished is how many finished transfers are remembered for listing.
	maxFinished = 50
	// maxStrikes disconnects a peer that keeps streaming data we never accepted.
	maxStrikes  = 64
	janitorTick = 2 * time.Second
	partPrefix  = ".lazychat-"
	partSuffix  = ".part"
)

// transfer is the internal, mutable record.
type transfer struct {
	mu    sync.Mutex
	state TransferState

	closing bool // finish() is in progress; no further data is accepted

	// receiving
	sha      string // expected SHA-256 (hex)
	file     *os.File
	tmpPath  string
	hasher   hash.Hash
	activity time.Time
	expires  time.Time

	// sending
	cancel   context.CancelFunc
	acceptCh chan protocol.FileAccept
	resultCh chan protocol.FileResult
}

func (t *transfer) snapshot() TransferState {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

// Manager manages file transfers. It is safe for concurrent use.
type Manager struct {
	opts Options
	Deps

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	progress *ui.MultiProgressManager

	mu        sync.Mutex
	active    map[string]*transfer // key: peerID + "/" + transferID
	finished  []TransferState      // newest last, capped
	strikes   map[string]int
	closed    bool
	janitorOn bool
}

var _ interfaces.PeerListener = (*Manager)(nil)

func key(peerID, transferID string) string { return peerID + "/" + transferID }

// NewManager creates a transfer manager.
func NewManager(opts Options, deps Deps) *Manager {
	opts.applyDefaults()
	if deps.Names == nil {
		deps.Names = func(id string) string { return id }
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		opts: opts, Deps: deps, ctx: ctx, cancel: cancel,
		active:  make(map[string]*transfer),
		strikes: make(map[string]int),
	}
	if deps.Display != nil {
		m.progress = ui.NewMultiProgressManager(deps.Display)
	}
	return m
}

// Register attaches the manager to the network and starts its housekeeping.
func (m *Manager) Register() {
	m.Net.Handle(protocol.KindFileOffer, m.onOffer)
	m.Net.Handle(protocol.KindFileAccept, m.onAccept)
	m.Net.Handle(protocol.KindFileChunk, m.onChunk)
	m.Net.Handle(protocol.KindFileDone, m.onDone)
	m.Net.Handle(protocol.KindFileResult, m.onResult)
	m.Net.Handle(protocol.KindFileAbort, m.onAbort)
	m.Net.AddListener(m)

	m.mu.Lock()
	if !m.janitorOn && !m.closed {
		m.janitorOn = true
		m.wg.Add(1)
		go m.janitor()
	}
	m.mu.Unlock()
}

// Close cancels every transfer, removes partial files and waits for workers.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	all := make([]*transfer, 0, len(m.active))
	for _, t := range m.active {
		all = append(all, t)
	}
	m.mu.Unlock()

	m.cancel()
	for _, t := range all {
		m.finish(t, StatusCancelled, "shutting down", false)
	}
	m.wg.Wait()
}

// ---- Helpers ---------------------------------------------------------------

func validTransferID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func (m *Manager) lookup(peerID, transferID string) *transfer {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active[key(peerID, transferID)]
}

func (m *Manager) say(format string, args ...any) {
	if m.Out != nil {
		m.Out.Printf(format, args...)
	}
}

func (m *Manager) send(ctx context.Context, peerID string, kind protocol.Kind, payload any) error {
	return m.Net.SendJSON(ctx, peerID, kind, payload)
}

// sendAsync sends from handlers, which run on a connection's read goroutine
// and must not block on that same connection's full send queue.
func (m *Manager) sendAsync(peerID string, kind protocol.Kind, payload any) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
		defer cancel()
		if err := m.send(ctx, peerID, kind, payload); err != nil {
			m.Logger.Debug("Failed to send file control frame", "peer", short(peerID), "error", err)
		}
	}()
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func shortTransfer(id string) string { return short(id) }

// finish moves a transfer to a terminal state exactly once. Resources are
// released first and the terminal status is published last, so anyone who sees
// "failed"/"cancelled" can rely on the partial file already being gone. If
// notifyPeer is set an abort is sent to the other side.
func (m *Manager) finish(t *transfer, st Status, reason string, notifyPeer bool) {
	t.mu.Lock()
	if t.state.Status.finished() || t.closing {
		t.mu.Unlock()
		return
	}
	t.closing = true
	file, tmp, cancel := t.file, t.tmpPath, t.cancel
	t.file, t.tmpPath, t.hasher = nil, "", nil
	t.mu.Unlock()

	if file != nil {
		_ = file.Close()
	}
	if tmp != "" && st != StatusCompleted {
		_ = os.Remove(tmp)
	}
	if cancel != nil {
		cancel()
	}

	t.mu.Lock()
	t.state.Status = st
	t.state.Reason = reason
	t.state.CompletedAt = time.Now()
	snap := t.state
	t.mu.Unlock()

	if m.progress != nil {
		if st == StatusCompleted {
			m.progress.FinishProgress(key(snap.PeerID, snap.TransferID))
		} else {
			m.progress.RemoveProgress(key(snap.PeerID, snap.TransferID))
		}
	}

	m.mu.Lock()
	delete(m.active, key(snap.PeerID, snap.TransferID))
	m.finished = append(m.finished, snap)
	if len(m.finished) > maxFinished {
		m.finished = m.finished[len(m.finished)-maxFinished:]
	}
	m.mu.Unlock()

	if notifyPeer {
		m.sendAsync(snap.PeerID, protocol.KindFileAbort, protocol.FileAbort{TransferID: snap.TransferID, Reason: reason})
	}
}

// ---- Queries ---------------------------------------------------------------

// List returns unfinished transfers followed by recently finished ones.
func (m *Manager) List() []TransferState {
	m.mu.Lock()
	active := make([]*transfer, 0, len(m.active))
	for _, t := range m.active {
		active = append(active, t)
	}
	finished := slices.Clone(m.finished)
	m.mu.Unlock()

	out := make([]TransferState, 0, len(active)+len(finished))
	for _, t := range active {
		out = append(out, t.snapshot())
	}
	slices.SortFunc(out, func(a, b TransferState) int { return a.StartedAt.Compare(b.StartedAt) })
	slices.Reverse(finished)
	return append(out, finished...)
}

// GetActiveTransfers returns the transfers that have not finished.
func (m *Manager) GetActiveTransfers() []TransferState {
	var out []TransferState
	for _, s := range m.List() {
		if !s.Status.finished() {
			out = append(out, s)
		}
	}
	return out
}

// Resolve finds a transfer by full ID or unique prefix (at least 4 characters).
func (m *Manager) Resolve(prefix string) (TransferState, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if len(prefix) < 4 {
		return TransferState{}, errors.New("transfer ID must be at least 4 characters")
	}
	var found []TransferState
	for _, s := range m.List() {
		if strings.HasPrefix(s.TransferID, prefix) && !s.Status.finished() {
			found = append(found, s)
		}
	}
	switch len(found) {
	case 0:
		return TransferState{}, apperrors.NewFileTransferError("no such open transfer: "+prefix, nil)
	case 1:
		return found[0], nil
	default:
		return TransferState{}, apperrors.NewFileTransferError("ambiguous transfer ID; use more characters", nil)
	}
}

// ---- Sending ---------------------------------------------------------------

// SendFile offers a file to a peer and, once accepted, streams it in the
// background. It returns the transfer ID immediately.
func (m *Manager) SendFile(_ context.Context, peerID, filePath string) (string, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return "", apperrors.NewFileTransferError("cannot read file", err)
	}
	if !info.Mode().IsRegular() {
		return "", apperrors.NewFileTransferError("not a regular file: "+filepath.Base(filePath), nil)
	}

	ctx, cancel := context.WithCancel(m.ctx)
	t := &transfer{
		cancel:   cancel,
		acceptCh: make(chan protocol.FileAccept, 1),
		resultCh: make(chan protocol.FileResult, 1),
		state: TransferState{
			TransferID: utils.NewID(), Direction: Sending, PeerID: peerID,
			FileName: filepath.Base(filePath), FileSize: info.Size(),
			Status: StatusOffered, StartedAt: time.Now(),
		},
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		cancel()
		return "", apperrors.ErrAppNotRunning
	}
	m.active[key(peerID, t.state.TransferID)] = t
	m.wg.Add(1)
	m.mu.Unlock()

	go func() {
		defer m.wg.Done()
		m.runSend(ctx, t, filePath)
	}()
	return t.state.TransferID, nil
}

func (m *Manager) runSend(ctx context.Context, t *transfer, path string) {
	snap := t.snapshot()
	fail := func(reason string, notify bool) { m.finish(t, StatusFailed, reason, notify) }
	peerName := m.Names(snap.PeerID)

	f, err := os.Open(path)
	if err != nil {
		fail("cannot open file: "+err.Error(), false)
		m.say("* File %q not sent: %v", snap.FileName, err)
		return
	}
	defer f.Close()

	// Hash first so the receiver can verify what it gets.
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		fail("cannot read file: "+err.Error(), false)
		m.say("* File %q not sent: %v", snap.FileName, err)
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		fail("cannot rewind file", false)
		return
	}

	offer := protocol.FileOffer{TransferID: snap.TransferID, Name: snap.FileName, Size: size, SHA256: hex.EncodeToString(h.Sum(nil))}
	t.mu.Lock()
	t.state.FileSize = size
	t.mu.Unlock()
	if err := m.send(ctx, snap.PeerID, protocol.KindFileOffer, offer); err != nil {
		fail("could not reach peer: "+err.Error(), false)
		m.say("* File %q not sent to %s: %v", snap.FileName, peerName, err)
		return
	}
	m.say("* Offered %q (%s) to %s - waiting for them to accept", snap.FileName, ui.FormatBytes(size), peerName)

	// Wait for the receiver's decision.
	select {
	case a := <-t.acceptCh:
		if !a.Accepted {
			reason := utils.SanitizeText(a.Reason, 100)
			if reason == "" {
				reason = "declined"
			}
			m.finish(t, StatusRejected, reason, false)
			m.say("* %s refused %q: %s", peerName, snap.FileName, reason)
			return
		}
	case <-time.After(m.opts.AcceptTimeout):
		fail("no answer from peer", true)
		m.say("* %s did not answer the offer of %q", peerName, snap.FileName)
		return
	case <-ctx.Done():
		m.finish(t, StatusCancelled, "cancelled", true)
		return
	}

	t.mu.Lock()
	t.state.Status = StatusActive
	t.mu.Unlock()
	pkey := key(snap.PeerID, snap.TransferID)
	if m.progress != nil {
		m.progress.AddProgress(pkey, fmt.Sprintf("Sending %s", snap.FileName), size)
	}

	buf := make([]byte, protocol.MaxChunkSize)
	var sent int64
	for sent < size {
		n, err := f.Read(buf)
		if n > 0 {
			body, encErr := protocol.EncodeChunk(snap.TransferID, buf[:n])
			if encErr != nil {
				fail("internal error: "+encErr.Error(), true)
				return
			}
			if err := m.Net.Send(ctx, snap.PeerID, protocol.KindFileChunk, body); err != nil {
				if ctx.Err() != nil {
					m.finish(t, StatusCancelled, "cancelled", false)
				} else {
					fail("connection lost: "+err.Error(), false)
					m.say("* Transfer of %q to %s failed: %v", snap.FileName, peerName, err)
				}
				return
			}
			sent += int64(n)
			t.mu.Lock()
			t.state.BytesTransferred = sent
			t.mu.Unlock()
			if m.progress != nil {
				m.progress.UpdateProgress(pkey, sent)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			fail("read error: "+err.Error(), true)
			m.say("* Transfer of %q failed: %v", snap.FileName, err)
			return
		}
	}
	if sent != size {
		// The file changed while we were sending it.
		fail("file changed during transfer", true)
		m.say("* %q changed while it was being sent; transfer aborted", snap.FileName)
		return
	}

	if err := m.send(ctx, snap.PeerID, protocol.KindFileDone, protocol.FileDone{TransferID: snap.TransferID}); err != nil {
		fail("connection lost: "+err.Error(), false)
		return
	}

	select {
	case r := <-t.resultCh:
		if r.OK {
			m.finish(t, StatusCompleted, "", false)
			m.say("* %s received %q intact", peerName, snap.FileName)
		} else {
			reason := utils.SanitizeText(r.Reason, 100)
			m.finish(t, StatusFailed, "receiver reported: "+reason, false)
			m.say("* %s could not store %q: %s", peerName, snap.FileName, reason)
		}
	case <-time.After(m.opts.ResultTimeout):
		fail("no confirmation from peer", true)
		m.say("* %s did not confirm receipt of %q", peerName, snap.FileName)
	case <-ctx.Done():
		m.finish(t, StatusCancelled, "cancelled", false)
	}
}

func (m *Manager) onAccept(from string, body []byte) {
	var a protocol.FileAccept
	if err := protocol.Unmarshal(body, &a); err != nil {
		return
	}
	t := m.lookup(from, a.TransferID)
	if t == nil {
		return
	}
	t.mu.Lock()
	ok := t.state.Direction == Sending && t.state.Status == StatusOffered
	t.mu.Unlock()
	if !ok {
		return
	}
	select {
	case t.acceptCh <- a:
	default: // already answered
	}
}

func (m *Manager) onResult(from string, body []byte) {
	var r protocol.FileResult
	if err := protocol.Unmarshal(body, &r); err != nil {
		return
	}
	t := m.lookup(from, r.TransferID)
	if t == nil {
		return
	}
	t.mu.Lock()
	ok := t.state.Direction == Sending && t.state.Status == StatusActive
	t.mu.Unlock()
	if !ok {
		return
	}
	select {
	case t.resultCh <- r:
	default:
	}
}

// ---- Receiving -------------------------------------------------------------

func (m *Manager) reject(peerID, transferID, reason string) {
	m.sendAsync(peerID, protocol.KindFileAccept, protocol.FileAccept{TransferID: transferID, Accepted: false, Reason: reason})
}

func (m *Manager) onOffer(from string, body []byte) {
	var o protocol.FileOffer
	if err := protocol.Unmarshal(body, &o); err != nil || !validTransferID(o.TransferID) {
		return
	}

	name, nameErr := utils.SafeFileName(o.Name)
	switch {
	case nameErr != nil:
		m.reject(from, o.TransferID, "unacceptable file name")
		return
	case o.Size < 0 || o.Size > m.opts.MaxFileSize:
		m.reject(from, o.TransferID, fmt.Sprintf("file too large (limit %s)", ui.FormatBytes(m.opts.MaxFileSize)))
		return
	case !validSHA256(o.SHA256):
		m.reject(from, o.TransferID, "malformed offer")
		return
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	if _, dup := m.active[key(from, o.TransferID)]; dup {
		m.mu.Unlock()
		return
	}
	incoming, pendingFromPeer := 0, 0
	for _, t := range m.active {
		t.mu.Lock()
		if t.state.Direction == Receiving {
			incoming++
			if t.state.PeerID == from && t.state.Status == StatusOffered {
				pendingFromPeer++
			}
		}
		t.mu.Unlock()
	}
	if incoming >= m.opts.MaxActive || pendingFromPeer >= m.opts.MaxPendingPerPeer {
		m.mu.Unlock()
		m.reject(from, o.TransferID, "too many transfers in progress")
		return
	}
	now := time.Now()
	t := &transfer{
		sha: strings.ToLower(o.SHA256), expires: now.Add(m.opts.OfferTTL), activity: now,
		state: TransferState{
			TransferID: o.TransferID, Direction: Receiving, PeerID: from,
			FileName: name, FileSize: o.Size, Status: StatusOffered, StartedAt: now,
		},
	}
	m.active[key(from, o.TransferID)] = t
	m.mu.Unlock()

	who := m.Names(from)
	if m.opts.AutoAccept {
		m.say("* Receiving %q (%s) from %s (auto-accepted)", name, ui.FormatBytes(o.Size), who)
		if _, err := m.accept(t); err != nil {
			m.say("* Could not accept %q: %v", name, err)
		}
		return
	}
	m.say("* %s wants to send you %q (%s) - /getfile %s  or  /rejectfile %s",
		who, name, ui.FormatBytes(o.Size), shortTransfer(o.TransferID), shortTransfer(o.TransferID))
	if m.Notifier != nil {
		_ = m.Notifier.NotifyMessageReceived(who, "wants to send you "+name)
	}
}

// Accept agrees to receive an offered file (identified by ID or unique prefix).
func (m *Manager) Accept(idOrPrefix string) (TransferState, error) {
	s, err := m.Resolve(idOrPrefix)
	if err != nil {
		return TransferState{}, err
	}
	t := m.lookup(s.PeerID, s.TransferID)
	if t == nil || s.Direction != Receiving {
		return TransferState{}, apperrors.NewFileTransferError("that transfer is not an incoming offer", nil)
	}
	return m.accept(t)
}

func (m *Manager) accept(t *transfer) (TransferState, error) {
	t.mu.Lock()
	if t.state.Status != StatusOffered {
		t.mu.Unlock()
		return TransferState{}, apperrors.NewFileTransferError("offer is no longer open", nil)
	}
	snap := t.state
	t.mu.Unlock()

	if err := os.MkdirAll(m.opts.DownloadDir, 0o755); err != nil {
		m.finish(t, StatusFailed, "cannot create download directory", true)
		return TransferState{}, apperrors.NewFileTransferError("cannot create download directory", err)
	}
	tmp := filepath.Join(m.opts.DownloadDir, partPrefix+snap.TransferID+partSuffix)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		m.finish(t, StatusFailed, "cannot create temporary file", true)
		return TransferState{}, apperrors.NewFileTransferError("cannot create temporary file", err)
	}

	t.mu.Lock()
	if t.state.Status != StatusOffered { // cancelled meanwhile
		t.mu.Unlock()
		f.Close()
		os.Remove(tmp)
		return TransferState{}, apperrors.NewFileTransferError("offer is no longer open", nil)
	}
	t.file, t.tmpPath, t.hasher = f, tmp, sha256.New()
	t.state.Status = StatusActive
	t.activity = time.Now()
	t.mu.Unlock()

	if m.progress != nil {
		m.progress.AddProgress(key(snap.PeerID, snap.TransferID), "Receiving "+snap.FileName, snap.FileSize)
	}
	m.sendAsync(snap.PeerID, protocol.KindFileAccept, protocol.FileAccept{TransferID: snap.TransferID, Accepted: true})
	return t.snapshot(), nil
}

// Reject declines an incoming offer.
func (m *Manager) Reject(idOrPrefix string) (TransferState, error) {
	s, err := m.Resolve(idOrPrefix)
	if err != nil {
		return TransferState{}, err
	}
	t := m.lookup(s.PeerID, s.TransferID)
	if t == nil || s.Direction != Receiving || s.Status != StatusOffered {
		return TransferState{}, apperrors.NewFileTransferError("that transfer is not an open incoming offer", nil)
	}
	m.reject(s.PeerID, s.TransferID, "declined")
	m.finish(t, StatusRejected, "declined", false)
	return t.snapshot(), nil
}

// Cancel aborts any unfinished transfer and tells the peer.
func (m *Manager) Cancel(idOrPrefix string) (TransferState, error) {
	s, err := m.Resolve(idOrPrefix)
	if err != nil {
		return TransferState{}, err
	}
	t := m.lookup(s.PeerID, s.TransferID)
	if t == nil {
		return TransferState{}, apperrors.NewFileTransferError("transfer not found", nil)
	}
	m.finish(t, StatusCancelled, "cancelled by you", true)
	return t.snapshot(), nil
}

func (m *Manager) onChunk(from string, body []byte) {
	id, data, err := protocol.DecodeChunk(body)
	if err != nil {
		return
	}
	t := m.lookup(from, id)
	if t == nil {
		m.strike(from, id)
		return
	}

	t.mu.Lock()
	if t.closing {
		t.mu.Unlock()
		return // a late chunk for a transfer that is being torn down
	}
	if t.state.Direction != Receiving || t.state.Status != StatusActive || t.file == nil {
		t.mu.Unlock()
		m.strike(from, id)
		return
	}
	if t.state.BytesTransferred+int64(len(data)) > t.state.FileSize {
		t.mu.Unlock()
		m.finish(t, StatusFailed, "sender sent more data than it offered", true)
		m.say("* Transfer of %q from %s aborted: more data than offered", t.snapshot().FileName, m.Names(from))
		return
	}
	_, werr := t.file.Write(data)
	if werr == nil {
		t.hasher.Write(data)
		t.state.BytesTransferred += int64(len(data))
		t.activity = time.Now()
	}
	received := t.state.BytesTransferred
	t.mu.Unlock()

	if werr != nil {
		m.finish(t, StatusFailed, "disk write failed: "+werr.Error(), true)
		m.say("* Could not save incoming file: %v", werr)
		return
	}
	if m.progress != nil {
		m.progress.UpdateProgress(key(from, id), received)
	}
}

// strike counts chunks for transfers we are not receiving. A peer that keeps
// streaming data nobody asked for is cut off.
func (m *Manager) strike(peerID, transferID string) {
	m.mu.Lock()
	m.strikes[peerID]++
	n := m.strikes[peerID]
	m.mu.Unlock()
	if n == 1 {
		m.sendAsync(peerID, protocol.KindFileAbort, protocol.FileAbort{TransferID: transferID, Reason: "no such transfer"})
	}
	if n >= maxStrikes {
		m.Logger.Warn("Peer keeps sending unsolicited file data; disconnecting", "peer", short(peerID))
		m.Net.Disconnect(peerID)
	}
}

func (m *Manager) onDone(from string, body []byte) {
	var d protocol.FileDone
	if err := protocol.Unmarshal(body, &d); err != nil {
		return
	}
	t := m.lookup(from, d.TransferID)
	if t == nil {
		return
	}

	t.mu.Lock()
	if t.state.Direction != Receiving || t.state.Status != StatusActive || t.file == nil {
		t.mu.Unlock()
		return
	}
	snap, file, tmp, hasher, want := t.state, t.file, t.tmpPath, t.hasher, t.sha
	t.mu.Unlock()

	fail := func(reason string) {
		m.finish(t, StatusFailed, reason, false)
		m.sendAsync(from, protocol.KindFileResult, protocol.FileResult{TransferID: d.TransferID, OK: false, Reason: reason})
		m.say("* Received %q from %s is unusable: %s", snap.FileName, m.Names(from), reason)
	}

	switch {
	case snap.BytesTransferred != snap.FileSize:
		fail("incomplete: got " + ui.FormatBytes(snap.BytesTransferred) + " of " + ui.FormatBytes(snap.FileSize))
		return
	case hex.EncodeToString(hasher.Sum(nil)) != want:
		fail("checksum mismatch")
		return
	}
	if err := file.Sync(); err != nil {
		fail("disk write failed")
		return
	}
	if err := file.Close(); err != nil {
		fail("disk write failed")
		return
	}

	final, err := m.placeFile(tmp, snap.FileName)
	if err != nil {
		fail("could not save file")
		m.Logger.Error("Could not move received file into place", "error", err)
		return
	}

	t.mu.Lock()
	t.file, t.tmpPath = nil, "" // already closed and moved
	t.state.Path = final
	t.mu.Unlock()
	m.finish(t, StatusCompleted, "", false)
	m.sendAsync(from, protocol.KindFileResult, protocol.FileResult{TransferID: d.TransferID, OK: true})

	m.say("* Received %q from %s (%s) -> %s", snap.FileName, m.Names(from), ui.FormatBytes(snap.FileSize), final)
	if m.Notifier != nil {
		_ = m.Notifier.NotifyFileReceived(m.Names(from), snap.FileName)
	}
}

// placeFile moves the verified temporary file to a unique final name in the
// download directory without ever overwriting an existing file: the name is
// first claimed with O_EXCL, then the data is renamed over our own empty
// placeholder.
func (m *Manager) placeFile(tmp, name string) (string, error) {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)

	for i := 0; i < 1000; i++ {
		candidate := name
		if i > 0 {
			candidate = fmt.Sprintf("%s (%d)%s", stem, i, ext)
		}
		final := filepath.Join(m.opts.DownloadDir, candidate)
		f, err := os.OpenFile(final, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		f.Close()
		if err := os.Rename(tmp, final); err != nil {
			os.Remove(final)
			return "", err
		}
		_ = os.Chmod(final, 0o644)
		return final, nil
	}
	return "", errors.New("could not find a free file name")
}

func (m *Manager) onAbort(from string, body []byte) {
	var a protocol.FileAbort
	if err := protocol.Unmarshal(body, &a); err != nil {
		return
	}
	t := m.lookup(from, a.TransferID)
	if t == nil {
		return
	}
	reason := utils.SanitizeText(a.Reason, 100)
	if reason == "" {
		reason = "cancelled by peer"
	}
	snap := t.snapshot()
	m.finish(t, StatusCancelled, reason, false)
	m.say("* %s cancelled the transfer of %q: %s", m.Names(from), snap.FileName, reason)
}

// ---- Peer events and housekeeping ------------------------------------------

// PeerConnected implements interfaces.PeerListener.
func (m *Manager) PeerConnected(peerID, _ string) {
	m.mu.Lock()
	delete(m.strikes, peerID)
	m.mu.Unlock()
}

// PeerDisconnected abandons every transfer with the peer and removes partial files.
func (m *Manager) PeerDisconnected(peerID string) {
	m.mu.Lock()
	var affected []*transfer
	for _, t := range m.active {
		if t.snapshot().PeerID == peerID {
			affected = append(affected, t)
		}
	}
	delete(m.strikes, peerID)
	m.mu.Unlock()

	for _, t := range affected {
		snap := t.snapshot()
		m.finish(t, StatusFailed, "peer disconnected", false)
		m.say("* Transfer of %q with %s interrupted: peer disconnected", snap.FileName, m.Names(peerID))
	}
}

// janitor expires stale offers and stalled transfers.
func (m *Manager) janitor() {
	defer m.wg.Done()
	ticker := time.NewTicker(janitorTick)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.reap(time.Now())
		}
	}
}

func (m *Manager) reap(now time.Time) {
	m.mu.Lock()
	all := make([]*transfer, 0, len(m.active))
	for _, t := range m.active {
		all = append(all, t)
	}
	m.mu.Unlock()

	for _, t := range all {
		t.mu.Lock()
		recv := t.state.Direction == Receiving
		status := t.state.Status
		expired := status == StatusOffered && recv && now.After(t.expires)
		stalled := status == StatusActive && recv && now.Sub(t.activity) > m.opts.IdleTimeout
		name, peer := t.state.FileName, t.state.PeerID
		t.mu.Unlock()

		switch {
		case expired:
			m.reject(peer, t.snapshot().TransferID, "offer expired")
			m.finish(t, StatusCancelled, "offer expired", false)
			m.say("* Offer of %q from %s expired", name, m.Names(peer))
		case stalled:
			m.finish(t, StatusFailed, "stalled", true)
			m.say("* Transfer of %q from %s stalled and was cancelled", name, m.Names(peer))
		}
	}
}
