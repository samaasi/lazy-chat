// Package relay delivers messages to peers that are offline, by store-and-forward,
// without letting the peers that carry them learn who is talking.
//
// A sender encrypts the message to the recipient's prekeys (package offline),
// hiding her own identity inside, and asks a few peers - relays - to hold the
// ciphertext. The recipient collects it from any of them when they next
// connect, stores it as an ordinary message, and returns a signed receipt.
//
// # Who learns what
//
// A relay sees who a message is for, when and how big, never what it says. With
// sealed sender it does not see who it is from either, at two levels:
//
//   - In the data: the sender's identity is inside the end-to-end encryption.
//   - On the wire: a relay sees whoever connects to it, and that would be the
//     sender. So requests are sealed to the relay and carried by a one-hop
//     forwarder, a second peer the sender is connected to. The forwarder knows
//     who is asking and which relay, but not what, nor for whom (the request is
//     sealed); the relay knows the recipient, but sees only the forwarder.
//     Neither alone can link sender to recipient.
//
// Receipts follow the same discipline: the recipient files them under a random
// mailbox tag that only it and the sender know, and the sender collects them
// through a forwarder, so the relay never learns whose mailbox it is.
//
// When fewer than three peers are connected (sender, forwarder, relay) no
// forwarder exists, and the sender is visible to the relay it talks to.
// By default the request then goes direct and the user is told; with
// RequireAnonymous it waits instead.
package relay

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/samaasi/lazy-chat/internal/identity"
	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/offline"
	"github.com/samaasi/lazy-chat/internal/protocol"
	"github.com/samaasi/lazy-chat/internal/storage"
	"github.com/samaasi/lazy-chat/internal/utils"
)

const (
	// DefaultMaxStorage is how much ciphertext a peer holds for others.
	DefaultMaxStorage = 64 << 20
	// MaxTTL is the longest an envelope or receipt is kept.
	MaxTTL = 7 * 24 * time.Hour

	minTTL           = time.Minute
	defaultReplicas  = 3
	maxStoreAttempts = 8
	maxForwarders    = 2 // forwarders tried per request
	deliverBatch     = 100
	maxFetchTags     = 100
	opTimeout        = 15 * time.Second
	maxWireID        = 64

	maxPendingForwards = 2048
	forwardTTL         = 30 * time.Second

	purposeRequest = "relay-request"
	purposeReply   = "relay-reply"
)

// Errors returned by Dispatch.
var (
	ErrNoRelay         = errors.New("no connected peer agreed to hold the message")
	ErrNoPeers         = errors.New("not connected to anyone who could hold the message")
	ErrNoAnonymousPath = errors.New("no way to queue the message without revealing who sent it (connect to more peers, or allow it with sealed_sender=auto)")
	errRejected        = errors.New("message rejected")
)

// Options configures a Manager. Zero values select the defaults.
type Options struct {
	// Enabled makes this peer hold messages and forward requests for others.
	// Sending through other peers' relays works either way.
	Enabled    bool
	MaxStorage int64
	// Limits overrides the derived storage limits (mainly for tests).
	Limits *storage.RelayLimits
	// RequireAnonymous refuses to contact a relay except through a forwarder.
	RequireAnonymous bool

	Replicas      int           // relays asked per message
	StoreTimeout  time.Duration // wait for an answer
	BundleTimeout time.Duration // wait for a gossiped bundle
}

func (o *Options) defaults() {
	if o.MaxStorage <= 0 {
		o.MaxStorage = DefaultMaxStorage
	}
	if o.Replicas <= 0 {
		o.Replicas = defaultReplicas
	}
	if o.StoreTimeout <= 0 {
		o.StoreTimeout = 5 * time.Second
	}
	if o.BundleTimeout <= 0 {
		o.BundleTimeout = 3 * time.Second
	}
}

func (o *Options) limits() storage.RelayLimits {
	if o.Limits != nil {
		return *o.Limits
	}
	return storage.RelayLimits{
		MaxTotalBytes:     o.MaxStorage,
		MaxPerSender:      200,
		MaxBytesPerSender: min(4<<20, o.MaxStorage/4),
		MaxPerRecipient:   500,
		MaxReceipts:       1000,
	}
}

// MessageFunc is called for each message delivered through a relay. It must
// store the message and report whether it was accepted (a duplicate counts as
// accepted); msgID names it for the receipt.
type MessageFunc func(ctx context.Context, senderID string, plaintext []byte) (msgID string, accepted bool)

// ReceiptFunc is called when a verified delivery receipt arrives. signerID is
// who signed it, and has been checked to be the recipient we addressed.
type ReceiptFunc func(ctx context.Context, msgID, signerID string)

// Deps are the collaborators of a Manager.
type Deps struct {
	Logger  interfaces.Logger
	Self    *identity.Identity
	Net     interfaces.NetworkManager
	Offline *offline.Service
	Store   storage.RelayStorage
}

// result is what a waiting request receives.
type result struct {
	sealed []byte
	err    error
}

type forward struct {
	from string
	at   time.Time
}

// Manager implements all four roles: sender, forwarder, relay and recipient.
type Manager struct {
	Deps
	opts Options
	now  func() time.Time

	forwardLimiter *utils.KeyedLimiter

	mu            sync.Mutex
	onMessage     MessageFunc
	onReceipt     ReceiptFunc
	waiters       map[string]chan result // "fwd:forwarder/id" or "direct:relay/id"
	forwards      map[string]forward     // "relay/id" -> who asked us to forward it
	bundleWaiters map[string][]chan struct{}
	fetching      bool
	closed        bool
	wg            sync.WaitGroup
}

var _ interfaces.PeerListener = (*Manager)(nil)

// NewManager creates a relay manager.
func NewManager(opts Options, deps Deps) *Manager {
	opts.defaults()
	return &Manager{
		Deps: deps, opts: opts, now: time.Now,
		forwardLimiter: utils.NewKeyedLimiter(2, 20, 1024),
		waiters:        map[string]chan result{},
		forwards:       map[string]forward{},
		bundleWaiters:  map[string][]chan struct{}{},
	}
}

// SetHandlers installs the callbacks for delivered messages and receipts.
func (m *Manager) SetHandlers(onMessage MessageFunc, onReceipt ReceiptFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onMessage, m.onReceipt = onMessage, onReceipt
}

// Register attaches the manager to the network.
func (m *Manager) Register() {
	m.Net.Handle(protocol.KindPrekeys, m.onPrekeys)
	m.Net.Handle(protocol.KindBundleRequest, m.onBundleRequest)
	m.Net.Handle(protocol.KindBundleResponse, m.onBundleResponse)
	m.Net.Handle(protocol.KindRelayRequest, m.onRequest)
	m.Net.Handle(protocol.KindRelayResponse, m.onResponse)
	m.Net.Handle(protocol.KindRelayDeliver, m.onDeliver)
	m.Net.Handle(protocol.KindRelayAck, m.onAck)
	m.Net.Handle(protocol.KindRelayForward, m.onForward)
	m.Net.Handle(protocol.KindRelayForwardReply, m.onForwardReply)
	m.Net.AddListener(m)
}

// Close waits for background work to finish.
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *Manager) background(fn func(ctx context.Context)) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
		defer cancel()
		fn(ctx)
	}()
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func validWireID(s string) bool {
	if s == "" || len(s) > maxWireID {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Usage reports what this peer is holding for others.
func (m *Manager) Usage(ctx context.Context) (envelopes int, bytes, capacity int64, err error) {
	envelopes, bytes, err = m.Store.RelayUsage(ctx)
	return envelopes, bytes, m.opts.MaxStorage, err
}

// Enabled reports whether this peer holds messages for others.
func (m *Manager) Enabled() bool { return m.opts.Enabled }

// Maintain purges expired envelopes, receipts, bookkeeping and old prekeys.
func (m *Manager) Maintain(ctx context.Context) error {
	now := m.now()
	if _, _, err := m.Store.PurgeRelay(ctx, now); err != nil {
		return err
	}
	if _, err := m.Store.PurgeOutbox(ctx, now.Add(-MaxTTL)); err != nil {
		return err
	}
	m.expireForwards(now)
	m.FetchReceipts(ctx)
	return m.Offline.Maintain(ctx)
}

// ---- Connections ---------------------------------------------------------------

// PeerConnected sends our bundle to the new peer, hands over whatever we hold
// for them, and looks for receipts that may be waiting.
func (m *Manager) PeerConnected(peerID, _ string) {
	m.background(func(ctx context.Context) {
		b, err := m.Offline.OurBundleFor(ctx, peerID)
		if err != nil {
			m.Logger.Debug("Could not prepare our prekey bundle", "error", err)
		} else if raw, err := json.Marshal(b); err == nil {
			if err := m.Net.SendJSON(ctx, peerID, protocol.KindPrekeys, protocol.Prekeys{Bundle: raw}); err != nil {
				m.Logger.Debug("Could not send our prekey bundle", "peer", short(peerID), "error", err)
			}
		}
		m.deliverHeld(ctx, peerID)
		m.FetchReceipts(ctx)
	})
}

// PeerDisconnected implements interfaces.PeerListener.
func (m *Manager) PeerDisconnected(string) {}

// ---- Bundles -------------------------------------------------------------------

func (m *Manager) onPrekeys(from string, body []byte) {
	var p protocol.Prekeys
	var b offline.Bundle
	if protocol.Unmarshal(body, &p) != nil || json.Unmarshal(p.Bundle, &b) != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	// The bundle must belong to the authenticated peer that sent it.
	if err := m.Offline.RememberBundle(ctx, from, &b); err != nil {
		m.Logger.Debug("Ignored prekey bundle", "peer", short(from), "reason", err.Error())
		return
	}
	m.wakeBundleWaiters(from)
}

func (m *Manager) wakeBundleWaiters(peerID string) {
	m.mu.Lock()
	waiters := m.bundleWaiters[peerID]
	delete(m.bundleWaiters, peerID)
	m.mu.Unlock()
	for _, w := range waiters {
		close(w)
	}
}

func (m *Manager) onBundleRequest(from string, body []byte) {
	var r protocol.BundleRequest
	if protocol.Unmarshal(body, &r) != nil || !identity.ValidID(r.PeerID) {
		return
	}
	m.background(func(ctx context.Context) {
		resp := protocol.BundleResponse{PeerID: r.PeerID}
		if b, err := m.Offline.BundleForGossip(ctx, r.PeerID); err == nil {
			resp.Bundle, _ = json.Marshal(b)
		}
		_ = m.Net.SendJSON(ctx, from, protocol.KindBundleResponse, resp)
	})
}

func (m *Manager) onBundleResponse(from string, body []byte) {
	var r protocol.BundleResponse
	var b offline.Bundle
	if protocol.Unmarshal(body, &r) != nil || len(r.Bundle) == 0 || json.Unmarshal(r.Bundle, &b) != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	// A bundle is self-certifying, so it does not matter who relayed it: it is
	// only accepted if it verifies and belongs to the peer it claims to.
	if err := m.Offline.RememberBundle(ctx, r.PeerID, &b); err != nil {
		return
	}
	m.wakeBundleWaiters(r.PeerID)
}

// fetchBundle asks connected peers whether they hold a bundle for target.
func (m *Manager) fetchBundle(ctx context.Context, target string) error {
	asked := 0
	wait := make(chan struct{})
	m.mu.Lock()
	m.bundleWaiters[target] = append(m.bundleWaiters[target], wait)
	m.mu.Unlock()
	for _, peerID := range m.candidates(target) {
		if asked == 3 {
			break
		}
		if err := m.Net.SendJSON(ctx, peerID, protocol.KindBundleRequest, protocol.BundleRequest{PeerID: target}); err == nil {
			asked++
		}
	}
	if asked == 0 {
		return ErrNoPeers
	}
	select {
	case <-wait:
		return nil
	case <-time.After(m.opts.BundleTimeout):
		return offline.ErrNoBundle
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ---- Requests: the sender's side ---------------------------------------------------

// request is the plaintext inside a sealed RelayRequest.
type request struct {
	Op    string `json:"op"`    // "store" or "fetch"
	Reply []byte `json:"reply"` // one-off X25519 public key to seal the answer to

	ID      string `json:"id,omitempty"` // store: the envelope's ID
	To      string `json:"to,omitempty"`
	Blob    []byte `json:"blob,omitempty"`
	Expires int64  `json:"expires,omitempty"`

	Tags []string `json:"tags,omitempty"` // fetch: mailbox tags to look under
}

type receiptEntry struct {
	Tag    string `json:"tag"`
	MsgID  string `json:"msg_id"`
	Signer string `json:"signer"`
	EdPub  []byte `json:"ed"`
	Sig    []byte `json:"sig"`
}

// response is the plaintext inside a sealed RelayResponse.
type response struct {
	OK       bool           `json:"ok"`
	Reason   string         `json:"reason,omitempty"`
	Receipts []receiptEntry `json:"receipts,omitempty"`
}

// candidates lists connected peers other than the excluded ones and ourselves,
// in random order so that load and trust are spread around.
func (m *Manager) candidates(exclude ...string) []string {
	skip := map[string]bool{m.Self.ID(): true}
	for _, e := range exclude {
		skip[e] = true
	}
	var out []string
	for _, id := range m.Net.ConnectedPeers() {
		if !skip[id] {
			out = append(out, id)
		}
	}
	for i := len(out) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			break
		}
		out[i], out[j.Int64()] = out[int(j.Int64())], out[i]
	}
	return out
}

// call sends a request to relayID and returns its answer. It goes through a
// forwarder when one exists, so the relay does not see us; anonymous reports
// whether it did. avoid is a peer that must not be used as forwarder (the
// message's recipient).
func (m *Manager) call(ctx context.Context, relayID, avoid string, req request) (resp response, anonymous bool, err error) {
	replyKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return resp, false, err
	}
	req.Reply = replyKey.PublicKey().Bytes()
	plain, err := json.Marshal(req)
	if err != nil {
		return resp, false, err
	}
	// A relay's prekeys arrive just after we connect to it; a request made in
	// that instant waits for them rather than failing.
	m.awaitBundle(ctx, relayID)
	sealed, err := m.Offline.SealFor(ctx, relayID, purposeRequest, plain)
	if err != nil {
		return resp, false, err
	}
	id := utils.NewID()

	answer, anonymous, err := m.carry(ctx, relayID, avoid, id, sealed)
	if err != nil {
		return resp, false, err
	}
	out, err := offline.OpenWithKey(replyKey, purposeReply+"|"+id, answer)
	if err != nil {
		return resp, false, fmt.Errorf("the relay's answer could not be read: %w", err)
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return resp, false, err
	}
	return resp, anonymous, nil
}

// awaitBundle waits briefly for peerID's prekey bundle, which a connected
// peer sends unprompted.
func (m *Manager) awaitBundle(ctx context.Context, peerID string) {
	if m.Offline.HasBundle(ctx, peerID) {
		return
	}
	wait := make(chan struct{})
	m.mu.Lock()
	m.bundleWaiters[peerID] = append(m.bundleWaiters[peerID], wait)
	m.mu.Unlock()
	if m.Offline.HasBundle(ctx, peerID) { // it arrived while we registered
		return
	}
	select {
	case <-wait:
	case <-time.After(m.opts.BundleTimeout):
	case <-ctx.Done():
	}
}

// carry delivers a sealed request and returns the sealed answer.
func (m *Manager) carry(ctx context.Context, relayID, avoid, id string, sealed []byte) (answer []byte, anonymous bool, err error) {
	var lastErr error
	tried := 0
	for _, fwd := range m.candidates(relayID, avoid) {
		if tried == maxForwarders {
			break
		}
		tried++
		a, err := m.viaForwarder(ctx, fwd, relayID, id, sealed)
		if err == nil {
			return a, true, nil
		}
		lastErr = err
	}
	if m.opts.RequireAnonymous {
		if lastErr != nil {
			return nil, false, fmt.Errorf("%w: %v", ErrNoAnonymousPath, lastErr)
		}
		return nil, false, ErrNoAnonymousPath
	}
	a, err := m.direct(ctx, relayID, id, sealed)
	return a, false, err
}

func (m *Manager) await(ctx context.Context, key string, send func() error) ([]byte, error) {
	w := make(chan result, 1)
	m.mu.Lock()
	m.waiters[key] = w
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.waiters, key)
		m.mu.Unlock()
	}()
	if err := send(); err != nil {
		return nil, err
	}
	select {
	case r := <-w:
		return r.sealed, r.err
	case <-time.After(m.opts.StoreTimeout):
		return nil, errors.New("no answer")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *Manager) viaForwarder(ctx context.Context, fwd, relayID, id string, sealed []byte) ([]byte, error) {
	return m.await(ctx, "fwd:"+fwd+"/"+id, func() error {
		return m.Net.SendJSON(ctx, fwd, protocol.KindRelayForward, protocol.RelayForward{ID: id, Relay: relayID, Sealed: sealed})
	})
}

func (m *Manager) direct(ctx context.Context, relayID, id string, sealed []byte) ([]byte, error) {
	return m.await(ctx, "direct:"+relayID+"/"+id, func() error {
		return m.Net.SendJSON(ctx, relayID, protocol.KindRelayRequest, protocol.RelayRequest{ID: id, Sealed: sealed})
	})
}

// wrapped is the payload inside the end-to-end encryption of a relayed message:
// the application message and the mailbox tag its receipt will be filed under.
type wrapped struct {
	Tag     string          `json:"tag"`
	Payload json.RawMessage `json:"payload"`
}

// Dispatch encrypts plaintext for `to` and asks connected peers to hold it.
// msgID names the message for the delivery receipt. It fails when the
// recipient's prekeys cannot be found, nobody is connected, nobody accepts, or
// (with RequireAnonymous) no forwarder is available.
func (m *Manager) Dispatch(ctx context.Context, to, msgID string, plaintext []byte) (models.RelayResult, error) {
	var res models.RelayResult
	if !identity.ValidID(to) || to == m.Self.ID() || !validWireID(msgID) {
		return res, errors.New("invalid recipient or message")
	}
	if !m.Offline.HasBundle(ctx, to) {
		if err := m.fetchBundle(ctx, to); err != nil && !m.Offline.HasBundle(ctx, to) {
			return res, fmt.Errorf("cannot encrypt for an offline recipient: %w", err)
		}
	}
	tag := utils.NewID()
	inner, err := json.Marshal(wrapped{Tag: tag, Payload: plaintext})
	if err != nil {
		return res, err
	}
	sealed, err := m.Offline.Seal(ctx, to, inner)
	if err != nil {
		return res, fmt.Errorf("cannot encrypt for an offline recipient: %w", err)
	}

	cands := m.candidates(to)
	if len(cands) == 0 {
		return res, ErrNoPeers
	}
	req := request{Op: "store", ID: utils.NewID(), To: to, Blob: sealed, Expires: m.now().Add(MaxTTL).UnixMilli()}

	var lastErr error
	for i, relayID := range cands {
		if res.Relays >= m.opts.Replicas || i >= maxStoreAttempts {
			break
		}
		resp, anonymous, err := m.call(ctx, relayID, to, req)
		switch {
		case errors.Is(err, ErrNoAnonymousPath):
			return res, err // the same for every relay: stop asking
		case err != nil:
			lastErr = err
			continue
		case !resp.OK:
			lastErr = errors.New(resp.Reason)
			continue
		}
		res.Relays++
		if !anonymous {
			res.Exposed++
		}
		if err := m.Store.AddOutbox(ctx, storage.OutboxEntry{MsgID: msgID, RelayID: relayID, To: to, Tag: tag, Created: m.now()}); err != nil {
			m.Logger.Warn("Could not record a queued message", "error", err)
		}
	}
	if res.Relays == 0 {
		if lastErr != nil {
			return res, fmt.Errorf("%w (%v)", ErrNoRelay, lastErr)
		}
		return res, ErrNoRelay
	}
	return res, nil
}

// FetchReceipts asks the relays that hold our messages whether the recipients
// have collected them, and applies the signed receipts that are there. Each
// receipt is verified and must come from the recipient we addressed.
func (m *Manager) FetchReceipts(ctx context.Context) {
	m.mu.Lock()
	if m.fetching || m.closed {
		m.mu.Unlock()
		return
	}
	m.fetching = true
	onReceipt := m.onReceipt
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.fetching = false; m.mu.Unlock() }()

	entries, err := m.Store.Outbox(ctx, m.now().Add(-MaxTTL))
	if err != nil || len(entries) == 0 {
		return
	}
	byRelay := map[string][]storage.OutboxEntry{}
	for _, e := range entries {
		byRelay[e.RelayID] = append(byRelay[e.RelayID], e)
	}

	for relayID, list := range byRelay {
		if ctx.Err() != nil {
			return
		}
		tags := map[string]bool{}
		for _, e := range list {
			if len(tags) < maxFetchTags {
				tags[e.Tag] = true
			}
		}
		req := request{Op: "fetch"}
		for t := range tags {
			req.Tags = append(req.Tags, t)
		}
		resp, _, err := m.call(ctx, relayID, "", req)
		if err != nil || !resp.OK {
			m.Logger.Debug("Could not collect receipts", "relay", short(relayID), "error", err)
			continue
		}
		for _, r := range resp.Receipts {
			m.applyReceipt(ctx, list, r, onReceipt)
		}
	}
}

func (m *Manager) applyReceipt(ctx context.Context, outbox []storage.OutboxEntry, r receiptEntry, onReceipt ReceiptFunc) {
	// Genuinely signed for us, about that message, by whoever claims to be the signer...
	signer, err := offline.VerifyReceipt(r.EdPub, r.Sig, r.MsgID, m.Self.ID())
	if err != nil || signer != r.Signer {
		return
	}
	// ...and that signer is the person we sent it to, under the tag we chose.
	for _, e := range outbox {
		if e.Tag == r.Tag && e.MsgID == r.MsgID && e.To == signer {
			if onReceipt != nil {
				onReceipt(ctx, r.MsgID, signer)
			}
			_ = m.Store.DeleteOutbox(ctx, r.MsgID, signer)
			return
		}
	}
}

// ---- Forwarder role --------------------------------------------------------------------

func (m *Manager) expireForwards(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, f := range m.forwards {
		if now.Sub(f.at) > forwardTTL {
			delete(m.forwards, k)
		}
	}
}

func (m *Manager) onForward(from string, body []byte) {
	var f protocol.RelayForward
	if protocol.Unmarshal(body, &f) != nil || !validWireID(f.ID) {
		return
	}
	fail := func(reason string) {
		m.background(func(ctx context.Context) {
			_ = m.Net.SendJSON(ctx, from, protocol.KindRelayForwardReply, protocol.RelayForwardReply{ID: f.ID, Reason: reason})
		})
	}
	switch {
	case !m.opts.Enabled:
		fail("this peer does not forward requests")
		return
	case !identity.ValidID(f.Relay) || f.Relay == from || f.Relay == m.Self.ID():
		fail("invalid relay")
		return
	case len(f.Sealed) == 0 || len(f.Sealed) > offline.MaxSealed:
		fail("request size not accepted")
		return
	case !m.forwardLimiter.Allow(from):
		fail("too many requests")
		return
	}

	key := f.Relay + "/" + f.ID
	m.expireForwards(m.now())
	m.mu.Lock()
	if len(m.forwards) >= maxPendingForwards {
		m.mu.Unlock()
		fail("busy")
		return
	}
	m.forwards[key] = forward{from: from, at: m.now()}
	m.mu.Unlock()

	m.background(func(ctx context.Context) {
		err := m.Net.SendJSON(ctx, f.Relay, protocol.KindRelayRequest, protocol.RelayRequest{ID: f.ID, Sealed: f.Sealed})
		if err != nil {
			m.mu.Lock()
			delete(m.forwards, key)
			m.mu.Unlock()
			_ = m.Net.SendJSON(ctx, from, protocol.KindRelayForwardReply, protocol.RelayForwardReply{ID: f.ID, Reason: "could not reach that relay"})
		}
	})
}

func (m *Manager) onForwardReply(from string, body []byte) {
	var r protocol.RelayForwardReply
	if protocol.Unmarshal(body, &r) != nil {
		return
	}
	m.mu.Lock()
	w := m.waiters["fwd:"+from+"/"+r.ID] // only the forwarder we asked can answer
	m.mu.Unlock()
	if w == nil {
		return
	}
	res := result{sealed: r.Sealed}
	if !r.OK {
		res.err = errors.New(r.Reason)
	}
	select {
	case w <- res:
	default:
	}
}

// ---- Relay role ------------------------------------------------------------------------

func (m *Manager) onRequest(from string, body []byte) {
	var r protocol.RelayRequest
	if protocol.Unmarshal(body, &r) != nil || !validWireID(r.ID) || len(r.Sealed) > offline.MaxSealed {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	plain, err := m.Offline.OpenFor(ctx, purposeRequest, r.Sealed)
	if err != nil {
		return // not for us, damaged, or from before our signed prekey was replaced
	}
	var req request
	if json.Unmarshal(plain, &req) != nil || len(req.Reply) != 32 {
		return
	}
	// `from` is the submitter: the sender if she came directly, otherwise the
	// forwarder. We cannot tell which, and do not try.
	resp := m.handle(ctx, from, req)
	out, err := json.Marshal(resp)
	if err != nil {
		return
	}
	sealed, err := offline.SealToKey(req.Reply, purposeReply+"|"+r.ID, out)
	if err != nil {
		return
	}
	m.background(func(ctx context.Context) {
		_ = m.Net.SendJSON(ctx, from, protocol.KindRelayResponse, protocol.RelayResponse{ID: r.ID, Sealed: sealed})
	})
}

func (m *Manager) handle(ctx context.Context, submitter string, req request) response {
	switch req.Op {
	case "store":
		return m.handleStore(ctx, submitter, req)
	case "fetch":
		return m.handleFetch(ctx, req)
	default:
		return response{Reason: "unknown request"}
	}
}

func (m *Manager) handleStore(ctx context.Context, submitter string, req request) response {
	switch {
	case !m.opts.Enabled:
		return response{Reason: "this peer does not hold messages for others"}
	case !validWireID(req.ID):
		return response{Reason: "invalid message"}
	case !identity.ValidID(req.To) || req.To == submitter:
		return response{Reason: "invalid recipient"}
	case req.To == m.Self.ID():
		return response{Reason: "that message is for me; send it directly"}
	case len(req.Blob) == 0 || len(req.Blob) > offline.MaxSealed:
		return response{Reason: "message size not accepted"}
	}

	now := m.now()
	expires := now.Add(MaxTTL)
	if req.Expires > 0 {
		if want := time.UnixMilli(req.Expires); want.Before(expires) {
			expires = want
		}
	}
	if expires.Before(now.Add(minTTL)) {
		expires = now.Add(minTTL)
	}

	err := m.Store.PutEnvelope(ctx, storage.RelayEnvelope{
		ID: req.ID, Submitter: submitter, To: req.To, Blob: req.Blob, Created: now, Expires: expires,
	}, m.opts.limits())
	var quota *storage.QuotaError
	switch {
	case errors.As(err, &quota):
		return response{Reason: quota.Reason}
	case err != nil:
		m.Logger.Warn("Could not store a message for relaying", "error", err)
		return response{Reason: "internal error"}
	}

	// If the recipient is connected to us right now, pass it on immediately.
	if m.Net.IsConnected(req.To) {
		to := req.To
		m.background(func(ctx context.Context) { m.deliverHeld(ctx, to) })
	}
	return response{OK: true}
}

func (m *Manager) handleFetch(ctx context.Context, req request) response {
	var tags []string
	for _, t := range req.Tags {
		if validWireID(t) && len(tags) < maxFetchTags {
			tags = append(tags, t)
		}
	}
	recs, err := m.Store.ReceiptsForTags(ctx, tags, m.now(), maxFetchTags)
	if err != nil {
		return response{Reason: "internal error"}
	}
	resp := response{OK: true}
	for _, r := range recs {
		resp.Receipts = append(resp.Receipts, receiptEntry{Tag: r.Tag, MsgID: r.MsgID, Signer: r.Signer, EdPub: r.EdPub, Sig: r.Sig})
	}
	return resp
}

// onResponse routes an answer from a relay: back to the peer that asked us to
// forward the request, or to our own waiting call.
func (m *Manager) onResponse(from string, body []byte) {
	var r protocol.RelayResponse
	if protocol.Unmarshal(body, &r) != nil || !validWireID(r.ID) {
		return
	}
	key := from + "/" + r.ID // only the relay we sent the request to can answer
	m.mu.Lock()
	fw, forwarding := m.forwards[key]
	delete(m.forwards, key)
	w := m.waiters["direct:"+key]
	m.mu.Unlock()

	switch {
	case forwarding:
		m.background(func(ctx context.Context) {
			_ = m.Net.SendJSON(ctx, fw.from, protocol.KindRelayForwardReply, protocol.RelayForwardReply{ID: r.ID, OK: true, Sealed: r.Sealed})
		})
	case w != nil:
		select {
		case w <- result{sealed: r.Sealed}:
		default:
		}
	}
}

// deliverHeld sends the recipient everything we hold for them.
func (m *Manager) deliverHeld(ctx context.Context, peerID string) {
	envs, err := m.Store.EnvelopesFor(ctx, peerID, m.now(), deliverBatch)
	if err != nil {
		m.Logger.Debug("Could not read held messages", "error", err)
		return
	}
	for _, e := range envs {
		d := protocol.RelayDeliver{ID: e.ID, Blob: e.Blob, Created: e.Created.UnixMilli()}
		if err := m.Net.SendJSON(ctx, peerID, protocol.KindRelayDeliver, d); err != nil {
			return // they went away; the rest waits for next time
		}
	}
}

// onAck: the recipient has dealt with an envelope. Only the addressee can
// acknowledge (the store enforces it). Its receipt is filed under the mailbox
// tag it found inside the message; we cannot verify the receipt (we do not
// know who wrote the message) and do not need to: the sender will.
func (m *Manager) onAck(from string, body []byte) {
	var a protocol.RelayAck
	if protocol.Unmarshal(body, &a) != nil || !validWireID(a.ID) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if _, err := m.Store.TakeEnvelope(ctx, a.ID, from); err != nil {
		return
	}
	if !a.Delivered || !validWireID(a.MsgID) || !validWireID(a.Tag) || len(a.Sig) == 0 ||
		len(a.EdPub) == 0 || identity.PeerIDFromPublicKey(a.EdPub) != from {
		return
	}
	_ = m.Store.PutReceipt(ctx, storage.RelayReceipt{
		Tag: a.Tag, MsgID: a.MsgID, Signer: from, EdPub: a.EdPub, Sig: a.Sig, Expires: m.now().Add(MaxTTL),
	}, m.opts.limits())
}

// ---- Recipient role ----------------------------------------------------------------------

func (m *Manager) onDeliver(from string, body []byte) {
	var d protocol.RelayDeliver
	if protocol.Unmarshal(body, &d) != nil || !validWireID(d.ID) {
		return
	}
	m.mu.Lock()
	onMessage := m.onMessage
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	var msgID, tag string
	_, sender, err := m.Offline.OpenThen(ctx, d.Blob, func(plain []byte, senderID string) error {
		var w wrapped
		if onMessage == nil || json.Unmarshal(plain, &w) != nil {
			return errRejected
		}
		id, ok := onMessage(ctx, senderID, w.Payload)
		if !ok {
			return errRejected
		}
		msgID, tag = id, w.Tag
		return nil
	})

	ack := protocol.RelayAck{ID: d.ID}
	switch {
	case err == nil:
		ack.Delivered, ack.MsgID, ack.Tag = true, msgID, tag
		ack.EdPub, ack.Sig = m.Self.PublicKey(), offline.SignReceipt(m.Self, msgID, sender)
	case errors.Is(err, offline.ErrNoPrekey):
		// Usually a second copy of a message we already opened (the sender
		// asks several relays). Drop it without a receipt.
	default:
		m.Logger.Debug("Could not open a relayed message", "relay", short(from), "reason", err.Error())
	}
	m.background(func(ctx context.Context) {
		_ = m.Net.SendJSON(ctx, from, protocol.KindRelayAck, ack)
	})
}
