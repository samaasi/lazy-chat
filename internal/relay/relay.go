// Package relay delivers messages to peers that are offline, by store-and-forward.
//
// A sender encrypts the message to the recipient's prekeys (package offline)
// and hands the ciphertext to a few of the peers it is connected to. Those
// relays hold it until the recipient next connects to any of them, then pass it
// on. The recipient decrypts it, stores it as an ordinary message, and returns a
// signed receipt that travels back through the relay to the sender.
//
// What a relay learns: who the message is from and for, when, and roughly how
// big it is. What it cannot do: read it (only the recipient holds the keys),
// alter it (it is authenticated), forge a receipt (signed by the recipient), or
// impersonate the sender. What it can do is delay or drop it, which is why
// senders use several relays and keep retrying direct delivery.
package relay

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/samaasi/lazy-chat/internal/identity"
	"github.com/samaasi/lazy-chat/internal/interfaces"
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
	deliverBatch     = 100
	receiptBatch     = 200
	opTimeout        = 15 * time.Second
	maxWireID        = 64
)

// Errors returned by Dispatch.
var (
	ErrNoRelay = errors.New("no connected peer agreed to hold the message")
	ErrNoPeers = errors.New("not connected to anyone who could hold the message")
	errRejects = errors.New("message rejected")
)

// Options configures a Manager. Zero values select the defaults.
type Options struct {
	// Enabled makes this peer hold messages for others. Sending through other
	// relays works either way.
	Enabled    bool
	MaxStorage int64
	// Limits overrides the derived storage limits (mainly for tests).
	Limits        *storage.RelayLimits
	Replicas      int           // relays asked per message
	StoreTimeout  time.Duration // wait for a relay's answer
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
// who signed it; the caller must check that is really the message's recipient.
type ReceiptFunc func(ctx context.Context, msgID, signerID string)

// Deps are the collaborators of a Manager.
type Deps struct {
	Logger  interfaces.Logger
	Self    *identity.Identity
	Net     interfaces.NetworkManager
	Offline *offline.Service
	Store   storage.RelayStorage
}

// Manager implements all three roles: sender, relay and recipient.
type Manager struct {
	Deps
	opts Options
	now  func() time.Time

	mu            sync.Mutex
	onMessage     MessageFunc
	onReceipt     ReceiptFunc
	storeWaiters  map[string]chan protocol.RelayStored // "relayID/envelopeID"
	bundleWaiters map[string][]chan struct{}
	closed        bool
	wg            sync.WaitGroup
}

var _ interfaces.PeerListener = (*Manager)(nil)

// NewManager creates a relay manager.
func NewManager(opts Options, deps Deps) *Manager {
	opts.defaults()
	return &Manager{
		Deps: deps, opts: opts, now: time.Now,
		storeWaiters:  map[string]chan protocol.RelayStored{},
		bundleWaiters: map[string][]chan struct{}{},
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
	m.Net.Handle(protocol.KindRelayStore, m.onStore)
	m.Net.Handle(protocol.KindRelayStored, m.onStored)
	m.Net.Handle(protocol.KindRelayDeliver, m.onDeliver)
	m.Net.Handle(protocol.KindRelayAck, m.onAck)
	m.Net.Handle(protocol.KindRelayReceipt, m.onReceiptFrame)
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

// Maintain purges expired envelopes and receipts and old prekeys.
func (m *Manager) Maintain(ctx context.Context) error {
	if _, _, err := m.Store.PurgeRelay(ctx, m.now()); err != nil {
		return err
	}
	return m.Offline.Maintain(ctx)
}

// ---- Connections ---------------------------------------------------------------

// PeerConnected sends our bundle to the new peer and, as a relay, hands over
// whatever we are holding for them.
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
		m.deliverReceipts(ctx, peerID)
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
	m.mu.Lock()
	waiters := m.bundleWaiters[r.PeerID]
	delete(m.bundleWaiters, r.PeerID)
	m.mu.Unlock()
	for _, w := range waiters {
		close(w)
	}
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

// ---- Sending ---------------------------------------------------------------------

// candidates lists connected peers other than exclude and ourselves, in random
// order so that load and trust are spread around.
func (m *Manager) candidates(exclude string) []string {
	var out []string
	for _, id := range m.Net.ConnectedPeers() {
		if id != exclude && id != m.Self.ID() {
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

// Dispatch encrypts plaintext for `to` and asks connected peers to hold it.
// It returns how many accepted. It fails when the recipient's prekeys cannot
// be found, nobody is connected, or nobody accepts.
func (m *Manager) Dispatch(ctx context.Context, to string, plaintext []byte) (int, error) {
	if !identity.ValidID(to) || to == m.Self.ID() {
		return 0, errors.New("invalid recipient")
	}
	if !m.Offline.HasBundle(ctx, to) {
		if err := m.fetchBundle(ctx, to); err != nil && !m.Offline.HasBundle(ctx, to) {
			return 0, fmt.Errorf("cannot encrypt for an offline recipient: %w", err)
		}
	}
	blob, err := m.Offline.Seal(ctx, to, plaintext)
	if err != nil {
		return 0, fmt.Errorf("cannot encrypt for an offline recipient: %w", err)
	}

	cands := m.candidates(to)
	if len(cands) == 0 {
		return 0, ErrNoPeers
	}
	envelopeID := utils.NewID()
	req := protocol.RelayStore{ID: envelopeID, To: to, Blob: blob, Expires: m.now().Add(MaxTTL).UnixMilli()}

	stored := 0
	var lastReason string
	for i, relayID := range cands {
		if stored >= m.opts.Replicas || i >= maxStoreAttempts {
			break
		}
		ok, reason := m.storeAt(ctx, relayID, req)
		if ok {
			stored++
		} else if reason != "" {
			lastReason = reason
		}
	}
	if stored == 0 {
		if lastReason != "" {
			return 0, fmt.Errorf("%w (%s)", ErrNoRelay, lastReason)
		}
		return 0, ErrNoRelay
	}
	return stored, nil
}

func (m *Manager) storeAt(ctx context.Context, relayID string, req protocol.RelayStore) (bool, string) {
	key := relayID + "/" + req.ID
	waiter := make(chan protocol.RelayStored, 1)
	m.mu.Lock()
	m.storeWaiters[key] = waiter
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.storeWaiters, key)
		m.mu.Unlock()
	}()

	if err := m.Net.SendJSON(ctx, relayID, protocol.KindRelayStore, req); err != nil {
		return false, ""
	}
	select {
	case r := <-waiter:
		return r.OK, r.Reason
	case <-time.After(m.opts.StoreTimeout):
		return false, ""
	case <-ctx.Done():
		return false, ""
	}
}

func (m *Manager) onStored(from string, body []byte) {
	var r protocol.RelayStored
	if protocol.Unmarshal(body, &r) != nil {
		return
	}
	m.mu.Lock()
	w := m.storeWaiters[from+"/"+r.ID] // only the relay we asked can answer
	m.mu.Unlock()
	if w != nil {
		select {
		case w <- r:
		default:
		}
	}
}

// ---- Relay role: hold messages for others ----------------------------------------

func (m *Manager) onStore(from string, body []byte) {
	var req protocol.RelayStore
	if protocol.Unmarshal(body, &req) != nil || !validWireID(req.ID) {
		return
	}
	reply := func(ok bool, reason string) {
		m.background(func(ctx context.Context) {
			_ = m.Net.SendJSON(ctx, from, protocol.KindRelayStored, protocol.RelayStored{ID: req.ID, OK: ok, Reason: reason})
		})
	}

	switch {
	case !m.opts.Enabled:
		reply(false, "this peer does not hold messages for others")
		return
	case !identity.ValidID(req.To) || req.To == from:
		reply(false, "invalid recipient")
		return
	case req.To == m.Self.ID():
		reply(false, "that message is for me; send it directly")
		return
	case len(req.Blob) == 0 || len(req.Blob) > offline.MaxBlob:
		reply(false, "message size not accepted")
		return
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

	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	err := m.Store.PutEnvelope(ctx, storage.RelayEnvelope{
		ID: req.ID, From: from, To: req.To, Blob: req.Blob, Created: now, Expires: expires,
	}, m.opts.limits())
	var quota *storage.QuotaError
	switch {
	case errors.As(err, &quota):
		reply(false, quota.Reason)
		return
	case err != nil:
		m.Logger.Warn("Could not store a message for relaying", "error", err)
		reply(false, "internal error")
		return
	}
	reply(true, "")

	// If the recipient is connected to us right now, pass it on immediately.
	if m.Net.IsConnected(req.To) {
		to := req.To
		m.background(func(ctx context.Context) { m.deliverHeld(ctx, to) })
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
		d := protocol.RelayDeliver{ID: e.ID, From: e.From, Blob: e.Blob, Created: e.Created.UnixMilli()}
		if err := m.Net.SendJSON(ctx, peerID, protocol.KindRelayDeliver, d); err != nil {
			return // they went away; the rest waits for next time
		}
	}
}

// deliverReceipts hands a sender the receipts we hold for them.
func (m *Manager) deliverReceipts(ctx context.Context, peerID string) {
	recs, err := m.Store.ReceiptsFor(ctx, peerID, m.now(), receiptBatch)
	if err != nil {
		return
	}
	for _, r := range recs {
		fr := protocol.RelayReceipt{MsgID: r.MsgID, Signer: r.Signer, EdPub: r.EdPub, Sig: r.Sig}
		if err := m.Net.SendJSON(ctx, peerID, protocol.KindRelayReceipt, fr); err != nil {
			return
		}
		_ = m.Store.DeleteReceipt(ctx, r.To, r.MsgID, r.Signer)
	}
}

// onAck: the recipient has dealt with an envelope. Only the addressee can
// acknowledge (the store enforces it), and a receipt is kept only if it is
// genuinely signed by that recipient.
func (m *Manager) onAck(from string, body []byte) {
	var a protocol.RelayAck
	if protocol.Unmarshal(body, &a) != nil || !validWireID(a.ID) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	env, err := m.Store.TakeEnvelope(ctx, a.ID, from)
	if err != nil {
		return
	}
	if !a.Delivered || !validWireID(a.MsgID) {
		return
	}
	signer, err := offline.VerifyReceipt(a.EdPub, a.Sig, a.MsgID, env.From)
	if err != nil || signer != from {
		return
	}
	rec := storage.RelayReceipt{To: env.From, MsgID: a.MsgID, Signer: from, EdPub: a.EdPub, Sig: a.Sig, Expires: m.now().Add(MaxTTL)}
	if err := m.Store.PutReceipt(ctx, rec, m.opts.limits()); err != nil {
		return
	}
	if m.Net.IsConnected(env.From) {
		to := env.From
		m.background(func(ctx context.Context) { m.deliverReceipts(ctx, to) })
	}
}

// ---- Recipient role ----------------------------------------------------------------

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

	var msgID string
	_, sender, err := m.Offline.OpenThen(ctx, d.Blob, func(plain []byte, senderID string) error {
		if onMessage == nil {
			return errRejects
		}
		id, ok := onMessage(ctx, senderID, plain)
		if !ok {
			return errRejects
		}
		msgID = id
		return nil
	})

	ack := protocol.RelayAck{ID: d.ID}
	switch {
	case err == nil:
		ack.Delivered, ack.MsgID = true, msgID
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

// ---- Sender role: receipts ---------------------------------------------------------

func (m *Manager) onReceiptFrame(from string, body []byte) {
	var r protocol.RelayReceipt
	if protocol.Unmarshal(body, &r) != nil || !validWireID(r.MsgID) {
		return
	}
	// The receipt is addressed to us, so it must be signed for our ID.
	signer, err := offline.VerifyReceipt(r.EdPub, r.Sig, r.MsgID, m.Self.ID())
	if err != nil || signer != r.Signer {
		m.Logger.Debug("Ignored an invalid delivery receipt", "relay", short(from))
		return
	}
	m.mu.Lock()
	onReceipt := m.onReceipt
	m.mu.Unlock()
	if onReceipt == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	onReceipt(ctx, r.MsgID, signer)
}
