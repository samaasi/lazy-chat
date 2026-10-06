// Package network runs the peer-to-peer transport.
//
// Every connection is TLS 1.3 with mutual authentication. Certificates are
// self-signed and carry the peer's Ed25519 key; instead of a certificate
// authority, trust comes from the peer ID being the fingerprint of that key.
// When we dial a peer we require its key to hash to the ID we discovered, so a
// forged or hijacked discovery announcement cannot redirect us to an
// impostor. When a peer dials us, the handshake proves which ID it holds, and
// that ID (never anything the peer writes in a frame) is what upper layers
// see as the sender.
package network

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/samaasi/lazy-chat/internal/config"
	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/identity"
	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/protocol"
	"github.com/samaasi/lazy-chat/internal/ratchet"
	"github.com/samaasi/lazy-chat/internal/utils"
)

const (
	dialTimeout             = 10 * time.Second
	defaultHandshakeTimeout = 10 * time.Second
	defaultMaxInbound       = 64
	defaultMaxPerIP         = 8
)

// Options configures a Manager. Zero values select the defaults.
type Options struct {
	Port       int    // TCP port; 0 picks a free one (see Manager.Port)
	ListenAddr string // empty = all interfaces
	Username   string // announced to peers in Hello

	MaxInbound       int           // simultaneous inbound connections
	MaxPerIP         int           // simultaneous inbound connections per remote IP
	HandshakeTimeout time.Duration // TLS + Hello deadline
	FrameRate        float64       // sustained non-file frames/second per connection
	FrameBurst       int
}

func (o *Options) applyDefaults() {
	if o.MaxInbound <= 0 {
		o.MaxInbound = defaultMaxInbound
	}
	if o.MaxPerIP <= 0 {
		o.MaxPerIP = defaultMaxPerIP
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = defaultHandshakeTimeout
	}
	if o.FrameRate <= 0 {
		o.FrameRate = defaultFrameRate
	}
	if o.FrameBurst <= 0 {
		o.FrameBurst = defaultFrameBurst
	}
}

// Manager implements interfaces.NetworkManager.
type Manager struct {
	opts   Options
	id     *identity.Identity
	cert   tls.Certificate
	logger interfaces.Logger
	peers  interfaces.PeerManager

	hmu      sync.RWMutex
	handlers map[protocol.Kind]interfaces.FrameHandler

	mu        sync.Mutex
	conns     map[string]*peerConn
	dialing   map[string]*dialCall
	listeners []interfaces.PeerListener
	inbound   int
	perIP     map[string]int
	listener  net.Listener
	stopped   bool
	started   bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type dialCall struct {
	done chan struct{}
	err  error
}

var _ interfaces.NetworkManager = (*Manager)(nil)

// NewManager creates a network manager for the given identity.
func NewManager(opts Options, id *identity.Identity, logger interfaces.Logger, peers interfaces.PeerManager) (*Manager, error) {
	opts.applyDefaults()
	cert, err := id.TLSCertificate()
	if err != nil {
		return nil, err
	}
	return &Manager{
		opts: opts, id: id, cert: cert, logger: logger, peers: peers,
		handlers: make(map[protocol.Kind]interfaces.FrameHandler),
		conns:    make(map[string]*peerConn),
		dialing:  make(map[string]*dialCall),
		perIP:    make(map[string]int),
	}, nil
}

// Port returns the TCP port being listened on (useful when Options.Port is 0).
func (m *Manager) Port() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tcp, ok := m.listenerAddrLocked(); ok {
		return tcp.Port
	}
	return m.opts.Port
}

func (m *Manager) listenerAddrLocked() (*net.TCPAddr, bool) {
	if m.listener == nil {
		return nil, false
	}
	tcp, ok := m.listener.Addr().(*net.TCPAddr)
	return tcp, ok
}

// Handle registers the handler for a frame kind. Register handlers before Start.
func (m *Manager) Handle(kind protocol.Kind, h interfaces.FrameHandler) {
	m.hmu.Lock()
	defer m.hmu.Unlock()
	m.handlers[kind] = h
}

// AddListener subscribes to connect/disconnect events.
func (m *Manager) AddListener(l interfaces.PeerListener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, l)
}

// Start begins listening for incoming connections
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started {
		return apperrors.ErrAppAlreadyRunning.WithContext("component", "network_manager")
	}
	addr := net.JoinHostPort(m.opts.ListenAddr, strconv.Itoa(m.opts.Port))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return apperrors.Wrap(err, apperrors.ErrorTypeNetwork, "NET002", "failed to start TCP listener").WithContext("address", addr)
	}

	m.ctx, m.cancel = context.WithCancel(ctx)
	m.listener = listener
	m.started = true
	m.logger.Info("Listening for peers", "address", listener.Addr().String(), "peer_id", m.id.ID())

	m.wg.Add(1)
	go m.acceptLoop()
	return nil
}

// Stop closes the listener and every connection and waits for all goroutines.
func (m *Manager) Stop() error {
	m.mu.Lock()
	if m.stopped || !m.started {
		m.stopped = true
		m.mu.Unlock()
		return nil
	}
	m.stopped = true
	m.cancel()
	listener := m.listener
	conns := make([]*peerConn, 0, len(m.conns))
	for _, pc := range m.conns {
		conns = append(conns, pc)
	}
	m.mu.Unlock()

	// Close outside the lock: retiring a connection takes it again.
	_ = listener.Close()
	for _, pc := range conns {
		pc.close()
	}
	m.wg.Wait()
	m.logger.Info("Network manager stopped")
	return nil
}

// ---- TLS -------------------------------------------------------------------

// tlsConfig returns the TLS settings for a connection. expectedID, when
// non-empty, is the only peer ID the remote may prove.
func (m *Manager) tlsConfig(expectedID string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{m.cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{protocol.ALPN},
		ClientAuth:   tls.RequireAnyClientCert,
		// Certificates are self-signed, so chain verification cannot work.
		// InsecureSkipVerify only disables that default check; the
		// VerifyConnection callback below replaces it with a strictly
		// stronger one by pinning the peer's key fingerprint.
		InsecureSkipVerify: true, //nolint:gosec // see comment above
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != protocol.ALPN {
				return errors.New("peer does not speak lazy-chat")
			}
			if len(cs.PeerCertificates) == 0 {
				return errors.New("peer presented no certificate")
			}
			id, err := identity.PeerIDFromCertificate(cs.PeerCertificates[0].Raw)
			if err != nil {
				return err
			}
			if expectedID != "" && id != expectedID {
				return fmt.Errorf("peer identity mismatch: expected %s, connection proved %s", short(expectedID), short(id))
			}
			return nil
		},
	}
}

// ---- Accepting -------------------------------------------------------------

func (m *Manager) acceptLoop() {
	defer m.wg.Done()

	var backoff time.Duration
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			if m.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// Persistent accept errors (for example running out of file
			// descriptors) must not turn into a busy loop.
			backoff = min(max(backoff*2, 50*time.Millisecond), time.Second)
			m.logger.Warn("Failed to accept connection", "error", err, "retry_in", backoff)
			select {
			case <-time.After(backoff):
				continue
			case <-m.ctx.Done():
				return
			}
		}
		backoff = 0

		ip := remoteIP(conn.RemoteAddr())
		if !m.reserveInbound(ip) {
			m.logger.Debug("Rejected inbound connection: limit reached", "remote_ip", ip)
			_ = conn.Close()
			continue
		}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.handleInbound(conn, ip)
		}()
	}
}

func (m *Manager) reserveInbound(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped || m.inbound >= m.opts.MaxInbound || m.perIP[ip] >= m.opts.MaxPerIP {
		return false
	}
	m.inbound++
	m.perIP[ip]++
	return true
}

func (m *Manager) releaseInbound(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inbound--
	if m.perIP[ip]--; m.perIP[ip] <= 0 {
		delete(m.perIP, ip)
	}
}

func (m *Manager) handleInbound(conn net.Conn, ip string) {
	tc := tls.Server(conn, m.tlsConfig(""))
	release := func() { m.releaseInbound(ip) }
	if _, err := m.establish(tc, "", false, ip, release, nil); err != nil {
		m.logger.Debug("Inbound connection rejected", "remote_ip", ip, "error", err)
		_ = conn.Close()
		release()
	}
}

// ---- Establishing ----------------------------------------------------------

// establish completes the TLS handshake, exchanges Hello frames, and registers
// the connection. identified, when set, runs once the peer is authenticated
// and before anyone is told it connected. On success the connection's goroutines are running. If a
// connection to the same peer already exists and wins, the new one is closed
// and the existing one is returned.
func (m *Manager) establish(tc *tls.Conn, expectedID string, outbound bool, ip string, release func(), identified func(id, name string)) (*peerConn, error) {
	ctx, cancel := context.WithTimeout(m.ctx, m.opts.HandshakeTimeout)
	defer cancel()
	// Unblocks the Hello exchange (plain deadline-based I/O) on Stop or timeout.
	stop := context.AfterFunc(ctx, func() { _ = tc.Close() })
	defer stop()

	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("no peer certificate")
	}
	peerID, err := identity.PeerIDFromCertificate(certs[0].Raw)
	if err != nil {
		return nil, err
	}
	if peerID == m.id.ID() {
		return nil, errors.New("refusing connection to ourselves")
	}
	if expectedID != "" && peerID != expectedID {
		return nil, fmt.Errorf("peer identity mismatch: expected %s, got %s", short(expectedID), short(peerID))
	}

	pc := newPeerConn(peerID, tc, outbound, m.id.ID(), ip, m.opts.FrameRate, m.opts.FrameBurst)
	pc.release = release

	name, err := m.exchangeHello(tc, pc)
	if err != nil {
		return nil, fmt.Errorf("hello: %w", err)
	}
	pc.name = name

	// Start the per-connection ratchet before any application frame flows.
	peerKey, ok := certs[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("peer certificate does not hold an Ed25519 key")
	}
	if pc.sess, err = m.exchangeRatchet(tc, pc, peerID, peerKey); err != nil {
		return nil, fmt.Errorf("ratchet: %w", err)
	}

	if identified != nil {
		identified(pc.id, pc.name)
	}
	winner, err := m.register(pc)
	if err != nil {
		return nil, err
	}
	return winner, nil
}

func (m *Manager) exchangeHello(tc *tls.Conn, pc *peerConn) (string, error) {
	_ = tc.SetDeadline(time.Now().Add(m.opts.HandshakeTimeout))
	defer tc.SetDeadline(time.Time{})

	body, err := protocol.Marshal(protocol.Hello{Version: protocol.Version, Username: m.opts.Username})
	if err != nil {
		return "", err
	}
	frame, err := protocol.EncodeFrame(protocol.KindHello, body)
	if err != nil {
		return "", err
	}
	if _, err := tc.Write(frame); err != nil {
		return "", err
	}

	kind, body, err := protocol.ReadFrame(pc.br)
	if err != nil {
		return "", err
	}
	if kind != protocol.KindHello {
		return "", errors.New("first frame was not Hello")
	}
	var hello protocol.Hello
	if err := protocol.Unmarshal(body, &hello); err != nil {
		return "", err
	}
	if hello.Version != protocol.Version {
		return "", fmt.Errorf("unsupported protocol version %d", hello.Version)
	}
	if err := config.ValidateUsername(hello.Username); err != nil {
		return "", fmt.Errorf("bad username: %w", err)
	}
	return utils.SanitizeText(hello.Username, config.MaxUsernameLen), nil
}

// exchangeRatchet performs the signed ephemeral key exchange that starts the
// message ratchet. It is bound to this TLS session through exported keying
// material, so it cannot be replayed on another connection.
func (m *Manager) exchangeRatchet(tc *tls.Conn, pc *peerConn, peerID string, peerKey ed25519.PublicKey) (*ratchet.Session, error) {
	_ = tc.SetDeadline(time.Now().Add(m.opts.HandshakeTimeout))
	defer tc.SetDeadline(time.Time{})

	state := tc.ConnectionState()
	binding, err := state.ExportKeyingMaterial("lazy-chat ratchet v1", nil, 32)
	if err != nil {
		return nil, err
	}
	hs, initMsg, err := ratchet.Start(m.id.ID(), peerID, m.id, binding)
	if err != nil {
		return nil, err
	}
	frame, err := protocol.EncodeFrame(protocol.KindRatchetInit, initMsg)
	if err != nil {
		return nil, err
	}
	if _, err := tc.Write(frame); err != nil {
		return nil, err
	}

	kind, body, err := protocol.ReadFrame(pc.br)
	if err != nil {
		return nil, err
	}
	if kind != protocol.KindRatchetInit {
		return nil, errors.New("expected the ratchet handshake")
	}
	return hs.Finish(body, peerKey)
}

// register installs pc as the connection for its peer, resolving duplicates.
func (m *Manager) register(pc *peerConn) (*peerConn, error) {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return nil, errors.New("network manager is stopped")
	}

	old, exists := m.conns[pc.id]
	if exists && !preferNew(old, pc) {
		m.mu.Unlock()
		m.discard(pc)
		return old, nil
	}
	m.conns[pc.id] = pc
	m.wg.Add(2)
	m.mu.Unlock()

	if exists {
		// Replaces a connection to the same peer; the peer never looked offline.
		old.close()
	}

	go func() {
		defer m.wg.Done()
		pc.writeLoop(func(err error) {
			m.logger.Debug("Write failed", "peer", short(pc.id), "error", err)
		})
	}()
	go func() {
		defer m.wg.Done()
		m.readLoop(pc)
	}()

	if !exists {
		m.logger.Info("Peer connected", "peer", short(pc.id), "username", pc.name, "outbound", pc.outbound)
		m.notify(func(l interfaces.PeerListener) { l.PeerConnected(pc.id, pc.name) })
	}
	return pc, nil
}

// preferNew decides between two simultaneous connections to one peer. Both
// ends evaluate the same rule on the same data, so both keep the same
// connection: the one opened by the peer with the smaller ID. When one side
// opened both (a reconnect) the newer wins.
func preferNew(old, new *peerConn) bool {
	return new.initiator <= old.initiator
}

// discard closes a connection that never got registered.
func (m *Manager) discard(pc *peerConn) {
	pc.close()
	pc.relOnce.Do(func() {
		if pc.release != nil {
			pc.release()
		}
	})
}

// retire cleans up after a registered connection ends.
func (m *Manager) retire(pc *peerConn) {
	pc.close()

	m.mu.Lock()
	current := m.conns[pc.id] == pc
	if current {
		delete(m.conns, pc.id)
	}
	m.mu.Unlock()

	pc.relOnce.Do(func() {
		if pc.release != nil {
			pc.release()
		}
	})
	if current {
		m.logger.Info("Peer disconnected", "peer", short(pc.id), "username", pc.name)
		m.notify(func(l interfaces.PeerListener) { l.PeerDisconnected(pc.id) })
	}
}

func (m *Manager) notify(fn func(interfaces.PeerListener)) {
	m.mu.Lock()
	ls := slices.Clone(m.listeners)
	m.mu.Unlock()
	for _, l := range ls {
		fn(l)
	}
}

// ---- Reading ---------------------------------------------------------------

func (m *Manager) readLoop(pc *peerConn) {
	defer m.retire(pc)

	for {
		_ = pc.conn.SetReadDeadline(time.Now().Add(idleTimeout))
		kind, body, err := protocol.ReadFrame(pc.br)
		if err != nil {
			if !isClosed(err) {
				m.logger.Debug("Connection error", "peer", short(pc.id), "error", err)
			}
			return
		}

		switch kind {
		case protocol.KindPing:
			continue
		case protocol.KindSecure:
			// handled below
		default:
			// Hello and RatchetInit happen once, before this loop; anything
			// else outside a sealed envelope is a protocol violation, and
			// that includes plaintext application frames.
			m.logger.Warn("Unexpected unencrypted frame; disconnecting", "peer", short(pc.id), "kind", kind)
			return
		}

		plain, err := pc.sess.Open(body)
		if err != nil {
			m.logger.Warn("Message failed authentication; disconnecting", "peer", short(pc.id), "error", err)
			return
		}
		if len(plain) == 0 {
			return
		}
		inner, payload := protocol.Kind(plain[0]), plain[1:]
		if !inner.Application() || len(payload) > protocol.MaxBody(inner) {
			m.logger.Warn("Invalid sealed frame; disconnecting", "peer", short(pc.id), "kind", inner)
			return
		}
		if inner.Throttled() && !pc.limiter.Allow() {
			m.logger.Warn("Peer exceeded the message rate limit; disconnecting", "peer", short(pc.id))
			return
		}
		m.dispatch(pc.id, inner, payload)
	}
}

// dispatch hands a frame to its handler. A panicking handler must not take
// the whole process down because of one peer's frame.
func (m *Manager) dispatch(peerID string, kind protocol.Kind, body []byte) {
	m.hmu.RLock()
	h := m.handlers[kind]
	m.hmu.RUnlock()
	if h == nil {
		m.logger.Debug("No handler for frame", "kind", kind, "peer", short(peerID))
		return
	}
	defer func() {
		if r := recover(); r != nil {
			m.logger.Error("Frame handler panicked", "kind", kind, "peer", short(peerID), "panic", fmt.Sprint(r))
		}
	}()
	h(peerID, body)
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// ---- Dialing ---------------------------------------------------------------

// ConnectToPeer establishes a connection to a discovered peer. It returns
// ErrPeerAlreadyConnected if one exists. Concurrent calls for the same peer
// share a single dial.
func (m *Manager) ConnectToPeer(ctx context.Context, peerID string) error {
	m.mu.Lock()
	if m.stopped || !m.started {
		m.mu.Unlock()
		return apperrors.ErrAppNotRunning.WithContext("component", "network_manager")
	}
	if _, ok := m.conns[peerID]; ok {
		m.mu.Unlock()
		return apperrors.ErrPeerAlreadyConnected.WithContext("peer_id", peerID)
	}
	if call, ok := m.dialing[peerID]; ok {
		m.mu.Unlock()
		select {
		case <-call.done:
			return call.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	call := &dialCall{done: make(chan struct{})}
	m.dialing[peerID] = call
	m.mu.Unlock()

	call.err = m.dial(ctx, peerID)

	m.mu.Lock()
	delete(m.dialing, peerID)
	m.mu.Unlock()
	close(call.done)
	return call.err
}

func (m *Manager) dial(ctx context.Context, peerID string) error {
	p, ok := m.peers.GetPeer(peerID)
	if !ok {
		return apperrors.ErrPeerNotFound.WithContext("peer_id", peerID)
	}

	// Also stop dialing when the manager shuts down.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(m.ctx, cancel)()

	d := net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", p.NetworkAddress())
	if err != nil {
		return apperrors.Wrap(err, apperrors.ErrorTypeNetwork, "NET001", "failed to connect to peer").
			WithContext("peer_id", peerID).WithContext("address", p.NetworkAddress())
	}

	tc := tls.Client(raw, m.tlsConfig(peerID))
	if _, err := m.establish(tc, peerID, true, "", nil, nil); err != nil {
		_ = raw.Close()
		return apperrors.Wrap(err, apperrors.ErrorTypeNetwork, "NET001", "failed to establish secure connection").
			WithContext("peer_id", peerID)
	}
	return nil
}

// Disconnect closes the connection to a peer, if any.
func (m *Manager) Disconnect(peerID string) {
	m.mu.Lock()
	pc := m.conns[peerID]
	m.mu.Unlock()
	if pc != nil {
		pc.close()
	}
}

// ---- Sending ---------------------------------------------------------------

// connFor returns the live connection to peerID, dialing if necessary.
func (m *Manager) connFor(ctx context.Context, peerID string) (*peerConn, error) {
	get := func() *peerConn {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.conns[peerID]
	}
	if pc := get(); pc != nil {
		return pc, nil
	}
	if err := m.ConnectToPeer(ctx, peerID); err != nil && !errors.Is(err, apperrors.ErrPeerAlreadyConnected) {
		return nil, err
	}
	if pc := get(); pc != nil {
		return pc, nil
	}
	return nil, apperrors.ErrPeerNotConnected.WithContext("peer_id", peerID)
}

// Send queues a frame for a peer, connecting first if needed. It returns once
// the frame is queued, not once it has been written.
func (m *Manager) Send(ctx context.Context, peerID string, kind protocol.Kind, body []byte) error {
	if !kind.Application() {
		return apperrors.New(apperrors.ErrorTypeMessage, "MSG005", "only application frames can be sent").WithContext("peer_id", peerID)
	}
	if len(body) > protocol.MaxBody(kind) {
		return apperrors.Wrap(protocol.ErrFrameSize, apperrors.ErrorTypeMessage, "MSG003", "frame too large for its kind").WithContext("peer_id", peerID)
	}
	pc, err := m.connFor(ctx, peerID)
	if err != nil {
		return err
	}
	if err := pc.enqueue(ctx, kind, body); err != nil {
		return apperrors.Wrap(err, apperrors.ErrorTypeNetwork, "NET003", "failed to send to peer").WithContext("peer_id", peerID)
	}
	return nil
}

// SendJSON marshals payload and sends it as a frame of the given kind.
func (m *Manager) SendJSON(ctx context.Context, peerID string, kind protocol.Kind, payload any) error {
	body, err := protocol.Marshal(payload)
	if err != nil {
		return apperrors.Wrap(err, apperrors.ErrorTypeMessage, "MSG005", "failed to marshal payload").WithContext("peer_id", peerID)
	}
	return m.Send(ctx, peerID, kind, body)
}

// ---- Queries ---------------------------------------------------------------

// IsConnected checks if connected to a specific peer
func (m *Manager) IsConnected(peerID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.conns[peerID]
	return ok
}

// ConnectedPeers returns the IDs of all connected peers, sorted.
func (m *Manager) ConnectedPeers() []string {
	m.mu.Lock()
	ids := make([]string, 0, len(m.conns))
	for id := range m.conns {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	slices.Sort(ids)
	return ids
}

// PeerName returns the display name a connected peer announced.
func (m *Manager) PeerName(peerID string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if pc, ok := m.conns[peerID]; ok {
		return pc.name, true
	}
	return "", false
}

// ---- Helpers ---------------------------------------------------------------

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func remoteIP(a net.Addr) string {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}
