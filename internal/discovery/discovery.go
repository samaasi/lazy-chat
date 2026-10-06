// Package discovery finds peers on the local network with UDP broadcasts.
//
// Announcements are signed with the sender's identity key and carry that key,
// so a receiver can check that the announced peer ID really is the
// fingerprint of the key that signed it. Anyone on the LAN can still *send*
// packets, but nobody can announce an ID they do not hold the key for, and
// replayed announcements are discarded. Discovery only says where to try;
// the TCP connection independently proves identity again (see package
// network), so a spoofed source address can at worst waste a connection
// attempt.
package discovery

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/samaasi/lazy-chat/internal/config"
	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/identity"
	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/utils"
)

const (
	announceType    = "announce"
	announceVersion = 1
	// maxClockSkew is how far an announcement's timestamp may differ from ours.
	maxClockSkew = time.Minute
	// maxPacket bounds what we will even try to parse.
	maxPacket = 1024
	// Per-source limits: announcements arrive about once per interval.
	sourceRate  = 2.0
	sourceBurst = 10
	maxSources  = 4096
	maxTracked  = 4096 // peers whose last timestamp we remember
)

// Options configures the discovery service.
type Options struct {
	BasePort      int           // first UDP port to try
	PortRange     int           // number of consecutive ports to try / announce to
	BroadcastAddr string        // IPv4 address announcements are sent to
	Interval      time.Duration // time between announcements
	Username      string
	TCPPort       int // port peers should connect to
}

// OptionsFromConfig derives Options from the application config.
func OptionsFromConfig(cfg *config.Config) Options {
	return Options{
		BasePort:      cfg.DiscoveryPort,
		PortRange:     cfg.DiscoveryRange,
		BroadcastAddr: cfg.BroadcastAddr,
		Interval:      time.Duration(cfg.BroadcastInterval) * time.Second,
		Username:      cfg.Username,
		TCPPort:       cfg.TCPPort,
	}
}

// announcement is the signed discovery datagram.
type announcement struct {
	Type      string `json:"type"`
	Version   int    `json:"version"`
	PeerID    string `json:"peer_id"`
	PublicKey []byte `json:"public_key"`
	Username  string `json:"username"`
	Port      int    `json:"port"`
	Timestamp int64  `json:"timestamp"` // unix milliseconds
	Signature []byte `json:"signature"`
}

// signedBytes is the canonical form covered by the signature. %q makes the
// encoding unambiguous whatever the username contains.
func (a *announcement) signedBytes() []byte {
	return fmt.Appendf(nil, "lazy-chat/announce/v%d|%q|%q|%d|%d", a.Version, a.PeerID, a.Username, a.Port, a.Timestamp)
}

// Service implements the PeerDiscovery interface.
type Service struct {
	opts   Options
	id     *identity.Identity
	logger interfaces.Logger
	peers  interfaces.PeerManager
	now    func() time.Time

	limiter *utils.KeyedLimiter

	// interfaces lists the machine's network interfaces (replaceable in tests).
	interfaces func() ([]iface, error)

	mu       sync.Mutex
	conn     *net.UDPConn
	port     int
	bcast    net.IP           // the configured broadcast address
	lastSeen map[string]int64 // peer ID -> newest accepted timestamp
	started  bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

var _ interfaces.PeerDiscovery = (*Service)(nil)

// NewService creates a new discovery service
func NewService(opts Options, id *identity.Identity, logger interfaces.Logger, peers interfaces.PeerManager) *Service {
	return &Service{
		opts: opts, id: id, logger: logger, peers: peers,
		now:        time.Now,
		limiter:    utils.NewKeyedLimiter(sourceRate, sourceBurst, maxSources),
		lastSeen:   make(map[string]int64),
		interfaces: systemInterfaces,
	}
}

// Port returns the UDP port the service is listening on.
func (s *Service) Port() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.port
}

// Start begins the discovery process
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return apperrors.ErrAppAlreadyRunning.WithContext("component", "discovery_service")
	}

	ip := net.ParseIP(s.opts.BroadcastAddr).To4()
	if ip == nil {
		return apperrors.ErrConfigValidation.WithContext("field", "broadcast_addr").WithContext("value", s.opts.BroadcastAddr)
	}

	// Several instances on one machine each take the next free port in the
	// range, and every instance announces to the whole range.
	var (
		conn    *net.UDPConn
		lastErr error
	)
	for p := s.opts.BasePort; p < s.opts.BasePort+s.opts.PortRange; p++ {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: p})
		if err == nil {
			conn, s.port = c, p
			break
		}
		lastErr = err
	}
	if conn == nil {
		return apperrors.Wrap(lastErr, apperrors.ErrorTypeDiscovery, "DISC001", "failed to bind to any discovery port").
			WithContext("port_range", fmt.Sprintf("%d-%d", s.opts.BasePort, s.opts.BasePort+s.opts.PortRange-1))
	}

	s.bcast = ip
	s.conn = conn
	s.started = true
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.logger.Info("Discovery started", "port", s.port)

	s.wg.Add(2)
	go s.listen(conn)
	go s.announceLoop(conn)
	return nil
}

// Stop gracefully stops the discovery process
func (s *Service) Stop() error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return nil
	}
	s.cancel()
	conn := s.conn
	s.mu.Unlock()

	// Closing the socket unblocks the read; no polling deadline needed.
	_ = conn.Close()
	s.wg.Wait()
	s.logger.Info("Discovery service stopped")
	return nil
}

// ---- Sending ---------------------------------------------------------------

func (s *Service) announceLoop(conn *net.UDPConn) {
	defer s.wg.Done()

	s.announce(conn) // do not make new peers wait a full interval
	ticker := time.NewTicker(s.opts.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.announce(conn)
		}
	}
}

func (s *Service) announce(conn *net.UDPConn) {
	data, err := s.buildAnnouncement()
	if err != nil {
		s.logger.Error("Failed to build announcement", "error", err)
		return
	}
	for _, t := range s.targets() {
		if _, err := conn.WriteToUDP(data, t); err != nil && s.ctx.Err() == nil {
			s.logger.Debug("Announcement not sent", "target", t.String(), "error", err)
		}
	}
}

// targets is every address an announcement goes to: each broadcast address
// (see broadcastAddrs) on every port of the range. That includes the port we
// listen on ourselves: on another machine a peer most likely took the very
// same one. (Our own copies are recognised and dropped on arrival.)
func (s *Service) targets() []*net.UDPAddr {
	var out []*net.UDPAddr
	for _, ip := range s.broadcastAddrs() {
		for p := s.opts.BasePort; p < s.opts.BasePort+s.opts.PortRange; p++ {
			out = append(out, &net.UDPAddr{IP: ip, Port: p})
		}
	}
	return out
}

// broadcastAddrs returns the configured broadcast address and, when that is
// the generic 255.255.255.255, also the broadcast address of each local IPv4
// network. Windows sends 255.255.255.255 out of a single adapter, which on a
// machine with virtual adapters (WSL, Hyper-V, VPNs) is often not the LAN;
// a subnet's own broadcast address is routed out of the right one. The list is
// rebuilt each time, so adapters that come and go are followed.
func (s *Service) broadcastAddrs() []net.IP {
	out := []net.IP{s.bcast}
	if !s.bcast.Equal(net.IPv4bcast) {
		return out // an explicit choice by the user: respect it
	}
	ifs, err := s.interfaces()
	if err != nil {
		s.logger.Debug("Could not list network interfaces", "error", err)
		return out
	}
	seen := map[string]bool{s.bcast.String(): true}
	for _, i := range ifs {
		for _, b := range i.broadcasts() {
			if !seen[b.String()] {
				seen[b.String()] = true
				out = append(out, b)
			}
		}
	}
	return out
}

// iface is the part of a network interface that broadcasting needs.
type iface struct {
	flags net.Flags
	addrs []net.Addr
}

func systemInterfaces() ([]iface, error) {
	sys, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]iface, 0, len(sys))
	for _, i := range sys {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		out = append(out, iface{flags: i.Flags, addrs: addrs})
	}
	return out, nil
}

// broadcasts returns the directed broadcast address of each IPv4 network on
// an interface that is up and can broadcast.
func (i iface) broadcasts() []net.IP {
	if i.flags&net.FlagUp == 0 || i.flags&net.FlagBroadcast == 0 || i.flags&net.FlagLoopback != 0 {
		return nil
	}
	var out []net.IP
	for _, a := range i.addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, mask := n.IP.To4(), n.Mask
		if ip == nil || len(mask) == net.IPv6len {
			mask = mask[len(mask)-4:]
		}
		if ip == nil || len(mask) != 4 || ip.IsLinkLocalUnicast() {
			continue
		}
		if ones, _ := net.IPMask(mask).Size(); ones == 0 || ones >= 31 {
			continue // no meaningful broadcast address
		}
		b := make(net.IP, 4)
		for k := range b {
			b[k] = ip[k] | ^mask[k]
		}
		out = append(out, b)
	}
	return out
}

func (s *Service) buildAnnouncement() ([]byte, error) {
	a := announcement{
		Type: announceType, Version: announceVersion,
		PeerID: s.id.ID(), PublicKey: s.id.PublicKey(),
		Username: s.opts.Username, Port: s.opts.TCPPort,
		Timestamp: s.now().UnixMilli(),
	}
	a.Signature = s.id.Sign(a.signedBytes())
	return json.Marshal(a)
}

// ---- Receiving -------------------------------------------------------------

func (s *Service) listen(conn *net.UDPConn) {
	defer s.wg.Done()

	buf := make([]byte, 2*maxPacket)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// On Windows an ICMP "port unreachable" from an earlier send
			// surfaces here as a read error; it is not actionable.
			s.logger.Debug("UDP read error", "error", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		s.handlePacket(buf[:n], addr)
	}
}

// handlePacket validates and applies one datagram. Everything about it is
// untrusted.
func (s *Service) handlePacket(data []byte, from *net.UDPAddr) {
	if len(data) > maxPacket {
		return
	}
	ip := from.IP.String()
	if !s.limiter.Allow(ip) {
		return
	}

	a, err := s.verify(data)
	if err != nil {
		s.logger.Debug("Ignored discovery packet", "from", ip, "reason", err.Error())
		return
	}
	if a.PeerID == s.id.ID() {
		return // our own broadcast
	}
	if !s.acceptTimestamp(a.PeerID, a.Timestamp) {
		s.logger.Debug("Ignored replayed announcement", "from", ip)
		return
	}

	s.peers.AddPeer(&models.Peer{
		ID:       a.PeerID,
		Username: utils.SanitizeText(a.Username, config.MaxUsernameLen),
		Address:  ip,
		Port:     a.Port,
		LastSeen: s.now(),
	})
}

// verify checks structure, binding between key and ID, signature and age.
func (s *Service) verify(data []byte) (*announcement, error) {
	var a announcement
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, errors.New("not an announcement")
	}
	switch {
	case a.Type != announceType || a.Version != announceVersion:
		return nil, errors.New("unsupported type or version")
	case len(a.PublicKey) != ed25519.PublicKeySize:
		return nil, errors.New("bad public key")
	case !identity.ValidID(a.PeerID) || identity.PeerIDFromPublicKey(a.PublicKey) != a.PeerID:
		return nil, errors.New("peer ID does not match public key")
	case a.Port < 1 || a.Port > 65535:
		return nil, errors.New("bad port")
	case config.ValidateUsername(a.Username) != nil:
		return nil, errors.New("bad username")
	}
	if skew := s.now().Sub(time.UnixMilli(a.Timestamp)).Abs(); skew > maxClockSkew {
		return nil, errors.New("timestamp outside the allowed window")
	}
	if !identity.Verify(a.PublicKey, a.signedBytes(), a.Signature) {
		return nil, errors.New("bad signature")
	}
	return &a, nil
}

// acceptTimestamp rejects announcements not newer than the last one accepted
// from the same peer, which defeats replaying a captured packet.
func (s *Service) acceptTimestamp(peerID string, ts int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.lastSeen[peerID]; ok && ts <= last {
		return false
	}
	if len(s.lastSeen) >= maxTracked {
		clear(s.lastSeen) // bounded memory; a reset only briefly weakens replay protection
	}
	s.lastSeen[peerID] = ts
	return true
}
