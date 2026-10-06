package network

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"time"

	"github.com/samaasi/lazy-chat/internal/address"
	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/models"
)

// ConnectToAddress dials a peer directly, without discovery. It is for
// networks where broadcasts do not get through. The connection is exactly as
// authenticated as any other: TLS 1.3 with mutual keys, the peer ID taken from
// the key it proves. When t.ID is set, only that peer is accepted at the
// address. Without it the address is trusted on first use, so compare safety
// numbers (/safety) afterwards. It returns the peer's ID and announced name.
func (m *Manager) ConnectToAddress(ctx context.Context, t address.Target) (peerID, name string, err error) {
	m.mu.Lock()
	if m.stopped || !m.started {
		m.mu.Unlock()
		return "", "", apperrors.ErrAppNotRunning.WithContext("component", "network_manager")
	}
	if _, ok := m.conns[t.ID]; ok && t.ID != "" {
		m.mu.Unlock()
		return t.ID, "", apperrors.ErrPeerAlreadyConnected.WithContext("peer_id", t.ID)
	}
	m.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(m.ctx, cancel)()

	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	d := net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", "", apperrors.Wrap(err, apperrors.ErrorTypeNetwork, "NET001", "failed to connect to "+addr)
	}
	tc := tls.Client(raw, m.tlsConfig(t.ID))
	pc, err := m.establish(tc, t.ID, true, "", nil)
	if err != nil {
		_ = raw.Close()
		return "", "", apperrors.Wrap(err, apperrors.ErrorTypeNetwork, "NET001", "failed to establish secure connection to "+addr)
	}

	// Remember where it is, so it shows in /list and can be reached by name.
	m.peers.AddPeer(&models.Peer{ID: pc.id, Username: pc.name, Address: t.Host, Port: t.Port, LastSeen: time.Now()})
	return pc.id, pc.name, nil
}
