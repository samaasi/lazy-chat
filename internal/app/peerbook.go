package app

import (
	"context"
	"sync"
	"time"

	"github.com/samaasi/lazy-chat/internal/address"
	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/storage"
)

const (
	// rememberFor is how long a peer stays in the book without a connection.
	rememberFor = 30 * 24 * time.Hour
	// maxReconnect bounds how many remembered peers are tried each round.
	maxReconnect = 20
	// reconnectEvery is how often remembered, unconnected peers are retried.
	reconnectEvery = 2 * time.Minute
	// reconnectParallel bounds simultaneous attempts.
	reconnectParallel = 4
)

// dialer is what the peer book needs from the network.
type dialer interface {
	ConnectToAddress(ctx context.Context, t address.Target) (string, string, error)
	IsConnected(peerID string) bool
}

// peerBook remembers where connected peers were reachable and reconnects to
// them, so after one meeting (by discovery or by address) a peer is found
// again even on networks where discovery does not work. Reconnection pins the
// remembered peer ID, so a different machine that now has the old address is
// refused.
type peerBook struct {
	store  storage.PeerBook
	peers  interfaces.PeerManager
	net    dialer
	logger interfaces.Logger
	now    func() time.Time

	ctx context.Context
	wg  *sync.WaitGroup
}

var _ interfaces.PeerListener = (*peerBook)(nil)

// PeerConnected records the peer's address. Only addresses learned from a
// discovery announcement or from dialing are recorded: for a peer that
// connected to us, the source port of its connection is not its listening port.
func (b *peerBook) PeerConnected(peerID, name string) {
	p, ok := b.peers.GetPeer(peerID)
	if !ok || p.Address == "" || p.Port <= 0 {
		return
	}
	if b.ctx.Err() != nil {
		return // shutting down
	}
	kp := storage.KnownPeer{ID: peerID, Username: name, Address: p.Address, Port: p.Port, LastConnected: b.now()}
	if kp.Username == "" {
		kp.Username = p.Username
	}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
		defer cancel()
		if err := b.store.RememberPeer(ctx, kp); err != nil && b.ctx.Err() == nil {
			b.logger.Debug("Could not remember peer", "peer", peerID[:8], "error", err)
		}
	}()
}

// PeerDisconnected implements interfaces.PeerListener.
func (b *peerBook) PeerDisconnected(string) {}

// run reconnects to remembered peers now and then periodically.
func (b *peerBook) run() {
	defer b.wg.Done()
	ticker := time.NewTicker(reconnectEvery)
	defer ticker.Stop()
	for {
		b.reconnect()
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// reconnect dials every remembered peer that is not connected. Failures are
// expected (the peer is simply offline) and only logged.
func (b *peerBook) reconnect() {
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	known, err := b.store.KnownPeers(ctx, b.now().Add(-rememberFor), maxReconnect)
	if err != nil {
		b.logger.Debug("Could not read known peers", "error", err)
		return
	}
	slots := make(chan struct{}, reconnectParallel)
	var wg sync.WaitGroup
	for _, kp := range known {
		if b.net.IsConnected(kp.ID) {
			continue
		}
		t := address.Target{ID: kp.ID, Host: kp.Address, Port: kp.Port}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				return
			}
			dctx, dcancel := context.WithTimeout(ctx, 15*time.Second)
			defer dcancel()
			if _, _, err := b.net.ConnectToAddress(dctx, t); err != nil && b.ctx.Err() == nil {
				b.logger.Debug("Remembered peer not reachable", "peer", kp.ID[:8], "address", t.String(), "error", err)
			}
		}()
	}
	wg.Wait()
}
