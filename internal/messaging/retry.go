package messaging

import (
	"context"
	"fmt"
	"time"

	"github.com/samaasi/lazy-chat/internal/protocol"
)

const (
	// retryWindow is how long an unacknowledged message keeps being retried.
	retryWindow = 7 * 24 * time.Hour
	// retryBatch caps how many messages are resent to one peer per attempt.
	retryBatch = 100
)

// RetryUndelivered resends direct messages to peerID that were never
// acknowledged, oldest first, and returns how many were queued. Resending is
// safe: receivers deduplicate by (sender, message ID) and simply acknowledge
// again. Only one retry per peer runs at a time.
func (h *Handler) RetryUndelivered(ctx context.Context, peerID string) (int, error) {
	if _, busy := h.retrying.LoadOrStore(peerID, struct{}{}); busy {
		return 0, nil
	}
	defer h.retrying.Delete(peerID)

	msgs, err := h.Store.GetUndeliveredDirect(ctx, h.SelfID, peerID, h.now().Add(-retryWindow), retryBatch)
	if err != nil {
		return 0, fmt.Errorf("could not read undelivered messages: %w", err)
	}
	if len(msgs) == 0 {
		return 0, nil
	}

	sent := 0
	for _, msg := range msgs {
		if err := h.Net.SendJSON(ctx, peerID, protocol.KindMessage, msg); err != nil {
			// Unreachable: queue the rest with relays so they reach the peer
			// even if we are offline when it comes back.
			h.relayPending(ctx, peerID)
			return sent, err
		}
		sent++
	}
	h.Out.Printf("* Resent %d undelivered message(s) to %s", sent, h.DisplayName(peerID))
	return sent, nil
}

// RetryAll retries every peer we have undelivered messages for and can
// currently see (connected or recently announced). Peers that have not been
// seen are skipped, so an offline peer costs nothing until it reappears.
func (h *Handler) RetryAll(ctx context.Context) {
	peers, err := h.Store.PeersWithUndelivered(ctx, h.SelfID, h.now().Add(-retryWindow))
	if err != nil {
		h.Logger.Debug("Could not list undelivered recipients", "error", err)
		return
	}
	for _, peerID := range peers {
		if ctx.Err() != nil {
			return
		}
		if _, known := h.Peers.GetPeer(peerID); !known && !h.Net.IsConnected(peerID) {
			continue
		}
		if _, err := h.RetryUndelivered(ctx, peerID); err != nil {
			h.Logger.Debug("Retry failed", "peer", shortID(peerID), "error", err)
		}
	}

	// Peers we cannot see at all are exactly who relays are for.
	for _, peerID := range h.pendingWithoutDirectPath(ctx) {
		if ctx.Err() != nil {
			return
		}
		if _, known := h.Peers.GetPeer(peerID); known || h.Net.IsConnected(peerID) {
			continue // handled above
		}
		h.relayPending(ctx, peerID)
	}
}
