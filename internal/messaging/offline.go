package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/utils"
)

// Relayer hands an end-to-end encrypted copy of a message to peers that will
// hold it for an offline recipient (implemented by package relay). It returns
// how many agreed to and how many of them could see who the sender was.
// msgID names the message in the delivery receipt.
type Relayer interface {
	Dispatch(ctx context.Context, to, msgID string, plaintext []byte) (models.RelayResult, error)
}

// QueuedError is returned by SendMessage when the recipient could not be
// reached but the message was safely queued with relays. It is not a failure:
// the message will be delivered when the recipient next comes online.
type QueuedError struct {
	Relays int
	// Exposed is how many relays saw who the sender was (no third peer was
	// available to forward the request anonymously).
	Exposed int
}

func (e *QueuedError) Error() string {
	s := fmt.Sprintf("recipient is offline; message queued with %d relay(s) for delivery when they return", e.Relays)
	if e.Exposed > 0 {
		s += fmt.Sprintf(" (%d of them could see that it is from you: too few peers connected to hide it)", e.Exposed)
	}
	return s
}

// IsQueued reports whether err is a QueuedError.
func IsQueued(err error) bool {
	var q *QueuedError
	return errors.As(err, &q)
}

const (
	// relayedMaxAge bounds how old a relayed message's own timestamp may be.
	relayedMaxAge = 8 * 24 * time.Hour
	// relayBatch bounds how many pending messages are handed to relays at once.
	relayBatch = 50
)

// relayedPayload is what travels inside the end-to-end encryption of a relayed
// message: the chat message itself plus the sender's display name. The
// recipient may never have seen the sender online, so without the name it could
// only show "unknown". The name has the same standing as the one in a live
// Hello: self-declared, but only ever displayed, never trusted for anything.
type relayedPayload struct {
	*models.ChatMessage
	SenderName string `json:"sender_name,omitempty"`
}

// relayCopy encrypts msg for its recipient and hands it to relays.
func (h *Handler) relayCopy(ctx context.Context, to string, msg *models.ChatMessage) (models.RelayResult, error) {
	if h.Relay == nil {
		return models.RelayResult{}, errors.New("offline delivery is not available")
	}
	plain, err := json.Marshal(relayedPayload{ChatMessage: msg, SenderName: h.SelfName})
	if err != nil {
		return models.RelayResult{}, err
	}
	return h.Relay.Dispatch(ctx, to, msg.ID, plain)
}

// relayPending hands our undelivered, not-yet-relayed direct messages for a
// peer to relays. It stops at the first failure and returns how many succeeded.
func (h *Handler) relayPending(ctx context.Context, peerID string) int {
	if h.Relay == nil {
		return 0
	}
	msgs, err := h.Store.GetUnrelayedDirect(ctx, h.SelfID, peerID, h.now().Add(-retryWindow), relayBatch)
	if err != nil || len(msgs) == 0 {
		return 0
	}
	done := 0
	for _, msg := range msgs {
		if _, err := h.relayCopy(ctx, peerID, msg); err != nil {
			h.Logger.Debug("Could not queue a message for an offline peer", "peer", shortID(peerID), "reason", err.Error())
			break
		}
		if err := h.Store.MarkMessageRelayed(ctx, h.SelfID, msg.ID); err != nil {
			break
		}
		done++
	}
	if done > 0 {
		h.Out.Printf("* %s is offline: %d message(s) queued with relays for delivery when they return", h.DisplayName(peerID), done)
	}
	return done
}

// AcceptRelayed handles a message that arrived through a relay. senderID is
// the authenticated sender recovered from the end-to-end encryption, never
// something a relay could choose. The message goes through exactly the same
// checks as one received live. It returns the message ID, for the receipt,
// and whether the message was accepted (a duplicate counts as accepted).
func (h *Handler) AcceptRelayed(ctx context.Context, senderID string, plaintext []byte) (string, bool) {
	in := relayedPayload{ChatMessage: &models.ChatMessage{}}
	if err := json.Unmarshal(plaintext, &in); err != nil {
		return "", false
	}
	msg := *in.ChatMessage
	sentAt := msg.Timestamp
	if name := strings.TrimSpace(utils.SanitizeText(in.SenderName, 32)); name != "" {
		h.names.Store(senderID, name)
	}

	group, err := h.checkInbound(ctx, senderID, &msg)
	if err != nil {
		h.Logger.Debug("Rejected a relayed message", "peer", shortID(senderID), "reason", err.Error())
		return "", false
	}
	// Unlike a live message, the original send time is meaningful here, so keep
	// it if it is plausible (not in the future, not absurdly old).
	now := h.now()
	if !sentAt.IsZero() && !sentAt.After(now.Add(time.Minute)) && sentAt.After(now.Add(-relayedMaxAge)) {
		msg.Timestamp = sentAt
	}

	inserted, err := h.Store.SaveMessage(ctx, &msg)
	if err != nil {
		h.Logger.Error("Failed to store a relayed message", "error", err)
		return "", false
	}
	if inserted {
		h.displayAt(&msg, group, "2006-01-02 15:04")
	}
	return msg.ID, true
}

// ApplyReceipt marks one of our messages delivered because its recipient
// signed a receipt (the relay layer has verified the signature). The signer
// must actually be a recipient of that message: any peer can sign a receipt for
// any message ID, but only the addressee's counts.
func (h *Handler) ApplyReceipt(ctx context.Context, msgID, signerID string) {
	msg, err := h.Store.GetMessage(ctx, h.SelfID, msgID)
	if err != nil {
		return
	}
	switch {
	case msg.IsDirectMessage() && msg.To == signerID:
	case msg.IsGroupMessage():
		member, err := h.Groups.IsMember(ctx, msg.GroupID, signerID)
		if err != nil || !member {
			return
		}
	default:
		h.Logger.Debug("Ignored a delivery receipt from someone other than the recipient", "signer", shortID(signerID))
		return
	}
	if err := h.Store.MarkMessageAsDelivered(ctx, h.SelfID, msgID); err != nil {
		h.Logger.Debug("Could not record delivery", "error", err)
	}
}

// pendingWithoutDirectPath returns recipients we hold unrelayed messages for.
func (h *Handler) pendingWithoutDirectPath(ctx context.Context) []string {
	peers, err := h.Store.PeersWithUnrelayed(ctx, h.SelfID, h.now().Add(-retryWindow))
	if err != nil {
		return nil
	}
	return peers
}
