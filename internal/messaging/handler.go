// Package messaging implements chat on top of the authenticated transport:
// direct messages, group messages and the group membership protocol.
//
// Everything arriving from the network is treated as hostile. The only thing
// taken from a peer's frame about *who sent it* is the connection's
// authenticated identity; claimed senders, timestamps and delivery flags in
// the payload are overwritten or ignored.
package messaging

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	apperrors "github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/models"
	"github.com/samaasi/lazy-chat/internal/protocol"
	"github.com/samaasi/lazy-chat/internal/services"
	"github.com/samaasi/lazy-chat/internal/storage"
	"github.com/samaasi/lazy-chat/internal/utils"
)

const (
	// MaxMessageBytes is the largest message body accepted or sent.
	MaxMessageBytes = 4096
	// maxWireIDLen bounds identifiers received from the network.
	maxWireIDLen = 64
	// opTimeout bounds each network or database operation done on behalf of
	// an incoming frame.
	opTimeout = 10 * time.Second
	// maxSendFanout caps concurrent connection attempts for one group message.
	maxSendFanout = 8
)

// Printer receives lines meant for the user.
type Printer interface {
	Printf(format string, args ...any)
}

// Deps are the collaborators a Handler needs.
type Deps struct {
	Logger   interfaces.Logger
	SelfID   string
	SelfName string
	Net      interfaces.NetworkManager
	Store    storage.MessageStorage
	Groups   *services.GroupService
	Peers    interfaces.PeerManager
	Notifier interfaces.NotificationManager
	Out      Printer
	// Relay, when set, delivers to offline recipients through other peers.
	Relay Relayer
}

// Handler processes chat traffic. It is safe for concurrent use.
type Handler struct {
	Deps
	now func() time.Time

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup

	// names remembers the last display name seen per peer, so a peer that
	// just disconnected can still be named in the "disconnected" line.
	names sync.Map // peer ID -> string

	retrying sync.Map // peer ID -> struct{}: a retry to that peer is in flight
}

var _ interfaces.PeerListener = (*Handler)(nil)

// NewHandler creates a handler. Call Register to attach it to the network.
func NewHandler(d Deps) *Handler {
	return &Handler{Deps: d, now: time.Now}
}

// Register installs the frame handlers on the network manager and subscribes
// to peer events.
func (h *Handler) Register() {
	h.Net.Handle(protocol.KindMessage, h.onMessage)
	h.Net.Handle(protocol.KindAck, h.onAck)
	h.Net.Handle(protocol.KindGroupInvite, h.onGroupInvite)
	h.Net.Handle(protocol.KindGroupInviteReply, h.onGroupInviteReply)
	h.Net.Handle(protocol.KindGroupUpdate, h.onGroupUpdate)
	h.Net.AddListener(h)
}

// Close waits for background work (acknowledgements, fan-out) to finish.
func (h *Handler) Close() {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	h.wg.Wait()
}

// background runs fn on a tracked goroutine, unless the handler is closed.
func (h *Handler) background(fn func(ctx context.Context)) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.wg.Add(1)
	h.mu.Unlock()

	go func() {
		defer h.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
		defer cancel()
		fn(ctx)
	}()
}

// ---- Validation ------------------------------------------------------------

// ValidateContent checks the text of a message.
func ValidateContent(text string) error {
	switch {
	case strings.TrimSpace(text) == "":
		return apperrors.ErrMessageEmpty
	case len(text) > MaxMessageBytes:
		return apperrors.ErrMessageTooLarge.WithContext("length", len(text)).WithContext("max_length", MaxMessageBytes)
	case !utf8.ValidString(text):
		return apperrors.ErrMessageInvalid.WithContext("reason", "not valid UTF-8")
	}
	return nil
}

// validWireID reports whether s is acceptable as an identifier from the network.
func validWireID(s string) bool {
	if s == "" || len(s) > maxWireIDLen {
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

// ---- Names -----------------------------------------------------------------

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// DisplayName renders a peer as "name (abcd1234)". The ID suffix keeps
// look-alike names distinguishable; the name is sanitised.
func (h *Handler) DisplayName(peerID string) string {
	if peerID == h.SelfID {
		return "you"
	}
	name, ok := h.Net.PeerName(peerID)
	if !ok {
		if cached, found := h.names.Load(peerID); found {
			name = cached.(string)
		} else if p, found := h.Peers.GetPeer(peerID); found {
			name = p.Username
		}
	}
	name = utils.SanitizeText(name, 32)
	if name == "" {
		name = "unknown"
	}
	return fmt.Sprintf("%s (%s)", name, shortID(peerID))
}

// ---- Receiving chat messages -----------------------------------------------

func (h *Handler) onMessage(from string, body []byte) {
	var msg models.ChatMessage
	if err := protocol.Unmarshal(body, &msg); err != nil {
		h.Logger.Debug("Malformed message", "peer", shortID(from), "error", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	group, err := h.checkInbound(ctx, from, &msg)
	if err != nil {
		h.Logger.Debug("Rejected message", "peer", shortID(from), "reason", err.Error())
		return
	}

	inserted, err := h.Store.SaveMessage(ctx, &msg)
	if err != nil {
		// No acknowledgement: the sender will see it as undelivered.
		h.Logger.Error("Failed to store received message", "error", err)
		return
	}

	// Acknowledge even duplicates, in case our earlier ack was lost.
	id := msg.ID
	h.background(func(ctx context.Context) {
		if err := h.Net.SendJSON(ctx, from, protocol.KindAck, protocol.Ack{MessageID: id}); err != nil {
			h.Logger.Debug("Failed to acknowledge message", "peer", shortID(from), "error", err)
		}
	})
	if !inserted {
		return
	}
	h.display(&msg, group)
}

// checkInbound validates a received message and rewrites the fields the
// sender must not control. It returns the group for group messages.
func (h *Handler) checkInbound(ctx context.Context, from string, msg *models.ChatMessage) (*models.Group, error) {
	// Authoritative values, regardless of what the payload claimed.
	msg.Seq = 0
	msg.From = from
	msg.Timestamp = h.now()
	msg.Delivered, msg.Read = true, false

	if !validWireID(msg.ID) {
		return nil, errors.New("bad message id")
	}
	if err := ValidateContent(msg.Message); err != nil {
		return nil, err
	}

	switch msg.Type {
	case models.MessageTypeDirect:
		if msg.To != h.SelfID || msg.GroupID != "" {
			return nil, errors.New("direct message not addressed to us")
		}
		return nil, nil

	case models.MessageTypeGroup:
		if msg.To != "" || !validWireID(msg.GroupID) {
			return nil, errors.New("malformed group message")
		}
		// Membership is checked against *our* records, before anything is
		// stored, using the authenticated sender.
		group, err := h.Groups.GetGroup(ctx, msg.GroupID)
		if err != nil {
			return nil, fmt.Errorf("group %s: %w", shortID(msg.GroupID), err)
		}
		if !group.HasMember(from) {
			return nil, errors.New("sender is not a member of the group")
		}
		return group, nil

	default:
		// "system" messages are local-only; peers may not send them.
		return nil, fmt.Errorf("message type %q not accepted from peers", msg.Type)
	}
}

func (h *Handler) display(msg *models.ChatMessage, group *models.Group) {
	h.displayAt(msg, group, "15:04:05")
}

// displayAt prints a received message, stamped with the given time layout
// (messages that arrive late show their date).
func (h *Handler) displayAt(msg *models.ChatMessage, group *models.Group, layout string) {
	ts := msg.Timestamp.Format(layout)
	text := utils.SanitizeText(msg.Message, 0)

	who := h.DisplayName(msg.From)
	if group != nil {
		// A peer we have no live connection to is still named in the roster.
		if _, known := h.Net.PeerName(msg.From); !known {
			if rosterName := group.Members[msg.From]; rosterName != "" {
				who = fmt.Sprintf("%s (%s)", utils.SanitizeText(rosterName, 32), shortID(msg.From))
			}
		}
		h.Out.Printf("[%s] [%s] %s: %s", ts, utils.SanitizeText(group.Name, models.MaxGroupNameLen), who, text)
	} else {
		h.Out.Printf("[%s] %s: %s", ts, who, text)
	}
	if h.Notifier != nil {
		prefix := who
		if group != nil {
			prefix = group.Name + " / " + who
		}
		_ = h.Notifier.NotifyMessageReceived(prefix, text)
	}
}

func (h *Handler) onAck(from string, body []byte) {
	var ack protocol.Ack
	if err := protocol.Unmarshal(body, &ack); err != nil || !validWireID(ack.MessageID) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	// Only messages we sent can be marked: the store scopes this to SelfID.
	if err := h.Store.MarkMessageAsDelivered(ctx, h.SelfID, ack.MessageID); err != nil && !errors.Is(err, storage.ErrNotFound) {
		h.Logger.Debug("Failed to record delivery", "error", err)
	}
}

// ---- Sending chat messages -------------------------------------------------

// SendMessage stores and sends a direct message. If the peer cannot be
// reached the message stays in history marked undelivered and an error is
// returned.
func (h *Handler) SendMessage(ctx context.Context, peerID, content string) error {
	if err := ValidateContent(content); err != nil {
		return err
	}
	msg := models.NewChatMessage(utils.NewID(), h.SelfID, peerID, content)
	if _, err := h.Store.SaveMessage(ctx, msg); err != nil {
		return fmt.Errorf("could not save message: %w", err)
	}
	if err := h.Net.SendJSON(ctx, peerID, protocol.KindMessage, msg); err != nil {
		// Unreachable: ask other peers to hold an encrypted copy for them.
		res, rerr := h.relayCopy(ctx, peerID, msg)
		if rerr != nil {
			return fmt.Errorf("message saved but not delivered: %w", err)
		}
		_ = h.Store.MarkMessageRelayed(ctx, h.SelfID, msg.ID)
		return &QueuedError{Relays: res.Relays, Exposed: res.Exposed}
	}
	return nil
}

// GroupSendResult reports per-member outcomes of a group message.
type GroupSendResult struct {
	Queued  []string         // delivered to a live connection
	Relayed []string         // offline; an encrypted copy is queued with relays
	Failed  map[string]error // could not be reached or queued
}

// SendGroupMessage stores a message and sends it to every other member.
// It returns an error only when the message could not be stored or reached
// nobody; partial failures are in the result.
func (h *Handler) SendGroupMessage(ctx context.Context, groupID, content string) (*GroupSendResult, error) {
	if err := ValidateContent(content); err != nil {
		return nil, err
	}
	targets, err := h.Groups.BroadcastTargets(ctx, groupID)
	if err != nil {
		return nil, err
	}

	msg := models.NewGroupMessage(utils.NewID(), h.SelfID, groupID, content)
	if _, err := h.Store.SaveMessage(ctx, msg); err != nil {
		return nil, fmt.Errorf("could not save message: %w", err)
	}

	res := &GroupSendResult{Failed: make(map[string]error)}
	var mu sync.Mutex
	h.fanOut(ctx, targets, func(ctx context.Context, peerID string) error {
		return h.Net.SendJSON(ctx, peerID, protocol.KindMessage, msg)
	}, func(peerID string, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			res.Failed[peerID] = err
		} else {
			res.Queued = append(res.Queued, peerID)
		}
	})

	// Members we could not reach get an encrypted copy through relays.
	for peerID, sendErr := range res.Failed {
		if _, err := h.relayCopy(ctx, peerID, msg); err == nil {
			res.Relayed = append(res.Relayed, peerID)
			delete(res.Failed, peerID)
		} else {
			res.Failed[peerID] = fmt.Errorf("%w (and could not be queued: %v)", sendErr, err)
		}
	}

	if len(targets) > 0 && len(res.Queued)+len(res.Relayed) == 0 {
		return res, fmt.Errorf("message saved but not delivered to anyone: %w", firstError(res.Failed))
	}
	return res, nil
}

func firstError(m map[string]error) error {
	for _, err := range m {
		return err
	}
	return nil
}

// fanOut runs send for each target with bounded concurrency (dialing an
// offline peer can take seconds, and a group should not wait for them one by one).
func (h *Handler) fanOut(ctx context.Context, targets []string, send func(context.Context, string) error, done func(string, error)) {
	sem := make(chan struct{}, maxSendFanout)
	var wg sync.WaitGroup
	for _, peerID := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			done(peerID, send(ctx, peerID))
		}()
	}
	wg.Wait()
}

// ---- Peer events -----------------------------------------------------------

func (h *Handler) isClosed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

// PeerConnected implements interfaces.PeerListener.
func (h *Handler) PeerConnected(peerID, username string) {
	h.names.Store(peerID, utils.SanitizeText(username, 32))
	if h.isClosed() {
		return
	}
	// Anything we could not deliver earlier goes out now.
	h.background(func(ctx context.Context) {
		if _, err := h.RetryUndelivered(ctx, peerID); err != nil {
			h.Logger.Debug("Retry on connect failed", "peer", shortID(peerID), "error", err)
		}
	})
	name := h.DisplayName(peerID)
	h.Out.Printf("* %s connected", name)
	if h.Notifier != nil {
		_ = h.Notifier.NotifyPeerConnected(name)
	}
}

// PeerDisconnected implements interfaces.PeerListener.
func (h *Handler) PeerDisconnected(peerID string) {
	if h.isClosed() {
		return // connections closing during shutdown are not news
	}
	name := h.DisplayName(peerID)
	h.Out.Printf("* %s disconnected", name)
	if h.Notifier != nil {
		_ = h.Notifier.NotifyPeerDisconnected(name)
	}
}
