// Package protocol defines the wire format spoken between peers after the
// TLS handshake: a stream of frames, each
//
//	kind (1 byte) | body length (4 bytes, big endian) | body
//
// Control frames carry JSON; file chunks carry raw bytes so file data is not
// inflated by base64. The maximum body size is fixed per kind and checked
// before any buffer is allocated, so a peer cannot make us reserve memory by
// announcing a huge frame.
package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version is the protocol version exchanged in Hello.
const Version = 1

// ALPN is the TLS application protocol name for lazy-chat connections.
const ALPN = "lazy-chat/1"

// Kind identifies the type of a frame.
type Kind uint8

const (
	KindHello            Kind = 1
	KindPing             Kind = 2
	KindMessage          Kind = 3
	KindAck              Kind = 4
	KindGroupInvite      Kind = 5
	KindGroupInviteReply Kind = 6
	KindGroupUpdate      Kind = 7

	KindFileOffer  Kind = 10
	KindFileAccept Kind = 11
	KindFileChunk  Kind = 12
	KindFileDone   Kind = 13
	KindFileResult Kind = 14
	KindFileAbort  Kind = 15
)

// MaxChunkSize is the largest payload of one file chunk frame.
const MaxChunkSize = 32 * 1024

const idRawLen = 16 // transfer IDs are 128-bit values

const headerLen = 5

var (
	ErrUnknownKind = errors.New("protocol: unknown frame kind")
	ErrFrameSize   = errors.New("protocol: frame too large for its kind")
	ErrBadChunk    = errors.New("protocol: malformed file chunk")
)

// MaxBody returns the largest body allowed for kind, or 0 if kind is unknown.
func MaxBody(k Kind) int {
	switch k {
	case KindPing:
		return 0
	case KindHello, KindAck, KindGroupInviteReply, KindFileAccept, KindFileDone, KindFileResult, KindFileAbort:
		return 4 << 10
	case KindFileOffer:
		return 8 << 10
	case KindMessage:
		return 16 << 10
	case KindGroupInvite, KindGroupUpdate:
		return 64 << 10
	case KindFileChunk:
		return idRawLen + MaxChunkSize
	default:
		return 0
	}
}

func (k Kind) known() bool {
	switch k {
	case KindHello, KindPing, KindMessage, KindAck, KindGroupInvite, KindGroupInviteReply,
		KindGroupUpdate, KindFileOffer, KindFileAccept, KindFileChunk, KindFileDone,
		KindFileResult, KindFileAbort:
		return true
	}
	return false
}

// Throttled reports whether frames of this kind count against the per-peer
// rate limit. Bulk file chunks are paced by TCP backpressure instead.
func (k Kind) Throttled() bool {
	return k != KindFileChunk && k != KindPing
}

// EncodeFrame builds the wire bytes for one frame.
func EncodeFrame(k Kind, body []byte) ([]byte, error) {
	if !k.known() {
		return nil, ErrUnknownKind
	}
	if len(body) > MaxBody(k) {
		return nil, fmt.Errorf("%w (kind %d, %d bytes)", ErrFrameSize, k, len(body))
	}
	buf := make([]byte, headerLen+len(body))
	buf[0] = byte(k)
	binary.BigEndian.PutUint32(buf[1:headerLen], uint32(len(body)))
	copy(buf[headerLen:], body)
	return buf, nil
}

// ReadFrame reads one frame. It returns io.EOF only on a clean end of stream
// between frames.
func ReadFrame(r io.Reader) (Kind, []byte, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	k := Kind(hdr[0])
	if !k.known() {
		return 0, nil, fmt.Errorf("%w: %d", ErrUnknownKind, hdr[0])
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if int64(n) > int64(MaxBody(k)) {
		return 0, nil, fmt.Errorf("%w (kind %d, declared %d)", ErrFrameSize, k, n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	return k, body, nil
}

// Marshal encodes a control payload.
func Marshal(v any) ([]byte, error) { return json.Marshal(v) }

// Unmarshal decodes a control payload, rejecting trailing garbage.
func Unmarshal(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("protocol: trailing data after payload")
	}
	return nil
}

// EncodeChunk builds the body of a KindFileChunk frame.
func EncodeChunk(transferID string, data []byte) ([]byte, error) {
	raw, err := hex.DecodeString(transferID)
	if err != nil || len(raw) != idRawLen {
		return nil, ErrBadChunk
	}
	if len(data) == 0 || len(data) > MaxChunkSize {
		return nil, ErrBadChunk
	}
	return append(raw, data...), nil
}

// DecodeChunk splits a KindFileChunk body into the transfer ID and data. The
// returned data aliases body.
func DecodeChunk(body []byte) (transferID string, data []byte, err error) {
	if len(body) <= idRawLen {
		return "", nil, ErrBadChunk
	}
	return hex.EncodeToString(body[:idRawLen]), body[idRawLen:], nil
}

// ---- Payloads -------------------------------------------------------------

// Hello is the first frame each side sends after the TLS handshake.
type Hello struct {
	Version  int    `json:"version"`
	Username string `json:"username"`
}

// Ack confirms that a message was received and stored.
type Ack struct {
	MessageID string `json:"message_id"`
}

// MemberInfo names a group member.
type MemberInfo struct {
	PeerID   string `json:"peer_id"`
	Username string `json:"username"`
}

// GroupInvite invites the receiver to a group and carries enough of the group
// for the receiver to create it locally on acceptance.
type GroupInvite struct {
	InviteID         string       `json:"invite_id"`
	GroupID          string       `json:"group_id"`
	GroupName        string       `json:"group_name"`
	GroupDescription string       `json:"group_description"`
	ExpiresAt        int64        `json:"expires_at"` // unix milliseconds
	Members          []MemberInfo `json:"members"`
}

// GroupInviteReply answers a GroupInvite.
type GroupInviteReply struct {
	InviteID string `json:"invite_id"`
	GroupID  string `json:"group_id"`
	Accepted bool   `json:"accepted"`
	Username string `json:"username"`
}

// GroupUpdate changes group membership. Only a group admin may add or remove
// others; any member may remove itself.
type GroupUpdate struct {
	GroupID string       `json:"group_id"`
	Added   []MemberInfo `json:"added,omitempty"`
	Removed []string     `json:"removed,omitempty"`
}

// FileOffer proposes a file transfer; nothing is written until it is accepted.
type FileOffer struct {
	TransferID string `json:"transfer_id"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"` // hex
}

// FileAccept answers a FileOffer.
type FileAccept struct {
	TransferID string `json:"transfer_id"`
	Accepted   bool   `json:"accepted"`
	Reason     string `json:"reason,omitempty"`
}

// FileDone is sent after the last chunk.
type FileDone struct {
	TransferID string `json:"transfer_id"`
}

// FileResult reports whether the receiver stored the file intact.
type FileResult struct {
	TransferID string `json:"transfer_id"`
	OK         bool   `json:"ok"`
	Reason     string `json:"reason,omitempty"`
}

// FileAbort cancels a transfer from either side.
type FileAbort struct {
	TransferID string `json:"transfer_id"`
	Reason     string `json:"reason,omitempty"`
}
