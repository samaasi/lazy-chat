package network

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	"github.com/samaasi/lazy-chat/internal/protocol"
	"github.com/samaasi/lazy-chat/internal/ratchet"
	"github.com/samaasi/lazy-chat/internal/utils"
)

const (
	// writeTimeout bounds one frame write. A peer that stops reading is
	// disconnected rather than allowed to wedge senders.
	writeTimeout = 30 * time.Second
	// idleTimeout drops connections that send nothing, not even pings.
	idleTimeout = 90 * time.Second
	// pingInterval keeps healthy idle connections inside idleTimeout.
	pingInterval = 30 * time.Second
	// sendQueueSize is the number of frames buffered per connection.
	sendQueueSize = 256

	// Default per-connection ceiling for chat/control frames (file chunks are
	// exempt); see Options.
	defaultFrameRate  = 30.0
	defaultFrameBurst = 100
)

// ErrConnClosed is returned when sending on a connection that has closed.
var ErrConnClosed = errors.New("connection closed")

// outFrame is an application frame waiting to be sealed and written. It is
// queued unencrypted and sealed by the writer goroutine just before it hits
// the wire, so message numbers always match wire order and a send that is
// cancelled while queued never consumes a ratchet key.
type outFrame struct {
	kind protocol.Kind
	body []byte
}

// peerConn is one authenticated connection to a peer.
type peerConn struct {
	id       string
	name     string // display name from the peer's Hello (sanitised)
	conn     *tls.Conn
	outbound bool
	remote   string // remote IP, for slot accounting

	br      *bufio.Reader
	out     chan outFrame
	done    chan struct{}
	sess    *ratchet.Session // set once the ratchet handshake has completed
	once    sync.Once
	limiter *utils.Limiter

	// initiator is the peer ID that opened the TCP connection; both sides
	// compute the same value, which makes duplicate resolution consistent.
	initiator string

	// release returns the inbound connection slot; it runs exactly once.
	release func()
	relOnce sync.Once
}

func newPeerConn(id string, conn *tls.Conn, outbound bool, selfID, remote string, rate float64, burst int) *peerConn {
	pc := &peerConn{
		id: id, conn: conn, outbound: outbound, remote: remote,
		br:      bufio.NewReader(conn),
		out:     make(chan outFrame, sendQueueSize),
		done:    make(chan struct{}),
		limiter: utils.NewLimiter(rate, burst),
	}
	if outbound {
		pc.initiator = selfID
	} else {
		pc.initiator = id
	}
	return pc
}

// close tears the connection down; safe to call repeatedly and concurrently.
func (pc *peerConn) close() {
	pc.once.Do(func() {
		close(pc.done)
		_ = pc.conn.Close()
	})
}

// enqueue schedules an application frame for writing. It blocks while the
// queue is full (this is the back-pressure that paces file transfers) and
// returns when the frame is queued, the context ends, or the connection dies.
func (pc *peerConn) enqueue(ctx context.Context, kind protocol.Kind, body []byte) error {
	frame := outFrame{kind: kind, body: body}
	select {
	case <-pc.done:
		return ErrConnClosed
	default:
	}
	select {
	case pc.out <- frame:
		return nil
	case <-pc.done:
		return ErrConnClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// seal wraps an application frame in a ratchet-encrypted KindSecure frame.
func (pc *peerConn) seal(f outFrame) ([]byte, error) {
	plain := make([]byte, 1+len(f.body))
	plain[0] = byte(f.kind)
	copy(plain[1:], f.body)
	sealed, err := pc.sess.Seal(plain)
	if err != nil {
		return nil, err
	}
	return protocol.EncodeFrame(protocol.KindSecure, sealed)
}

// writeLoop is the only goroutine that writes to the connection after setup.
func (pc *peerConn) writeLoop(onError func(error)) {
	ping, _ := protocol.EncodeFrame(protocol.KindPing, nil)
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	write := func(frame []byte) bool {
		_ = pc.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := pc.conn.Write(frame); err != nil {
			onError(err)
			pc.close()
			return false
		}
		return true
	}

	for {
		select {
		case <-pc.done:
			return
		case f := <-pc.out:
			wire, err := pc.seal(f)
			if err != nil {
				onError(err)
				pc.close()
				return
			}
			if !write(wire) {
				return
			}
		case <-ticker.C:
			if !write(ping) {
				return
			}
		}
	}
}
