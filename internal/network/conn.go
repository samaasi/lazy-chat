package network

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	"github.com/samaasi/lazy-chat/internal/protocol"
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

// peerConn is one authenticated connection to a peer.
type peerConn struct {
	id       string
	name     string // display name from the peer's Hello (sanitised)
	conn     *tls.Conn
	outbound bool
	remote   string // remote IP, for slot accounting

	br      *bufio.Reader
	out     chan []byte
	done    chan struct{}
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
		out:     make(chan []byte, sendQueueSize),
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

// enqueue schedules an encoded frame for writing. It blocks while the queue
// is full (this is the back-pressure that paces file transfers) and returns
// when the frame is queued, the context ends, or the connection dies.
func (pc *peerConn) enqueue(ctx context.Context, frame []byte) error {
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
		case frame := <-pc.out:
			if !write(frame) {
				return
			}
		case <-ticker.C:
			if !write(ping) {
				return
			}
		}
	}
}
