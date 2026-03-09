// Package spec – net.PacketConn adapters for MASQUE UDP tunnels.
//
// MASQUEPacketConnH2 implements net.PacketConn on top of an HTTP/2
// Extended-CONNECT (connect-udp) stream.  UDP payloads are carried inside
// DATAGRAM capsules (RFC 9297 §3.5 / RFC 9298 §5).
//
// MASQUEPacketConnH3 implements net.PacketConn on top of an HTTP/3
// Extended-CONNECT stream using QUIC DATAGRAM frames (RFC 9297 §2).
//
// H3GetThroughPacketConn is a shared helper that sends an HTTP/3 GET request
// through either kind of PacketConn, using quic.DialEarly and http3.Transport.
package spec

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ─── MASQUEPacketConnH2 ─────────────────────────────────────────────────────

// MASQUEPacketConnH2 implements net.PacketConn on top of an HTTP/2
// connect-udp stream.  A background goroutine decodes incoming DATAGRAM
// capsules and feeds UDP payloads into an internal channel.
//
// Additional methods BadContextIDErr and EvenContextIDSeen let §5/2 and §4/3
// tests inspect the context IDs used by proxy-originated capsules.
type MASQUEPacketConnH2 struct {
	h2conn     *H2Conn
	streamID   uint32
	targetAddr net.Addr
	timeout    time.Duration

	incoming chan []byte
	done     chan struct{}

	dlMu sync.Mutex
	dl   time.Time

	// §5/2: non-nil if any proxy-sent capsule carried a non-zero context ID.
	badContextID atomic.Value // stores a string
	// §4/3: true if any proxy-sent capsule carried an even, non-zero context ID.
	evenContextIDSeen atomic.Bool
}

// NewMASQUEPacketConnH2 creates a MASQUEPacketConnH2 and starts its read loop.
func NewMASQUEPacketConnH2(c *H2Conn, sid uint32, targetAddr net.Addr, timeout time.Duration) *MASQUEPacketConnH2 {
	pc := &MASQUEPacketConnH2{
		h2conn:     c,
		streamID:   sid,
		targetAddr: targetAddr,
		timeout:    timeout,
		incoming:   make(chan []byte, 64),
		done:       make(chan struct{}),
	}
	go pc.readLoop()
	return pc
}

func (pc *MASQUEPacketConnH2) readLoop() {
	for {
		select {
		case <-pc.done:
			return
		default:
		}

		df, err := pc.h2conn.ReadDataFrame(pc.streamID, time.Second)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue // read deadline hit; loop and check done
			}
			return
		}

		caps, _ := ReadCapsules(df.Data())
		for _, c := range caps {
			if c.Type != CapsuleTypeDatagram {
				continue
			}
			r := bytes.NewReader(c.Value)
			ctxID, err := ReadVarint(r)
			if err != nil {
				continue
			}
			if ctxID != 0 {
				// RFC 9298 §5: proxy MUST use context ID 0 for UDP proxying payloads.
				pc.badContextID.Store(fmt.Sprintf("unexpected context ID %d (expected 0)", ctxID))
				if ctxID%2 == 0 {
					// RFC 9298 §4: even IDs are client-allocated; proxy MUST NOT use them.
					pc.evenContextIDSeen.Store(true)
				}
				continue
			}

			udpPayload := c.Value[VarintLen(ctxID):]
			buf := make([]byte, len(udpPayload))
			copy(buf, udpPayload)

			select {
			case pc.incoming <- buf:
			case <-pc.done:
				return
			default: // channel full – drop
			}
		}
	}
}

// WriteTo encodes b as a DATAGRAM capsule with context ID 0 and writes it to
// the H2 stream.  The addr parameter is ignored.
func (pc *MASQUEPacketConnH2) WriteTo(b []byte, _ net.Addr) (int, error) {
	capsule := EncodeDatagramCapsule(b)
	if err := pc.h2conn.WriteData(pc.streamID, capsule, false); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ReadFrom waits for a decoded UDP payload from the read loop and copies it
// into b.  It honours the deadline set by SetDeadline / SetReadDeadline.
func (pc *MASQUEPacketConnH2) ReadFrom(b []byte) (int, net.Addr, error) {
	pc.dlMu.Lock()
	dl := pc.dl
	pc.dlMu.Unlock()

	var timer <-chan time.Time
	if !dl.IsZero() {
		remaining := time.Until(dl)
		if remaining <= 0 {
			return 0, nil, &masqueTimeoutErr{"read deadline exceeded"}
		}
		timer = time.After(remaining)
	}

	select {
	case payload := <-pc.incoming:
		n := copy(b, payload)
		return n, pc.targetAddr, nil
	case <-pc.done:
		return 0, nil, fmt.Errorf("packet conn closed")
	case <-timer:
		return 0, nil, &masqueTimeoutErr{"read deadline exceeded"}
	}
}

// Close stops the read loop.
func (pc *MASQUEPacketConnH2) Close() error {
	select {
	case <-pc.done:
	default:
		close(pc.done)
	}
	return nil
}

// LocalAddr returns a placeholder UDP address.
func (pc *MASQUEPacketConnH2) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (pc *MASQUEPacketConnH2) SetDeadline(t time.Time) error { return pc.SetReadDeadline(t) }

func (pc *MASQUEPacketConnH2) SetReadDeadline(t time.Time) error {
	pc.dlMu.Lock()
	pc.dl = t
	pc.dlMu.Unlock()
	return nil
}

func (pc *MASQUEPacketConnH2) SetWriteDeadline(time.Time) error { return nil }

// BadContextIDErr returns a non-nil error if the proxy sent any DATAGRAM
// capsule with a non-zero context ID (RFC 9298 §5 violation).
func (pc *MASQUEPacketConnH2) BadContextIDErr() error {
	if v := pc.badContextID.Load(); v != nil {
		return fmt.Errorf("%s", v.(string)) //nolint:errorlint
	}
	return nil
}

// EvenContextIDSeen reports whether the proxy sent any DATAGRAM capsule with
// an even, non-zero context ID (RFC 9298 §4 violation).
func (pc *MASQUEPacketConnH2) EvenContextIDSeen() bool {
	return pc.evenContextIDSeen.Load()
}

// ─── MASQUEPacketConnH3Capsule ──────────────────────────────────────────────

// MASQUEPacketConnH3Capsule implements net.PacketConn on top of an HTTP/3
// connect-udp stream using the Capsule Protocol (RFC 9297 §3).  UDP payloads
// are encoded as DATAGRAM capsules inside HTTP/3 DATA frames on the request
// stream.  This is used when the proxy sends "capsule-protocol: ?1" in its
// response even over HTTP/3 (as envoy does).
type MASQUEPacketConnH3Capsule struct {
	h3conn     *H3Conn
	stream     *quic.Stream
	targetAddr net.Addr
	timeout    time.Duration

	incoming chan []byte
	done     chan struct{}

	dlMu sync.Mutex
	dl   time.Time
}

// NewMASQUEPacketConnH3Capsule creates a MASQUEPacketConnH3Capsule and starts its read loop.
func NewMASQUEPacketConnH3Capsule(c *H3Conn, s *quic.Stream, targetAddr net.Addr, timeout time.Duration) *MASQUEPacketConnH3Capsule {
	pc := &MASQUEPacketConnH3Capsule{
		h3conn:     c,
		stream:     s,
		targetAddr: targetAddr,
		timeout:    timeout,
		incoming:   make(chan []byte, 64),
		done:       make(chan struct{}),
	}
	go pc.readLoop()
	return pc
}

func (pc *MASQUEPacketConnH3Capsule) readLoop() {
	for {
		select {
		case <-pc.done:
			return
		default:
		}

		data, err := pc.h3conn.ReadDataFrame(pc.stream, time.Second)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}

		caps, _ := ReadCapsules(data)
		for _, c := range caps {
			if c.Type != CapsuleTypeDatagram {
				continue
			}
			r := bytes.NewReader(c.Value)
			ctxID, err := ReadVarint(r)
			if err != nil || ctxID != 0 {
				continue
			}
			udpPayload := c.Value[VarintLen(ctxID):]
			buf := make([]byte, len(udpPayload))
			copy(buf, udpPayload)
			select {
			case pc.incoming <- buf:
			case <-pc.done:
				return
			default:
			}
		}
	}
}

// WriteTo encodes b as a DATAGRAM capsule and sends it as an H3 DATA frame.
func (pc *MASQUEPacketConnH3Capsule) WriteTo(b []byte, _ net.Addr) (int, error) {
	capsule := EncodeDatagramCapsule(b)
	if err := pc.h3conn.WriteData(pc.stream, capsule); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ReadFrom waits for a decoded UDP payload from the read loop.
func (pc *MASQUEPacketConnH3Capsule) ReadFrom(b []byte) (int, net.Addr, error) {
	pc.dlMu.Lock()
	dl := pc.dl
	pc.dlMu.Unlock()

	var timer <-chan time.Time
	if !dl.IsZero() {
		remaining := time.Until(dl)
		if remaining <= 0 {
			return 0, nil, &masqueTimeoutErr{"read deadline exceeded"}
		}
		timer = time.After(remaining)
	}

	select {
	case payload := <-pc.incoming:
		n := copy(b, payload)
		return n, pc.targetAddr, nil
	case <-pc.done:
		return 0, nil, fmt.Errorf("packet conn closed")
	case <-timer:
		return 0, nil, &masqueTimeoutErr{"read deadline exceeded"}
	}
}

func (pc *MASQUEPacketConnH3Capsule) Close() error {
	select {
	case <-pc.done:
	default:
		close(pc.done)
	}
	return nil
}

func (pc *MASQUEPacketConnH3Capsule) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (pc *MASQUEPacketConnH3Capsule) SetDeadline(t time.Time) error { return pc.SetReadDeadline(t) }

func (pc *MASQUEPacketConnH3Capsule) SetReadDeadline(t time.Time) error {
	pc.dlMu.Lock()
	pc.dl = t
	pc.dlMu.Unlock()
	return nil
}

func (pc *MASQUEPacketConnH3Capsule) SetWriteDeadline(time.Time) error { return nil }

// ─── MASQUEPacketConnH3 ─────────────────────────────────────────────────────

// MASQUEPacketConnH3 implements net.PacketConn on top of an HTTP/3
// connect-udp stream.  UDP payloads are carried inside QUIC DATAGRAM frames.
type MASQUEPacketConnH3 struct {
	h3conn     *H3Conn
	stream     *quic.Stream
	targetAddr net.Addr
	timeout    time.Duration

	incoming chan []byte
	done     chan struct{}

	dlMu sync.Mutex
	dl   time.Time
}

// NewMASQUEPacketConnH3 creates a MASQUEPacketConnH3 and starts its read loop.
func NewMASQUEPacketConnH3(c *H3Conn, s *quic.Stream, targetAddr net.Addr, timeout time.Duration) *MASQUEPacketConnH3 {
	pc := &MASQUEPacketConnH3{
		h3conn:     c,
		stream:     s,
		targetAddr: targetAddr,
		timeout:    timeout,
		incoming:   make(chan []byte, 64),
		done:       make(chan struct{}),
	}
	go pc.readLoop()
	return pc
}

func (pc *MASQUEPacketConnH3) readLoop() {
	for {
		select {
		case <-pc.done:
			return
		default:
		}

		payload, err := pc.h3conn.ReceiveDatagram(pc.stream, time.Second)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				continue
			}
			return
		}

		buf := make([]byte, len(payload))
		copy(buf, payload)

		select {
		case pc.incoming <- buf:
		case <-pc.done:
			return
		default: // channel full – drop
		}
	}
}

// WriteTo sends b as a QUIC DATAGRAM frame on the connect-udp stream.
func (pc *MASQUEPacketConnH3) WriteTo(b []byte, _ net.Addr) (int, error) {
	if err := pc.h3conn.SendDatagram(pc.stream, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ReadFrom waits for a decoded UDP payload from the read loop.
func (pc *MASQUEPacketConnH3) ReadFrom(b []byte) (int, net.Addr, error) {
	pc.dlMu.Lock()
	dl := pc.dl
	pc.dlMu.Unlock()

	var timer <-chan time.Time
	if !dl.IsZero() {
		remaining := time.Until(dl)
		if remaining <= 0 {
			return 0, nil, &masqueTimeoutErr{"read deadline exceeded"}
		}
		timer = time.After(remaining)
	}

	select {
	case payload := <-pc.incoming:
		n := copy(b, payload)
		return n, pc.targetAddr, nil
	case <-pc.done:
		return 0, nil, fmt.Errorf("packet conn closed")
	case <-timer:
		return 0, nil, &masqueTimeoutErr{"read deadline exceeded"}
	}
}

// Close stops the read loop.
func (pc *MASQUEPacketConnH3) Close() error {
	select {
	case <-pc.done:
	default:
		close(pc.done)
	}
	return nil
}

// LocalAddr returns a placeholder UDP address.
func (pc *MASQUEPacketConnH3) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (pc *MASQUEPacketConnH3) SetDeadline(t time.Time) error { return pc.SetReadDeadline(t) }

func (pc *MASQUEPacketConnH3) SetReadDeadline(t time.Time) error {
	pc.dlMu.Lock()
	pc.dl = t
	pc.dlMu.Unlock()
	return nil
}

func (pc *MASQUEPacketConnH3) SetWriteDeadline(time.Time) error { return nil }

// ─── H3GetThroughPacketConn ────────────────────────────────────────────────

// H3GetThroughPacketConn sends an HTTP/3 GET to https://targetAuthority/path
// through pc, which tunnels QUIC datagrams via a MASQUE UDP proxy.
//
// It creates a one-shot http3.Transport whose Dial function calls
// quic.DialEarly with pc and targetAddr instead of opening a real UDP socket.
// The self-signed certificate on the HTTP/3 target is accepted without
// verification (InsecureSkipVerify).
func H3GetThroughPacketConn(
	ctx context.Context,
	pc net.PacketConn,
	targetAddr net.Addr,
	targetAuthority, path string,
) (*http.Response, error) {
	host, _, err := net.SplitHostPort(targetAuthority)
	if err != nil {
		host = targetAuthority
	}

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
			ServerName:         host,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialEarly(ctx, pc, targetAddr, tlsCfg, cfg)
		},
	}
	defer tr.Close() //nolint:errcheck

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+targetAuthority+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	return tr.RoundTrip(req)
}

// NewH3ClientForPacketConn creates an *http.Client backed by an http3.Transport
// that routes all traffic through pc.  The second return value is a cleanup
// function that must be called when done.  Using the same client for multiple
// requests reuses the underlying QUIC connection.
func NewH3ClientForPacketConn(
	pc net.PacketConn,
	targetAddr net.Addr,
	host string,
) (*http.Client, func()) {
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
			ServerName:         host,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialEarly(ctx, pc, targetAddr, tlsCfg, cfg)
		},
	}
	return &http.Client{Transport: tr}, func() { tr.Close() } //nolint:errcheck
}

// ─── H3 PacketConn factory ────────────────────────────────────────────────

// NewMASQUEPacketConnH3Auto creates the appropriate PacketConn for an HTTP/3
// connect-udp stream based on the proxy's response headers.
//
// When the proxy sends "capsule-protocol: ?1" (as envoy does), UDP payloads
// must be carried as DATAGRAM capsules in HTTP/3 DATA frames.  Otherwise the
// RFC 9297 §2 QUIC DATAGRAM frame approach is used.
func NewMASQUEPacketConnH3Auto(c *H3Conn, s *quic.Stream, rh *H3Response, targetAddr net.Addr, timeout time.Duration) net.PacketConn {
	if rh.HasCapsuleProtocol() {
		return NewMASQUEPacketConnH3Capsule(c, s, targetAddr, timeout)
	}
	return NewMASQUEPacketConnH3(c, s, targetAddr, timeout)
}

// ResolveTargetAddr resolves cfg.TargetAddr() to a *net.UDPAddr.
func ResolveTargetAddr(cfg interface{ TargetAddr() string }) (*net.UDPAddr, error) {
	return net.ResolveUDPAddr("udp", cfg.TargetAddr())
}

// ─── internal helpers ──────────────────────────────────────────────────────

// masqueTimeoutErr is a net.Error with Timeout() == true, returned when a
// read deadline is exceeded on a MASQUEPacketConn.
type masqueTimeoutErr struct{ msg string }

func (e *masqueTimeoutErr) Error() string   { return e.msg }
func (e *masqueTimeoutErr) Timeout() bool   { return true }
func (e *masqueTimeoutErr) Temporary() bool { return true }
