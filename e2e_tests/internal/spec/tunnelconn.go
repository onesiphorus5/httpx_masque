// Package spec – net.Conn adapters for HTTP/2 and HTTP/3 CONNECT tunnels.
//
// TunnelConnH2 wraps an H2Conn CONNECT stream as a net.Conn so that
// golang.org/x/net/http2.Transport can speak h2c cleartext through a
// TCP-CONNECT tunnel.
//
// TunnelConnH3 provides the same adapter for an H3Conn CONNECT stream.
package spec

import (
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// ─── TunnelConnH2 ──────────────────────────────────────────────────────────

// TunnelConnH2 wraps an HTTP/2 CONNECT tunnel stream as a net.Conn, allowing
// an http2.Transport to speak h2c through the tunnel.
type TunnelConnH2 struct {
	h2conn   *H2Conn
	streamID uint32
	timeout  time.Duration
	buf      []byte // excess bytes buffered from a larger-than-needed DATA frame
}

// NewTunnelConnH2 creates a TunnelConnH2 for the given H2Conn CONNECT stream.
func NewTunnelConnH2(c *H2Conn, sid uint32, timeout time.Duration) *TunnelConnH2 {
	return &TunnelConnH2{h2conn: c, streamID: sid, timeout: timeout}
}

// Read drains any internally buffered bytes first, then reads the next DATA
// frame from the tunnel stream and buffers any excess.
func (t *TunnelConnH2) Read(b []byte) (int, error) {
	if len(t.buf) > 0 {
		n := copy(b, t.buf)
		t.buf = t.buf[n:]
		return n, nil
	}
	df, err := t.h2conn.ReadDataFrame(t.streamID, t.timeout)
	if err != nil {
		return 0, err
	}
	data := df.Data()
	n := copy(b, data)
	if n < len(data) {
		t.buf = append(t.buf[:0], data[n:]...)
	}
	return n, nil
}

// Write sends b as a DATA frame on the tunnel stream.
func (t *TunnelConnH2) Write(b []byte) (int, error) {
	return len(b), t.h2conn.WriteData(t.streamID, b, false)
}

// Close is a no-op – the caller owns the underlying H2Conn.
func (t *TunnelConnH2) Close() error { return nil }

func (t *TunnelConnH2) LocalAddr() net.Addr              { return tunnelAddr{} }
func (t *TunnelConnH2) RemoteAddr() net.Addr             { return tunnelAddr{} }
func (t *TunnelConnH2) SetDeadline(time.Time) error      { return nil }
func (t *TunnelConnH2) SetReadDeadline(time.Time) error  { return nil }
func (t *TunnelConnH2) SetWriteDeadline(time.Time) error { return nil }

// ─── TunnelConnH3 ──────────────────────────────────────────────────────────

// TunnelConnH3 wraps an HTTP/3 CONNECT tunnel stream as a net.Conn, allowing
// an http2.Transport to speak h2c through the tunnel.
type TunnelConnH3 struct {
	h3conn  *H3Conn
	stream  *quic.Stream
	timeout time.Duration
	buf     []byte
}

// NewTunnelConnH3 creates a TunnelConnH3 for the given H3Conn CONNECT stream.
func NewTunnelConnH3(c *H3Conn, s *quic.Stream, timeout time.Duration) *TunnelConnH3 {
	return &TunnelConnH3{h3conn: c, stream: s, timeout: timeout}
}

// Read drains any internally buffered bytes first, then reads the next DATA
// frame from the tunnel stream and buffers any excess.
func (t *TunnelConnH3) Read(b []byte) (int, error) {
	if len(t.buf) > 0 {
		n := copy(b, t.buf)
		t.buf = t.buf[n:]
		return n, nil
	}
	data, err := t.h3conn.ReadDataFrame(t.stream, t.timeout)
	if err != nil {
		return 0, err
	}
	n := copy(b, data)
	if n < len(data) {
		t.buf = append(t.buf[:0], data[n:]...)
	}
	return n, nil
}

// Write sends b as an HTTP/3 DATA frame on the tunnel stream.
func (t *TunnelConnH3) Write(b []byte) (int, error) {
	return len(b), t.h3conn.WriteData(t.stream, b)
}

// Close closes the QUIC stream send side (FIN).
func (t *TunnelConnH3) Close() error { return t.stream.Close() }

func (t *TunnelConnH3) LocalAddr() net.Addr              { return tunnelAddr{} }
func (t *TunnelConnH3) RemoteAddr() net.Addr             { return tunnelAddr{} }
func (t *TunnelConnH3) SetDeadline(time.Time) error      { return nil }
func (t *TunnelConnH3) SetReadDeadline(time.Time) error  { return nil }
func (t *TunnelConnH3) SetWriteDeadline(time.Time) error { return nil }

// ─── shared stub ───────────────────────────────────────────────────────────

// tunnelAddr is a net.Addr stub returned by the Tunnel adapters.
type tunnelAddr struct{}

func (tunnelAddr) Network() string { return "tcp" }
func (tunnelAddr) String() string  { return "tunnel" }
