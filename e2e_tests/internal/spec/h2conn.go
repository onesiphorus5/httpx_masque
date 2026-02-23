// Package spec – raw HTTP/2 connection helper for conformance testing.
//
// H2Conn wraps a TLS connection and an http2.Framer, letting test cases send
// arbitrarily crafted HTTP/2 frames (including intentionally invalid ones) and
// read back structured responses without the sanitisation that higher-level
// HTTP clients apply.
package spec

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"rfc9298spec/internal/config"
)

// SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441 §3).
const SettingEnableConnectProtocol http2.SettingID = 0x8

// clientPreface is the fixed HTTP/2 connection preface (RFC 9113 §3.4).
const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// H2Conn is a low-level HTTP/2 connection that exposes the raw Framer.
type H2Conn struct {
	conn   net.Conn
	framer *http2.Framer

	hbuf bytes.Buffer
	henc *hpack.Encoder
	hdec *hpack.Decoder

	nextStreamID uint32

	// ServerSettings holds the SETTINGS received from the peer during handshake.
	ServerSettings map[http2.SettingID]uint32
}

// NewH2Conn dials the proxy, negotiates TLS with ALPN "h2", and returns an
// H2Conn ready for Handshake().
func NewH2Conn(cfg *config.Config) (*H2Conn, error) {
	tlsCfg := cfg.TLSConfig()
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: cfg.Timeout},
		"tcp", cfg.Addr(), tlsCfg,
	)
	if err != nil {
		return nil, fmt.Errorf("TLS dial: %w", err)
	}

	if proto := conn.ConnectionState().NegotiatedProtocol; proto != "h2" {
		conn.Close()
		return nil, fmt.Errorf("expected ALPN h2, got %q", proto)
	}

	c := &H2Conn{
		conn:           conn,
		framer:         http2.NewFramer(conn, conn),
		nextStreamID:   1,
		ServerSettings: make(map[http2.SettingID]uint32),
	}
	c.henc = hpack.NewEncoder(&c.hbuf)
	c.hdec = hpack.NewDecoder(4096, nil)

	// Allow the test to see large header blocks.
	c.framer.SetMaxReadFrameSize(1 << 20)
	return c, nil
}

// Close closes the underlying connection.
func (c *H2Conn) Close() error { return c.conn.Close() }

// Handshake sends the client connection preface + SETTINGS, then reads the
// server SETTINGS frame and acknowledges it.
//
// It returns whether the server advertised SETTINGS_ENABLE_CONNECT_PROTOCOL.
func (c *H2Conn) Handshake() (enableConnectProtocol bool, err error) {
	// Client preface.
	if _, err = io.WriteString(c.conn, clientPreface); err != nil {
		return false, fmt.Errorf("write client preface: %w", err)
	}

	// Client SETTINGS: enable extended CONNECT from our side.
	if err = c.framer.WriteSettings(http2.Setting{
		ID: SettingEnableConnectProtocol, Val: 1,
	}); err != nil {
		return false, fmt.Errorf("write SETTINGS: %w", err)
	}

	// Read frames until we have ACK'd the server SETTINGS.
	serverSettingsACKd := false
	for !serverSettingsACKd {
		c.conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
		f, err := c.framer.ReadFrame()
		if err != nil {
			return false, fmt.Errorf("read frame during handshake: %w", err)
		}
		c.conn.SetReadDeadline(time.Time{}) //nolint:errcheck

		switch f := f.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				// Our SETTINGS was acknowledged.
				continue
			}
			// Store server settings.
			f.ForeachSetting(func(s http2.Setting) error { //nolint:errcheck
				c.ServerSettings[s.ID] = s.Val
				return nil
			})
			if v, ok := c.ServerSettings[SettingEnableConnectProtocol]; ok && v == 1 {
				enableConnectProtocol = true
			}
			// ACK server SETTINGS.
			if err := c.framer.WriteSettingsAck(); err != nil {
				return false, fmt.Errorf("write SETTINGS ACK: %w", err)
			}
			serverSettingsACKd = true

		case *http2.WindowUpdateFrame:
			// Server is adjusting flow control; ignore during handshake.
		}
	}
	return enableConnectProtocol, nil
}

// ─── Frame helpers ─────────────────────────────────────────────────────────

// HeaderField is a convenience alias.
type HeaderField = hpack.HeaderField

// WriteHeaders sends a HEADERS frame on the next available client stream ID
// and returns that stream ID.
func (c *H2Conn) WriteHeaders(fields []HeaderField, endStream bool) (uint32, error) {
	sid := c.nextStreamID
	c.nextStreamID += 2

	c.hbuf.Reset()
	for _, f := range fields {
		if err := c.henc.WriteField(f); err != nil {
			return 0, fmt.Errorf("hpack encode %q: %w", f.Name, err)
		}
	}

	return sid, c.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      sid,
		BlockFragment: c.hbuf.Bytes(),
		EndHeaders:    true,
		EndStream:     endStream,
	})
}

// WriteData sends a DATA frame on the given stream.
func (c *H2Conn) WriteData(streamID uint32, data []byte, endStream bool) error {
	return c.framer.WriteData(streamID, endStream, data)
}

// WriteWindowUpdate sends a WINDOW_UPDATE for the given stream (or connection
// if streamID == 0).
func (c *H2Conn) WriteWindowUpdate(streamID, increment uint32) error {
	return c.framer.WriteWindowUpdate(streamID, increment)
}

// WriteRSTStream sends a RST_STREAM on streamID with the given error code.
func (c *H2Conn) WriteRSTStream(streamID uint32, code http2.ErrCode) error {
	return c.framer.WriteRSTStream(streamID, code)
}

// ─── Response reading ──────────────────────────────────────────────────────

// ResponseHeaders holds the decoded response header fields from a HEADERS frame.
type ResponseHeaders struct {
	StreamID uint32
	Fields   []hpack.HeaderField
	Status   int
}

// ReadResponseHeaders reads frames until it receives a HEADERS frame for
// streamID and returns the decoded headers.  SETTINGS ACKs and WINDOW_UPDATE
// frames encountered along the way are handled transparently.
//
// If the stream is reset (RST_STREAM), an error wrapping ErrRSTStream is
// returned together with the error code.
func (c *H2Conn) ReadResponseHeaders(streamID uint32, timeout time.Duration) (*ResponseHeaders, error) {
	deadline := time.Now().Add(timeout)
	for {
		c.conn.SetReadDeadline(deadline) //nolint:errcheck
		f, err := c.framer.ReadFrame()
		if err != nil {
			return nil, err
		}

		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				c.framer.WriteSettingsAck() //nolint:errcheck
			}

		case *http2.WindowUpdateFrame:
			// Ignore.

		case *http2.PingFrame:
			if !f.IsAck() {
				c.framer.WritePing(true, f.Data) //nolint:errcheck
			}

		case *http2.HeadersFrame:
			if f.StreamID != streamID {
				continue
			}
			fields, err := c.hdec.DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				return nil, fmt.Errorf("hpack decode: %w", err)
			}
			rh := &ResponseHeaders{StreamID: streamID, Fields: fields}
			for _, hf := range fields {
				if hf.Name == ":status" {
					fmt.Sscanf(hf.Value, "%d", &rh.Status) //nolint:errcheck
				}
			}
			return rh, nil

		case *http2.RSTStreamFrame:
			if f.StreamID == streamID {
				return nil, fmt.Errorf("%w: code=%v", ErrRSTStream, f.ErrCode)
			}

		case *http2.GoAwayFrame:
			return nil, fmt.Errorf("GOAWAY: code=%v lastStreamID=%d", f.ErrCode, f.LastStreamID)
		}
	}
}

// ReadDataFrame reads frames until it finds a DATA frame for streamID.
// Intervening SETTINGS, WINDOW_UPDATE, PING, and HEADERS frames are handled.
// RST_STREAM causes an error.
func (c *H2Conn) ReadDataFrame(streamID uint32, timeout time.Duration) (*http2.DataFrame, error) {
	deadline := time.Now().Add(timeout)
	for {
		c.conn.SetReadDeadline(deadline) //nolint:errcheck
		f, err := c.framer.ReadFrame()
		if err != nil {
			return nil, err
		}

		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				c.framer.WriteSettingsAck() //nolint:errcheck
			}
		case *http2.WindowUpdateFrame:
			// Ignore.
		case *http2.PingFrame:
			if !f.IsAck() {
				c.framer.WritePing(true, f.Data) //nolint:errcheck
			}
		case *http2.DataFrame:
			if f.StreamID == streamID {
				return f, nil
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == streamID {
				return nil, fmt.Errorf("%w: code=%v", ErrRSTStream, f.ErrCode)
			}
		case *http2.GoAwayFrame:
			return nil, fmt.Errorf("GOAWAY: code=%v", f.ErrCode)
		}
	}
}

// ErrRSTStream is wrapped by errors returned when the peer resets a stream.
var ErrRSTStream = fmt.Errorf("RST_STREAM received")

// ─── High-level connect-udp helpers ───────────────────────────────────────

// ConnectTCPFields builds the HEADERS for a plain TCP CONNECT request
// (RFC 9113 §8.5).  :scheme and :path MUST be omitted.
func ConnectTCPFields(authority string) []HeaderField {
	return []HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":authority", Value: authority},
	}
}

// SendConnectTCP sends a plain CONNECT request targeting the configured TCP
// echo server and returns the stream ID.
func (c *H2Conn) SendConnectTCP(cfg *config.Config) (uint32, error) {
	return c.WriteHeaders(ConnectTCPFields(cfg.TCPTargetAddr()), false)
}

// ConnectUDPFields builds the standard Extended CONNECT header fields for a
// connect-udp request (RFC 9298 §3.4).
func ConnectUDPFields(authority, path string) []HeaderField {
	return []HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":protocol", Value: "connect-udp"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
		{Name: "capsule-protocol", Value: "?1"},
	}
}

// SendConnectUDP sends a well-formed Extended CONNECT request targeting the
// proxy's configured target host/port and returns the stream ID.
func (c *H2Conn) SendConnectUDP(cfg *config.Config) (uint32, error) {
	path := cfg.BuildPath(cfg.TargetHost, cfg.TargetPort)
	fields := ConnectUDPFields(cfg.Addr(), path)
	return c.WriteHeaders(fields, false)
}
