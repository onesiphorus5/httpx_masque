// Package spec – HTTP/3 connection helper for RFC 9298 conformance testing.
//
// H3Conn opens a raw QUIC connection and implements just enough of HTTP/3
// (RFC 9114) to send Extended CONNECT requests (RFC 9220) and exchange QUIC
// DATAGRAM frames (RFC 9297/9298) without the sanitisation of a high-level
// HTTP client.
package spec

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"

	"rfc9298spec/internal/config"
)

// ─── HTTP/3 frame type codes (RFC 9114 §7.2) ──────────────────────────────

const (
	h3FrameData     uint64 = 0x00
	h3FrameHeaders  uint64 = 0x01
	h3FrameSettings uint64 = 0x04
)

// ─── HTTP/3 SETTINGS identifiers ──────────────────────────────────────────

const (
	// h3SettingQPACKMaxTableCapacity (RFC 9204 §5.1).
	h3SettingQPACKMaxTableCapacity uint64 = 0x01
	// h3SettingEnableConnectProtocol (RFC 9220 §3).
	h3SettingEnableConnectProtocol uint64 = 0x08
	// h3SettingH3Datagram (RFC 9297 §2.1.1).
	h3SettingH3Datagram uint64 = 0x33
)

// ─── HTTP/3 / QUIC unidirectional stream types (RFC 9114 §6.2) ────────────

const (
	h3StreamTypeControl     uint64 = 0x00
	h3StreamTypeQPACKEncoder uint64 = 0x02
	h3StreamTypeQPACKDecoder uint64 = 0x03
)

// ─── H3Conn ────────────────────────────────────────────────────────────────

// H3Conn is a low-level HTTP/3 connection for conformance testing.
type H3Conn struct {
	conn    *quic.Conn
	ctx     context.Context
	cancel  context.CancelFunc
	timeout time.Duration

	// ServerSettings holds the key→value pairs from the server's SETTINGS frame.
	ServerSettings map[uint64]uint64
}

// NewH3Conn dials the proxy with QUIC, negotiating ALPN "h3" and enabling
// QUIC DATAGRAM extension.
func NewH3Conn(cfg *config.Config) (*H3Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout*4)

	tlsCfg := &tls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.TLSSkipVerify, //nolint:gosec
		NextProtos:         []string{"h3"},
	}
	qcfg := &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  cfg.Timeout * 3,
	}

	conn, err := quic.DialAddr(ctx, cfg.Addr(), tlsCfg, qcfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}

	return &H3Conn{
		conn:           conn,
		ctx:            ctx,
		cancel:         cancel,
		timeout:        cfg.Timeout,
		ServerSettings: make(map[uint64]uint64),
	}, nil
}

// Close closes the QUIC connection.
func (c *H3Conn) Close() error {
	c.cancel()
	return c.conn.CloseWithError(0, "done")
}

// ─── Handshake ─────────────────────────────────────────────────────────────

// Handshake performs the HTTP/3 connection setup:
//  1. Opens the client control stream and sends SETTINGS.
//  2. Opens the required QPACK encoder and decoder streams.
//  3. Reads the server control stream and its SETTINGS frame.
//
// Returns whether the server advertises ENABLE_CONNECT_PROTOCOL and
// H3_DATAGRAM; both must be true for Extended CONNECT + datagrams to work.
func (c *H3Conn) Handshake() (enableConnect, enableDatagram bool, err error) {
	// ── Client → server: control stream ──────────────────────────────────
	ctrlStream, err := c.conn.OpenUniStream()
	if err != nil {
		return false, false, fmt.Errorf("open client control stream: %w", err)
	}
	// Stream type byte.
	if _, err := ctrlStream.Write(AppendVarint(nil, h3StreamTypeControl)); err != nil {
		return false, false, fmt.Errorf("write control stream type: %w", err)
	}
	// SETTINGS frame.
	if _, err := ctrlStream.Write(buildH3Settings()); err != nil {
		return false, false, fmt.Errorf("write SETTINGS: %w", err)
	}

	// ── QPACK encoder / decoder streams (required by RFC 9204 §4.2) ──────
	for _, st := range []uint64{h3StreamTypeQPACKEncoder, h3StreamTypeQPACKDecoder} {
		s, err := c.conn.OpenUniStream()
		if err != nil {
			return false, false, fmt.Errorf("open QPACK stream (type %d): %w", st, err)
		}
		s.Write(AppendVarint(nil, st)) //nolint:errcheck
	}

	// ── Server → client: find control stream, read SETTINGS ──────────────
	settingsCh := make(chan map[uint64]uint64, 1)
	acceptCtx, acceptCancel := context.WithTimeout(c.ctx, c.timeout)
	defer acceptCancel()

	go func() {
		for {
			rs, err := c.conn.AcceptUniStream(acceptCtx)
			if err != nil {
				return
			}
			go func(s io.Reader) {
				streamType, err := ReadVarint(s)
				if err != nil || streamType != h3StreamTypeControl {
					return
				}
				m, err := readH3SettingsFrame(s)
				if err != nil {
					return
				}
				select {
				case settingsCh <- m:
				default:
				}
			}(rs)
		}
	}()

	select {
	case m := <-settingsCh:
		for id, val := range m {
			c.ServerSettings[id] = val
		}
	case <-acceptCtx.Done():
		return false, false, fmt.Errorf("timeout waiting for server SETTINGS")
	}

	if v, ok := c.ServerSettings[h3SettingEnableConnectProtocol]; ok && v == 1 {
		enableConnect = true
	}
	if v, ok := c.ServerSettings[h3SettingH3Datagram]; ok && v == 1 {
		enableDatagram = true
	}
	return enableConnect, enableDatagram, nil
}

// ─── Request streams ───────────────────────────────────────────────────────

// H3Response holds the decoded response pseudo-headers from a HEADERS frame.
type H3Response struct {
	Fields []qpack.HeaderField
	Status int
}

// HasCapsuleProtocol reports whether the response carries the
// "capsule-protocol: ?1" header, indicating that UDP payloads must be sent as
// DATAGRAM capsules in HTTP DATA frames rather than QUIC DATAGRAM frames.
func (r *H3Response) HasCapsuleProtocol() bool {
	for _, f := range r.Fields {
		if f.Name == "capsule-protocol" && f.Value == "?1" {
			return true
		}
	}
	return false
}

// WriteHeaders opens a new client-initiated bidirectional stream, sends a
// HEADERS frame with the given QPACK-encoded fields, and returns the stream.
func (c *H3Conn) WriteHeaders(fields []qpack.HeaderField) (*quic.Stream, error) {
	stream, err := c.conn.OpenStreamSync(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("open request stream: %w", err)
	}

	block, err := encodeQPACK(fields)
	if err != nil {
		stream.Close() //nolint:errcheck
		return nil, fmt.Errorf("QPACK encode: %w", err)
	}

	frame := buildH3Frame(h3FrameHeaders, block)
	if _, err := stream.Write(frame); err != nil {
		stream.Close() //nolint:errcheck
		return nil, fmt.Errorf("write HEADERS frame: %w", err)
	}
	return stream, nil
}

// ReadResponseHeaders reads frames from stream until it finds a HEADERS frame
// and decodes it.  DATA frames before the HEADERS are skipped.
// A QUIC stream reset or connection-level application error from the peer is
// returned as a wrapped ErrRSTStream.
func (c *H3Conn) ReadResponseHeaders(stream *quic.Stream, timeout time.Duration) (*H3Response, error) {
	stream.SetReadDeadline(time.Now().Add(timeout)) //nolint:errcheck
	for {
		ft, payload, err := readH3Frame(stream)
		if err != nil {
			var se *quic.StreamError
			if errors.As(err, &se) {
				return nil, fmt.Errorf("%w: code=%d", ErrRSTStream, se.ErrorCode)
			}
			// A remote application error (e.g. H3_MESSAGE_ERROR 0x106) means the
			// server closed the connection in response to an invalid request — treat
			// it as a rejection equivalent to a stream reset.
			var ae *quic.ApplicationError
			if errors.As(err, &ae) && ae.Remote {
				return nil, fmt.Errorf("%w: app-error=0x%x", ErrRSTStream, ae.ErrorCode)
			}
			return nil, err
		}
		if ft != h3FrameHeaders {
			continue // skip DATA or unknown frames
		}

		fields, err := decodeQPACK(payload)
		if err != nil {
			return nil, fmt.Errorf("QPACK decode: %w", err)
		}
		rh := &H3Response{Fields: fields}
		for _, hf := range fields {
			if hf.Name == ":status" {
				fmt.Sscanf(hf.Value, "%d", &rh.Status) //nolint:errcheck
			}
		}
		return rh, nil
	}
}

// ─── QUIC DATAGRAM helpers (RFC 9297 §2 + RFC 9298 §5) ────────────────────

// SendDatagram sends a QUIC DATAGRAM frame carrying a UDP proxying payload
// for the given request stream.
//
// Payload format (RFC 9297 §2.1 + RFC 9298 §5):
//
//	Quarter Stream ID (varint) | Context ID = 0 (varint) | UDP payload
func (c *H3Conn) SendDatagram(stream *quic.Stream, udpPayload []byte) error {
	qsid := uint64(stream.StreamID()) / 4
	var dgram []byte
	dgram = AppendVarint(dgram, qsid)
	dgram = AppendVarint(dgram, ContextIDUDPProxy)
	dgram = append(dgram, udpPayload...)
	return c.conn.SendDatagram(dgram)
}

// SendDatagramRaw sends a QUIC DATAGRAM frame with an arbitrary payload.
// Used by negative tests that need to bypass correct framing.
func (c *H3Conn) SendDatagramRaw(stream *quic.Stream, payload []byte) error {
	qsid := uint64(stream.StreamID()) / 4
	var prefix []byte
	prefix = AppendVarint(prefix, qsid)
	return c.conn.SendDatagram(append(prefix, payload...))
}

// ReceiveDatagram waits for a QUIC DATAGRAM frame associated with stream and
// returns the UDP payload (strips Quarter Stream ID and Context ID).
func (c *H3Conn) ReceiveDatagram(stream *quic.Stream, timeout time.Duration) ([]byte, error) {
	qsid := uint64(stream.StreamID()) / 4
	ctx, cancel := context.WithTimeout(c.ctx, timeout)
	defer cancel()

	for {
		dgram, err := c.conn.ReceiveDatagram(ctx)
		if err != nil {
			return nil, err
		}

		r := bytes.NewReader(dgram)
		gotQSID, err := ReadVarint(r)
		if err != nil || gotQSID != qsid {
			continue
		}
		ctxID, err := ReadVarint(r)
		if err != nil || ctxID != ContextIDUDPProxy {
			continue
		}
		payload := make([]byte, r.Len())
		copy(payload, dgram[len(dgram)-r.Len():])
		return payload, nil
	}
}

// ─── High-level connect-udp helpers ───────────────────────────────────────

// ConnectTCPFieldsH3 builds the QPACK header fields for a plain TCP CONNECT
// request (RFC 9114 §4.4).  :scheme and :path MUST be omitted.
func ConnectTCPFieldsH3(authority string) []qpack.HeaderField {
	return []qpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":authority", Value: authority},
	}
}

// SendConnectTCP opens a request stream, sends a plain CONNECT targeting the
// configured TCP echo server, and returns the stream.
func (c *H3Conn) SendConnectTCP(cfg *config.Config) (*quic.Stream, error) {
	return c.WriteHeaders(ConnectTCPFieldsH3(cfg.TCPTargetAddr()))
}

// WriteData sends an HTTP/3 DATA frame (type 0x00) on stream.
func (c *H3Conn) WriteData(stream *quic.Stream, data []byte) error {
	_, err := stream.Write(buildH3Frame(h3FrameData, data))
	return err
}

// ReadDataFrame reads HTTP/3 frames from stream until it finds a DATA frame.
// HEADERS and unknown frames are skipped.  A stream reset returns ErrRSTStream.
func (c *H3Conn) ReadDataFrame(stream *quic.Stream, timeout time.Duration) ([]byte, error) {
	stream.SetReadDeadline(time.Now().Add(timeout)) //nolint:errcheck
	for {
		ft, payload, err := readH3Frame(stream)
		if err != nil {
			var se *quic.StreamError
			if errors.As(err, &se) {
				return nil, fmt.Errorf("%w: code=%d", ErrRSTStream, se.ErrorCode)
			}
			return nil, err
		}
		if ft == h3FrameData {
			return payload, nil
		}
		// Skip HEADERS, SETTINGS, or unknown frames.
	}
}

// ConnectUDPFieldsH3 builds the QPACK header fields for an Extended CONNECT
// request (RFC 9298 §3.4).
func ConnectUDPFieldsH3(authority, path string) []qpack.HeaderField {
	return []qpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":protocol", Value: "connect-udp"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	}
}

// SendConnectUDP opens a request stream, sends a well-formed Extended CONNECT
// request, and returns the stream.
func (c *H3Conn) SendConnectUDP(cfg *config.Config) (*quic.Stream, error) {
	path := cfg.BuildPath(cfg.TargetHost, cfg.TargetPort)
	fields := ConnectUDPFieldsH3(cfg.Addr(), path)
	return c.WriteHeaders(fields)
}

// ─── Frame I/O helpers ─────────────────────────────────────────────────────

// readH3Frame reads one HTTP/3 frame (type + length + payload) from r.
func readH3Frame(r io.Reader) (frameType uint64, payload []byte, err error) {
	frameType, err = ReadVarint(r)
	if err != nil {
		return
	}
	length, err := ReadVarint(r)
	if err != nil {
		return
	}
	if length > 1<<20 { // 1 MiB sanity cap
		err = fmt.Errorf("H3 frame payload too large: %d bytes", length)
		return
	}
	payload = make([]byte, length)
	_, err = io.ReadFull(r, payload)
	return
}

// buildH3Frame encodes an HTTP/3 frame.
func buildH3Frame(frameType uint64, payload []byte) []byte {
	var b []byte
	b = AppendVarint(b, frameType)
	b = AppendVarint(b, uint64(len(payload)))
	return append(b, payload...)
}

// buildH3Settings encodes the client SETTINGS frame payload.
func buildH3Settings() []byte {
	var payload []byte
	// ENABLE_CONNECT_PROTOCOL = 0x08 → 1
	payload = AppendVarint(payload, h3SettingEnableConnectProtocol)
	payload = AppendVarint(payload, 1)
	// H3_DATAGRAM = 0x33 → 1
	payload = AppendVarint(payload, h3SettingH3Datagram)
	payload = AppendVarint(payload, 1)
	// QPACK_MAX_TABLE_CAPACITY = 0 (no dynamic table)
	payload = AppendVarint(payload, h3SettingQPACKMaxTableCapacity)
	payload = AppendVarint(payload, 0)
	return buildH3Frame(h3FrameSettings, payload)
}

// readH3SettingsFrame skips frames on r until it reads a SETTINGS frame and
// returns the decoded key→value map.
func readH3SettingsFrame(r io.Reader) (map[uint64]uint64, error) {
	for {
		ft, payload, err := readH3Frame(r)
		if err != nil {
			return nil, err
		}
		if ft != h3FrameSettings {
			continue
		}
		m := make(map[uint64]uint64)
		br := bytes.NewReader(payload)
		for br.Len() > 0 {
			id, err := ReadVarint(br)
			if err != nil {
				break
			}
			val, err := ReadVarint(br)
			if err != nil {
				break
			}
			m[id] = val
		}
		return m, nil
	}
}

// ─── QPACK helpers ─────────────────────────────────────────────────────────

// encodeQPACK QPACK-encodes a slice of header fields into a header block.
func encodeQPACK(fields []qpack.HeaderField) ([]byte, error) {
	var buf bytes.Buffer
	enc := qpack.NewEncoder(&buf)
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			return nil, err
		}
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeQPACK decodes a QPACK header block and returns the header fields.
func decodeQPACK(block []byte) ([]qpack.HeaderField, error) {
	dec := qpack.NewDecoder()
	next := dec.Decode(block)
	var fields []qpack.HeaderField
	for {
		hf, err := next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		fields = append(fields, hf)
	}
	return fields, nil
}
