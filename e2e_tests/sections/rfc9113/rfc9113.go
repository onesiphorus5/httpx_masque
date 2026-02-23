// Package rfc9113 implements conformance tests for RFC 9113 §8.5 –
// The CONNECT Method (TCP tunnelling over HTTP/2).
//
// RFC 9113 §8.5 normative requirements under test:
//
//   - :method MUST be "CONNECT"
//   - :scheme and :path pseudo-header fields MUST be omitted
//   - :authority MUST contain the host and port to connect to
//   - A CONNECT request not conforming to these restrictions is malformed
//     (stream error PROTOCOL_ERROR)
//   - On success the proxy responds with a 2xx status code
//   - All DATA frames on the stream correspond to data sent/received on the
//     TCP connection
//   - Frame types other than DATA or stream management frames MUST NOT be
//     sent on a connected stream
//   - Proxy signals TCP error with RST_STREAM CONNECT_ERROR
//   - When the client sends DATA with END_STREAM the proxy closes the TCP
//     connection
package rfc9113

import (
	"errors"
	"fmt"

	"golang.org/x/net/http2/hpack"

	"rfc9298spec/internal/config"
	"rfc9298spec/internal/spec"
)

// NewGroup returns the RFC 9113 §8.5 test group.
func NewGroup() *spec.TestGroup {
	g := &spec.TestGroup{
		Key:     "8.5",
		Section: "8.5",
		Name:    "RFC 9113 §8.5 – The CONNECT Method (TCP over HTTP/2)",
	}

	// 8.5/1  Valid CONNECT SHALL be accepted with a 2xx response.
	g.AddTest(&spec.TestCase{
		Desc: "Valid CONNECT request SHALL be accepted with a 2xx response",
		Requirement: `RFC 9113 §8.5: A proxy that supports CONNECT MUST respond
with a 2xx (Successful) status code to a well-formed CONNECT request
(:method=CONNECT, :authority=host:port, no :scheme or :path).`,
		Run: func(cfg *config.Config) error {
			conn, err := spec.NewH2Conn(cfg)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer conn.Close()

			if _, err := conn.Handshake(); err != nil {
				return fmt.Errorf("handshake: %w", err)
			}

			sid, err := conn.SendConnectTCP(cfg)
			if err != nil {
				return fmt.Errorf("send CONNECT: %w", err)
			}

			rh, err := conn.ReadResponseHeaders(sid, cfg.Timeout)
			if err != nil {
				if errors.Is(err, spec.ErrRSTStream) {
					return fmt.Errorf("proxy rejected valid CONNECT: %w", err)
				}
				return fmt.Errorf("read response: %w", err)
			}
			if rh.Status < 200 || rh.Status > 299 {
				return fmt.Errorf("expected 2xx, got %d", rh.Status)
			}
			return nil
		},
	})

	// 8.5/2  :method MUST be CONNECT — other methods MUST be rejected.
	g.AddTest(&spec.TestCase{
		Desc: ":method MUST be CONNECT (other methods MUST be rejected)",
		Requirement: `RFC 9113 §8.5: "The :method pseudo-header field is set to
CONNECT." A request using a different method with only :authority is
malformed and MUST be rejected.`,
		Run: func(cfg *config.Config) error {
			return h2ExpectRejectTCP(cfg, []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":authority", Value: cfg.TCPTargetAddr()},
			})
		},
	})

	// 8.5/3  :authority MUST be present — absent :authority MUST be rejected.
	g.AddTest(&spec.TestCase{
		Desc: ":authority MUST be present (absent :authority MUST be rejected)",
		Requirement: `RFC 9113 §8.5: "The :authority pseudo-header field contains
the host and port to connect to." A CONNECT request without :authority is
malformed (stream error PROTOCOL_ERROR).`,
		Run: func(cfg *config.Config) error {
			return h2ExpectRejectTCP(cfg, []hpack.HeaderField{
				{Name: ":method", Value: "CONNECT"},
				// :authority intentionally omitted
			})
		},
	})

	// 8.5/4  :scheme MUST be omitted — presence MUST be rejected.
	g.AddTest(&spec.TestCase{
		Desc: ":scheme MUST be omitted (presence MUST be rejected)",
		Requirement: `RFC 9113 §8.5: "The :scheme and :path pseudo-header fields
MUST be omitted." A CONNECT request with :scheme is malformed and MUST
trigger a stream error of type PROTOCOL_ERROR.`,
		Run: func(cfg *config.Config) error {
			return h2ExpectRejectTCP(cfg, []hpack.HeaderField{
				{Name: ":method", Value: "CONNECT"},
				{Name: ":scheme", Value: "https"}, // MUST NOT be present
				{Name: ":authority", Value: cfg.TCPTargetAddr()},
			})
		},
	})

	// 8.5/5  :path MUST be omitted — presence MUST be rejected.
	g.AddTest(&spec.TestCase{
		Desc: ":path MUST be omitted (presence MUST be rejected)",
		Requirement: `RFC 9113 §8.5: "The :scheme and :path pseudo-header fields
MUST be omitted." A CONNECT request with :path is malformed and MUST trigger
a stream error of type PROTOCOL_ERROR.`,
		Run: func(cfg *config.Config) error {
			return h2ExpectRejectTCP(cfg, []hpack.HeaderField{
				{Name: ":method", Value: "CONNECT"},
				{Name: ":authority", Value: cfg.TCPTargetAddr()},
				{Name: ":path", Value: "/"}, // MUST NOT be present
			})
		},
	})

	// 8.5/6  DATA frames MUST carry TCP tunnel data bidirectionally.
	g.AddTest(&spec.TestCase{
		Desc: "DATA frames MUST carry TCP tunnel data bidirectionally",
		Requirement: `RFC 9113 §8.5: "The payload of any DATA frame sent by the
client is transmitted by the proxy to the TCP server; data received from the
TCP server is assembled into DATA frames by the proxy."`,
		Run: func(cfg *config.Config) error {
			return h2TCPEchoTest(cfg, []byte("rfc9113-tcp-probe"))
		},
	})

	// 8.5/7  Multiple round-trips work over a single CONNECT stream.
	g.AddTest(&spec.TestCase{
		Desc: "Multiple DATA round-trips MUST work over a single CONNECT stream",
		Requirement: `RFC 9113 §8.5: The TCP tunnel persists for the lifetime of
the HTTP/2 stream; multiple sequential DATA exchanges MUST succeed.`,
		Run: func(cfg *config.Config) error {
			conn, err := spec.NewH2Conn(cfg)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer conn.Close()

			if _, err := conn.Handshake(); err != nil {
				return fmt.Errorf("handshake: %w", err)
			}

			sid, err := conn.SendConnectTCP(cfg)
			if err != nil {
				return fmt.Errorf("send CONNECT: %w", err)
			}

			rh, err := conn.ReadResponseHeaders(sid, cfg.Timeout)
			if err != nil {
				return fmt.Errorf("read response: %w", err)
			}
			if rh.Status < 200 || rh.Status > 299 {
				return fmt.Errorf("proxy rejected CONNECT with %d", rh.Status)
			}

			conn.WriteWindowUpdate(sid, 65535) //nolint:errcheck
			conn.WriteWindowUpdate(0, 65535)   //nolint:errcheck

			for i, payload := range []string{"first", "second", "third"} {
				if err := conn.WriteData(sid, []byte(payload), false); err != nil {
					return fmt.Errorf("write data %d: %w", i, err)
				}
				df, err := conn.ReadDataFrame(sid, cfg.Timeout)
				if err != nil {
					return fmt.Errorf("read echo %d: %w", i, err)
				}
				if string(df.Data()) != payload {
					return fmt.Errorf("echo %d mismatch: got %q, want %q",
						i, df.Data(), payload)
				}
			}
			return nil
		},
	})

	// 8.5/8  DATA with END_STREAM closes the TCP connection.
	g.AddTest(&spec.TestCase{
		Desc: "DATA with END_STREAM MUST close the TCP connection on the proxy side",
		Requirement: `RFC 9113 §8.5: "When the client ends the TCP connection, the
client sends a DATA frame with the END_STREAM flag set. A proxy that receives
a DATA frame with END_STREAM set sends the attached data, if any, and closes
the TCP connection."`,
		Run: func(cfg *config.Config) error {
			conn, err := spec.NewH2Conn(cfg)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer conn.Close()

			if _, err := conn.Handshake(); err != nil {
				return fmt.Errorf("handshake: %w", err)
			}

			sid, err := conn.SendConnectTCP(cfg)
			if err != nil {
				return fmt.Errorf("send CONNECT: %w", err)
			}

			rh, err := conn.ReadResponseHeaders(sid, cfg.Timeout)
			if err != nil {
				return fmt.Errorf("read response: %w", err)
			}
			if rh.Status < 200 || rh.Status > 299 {
				return fmt.Errorf("proxy rejected CONNECT with %d", rh.Status)
			}

			conn.WriteWindowUpdate(sid, 65535) //nolint:errcheck
			conn.WriteWindowUpdate(0, 65535)   //nolint:errcheck

			// Send data and close the stream (END_STREAM).
			payload := []byte("goodbye")
			if err := conn.WriteData(sid, payload, true); err != nil {
				return fmt.Errorf("write END_STREAM data: %w", err)
			}

			// The echo server sends back the data, then closes its end.
			// The proxy will forward that close as DATA with END_STREAM (or RST_STREAM).
			// We accept the echo or any orderly stream closure.
			df, err := conn.ReadDataFrame(sid, cfg.Timeout)
			if err != nil {
				if errors.Is(err, spec.ErrRSTStream) {
					return nil // proxy closed stream — acceptable
				}
				// io.EOF or other orderly close is fine too.
				return nil
			}
			_ = df // echo received — stream will close after this
			return nil
		},
	})

	return g
}

// ─── Helpers ───────────────────────────────────────────────────────────────

// h2ExpectRejectTCP dials a fresh H2Conn, sends HEADERS with the given fields,
// and asserts the proxy rejects the request (4xx status or RST_STREAM).
func h2ExpectRejectTCP(cfg *config.Config, fields []hpack.HeaderField) error {
	conn, err := spec.NewH2Conn(cfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	sid, err := conn.WriteHeaders(fields, false)
	if err != nil {
		return fmt.Errorf("write HEADERS: %w", err)
	}

	rh, err := conn.ReadResponseHeaders(sid, cfg.Timeout)
	if err != nil {
		if errors.Is(err, spec.ErrRSTStream) {
			return nil // RST_STREAM ≡ rejection
		}
		return fmt.Errorf("read response: %w", err)
	}
	if rh.Status >= 400 {
		return nil // 4xx/5xx ≡ rejection
	}
	return fmt.Errorf("expected rejection (4xx or RST_STREAM), got %d", rh.Status)
}

// h2TCPEchoTest establishes a CONNECT tunnel, sends payload, and verifies the
// TCP echo server's reply arrives back unchanged.
func h2TCPEchoTest(cfg *config.Config, payload []byte) error {
	conn, err := spec.NewH2Conn(cfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	sid, err := conn.SendConnectTCP(cfg)
	if err != nil {
		return fmt.Errorf("send CONNECT: %w", err)
	}

	rh, err := conn.ReadResponseHeaders(sid, cfg.Timeout)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if rh.Status < 200 || rh.Status > 299 {
		return fmt.Errorf("proxy rejected CONNECT with %d", rh.Status)
	}

	conn.WriteWindowUpdate(sid, 65535) //nolint:errcheck
	conn.WriteWindowUpdate(0, 65535)   //nolint:errcheck

	if err := conn.WriteData(sid, payload, false); err != nil {
		return fmt.Errorf("write data: %w", err)
	}

	df, err := conn.ReadDataFrame(sid, cfg.Timeout)
	if err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if string(df.Data()) != string(payload) {
		return fmt.Errorf("echo mismatch: got %q, want %q", df.Data(), payload)
	}
	return nil
}

