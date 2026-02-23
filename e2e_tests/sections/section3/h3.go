package section3

// HTTP/3 conformance tests for:
//   §3.1  UDP Proxy Handling (via QUIC DATAGRAM frames)
//   §3.4  HTTP/3 Requests
//   §3.5  HTTP/3 Responses

import (
	"errors"
	"fmt"
	"time"

	"github.com/quic-go/qpack"

	"rfc9298spec/internal/config"
	"rfc9298spec/internal/spec"
)

// ─── §3.4 (HTTP/3) ─────────────────────────────────────────────────────────

func newSection34H3() *spec.TestGroup {
	g := &spec.TestGroup{
		Key:     "h3",
		Section: "3.4",
		Name:    "HTTP/3",
	}

	// 3.4-h3/1  Server MUST advertise ENABLE_CONNECT_PROTOCOL and H3_DATAGRAM.
	g.AddTest(&spec.TestCase{
		Desc: "Server MUST advertise ENABLE_CONNECT_PROTOCOL=1 and H3_DATAGRAM=1",
		Requirement: `RFC 9220 §3 + RFC 9297 §2.1.1: The server MUST send HTTP/3
SETTINGS with ENABLE_CONNECT_PROTOCOL=1 (0x08) and H3_DATAGRAM=1 (0x33) to
allow Extended CONNECT with QUIC DATAGRAM support.`,
		Run: func(cfg *config.Config) error {
			conn, err := spec.NewH3Conn(cfg)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer conn.Close()

			enableConnect, enableDatagram, err := conn.Handshake()
			if err != nil {
				return fmt.Errorf("handshake: %w", err)
			}
			if !enableConnect {
				return fmt.Errorf("server did not advertise ENABLE_CONNECT_PROTOCOL=1")
			}
			if !enableDatagram {
				return fmt.Errorf("server did not advertise H3_DATAGRAM=1")
			}
			return nil
		},
	})

	// 3.4-h3/2  :method SHALL be CONNECT.
	g.AddTest(&spec.TestCase{
		Desc: ":method SHALL be CONNECT (proxy MUST reject other methods)",
		Requirement: `RFC 9298 §3.4: "The :method pseudo-header field SHALL be
CONNECT." Sending :method=GET with :protocol=connect-udp MUST be rejected
with a 4xx response or stream reset.`,
		Run: func(cfg *config.Config) error {
			return h3ExpectRejection(cfg, []qpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":protocol", Value: "connect-udp"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: cfg.Addr()},
				{Name: ":path", Value: cfg.BuildPath(cfg.TargetHost, cfg.TargetPort)},
			})
		},
	})

	// 3.4-h3/3  :protocol SHALL be "connect-udp".
	g.AddTest(&spec.TestCase{
		Desc: ":protocol SHALL be connect-udp (absent :protocol MUST be rejected)",
		Requirement: `RFC 9298 §3.4: "The :protocol pseudo-header field SHALL be
'connect-udp'." An Extended CONNECT without :protocol is a plain tunnel and
MUST be rejected by a connect-udp proxy.`,
		Run: func(cfg *config.Config) error {
			return h3ExpectRejection(cfg, []qpack.HeaderField{
				{Name: ":method", Value: "CONNECT"},
				// :protocol intentionally omitted
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: cfg.Addr()},
				{Name: ":path", Value: cfg.BuildPath(cfg.TargetHost, cfg.TargetPort)},
			})
		},
	})

	// 3.4-h3/4  :protocol with wrong value MUST be rejected.
	g.AddTest(&spec.TestCase{
		Desc: ":protocol with unknown value MUST be rejected",
		Requirement: `RFC 9298 §3.4: :protocol SHALL be the token "connect-udp".
A proxy MUST reject requests with any other :protocol value.`,
		Run: func(cfg *config.Config) error {
			return h3ExpectRejection(cfg, []qpack.HeaderField{
				{Name: ":method", Value: "CONNECT"},
				{Name: ":protocol", Value: "connect-tcp"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: cfg.Addr()},
				{Name: ":path", Value: cfg.BuildPath(cfg.TargetHost, cfg.TargetPort)},
			})
		},
	})

	// 3.4-h3/5  :scheme SHALL NOT be empty.
	g.AddTest(&spec.TestCase{
		Desc: ":scheme SHALL NOT be empty",
		Requirement: `RFC 9298 §3.4: ":path and :scheme pseudo-header fields SHALL
NOT be empty." An empty :scheme MUST be rejected.`,
		Run: func(cfg *config.Config) error {
			return h3ExpectRejection(cfg, []qpack.HeaderField{
				{Name: ":method", Value: "CONNECT"},
				{Name: ":protocol", Value: "connect-udp"},
				{Name: ":scheme", Value: ""},
				{Name: ":authority", Value: cfg.Addr()},
				{Name: ":path", Value: cfg.BuildPath(cfg.TargetHost, cfg.TargetPort)},
			})
		},
	})

	// 3.4-h3/6  :path SHALL NOT be empty.
	g.AddTest(&spec.TestCase{
		Desc: ":path SHALL NOT be empty",
		Requirement: `RFC 9298 §3.4: ":path and :scheme pseudo-header fields SHALL
NOT be empty." An empty :path MUST be rejected.`,
		Run: func(cfg *config.Config) error {
			return h3ExpectRejection(cfg, []qpack.HeaderField{
				{Name: ":method", Value: "CONNECT"},
				{Name: ":protocol", Value: "connect-udp"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: cfg.Addr()},
				{Name: ":path", Value: ""},
			})
		},
	})

	// 3.4-h3/7  :authority SHALL be present.
	g.AddTest(&spec.TestCase{
		Desc: ":authority SHALL be present and non-empty",
		Requirement: `RFC 9298 §3.4: ":authority pseudo-header field SHALL contain
the authority of the proxy." An absent or empty :authority MUST be rejected.`,
		Run: func(cfg *config.Config) error {
			return h3ExpectRejection(cfg, []qpack.HeaderField{
				{Name: ":method", Value: "CONNECT"},
				{Name: ":protocol", Value: "connect-udp"},
				{Name: ":scheme", Value: "https"},
				// :authority intentionally omitted
				{Name: ":path", Value: cfg.BuildPath(cfg.TargetHost, cfg.TargetPort)},
			})
		},
	})

	// 3.4-h3/8  Valid Extended CONNECT SHALL be accepted.
	g.AddTest(&spec.TestCase{
		Desc: "Valid Extended CONNECT request SHALL be accepted",
		Requirement: `RFC 9298 §3.4: A well-formed Extended CONNECT request with
:method=CONNECT, :protocol=connect-udp, non-empty :scheme, :authority, and
:path MUST be accepted by the proxy with a 2xx response.`,
		Run: func(cfg *config.Config) error {
			conn, err := spec.NewH3Conn(cfg)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer conn.Close()

			if _, _, err := conn.Handshake(); err != nil {
				return fmt.Errorf("handshake: %w", err)
			}

			stream, err := conn.SendConnectUDP(cfg)
			if err != nil {
				return fmt.Errorf("send CONNECT: %w", err)
			}
			defer stream.Close()

			rh, err := conn.ReadResponseHeaders(stream, cfg.Timeout)
			if err != nil {
				if errors.Is(err, spec.ErrRSTStream) {
					return fmt.Errorf("proxy rejected valid CONNECT-UDP: %w", err)
				}
				return fmt.Errorf("read response: %w", err)
			}
			if rh.Status < 200 || rh.Status > 299 {
				return fmt.Errorf("expected 2xx, got %d", rh.Status)
			}
			return nil
		},
	})

	return g
}

// ─── §3.5 (HTTP/3) ─────────────────────────────────────────────────────────

func newSection35H3() *spec.TestGroup {
	g := &spec.TestGroup{
		Key:     "h3",
		Section: "3.5",
		Name:    "HTTP/3",
	}

	// 3.5-h3/1  Response status SHALL be in the 2xx range.
	g.AddTest(&spec.TestCase{
		Desc: "Success response status SHALL be in the 2xx (Successful) range",
		Requirement: `RFC 9298 §3.5: "The status code on a response to a request
for UDP proxying SHALL be in the 2xx (Successful) range if the request was
accepted."`,
		Run: func(cfg *config.Config) error {
			conn, err := spec.NewH3Conn(cfg)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer conn.Close()

			if _, _, err := conn.Handshake(); err != nil {
				return fmt.Errorf("handshake: %w", err)
			}

			stream, err := conn.SendConnectUDP(cfg)
			if err != nil {
				return fmt.Errorf("send CONNECT: %w", err)
			}
			defer stream.Close()

			rh, err := conn.ReadResponseHeaders(stream, cfg.Timeout)
			if err != nil {
				return fmt.Errorf("read response: %w", err)
			}
			if rh.Status < 200 || rh.Status > 299 {
				return fmt.Errorf("expected 2xx, got %d", rh.Status)
			}
			return nil
		},
	})

	return g
}

// ─── §3.1 UDP Proxy Handling (HTTP/3 / QUIC DATAGRAM) ─────────────────────

func newSection31H3() *spec.TestGroup {
	g := &spec.TestGroup{
		Key:     "h3",
		Section: "3.1",
		Name:    "HTTP/3",
	}

	// 3.1-h3/1  Proxy MUST forward UDP datagrams to the target.
	g.AddTest(&spec.TestCase{
		Desc: "Proxy MUST forward UDP datagrams from client to target (QUIC DATAGRAM)",
		Requirement: `RFC 9298 §3.1: "The proxy MUST forward UDP payloads received
in QUIC DATAGRAM frames to the target." Sent as QUIC DATAGRAM frames instead
of capsules when using HTTP/3.`,
		Run: func(cfg *config.Config) error {
			return h3UDPEchoTest(cfg, []byte("rfc9298-h3-probe"))
		},
	})

	// 3.1-h3/2  Proxy MUST return target UDP responses to the client.
	g.AddTest(&spec.TestCase{
		Desc: "Proxy MUST return UDP responses from target to client (QUIC DATAGRAM)",
		Requirement: `RFC 9298 §3.1: "The proxy MUST forward UDP payloads received
from the target to the client in QUIC DATAGRAM frames."`,
		Run: func(cfg *config.Config) error {
			return h3UDPEchoTest(cfg, []byte("ping-h3"))
		},
	})

	// 3.1-h3/3  Multiple datagrams can flow over a single stream.
	g.AddTest(&spec.TestCase{
		Desc: "Multiple UDP datagrams MAY flow over a single connect-udp stream (HTTP/3)",
		Requirement: `RFC 9298 §3.1: The proxy MUST keep the UDP socket open for
the lifetime of the request stream, allowing multiple QUIC DATAGRAM frames.`,
		Run: func(cfg *config.Config) error {
			return h3MultiDatagramTest(cfg, 3)
		},
	})

	// 3.1-h3/4  Socket MUST stay open while the stream is open.
	g.AddTest(&spec.TestCase{
		Desc: "UDP socket MUST remain open while the HTTP/3 request stream is open",
		Requirement: `RFC 9298 §3.1: "The proxy MUST keep the UDP socket open while
the request stream is open." Two sequential datagrams sent 1 second apart
must both be echoed.`,
		Run: func(cfg *config.Config) error {
			return h3SequentialDatagramTest(cfg, time.Second)
		},
	})

	return g
}

// ─── Helpers ───────────────────────────────────────────────────────────────

// h3ExpectRejection opens a fresh H3Conn, performs the handshake, sends the
// given HEADERS, and asserts the proxy responds with a 4xx status or a stream
// reset.
func h3ExpectRejection(cfg *config.Config, fields []qpack.HeaderField) error {
	conn, err := spec.NewH3Conn(cfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if _, _, err := conn.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	stream, err := conn.WriteHeaders(fields)
	if err != nil {
		return fmt.Errorf("write HEADERS: %w", err)
	}
	defer stream.Close()

	rh, err := conn.ReadResponseHeaders(stream, cfg.Timeout)
	if err != nil {
		if errors.Is(err, spec.ErrRSTStream) {
			return nil // stream reset ≡ rejection
		}
		return fmt.Errorf("read response: %w", err)
	}
	if rh.Status >= 400 {
		return nil // 4xx/5xx ≡ rejection
	}
	return fmt.Errorf("expected rejection (4xx or stream reset), got %d", rh.Status)
}

// h3UDPEchoTest establishes an Extended CONNECT stream, sends payload as a
// QUIC DATAGRAM frame, and asserts the echo arrives back.
func h3UDPEchoTest(cfg *config.Config, payload []byte) error {
	conn, err := spec.NewH3Conn(cfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if _, _, err := conn.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	stream, err := conn.SendConnectUDP(cfg)
	if err != nil {
		return fmt.Errorf("send CONNECT: %w", err)
	}
	defer stream.Close()

	rh, err := conn.ReadResponseHeaders(stream, cfg.Timeout)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if rh.Status < 200 || rh.Status > 299 {
		return fmt.Errorf("proxy rejected CONNECT-UDP with %d", rh.Status)
	}

	if err := conn.SendDatagram(stream, payload); err != nil {
		return fmt.Errorf("send DATAGRAM: %w", err)
	}

	echo, err := conn.ReceiveDatagram(stream, cfg.Timeout)
	if err != nil {
		return fmt.Errorf("waiting for echo: %w", err)
	}
	if string(echo) != string(payload) {
		return fmt.Errorf("echo mismatch: got %q, want %q", echo, payload)
	}
	return nil
}

// h3MultiDatagramTest sends n datagrams and verifies each is echoed back.
func h3MultiDatagramTest(cfg *config.Config, n int) error {
	conn, err := spec.NewH3Conn(cfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if _, _, err := conn.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	stream, err := conn.SendConnectUDP(cfg)
	if err != nil {
		return fmt.Errorf("send CONNECT: %w", err)
	}
	defer stream.Close()

	rh, err := conn.ReadResponseHeaders(stream, cfg.Timeout)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if rh.Status < 200 || rh.Status > 299 {
		return fmt.Errorf("proxy rejected CONNECT-UDP with %d", rh.Status)
	}

	payloads := make([]string, n)
	for i := 0; i < n; i++ {
		payloads[i] = fmt.Sprintf("h3-datagram-%d", i)
		if err := conn.SendDatagram(stream, []byte(payloads[i])); err != nil {
			return fmt.Errorf("send datagram %d: %w", i, err)
		}
	}

	received := make(map[string]bool)
	deadline := time.Now().Add(cfg.Timeout)
	for len(received) < n && time.Now().Before(deadline) {
		echo, err := conn.ReceiveDatagram(stream, time.Until(deadline))
		if err != nil {
			break
		}
		received[string(echo)] = true
	}

	if len(received) < n {
		return fmt.Errorf("expected %d echoes, got %d", n, len(received))
	}
	return nil
}

// h3SequentialDatagramTest sends one datagram, waits gap, sends another,
// verifying both are echoed (proving the socket stays open).
func h3SequentialDatagramTest(cfg *config.Config, gap time.Duration) error {
	conn, err := spec.NewH3Conn(cfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if _, _, err := conn.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	stream, err := conn.SendConnectUDP(cfg)
	if err != nil {
		return fmt.Errorf("send CONNECT: %w", err)
	}
	defer stream.Close()

	rh, err := conn.ReadResponseHeaders(stream, cfg.Timeout)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if rh.Status < 200 || rh.Status > 299 {
		return fmt.Errorf("proxy rejected CONNECT-UDP with %d", rh.Status)
	}

	for i, payload := range []string{"h3-first", "h3-second"} {
		if i > 0 {
			time.Sleep(gap)
		}
		if err := conn.SendDatagram(stream, []byte(payload)); err != nil {
			return fmt.Errorf("send datagram %d: %w", i, err)
		}
		echo, err := conn.ReceiveDatagram(stream, cfg.Timeout)
		if err != nil {
			return fmt.Errorf("echo %d: %w", i, err)
		}
		if string(echo) != payload {
			return fmt.Errorf("echo %d mismatch: got %q, want %q", i, echo, payload)
		}
	}
	return nil
}
