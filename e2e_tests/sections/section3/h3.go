package section3

// HTTP/3 conformance tests for:
//   §3.1  UDP Proxy Handling (via QUIC DATAGRAM frames)
//   §3.4  HTTP/3 Requests
//   §3.5  HTTP/3 Responses

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
		Desc: "Proxy MUST forward UDP datagrams from client to HTTP/3 target (QUIC DATAGRAM)",
		Requirement: `RFC 9298 §3.1: "The proxy MUST forward UDP payloads received
in QUIC DATAGRAM frames to the target." Verified by establishing a QUIC
connection to the HTTP/3 target through the tunnel and checking a 200 GET.`,
		Run: func(cfg *config.Config) error {
			return h3UDPHTTPTest(cfg)
		},
	})

	// 3.1-h3/2  Proxy MUST return target UDP responses to the client.
	g.AddTest(&spec.TestCase{
		Desc: "Proxy MUST return HTTP/3 target responses to the client (QUIC DATAGRAM)",
		Requirement: `RFC 9298 §3.1: "The proxy MUST forward UDP payloads received
from the target to the client in QUIC DATAGRAM frames." Verified by receiving
a 200 response from the HTTP/3 target via the tunnel.`,
		Run: func(cfg *config.Config) error {
			return h3UDPHTTPTest(cfg)
		},
	})

	// 3.1-h3/3  Multiple datagrams can flow over a single stream.
	g.AddTest(&spec.TestCase{
		Desc: "Multiple HTTP/3 requests MAY flow over a single connect-udp stream (HTTP/3 outer)",
		Requirement: `RFC 9298 §3.1: The proxy MUST keep the UDP socket open for
the lifetime of the request stream, allowing multiple QUIC DATAGRAM frames.
Verified by making 3 sequential HTTP/3 GET requests over the same QUIC conn.`,
		Run: func(cfg *config.Config) error {
			return h3MultiHTTPTest(cfg, 3)
		},
	})

	// 3.1-h3/4  Socket MUST stay open while the stream is open.
	g.AddTest(&spec.TestCase{
		Desc: "UDP socket MUST remain open while the HTTP/3 request stream is open",
		Requirement: `RFC 9298 §3.1: "The proxy MUST keep the UDP socket open while
the request stream is open." Verified by making two HTTP/3 GETs with a
1-second idle gap and checking both succeed.`,
		Run: func(cfg *config.Config) error {
			return h3SequentialHTTPTest(cfg, time.Second)
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

// h3UDPHTTPTest establishes a connect-udp tunnel over HTTP/3, then makes a
// single HTTP/3 GET to the HTTP/3 target through it, verifying a 200 response.
func h3UDPHTTPTest(cfg *config.Config) error {
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

	targetAddr, err := net.ResolveUDPAddr("udp", cfg.TargetAddr())
	if err != nil {
		return fmt.Errorf("resolve target addr: %w", err)
	}

	pc := spec.NewMASQUEPacketConnH3(conn, stream, targetAddr, cfg.Timeout)
	defer pc.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	resp, err := spec.H3GetThroughPacketConn(ctx, pc, targetAddr, cfg.TargetAddr(), "/")
	if err != nil {
		return fmt.Errorf("HTTP/3 GET through MASQUE tunnel: %w", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected 200, got %d", resp.StatusCode)
	}
	return nil
}

// h3MultiHTTPTest establishes a connect-udp tunnel over HTTP/3, then makes n
// sequential HTTP/3 GET requests over the same QUIC connection, verifying
// that multiple datagram flows can traverse a single connect-udp stream.
func h3MultiHTTPTest(cfg *config.Config, n int) error {
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

	targetAddr, err := net.ResolveUDPAddr("udp", cfg.TargetAddr())
	if err != nil {
		return fmt.Errorf("resolve target addr: %w", err)
	}

	pc := spec.NewMASQUEPacketConnH3(conn, stream, targetAddr, cfg.Timeout)
	defer pc.Close() //nolint:errcheck

	// One http3.Transport → one QUIC connection → n HTTP/3 requests.
	client, cleanup := spec.NewH3ClientForPacketConn(pc, targetAddr, cfg.TargetHost)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout*time.Duration(n+1))
	defer cancel()

	for i := 0; i < n; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+cfg.TargetAddr()+"/", nil)
		if err != nil {
			return fmt.Errorf("build request %d: %w", i, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("request %d: %w", i, err)
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("request %d: expected 200, got %d", i, resp.StatusCode)
		}
	}
	return nil
}

// h3SequentialHTTPTest establishes a connect-udp tunnel over HTTP/3, makes a
// first HTTP/3 GET, waits gap, then makes a second GET — both must succeed
// (proving the proxy UDP socket stays open across the idle gap).
func h3SequentialHTTPTest(cfg *config.Config, gap time.Duration) error {
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

	targetAddr, err := net.ResolveUDPAddr("udp", cfg.TargetAddr())
	if err != nil {
		return fmt.Errorf("resolve target addr: %w", err)
	}

	pc := spec.NewMASQUEPacketConnH3(conn, stream, targetAddr, cfg.Timeout)
	defer pc.Close() //nolint:errcheck

	// One http3.Transport reused for both GETs (same QUIC connection).
	client, cleanup := spec.NewH3ClientForPacketConn(pc, targetAddr, cfg.TargetHost)
	defer cleanup()

	totalTimeout := cfg.Timeout*2 + gap
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	for i, label := range []string{"first", "second"} {
		if i > 0 {
			time.Sleep(gap)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+cfg.TargetAddr()+"/", nil)
		if err != nil {
			return fmt.Errorf("build %s request: %w", label, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("%s GET after %s gap: %w", label, gap, err)
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s GET: expected 200, got %d", label, resp.StatusCode)
		}
	}
	return nil
}
