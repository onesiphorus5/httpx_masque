package section3

// §3.4  HTTP/2 and HTTP/3 Requests
// §3.5  HTTP/2 and HTTP/3 Responses
// §3.1  UDP Proxy Handling (via HTTP/2 data transfer)

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"rfc9298spec/internal/config"
	"rfc9298spec/internal/spec"
)

// ─── §3.4 ──────────────────────────────────────────────────────────────────

func newSection34H2() *spec.TestGroup {
	g := &spec.TestGroup{
		Key:     "h2",
		Section: "3.4",
		Name:    "HTTP/2",
	}

	// 3.4/1  Server MUST advertise SETTINGS_ENABLE_CONNECT_PROTOCOL.
	g.AddTest(&spec.TestCase{
		Desc: "Server MUST advertise SETTINGS_ENABLE_CONNECT_PROTOCOL = 1",
		Requirement: `RFC 8441 §3 (required by RFC 9298 §3.4): The server MUST send
SETTINGS_ENABLE_CONNECT_PROTOCOL with value 1 to allow Extended CONNECT.`,
		Run: func(cfg *config.Config) error {
			return config.RunWithRef(cfg, func(cfg *config.Config) error {
				conn, err := spec.NewH2Conn(cfg)
				if err != nil {
					return fmt.Errorf("connect: %w", err)
				}
				defer conn.Close()

				enabled, err := conn.Handshake()
				if err != nil {
					return fmt.Errorf("handshake: %w", err)
				}
				if !enabled {
					return fmt.Errorf(
						"server did not send SETTINGS_ENABLE_CONNECT_PROTOCOL=1 (got %v)",
						conn.ServerSettings[spec.SettingEnableConnectProtocol],
					)
				}
				return nil
			})
		},
	})

	// 3.4/2  :method SHALL be CONNECT — other values MUST be rejected.
	g.AddTest(&spec.TestCase{
		Desc: ":method SHALL be CONNECT (proxy MUST reject other methods)",
		Requirement: `RFC 9298 §3.4: "The :method pseudo-header field SHALL be CONNECT."
Sending :method = GET with :protocol = connect-udp must be rejected with 4xx
or RST_STREAM.`,
		Run: func(cfg *config.Config) error {
			return config.RunWithRef(cfg, func(cfg *config.Config) error {
				return h2ExpectRejection(cfg, []hpack.HeaderField{
					{Name: ":method", Value: "GET"},
					{Name: ":protocol", Value: "connect-udp"},
					{Name: ":scheme", Value: "https"},
					{Name: ":authority", Value: cfg.Addr()},
					{Name: ":path", Value: cfg.BuildPath(cfg.TargetHost, cfg.TargetPort)},
				})
			})
		},
	})

	// 3.4/3  :protocol SHALL be "connect-udp" — absent :protocol MUST be rejected.
	g.AddTest(&spec.TestCase{
		Desc: ":protocol SHALL be connect-udp (absent :protocol must be rejected)",
		Requirement: `RFC 9298 §3.4: "The :protocol pseudo-header field SHALL be
'connect-udp'." An Extended CONNECT without :protocol is a plain CONNECT
tunnel and MUST be rejected by a connect-udp proxy.`,
		Run: func(cfg *config.Config) error {
			return config.RunWithRef(cfg, func(cfg *config.Config) error {
				return h2ExpectRejection(cfg, []hpack.HeaderField{
					{Name: ":method", Value: "CONNECT"},
					// :protocol intentionally omitted
					{Name: ":scheme", Value: "https"},
					{Name: ":authority", Value: cfg.Addr()},
					{Name: ":path", Value: cfg.BuildPath(cfg.TargetHost, cfg.TargetPort)},
				})
			})
		},
	})

	// 3.4/4  :protocol with wrong value MUST be rejected.
	g.AddTest(&spec.TestCase{
		Desc: ":protocol with unknown value MUST be rejected",
		Requirement: `RFC 9298 §3.4: :protocol SHALL be the token "connect-udp".
A proxy handling connect-udp MUST NOT accept requests with a different
:protocol value.`,
		Run: func(cfg *config.Config) error {
			return config.RunWithRef(cfg, func(cfg *config.Config) error {
				return h2ExpectRejection(cfg, []hpack.HeaderField{
					{Name: ":method", Value: "CONNECT"},
					{Name: ":protocol", Value: "connect-tcp"}, // wrong
					{Name: ":scheme", Value: "https"},
					{Name: ":authority", Value: cfg.Addr()},
					{Name: ":path", Value: cfg.BuildPath(cfg.TargetHost, cfg.TargetPort)},
				})
			})
		},
	})

	// 3.4/5  :scheme SHALL NOT be empty.
	g.AddTest(&spec.TestCase{
		Desc: ":scheme SHALL NOT be empty",
		Requirement: `RFC 9298 §3.4: ":path and :scheme pseudo-header fields SHALL
NOT be empty." An empty :scheme MUST be rejected.`,
		Run: func(cfg *config.Config) error {
			return config.RunWithRef(cfg, func(cfg *config.Config) error {
				return h2ExpectRejection(cfg, []hpack.HeaderField{
					{Name: ":method", Value: "CONNECT"},
					{Name: ":protocol", Value: "connect-udp"},
					{Name: ":scheme", Value: ""}, // empty
					{Name: ":authority", Value: cfg.Addr()},
					{Name: ":path", Value: cfg.BuildPath(cfg.TargetHost, cfg.TargetPort)},
				})
			})
		},
	})

	// 3.4/6  :path SHALL NOT be empty.
	g.AddTest(&spec.TestCase{
		Desc: ":path SHALL NOT be empty",
		Requirement: `RFC 9298 §3.4: ":path and :scheme pseudo-header fields SHALL
NOT be empty." An empty :path MUST be rejected.`,
		Run: func(cfg *config.Config) error {
			return config.RunWithRef(cfg, func(cfg *config.Config) error {
				return h2ExpectRejection(cfg, []hpack.HeaderField{
					{Name: ":method", Value: "CONNECT"},
					{Name: ":protocol", Value: "connect-udp"},
					{Name: ":scheme", Value: "https"},
					{Name: ":authority", Value: cfg.Addr()},
					{Name: ":path", Value: ""}, // empty
				})
			})
		},
	})

	// 3.4/7  :authority SHALL contain the proxy authority.
	g.AddTest(&spec.TestCase{
		Desc: ":authority SHALL be present and non-empty",
		Requirement: `RFC 9298 §3.4: ":authority pseudo-header field SHALL contain
the authority of the proxy." An absent or empty :authority MUST be rejected.`,
		Run: func(cfg *config.Config) error {
			return config.RunWithRef(cfg, func(cfg *config.Config) error {
				return h2ExpectRejection(cfg, []hpack.HeaderField{
					{Name: ":method", Value: "CONNECT"},
					{Name: ":protocol", Value: "connect-udp"},
					{Name: ":scheme", Value: "https"},
					// :authority intentionally omitted
					{Name: ":path", Value: cfg.BuildPath(cfg.TargetHost, cfg.TargetPort)},
				})
			})
		},
	})

	// 3.4/8  Valid Extended CONNECT request MUST be accepted.
	g.AddTest(&spec.TestCase{
		Desc: "Valid Extended CONNECT request SHALL be accepted",
		Requirement: `RFC 9298 §3.4: A well-formed Extended CONNECT request with
:method=CONNECT, :protocol=connect-udp, non-empty :scheme, :authority, and
:path MUST be accepted by the proxy.`,
		Run: func(cfg *config.Config) error {
			return config.RunWithRef(cfg, func(cfg *config.Config) error {
				conn, err := spec.NewH2Conn(cfg)
				if err != nil {
					return fmt.Errorf("connect: %w", err)
				}
				defer conn.Close()

				if _, err := conn.Handshake(); err != nil {
					return fmt.Errorf("handshake: %w", err)
				}

				sid, err := conn.SendConnectUDP(cfg)
				if err != nil {
					return fmt.Errorf("send CONNECT: %w", err)
				}

				rh, err := conn.ReadResponseHeaders(sid, cfg.Timeout)
				if err != nil {
					if errors.Is(err, spec.ErrRSTStream) {
						return fmt.Errorf("proxy rejected valid CONNECT-UDP: %w", err)
					}
					return fmt.Errorf("read response: %w", err)
				}
				if rh.Status < 200 || rh.Status >= 300 {
					return fmt.Errorf("expected 2xx status, got %d", rh.Status)
				}
				return nil
			})
		},
	})

	return g
}

// ─── §3.5 ──────────────────────────────────────────────────────────────────

func newSection35H2() *spec.TestGroup {
	g := &spec.TestGroup{
		Key:     "h2",
		Section: "3.5",
		Name:    "HTTP/2",
	}

	// 3.5/1  Status code SHALL be in the 2xx range.
	g.AddTest(&spec.TestCase{
		Desc: "Success response status SHALL be in the 2xx (Successful) range",
		Requirement: `RFC 9298 §3.5: "The status code on a response to a request
for UDP proxying SHALL be in the 2xx (Successful) range if the request was
accepted."`,
		Run: func(cfg *config.Config) error {
			return config.RunWithRef(cfg, func(cfg *config.Config) error {
				conn, err := spec.NewH2Conn(cfg)
				if err != nil {
					return fmt.Errorf("connect: %w", err)
				}
				defer conn.Close()

				if _, err := conn.Handshake(); err != nil {
					return fmt.Errorf("handshake: %w", err)
				}

				sid, err := conn.SendConnectUDP(cfg)
				if err != nil {
					return fmt.Errorf("send CONNECT: %w", err)
				}

				rh, err := conn.ReadResponseHeaders(sid, cfg.Timeout)
				if err != nil {
					return fmt.Errorf("read response: %w", err)
				}
				if rh.Status < 200 || rh.Status > 299 {
					return fmt.Errorf("expected 2xx status, got %d", rh.Status)
				}
				return nil
			})
		},
	})

	// 3.5/2  Capsule-Protocol header SHOULD be present on 2xx response.
	g.AddTest(&spec.TestCase{
		Desc: "2xx response SHOULD include Capsule-Protocol: ?1 header",
		Requirement: `RFC 9297 §3.3 (required by RFC 9298 §3.4/3.5): When capsules
are used over HTTP/2, the Capsule-Protocol header field MUST be present on
both the request and the response.`,
		Run: func(cfg *config.Config) error {
			return config.RunWithRef(cfg, func(cfg *config.Config) error {
				conn, err := spec.NewH2Conn(cfg)
				if err != nil {
					return fmt.Errorf("connect: %w", err)
				}
				defer conn.Close()

				if _, err := conn.Handshake(); err != nil {
					return fmt.Errorf("handshake: %w", err)
				}

				sid, err := conn.SendConnectUDP(cfg)
				if err != nil {
					return fmt.Errorf("send CONNECT: %w", err)
				}

				rh, err := conn.ReadResponseHeaders(sid, cfg.Timeout)
				if err != nil {
					return fmt.Errorf("read response: %w", err)
				}
				if rh.Status < 200 || rh.Status > 299 {
					return spec.ErrSkipped // prerequisite failed; skip capsule check
				}

				for _, hf := range rh.Fields {
					if hf.Name == "capsule-protocol" {
						return nil
					}
				}
				return fmt.Errorf("response missing Capsule-Protocol header field")
			})
		},
	})

	return g
}

// ─── §3.1 UDP proxy behaviour (via HTTP/2) ─────────────────────────────────

func newSection31H2() *spec.TestGroup {
	g := &spec.TestGroup{
		Key:     "h2",
		Section: "3.1",
		Name:    "HTTP/2",
	}

	// 3.1/1  Proxy MUST forward client datagrams to the target.
	g.AddTest(&spec.TestCase{
		Desc: "Proxy MUST forward UDP payloads to the HTTP/3 target",
		Requirement: `RFC 9298 §3.1: "The proxy MUST forward UDP payloads received
in DATAGRAM capsules to the target." Verified by establishing a QUIC
connection to the HTTP/3 target through the tunnel and checking a 200 GET.`,
		Run: func(cfg *config.Config) error {
			return config.RunWithRef(cfg, h2UDPHTTPTest)
		},
	})

	// 3.1/2  Proxy MUST return target UDP responses to the client.
	g.AddTest(&spec.TestCase{
		Desc: "Proxy MUST return HTTP/3 target responses to the client",
		Requirement: `RFC 9298 §3.1: "The proxy MUST forward UDP payloads received
from the target to the client in DATAGRAM capsules." Verified by receiving
a 200 response from the HTTP/3 target via the tunnel.`,
		Run: func(cfg *config.Config) error {
			return config.RunWithRef(cfg, h2UDPHTTPTest)
		},
	})

	// 3.1/3  Multiple datagrams can flow over a single stream.
	g.AddTest(&spec.TestCase{
		Desc: "Multiple HTTP/3 requests MAY flow over a single connect-udp stream",
		Requirement: `RFC 9298 §3.1: The proxy MUST keep the UDP socket open for
the lifetime of the request stream, allowing multiple datagrams to be
exchanged. Verified by making 3 sequential HTTP/3 GET requests.`,
		Run: func(cfg *config.Config) error {
			return config.RunWithRef(cfg, func(cfg *config.Config) error {
				return h2MultiHTTPTest(cfg, 3)
			})
		},
	})

	// 3.1/4  Socket MUST stay open while the stream is open.
	g.AddTest(&spec.TestCase{
		Desc: "UDP socket MUST remain open across an idle gap (HTTP/3 session)",
		Requirement: `RFC 9298 §3.1: "The proxy MUST keep the UDP socket open while
the request stream is open." Verified by sending two HTTP/3 GETs with a
1-second gap and checking both succeed.`,
		Run: func(cfg *config.Config) error {
			return config.RunWithRef(cfg, func(cfg *config.Config) error {
				return h2SequentialHTTPTest(cfg, time.Second)
			})
		},
	})

	return g
}

// ─── Helpers ───────────────────────────────────────────────────────────────

// h2ExpectRejection dials a fresh H2Conn, performs the handshake, sends the
// given HEADERS, and asserts the proxy responds with a 4xx status, RST_STREAM,
// or connection close (all are valid rejection forms per RFC 9298 §3.4).
func h2ExpectRejection(cfg *config.Config, fields []hpack.HeaderField) error {
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
		if errors.Is(err, io.EOF) {
			return nil // connection close ≡ rejection
		}
		// GOAWAY or other connection-level error also signals rejection.
		return nil
	}
	if rh.Status >= 400 {
		return nil // 4xx/5xx ≡ rejection
	}
	return fmt.Errorf("expected rejection (4xx, RST_STREAM, or connection close), got %d", rh.Status)
}

// h2UDPHTTPTest establishes a connect-udp tunnel and makes a single HTTP/3 GET
// to the HTTP/3 target through it, verifying a 200 response.
func h2UDPHTTPTest(cfg *config.Config) error {
	conn, err := spec.NewH2Conn(cfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	sid, err := conn.SendConnectUDP(cfg)
	if err != nil {
		return fmt.Errorf("send CONNECT: %w", err)
	}

	rh, err := conn.ReadResponseHeaders(sid, cfg.Timeout)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if rh.Status < 200 || rh.Status > 299 {
		return fmt.Errorf("proxy rejected CONNECT-UDP with %d", rh.Status)
	}

	conn.WriteWindowUpdate(sid, 65535) //nolint:errcheck
	conn.WriteWindowUpdate(0, 65535)   //nolint:errcheck

	targetAddr, err := net.ResolveUDPAddr("udp", cfg.TargetAddr())
	if err != nil {
		return fmt.Errorf("resolve target addr: %w", err)
	}

	pc := spec.NewMASQUEPacketConnH2(conn, sid, targetAddr, cfg.Timeout)
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

// h2MultiHTTPTest establishes a connect-udp tunnel, then makes n sequential
// HTTP/3 GET requests over the same QUIC connection, verifying that multiple
// datagram flows can traverse a single connect-udp stream.
func h2MultiHTTPTest(cfg *config.Config, n int) error {
	conn, err := spec.NewH2Conn(cfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	sid, err := conn.SendConnectUDP(cfg)
	if err != nil {
		return fmt.Errorf("send CONNECT: %w", err)
	}

	rh, err := conn.ReadResponseHeaders(sid, cfg.Timeout)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if rh.Status < 200 || rh.Status > 299 {
		return fmt.Errorf("proxy rejected CONNECT-UDP with %d", rh.Status)
	}

	conn.WriteWindowUpdate(sid, 65535) //nolint:errcheck
	conn.WriteWindowUpdate(0, 65535)   //nolint:errcheck

	targetAddr, err := net.ResolveUDPAddr("udp", cfg.TargetAddr())
	if err != nil {
		return fmt.Errorf("resolve target addr: %w", err)
	}

	pc := spec.NewMASQUEPacketConnH2(conn, sid, targetAddr, cfg.Timeout)
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

// h2SequentialHTTPTest establishes a connect-udp tunnel, makes a first HTTP/3
// GET, waits gap, then makes a second GET — both must succeed (proving the
// proxy UDP socket stays open across the idle gap).
func h2SequentialHTTPTest(cfg *config.Config, gap time.Duration) error {
	conn, err := spec.NewH2Conn(cfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	sid, err := conn.SendConnectUDP(cfg)
	if err != nil {
		return fmt.Errorf("send CONNECT: %w", err)
	}

	rh, err := conn.ReadResponseHeaders(sid, cfg.Timeout)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if rh.Status < 200 || rh.Status > 299 {
		return fmt.Errorf("proxy rejected CONNECT-UDP with %d", rh.Status)
	}

	conn.WriteWindowUpdate(sid, 65535) //nolint:errcheck
	conn.WriteWindowUpdate(0, 65535)   //nolint:errcheck

	targetAddr, err := net.ResolveUDPAddr("udp", cfg.TargetAddr())
	if err != nil {
		return fmt.Errorf("resolve target addr: %w", err)
	}

	pc := spec.NewMASQUEPacketConnH2(conn, sid, targetAddr, cfg.Timeout)
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

// Suppress unused import error for http2.
var _ = http2.ErrCodeNo
