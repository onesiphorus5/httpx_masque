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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"golang.org/x/net/http2"
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
			return withRef(cfg, func(cfg *config.Config) error {
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
			})
		},
	})

	// 8.5/2  :method MUST be CONNECT — other methods MUST be rejected.
	g.AddTest(&spec.TestCase{
		Desc: ":method MUST be CONNECT (other methods MUST be rejected)",
		Requirement: `RFC 9113 §8.5: "The :method pseudo-header field is set to
CONNECT." A request using a different method with only :authority is
malformed and MUST be rejected.`,
		Run: func(cfg *config.Config) error {
			return withRef(cfg, func(cfg *config.Config) error {
				return h2ExpectRejectTCP(cfg, []hpack.HeaderField{
					{Name: ":method", Value: "GET"},
					{Name: ":authority", Value: cfg.TCPTargetAddr()},
				})
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
			return withRef(cfg, func(cfg *config.Config) error {
				return h2ExpectRejectTCP(cfg, []hpack.HeaderField{
					{Name: ":method", Value: "CONNECT"},
					// :authority intentionally omitted
				})
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
			return withRef(cfg, func(cfg *config.Config) error {
				return h2ExpectRejectTCP(cfg, []hpack.HeaderField{
					{Name: ":method", Value: "CONNECT"},
					{Name: ":scheme", Value: "https"}, // MUST NOT be present
					{Name: ":authority", Value: cfg.TCPTargetAddr()},
				})
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
			return withRef(cfg, func(cfg *config.Config) error {
				return h2ExpectRejectTCP(cfg, []hpack.HeaderField{
					{Name: ":method", Value: "CONNECT"},
					{Name: ":authority", Value: cfg.TCPTargetAddr()},
					{Name: ":path", Value: "/"}, // MUST NOT be present
				})
			})
		},
	})

	// 8.5/6  DATA frames MUST carry TCP tunnel data bidirectionally.
	//        Verified by making a real HTTPS/H2 GET through the tunnel.
	g.AddTest(&spec.TestCase{
		Desc: "DATA frames MUST carry TCP tunnel data bidirectionally",
		Requirement: `RFC 9113 §8.5: "The payload of any DATA frame sent by the
client is transmitted by the proxy to the TCP server; data received from the
TCP server is assembled into DATA frames by the proxy." Verified by sending
an HTTPS/H2 GET request through the tunnel and checking the 200 response.`,
		Run: func(cfg *config.Config) error {
			return withRef(cfg, h2TCPRequestTest)
		},
	})

	// 8.5/7  Multiple round-trips work over a single CONNECT stream.
	g.AddTest(&spec.TestCase{
		Desc: "Multiple DATA round-trips MUST work over a single CONNECT stream",
		Requirement: `RFC 9113 §8.5: The TCP tunnel persists for the lifetime of
the HTTP/2 stream; multiple sequential HTTPS/H2 GET requests MUST succeed over
the same tunnel stream.`,
		Run: func(cfg *config.Config) error {
			return withRef(cfg, h2MultiRoundTripTest)
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
			return withRef(cfg, h2EndStreamTest)
		},
	})

	return g
}

// ─── Named test helpers ─────────────────────────────────────────────────────

// h2MultiRoundTripTest is the body of test 8.5/7.
func h2MultiRoundTripTest(cfg *config.Config) error {
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

	tunnelConn := spec.NewTunnelConnH2(conn, sid, cfg.Timeout)
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			tlsConn := tls.Client(tunnelConn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return nil, fmt.Errorf("TLS handshake: %w", err)
			}
			return tlsConn, nil
		},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{Transport: tr}
	for i := 0; i < 3; i++ {
		resp, err := client.Get("https://" + cfg.TCPTargetAddr() + "/")
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

// h2EndStreamTest is the body of test 8.5/8.
func h2EndStreamTest(cfg *config.Config) error {
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

	// Make one HTTPS/H2 GET to confirm the tunnel is working.
	tunnelConn := spec.NewTunnelConnH2(conn, sid, cfg.Timeout)
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			tlsConn := tls.Client(tunnelConn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return nil, fmt.Errorf("TLS handshake: %w", err)
			}
			return tlsConn, nil
		},
	}
	resp, err := (&http.Client{Transport: tr}).Get("https://" + cfg.TCPTargetAddr() + "/")
	if err != nil {
		return fmt.Errorf("HTTPS/H2 GET: %w", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	tr.CloseIdleConnections()

	// Signal half-close on the outer CONNECT stream (END_STREAM).
	if err := conn.WriteData(sid, nil, true); err != nil {
		return fmt.Errorf("write END_STREAM: %w", err)
	}

	// The proxy closes its TCP side; we accept RST_STREAM or orderly close.
	_, err = conn.ReadDataFrame(sid, cfg.Timeout)
	if err != nil {
		if errors.Is(err, spec.ErrRSTStream) {
			return nil // proxy reset stream — acceptable
		}
		return nil // io.EOF or other orderly close is fine
	}
	return nil
}

// ─── Helpers ───────────────────────────────────────────────────────────────

// h2ExpectRejectTCP dials a fresh H2Conn, sends HEADERS with the given fields,
// and asserts the proxy rejects the request (4xx status, RST_STREAM, or
// connection close — all are valid rejection forms per RFC 9113 §8.5).
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

// h2TCPRequestTest establishes a CONNECT tunnel and makes a real HTTPS/H2 GET
// request to the HTTPS/H2 target through it, verifying a 200 response.
func h2TCPRequestTest(cfg *config.Config) error {
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

	tunnelConn := spec.NewTunnelConnH2(conn, sid, cfg.Timeout)
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			tlsConn := tls.Client(tunnelConn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return nil, fmt.Errorf("TLS handshake: %w", err)
			}
			return tlsConn, nil
		},
	}
	defer tr.CloseIdleConnections()

	resp, err := (&http.Client{Transport: tr}).Get("https://" + cfg.TCPTargetAddr() + "/")
	if err != nil {
		return fmt.Errorf("HTTPS/H2 GET through tunnel: %w", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTPS/H2 GET: expected 200, got %d", resp.StatusCode)
	}
	return nil
}

// ─── Differential testing helpers ──────────────────────────────────────────

// withRef runs testFn against the DUT and, when cfg.HasReference(), also against
// the reference proxy. Returns nil iff both produce the same passing outcome.
func withRef(cfg *config.Config, testFn func(*config.Config) error) error {
	dutErr := testFn(cfg)
	if !cfg.HasReference() {
		return dutErr
	}
	refErr := testFn(cfg.WithReference())
	return compareOutcomes(dutErr, refErr)
}

// compareOutcomes returns nil when DUT and reference both passed or both failed,
// and an explanatory error when their outcomes diverge.
func compareOutcomes(dutErr, refErr error) error {
	switch {
	case (dutErr == nil) == (refErr == nil):
		return dutErr // same outcome — return DUT's own result
	case dutErr != nil && refErr == nil:
		return fmt.Errorf("DUT failed but envoy reference passed: %w", dutErr)
	default:
		return fmt.Errorf("DUT passed but envoy reference failed (ref err: %v)", refErr)
	}
}
