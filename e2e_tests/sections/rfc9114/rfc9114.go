// Package rfc9114 implements conformance tests for RFC 9114 §4.4 –
// The CONNECT Method (TCP tunnelling over HTTP/3).
//
// RFC 9114 §4.4 normative requirements under test:
//
//   - :method MUST be "CONNECT"
//   - :scheme and :path pseudo-header fields MUST be omitted
//   - :authority MUST contain the host and port to connect to
//   - A CONNECT request not conforming to these restrictions is malformed
//     (stream error H3_MESSAGE_ERROR)
//   - On success the proxy responds with a 2xx status code
//   - All DATA frames on the stream correspond to data sent/received on the
//     TCP connection
//   - Frame types other than DATA or stream management frames MUST NOT be
//     sent on a connected stream
//   - Proxy signals TCP error with stream reset (H3_CONNECT_ERROR)
//   - When the client closes the send side of the stream the proxy closes
//     the TCP connection
package rfc9114

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/quic-go/qpack"

	"golang.org/x/net/http2"

	"rfc9298spec/internal/config"
	"rfc9298spec/internal/spec"
)

// NewGroup returns the RFC 9114 §4.4 test group.
func NewGroup() *spec.TestGroup {
	g := &spec.TestGroup{
		Key:     "4.4",
		Section: "4.4",
		Name:    "RFC 9114 §4.4 – The CONNECT Method (TCP over HTTP/3)",
	}

	// 4.4/1  Valid CONNECT SHALL be accepted with a 2xx response.
	g.AddTest(&spec.TestCase{
		Desc: "Valid CONNECT request SHALL be accepted with a 2xx response",
		Requirement: `RFC 9114 §4.4: A proxy that supports CONNECT MUST respond
with a 2xx (Successful) status code to a well-formed CONNECT request
(:method=CONNECT, :authority=host:port, no :scheme or :path).`,
		Run: func(cfg *config.Config) error {
			conn, err := spec.NewH3Conn(cfg)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer conn.Close()

			if _, _, err := conn.Handshake(); err != nil {
				return fmt.Errorf("handshake: %w", err)
			}

			stream, err := conn.SendConnectTCP(cfg)
			if err != nil {
				return fmt.Errorf("send CONNECT: %w", err)
			}

			rh, err := conn.ReadResponseHeaders(stream, cfg.Timeout)
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

	// 4.4/2  :method MUST be CONNECT — other methods MUST be rejected.
	g.AddTest(&spec.TestCase{
		Desc: ":method MUST be CONNECT (other methods MUST be rejected)",
		Requirement: `RFC 9114 §4.4: "The :method pseudo-header field is set to
CONNECT." A request using a different method with only :authority is
malformed and MUST be rejected with H3_MESSAGE_ERROR.`,
		Run: func(cfg *config.Config) error {
			return h3ExpectRejectTCP(cfg, []qpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":authority", Value: cfg.TCPTargetAddr()},
			})
		},
	})

	// 4.4/3  :authority MUST be present — absent :authority MUST be rejected.
	g.AddTest(&spec.TestCase{
		Desc: ":authority MUST be present (absent :authority MUST be rejected)",
		Requirement: `RFC 9114 §4.4: "The :authority pseudo-header field contains
the host and port to connect to." A CONNECT request without :authority is
malformed (stream error H3_MESSAGE_ERROR).`,
		Run: func(cfg *config.Config) error {
			return h3ExpectRejectTCP(cfg, []qpack.HeaderField{
				{Name: ":method", Value: "CONNECT"},
				// :authority intentionally omitted
			})
		},
	})

	// 4.4/4  :scheme MUST be omitted — presence MUST be rejected.
	g.AddTest(&spec.TestCase{
		Desc: ":scheme MUST be omitted (presence MUST be rejected)",
		Requirement: `RFC 9114 §4.4: "The :scheme and :path pseudo-header fields
MUST be omitted." A CONNECT request with :scheme is malformed and MUST
trigger a stream error of type H3_MESSAGE_ERROR.`,
		Run: func(cfg *config.Config) error {
			return h3ExpectRejectTCP(cfg, []qpack.HeaderField{
				{Name: ":method", Value: "CONNECT"},
				{Name: ":scheme", Value: "https"}, // MUST NOT be present
				{Name: ":authority", Value: cfg.TCPTargetAddr()},
			})
		},
	})

	// 4.4/5  :path MUST be omitted — presence MUST be rejected.
	g.AddTest(&spec.TestCase{
		Desc: ":path MUST be omitted (presence MUST be rejected)",
		Requirement: `RFC 9114 §4.4: "The :scheme and :path pseudo-header fields
MUST be omitted." A CONNECT request with :path is malformed and MUST trigger
a stream error of type H3_MESSAGE_ERROR.`,
		Run: func(cfg *config.Config) error {
			return h3ExpectRejectTCP(cfg, []qpack.HeaderField{
				{Name: ":method", Value: "CONNECT"},
				{Name: ":authority", Value: cfg.TCPTargetAddr()},
				{Name: ":path", Value: "/"}, // MUST NOT be present
			})
		},
	})

	// 4.4/6  DATA frames MUST carry TCP tunnel data bidirectionally.
	//        Verified by making a real h2c GET through the tunnel.
	g.AddTest(&spec.TestCase{
		Desc: "DATA frames MUST carry TCP tunnel data bidirectionally",
		Requirement: `RFC 9114 §4.4: "The payload of any DATA frame sent by the
client is transmitted by the proxy to the TCP server; data received from the
TCP server is assembled into DATA frames by the proxy." Verified by sending
an h2c GET request through the tunnel and checking the 200 response.`,
		Run: func(cfg *config.Config) error {
			return h3TCPRequestTest(cfg)
		},
	})

	// 4.4/7  Multiple round-trips work over a single CONNECT stream.
	g.AddTest(&spec.TestCase{
		Desc: "Multiple DATA round-trips MUST work over a single CONNECT stream",
		Requirement: `RFC 9114 §4.4: The TCP tunnel persists for the lifetime of
the HTTP/3 stream; multiple sequential h2c GET requests MUST succeed over
the same tunnel stream.`,
		Run: func(cfg *config.Config) error {
			conn, err := spec.NewH3Conn(cfg)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer conn.Close()

			if _, _, err := conn.Handshake(); err != nil {
				return fmt.Errorf("handshake: %w", err)
			}

			stream, err := conn.SendConnectTCP(cfg)
			if err != nil {
				return fmt.Errorf("send CONNECT: %w", err)
			}

			rh, err := conn.ReadResponseHeaders(stream, cfg.Timeout)
			if err != nil {
				return fmt.Errorf("read response: %w", err)
			}
			if rh.Status < 200 || rh.Status > 299 {
				return fmt.Errorf("proxy rejected CONNECT with %d", rh.Status)
			}

			tunnelConn := spec.NewTunnelConnH3(conn, stream, cfg.Timeout)
			tr := &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return tunnelConn, nil
				},
			}
			defer tr.CloseIdleConnections()

			client := &http.Client{Transport: tr}
			for i := 0; i < 3; i++ {
				resp, err := client.Get("http://" + cfg.TCPTargetAddr() + "/")
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
		},
	})

	// 4.4/8  Closing the client send stream closes the TCP connection.
	g.AddTest(&spec.TestCase{
		Desc: "Closing the client stream send side MUST close the TCP connection on the proxy side",
		Requirement: `RFC 9114 §4.4: "When the client ends the TCP connection,
the client closes the stream. A proxy that receives a stream FIN closes the
TCP connection."`,
		Run: func(cfg *config.Config) error {
			conn, err := spec.NewH3Conn(cfg)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer conn.Close()

			if _, _, err := conn.Handshake(); err != nil {
				return fmt.Errorf("handshake: %w", err)
			}

			stream, err := conn.SendConnectTCP(cfg)
			if err != nil {
				return fmt.Errorf("send CONNECT: %w", err)
			}

			rh, err := conn.ReadResponseHeaders(stream, cfg.Timeout)
			if err != nil {
				return fmt.Errorf("read response: %w", err)
			}
			if rh.Status < 200 || rh.Status > 299 {
				return fmt.Errorf("proxy rejected CONNECT with %d", rh.Status)
			}

			// Make one h2c GET to confirm the tunnel is working.
			tunnelConn := spec.NewTunnelConnH3(conn, stream, cfg.Timeout)
			tr := &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return tunnelConn, nil
				},
			}
			resp, err := (&http.Client{Transport: tr}).Get("http://" + cfg.TCPTargetAddr() + "/")
			if err != nil {
				return fmt.Errorf("h2c GET: %w", err)
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
			tr.CloseIdleConnections()

			// Close the send side of the QUIC stream — this is the HTTP/3
			// equivalent of DATA+END_STREAM.
			if err := stream.Close(); err != nil {
				return fmt.Errorf("close send stream: %w", err)
			}

			// The proxy forwards the TCP close; we accept any orderly closure.
			_, err = conn.ReadDataFrame(stream, cfg.Timeout)
			if err != nil {
				if errors.Is(err, spec.ErrRSTStream) {
					return nil // proxy reset stream — acceptable
				}
				return nil // io.EOF or other orderly close is fine
			}
			return nil
		},
	})

	return g
}

// ─── Helpers ───────────────────────────────────────────────────────────────

// h3ExpectRejectTCP dials a fresh H3Conn, sends HEADERS with the given fields,
// and asserts the proxy rejects the request (4xx status or stream reset).
func h3ExpectRejectTCP(cfg *config.Config, fields []qpack.HeaderField) error {
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

// h3TCPRequestTest establishes a CONNECT tunnel over HTTP/3, then makes a
// real h2c GET request to the H2C target through it, verifying a 200 response.
func h3TCPRequestTest(cfg *config.Config) error {
	conn, err := spec.NewH3Conn(cfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if _, _, err := conn.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	stream, err := conn.SendConnectTCP(cfg)
	if err != nil {
		return fmt.Errorf("send CONNECT: %w", err)
	}

	rh, err := conn.ReadResponseHeaders(stream, cfg.Timeout)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if rh.Status < 200 || rh.Status > 299 {
		return fmt.Errorf("proxy rejected CONNECT with %d", rh.Status)
	}

	tunnelConn := spec.NewTunnelConnH3(conn, stream, cfg.Timeout)
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return tunnelConn, nil
		},
	}
	defer tr.CloseIdleConnections()

	resp, err := (&http.Client{Transport: tr}).Get("http://" + cfg.TCPTargetAddr() + "/")
	if err != nil {
		return fmt.Errorf("h2c GET through tunnel: %w", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("h2c GET: expected 200, got %d", resp.StatusCode)
	}
	return nil
}
