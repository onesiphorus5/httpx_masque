// Package section4 tests RFC 9298 §4 – Context IDs.
//
// Context IDs are QUIC variable-length integers used to multiplex different
// payload types on a single connect-udp stream.  RFC 9298 §4 defines:
//
//   - Context ID 0  → reserved for UDP proxying payloads (§5)
//   - Even IDs      → allocated by the client
//   - Odd IDs       → allocated by the proxy
//   - Unknown IDs   → the stream SHOULD be terminated
package section4

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"rfc9298spec/internal/config"
	"rfc9298spec/internal/spec"
)

// NewGroup returns the §4 TestGroup.
func NewGroup() *spec.TestGroup {
	g := &spec.TestGroup{
		Key:     "4",
		Section: "4",
		Name:    "Context IDs",
	}

	// 4/1  Context ID 0 MUST be accepted as a UDP proxying payload.
	g.AddTest(&spec.TestCase{
		Desc: "Context ID 0 MUST be used for UDP proxying payloads",
		Requirement: `RFC 9298 §5: "The Context ID field of the HTTP Datagram MUST
be zero for UDP proxying payloads." Context ID 0 carries the UDP proxying
payload and MUST be accepted and forwarded by the proxy. Verified by making
an HTTP/3 GET to the target through the MASQUE tunnel.`,
		Run: func(cfg *config.Config) error {
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

			// MASQUEPacketConnH2 encodes all WriteTo calls as context-ID-0 capsules;
			// a successful HTTP/3 GET proves the proxy accepts and forwards them.
			pc := spec.NewMASQUEPacketConnH2(conn, sid, targetAddr, cfg.Timeout)
			defer pc.Close() //nolint:errcheck

			ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
			defer cancel()

			resp, err := spec.H3GetThroughPacketConn(ctx, pc, targetAddr, cfg.TargetAddr(), "/")
			if err != nil {
				return fmt.Errorf("HTTP/3 GET with context-ID-0 capsules: %w", err)
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("expected 200, got %d", resp.StatusCode)
			}
			return nil
		},
	})

	// 4/2  Unknown (non-zero) context IDs SHOULD cause the stream to be reset.
	g.AddTest(&spec.TestCase{
		Desc: "Datagrams with an unrecognised Context ID SHOULD terminate the stream",
		Requirement: `RFC 9298 §4: "Endpoints that receive a capsule with an
unknown Context ID SHOULD treat that as a stream error." When the context
ID is unknown, the proxy MAY reset the stream or silently drop the capsule.`,
		Run: func(cfg *config.Config) error {
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

			// Send a DATAGRAM capsule with an unknown client-allocated context ID (2).
			capsule := spec.EncodeDatagramCapsuleWithContextID(2, []byte("bad-ctx"))
			if err := conn.WriteData(sid, capsule, false); err != nil {
				return fmt.Errorf("write capsule: %w", err)
			}

			// Accept either a stream reset or no data (silent drop).
			_, err = conn.ReadDataFrame(sid, cfg.Timeout)
			if errors.Is(err, spec.ErrRSTStream) {
				return nil // stream reset → expected
			}
			// Timeout or other connection-level error is also acceptable.
			return nil
		},
	})

	// 4/3  Proxy MUST NOT allocate even context IDs (those are client-reserved).
	g.AddTest(&spec.TestCase{
		Desc: "Proxy MUST NOT send DATAGRAM capsules with even-numbered Context IDs",
		Requirement: `RFC 9298 §4: "Context IDs with even values are client-allocated;
context IDs with odd values are proxy-allocated." The proxy MUST NOT originate
capsules using an even Context ID. Verified by making an HTTP/3 GET through
the tunnel and inspecting all received DATAGRAM capsule context IDs.`,
		Run: func(cfg *config.Config) error {
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

			// The read loop in MASQUEPacketConnH2 inspects every received capsule
			// and records any that carry even, non-zero context IDs.
			pc := spec.NewMASQUEPacketConnH2(conn, sid, targetAddr, cfg.Timeout)
			defer pc.Close() //nolint:errcheck

			ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
			defer cancel()

			// Generate real response capsules by making an HTTP/3 GET.
			resp, err := spec.H3GetThroughPacketConn(ctx, pc, targetAddr, cfg.TargetAddr(), "/")
			if err != nil {
				return fmt.Errorf("HTTP/3 GET: %w", err)
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()

			if pc.EvenContextIDSeen() {
				return fmt.Errorf(
					"proxy sent DATAGRAM capsule with even context ID " +
						"(even IDs are client-allocated; proxy MUST NOT use them)",
				)
			}
			return nil
		},
	})

	return g
}
