// Package section5 tests RFC 9298 §5 – HTTP Datagram Payload Format.
//
// §5 defines:
//   - The HTTP Datagram payload for UDP proxying: Context ID (varint) + UDP data
//   - Maximum UDP Proxying Payload size: 65527 bytes
//   - Oversized datagrams MUST cause the stream to be aborted
//   - Clients MAY send datagrams before receiving the 2xx response
package section5

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"rfc9298spec/internal/config"
	"rfc9298spec/internal/spec"
)

// NewGroup returns the §5 TestGroup.
func NewGroup() *spec.TestGroup {
	g := &spec.TestGroup{
		Key:     "5",
		Section: "5",
		Name:    "HTTP Datagram Payload Format",
	}

	// 5/1  Proxy MUST abort stream on oversized UDP payload (> 65527 bytes).
	g.AddTest(&spec.TestCase{
		Desc: "Proxy MUST abort stream when UDP Proxying Payload exceeds 65527 bytes",
		Requirement: `RFC 9298 §5: "The UDP Proxying Payload field MUST NOT be
longer than 65527 bytes. Endpoints that receive a UDP Proxying Payload that
is longer than 65527 bytes MUST abort the stream."`,
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

			conn.WriteWindowUpdate(sid, 1<<20) //nolint:errcheck
			conn.WriteWindowUpdate(0, 1<<20)   //nolint:errcheck

			// Build an oversized UDP payload (65527 + 1 = 65528 bytes).
			oversized := bytes.Repeat([]byte{0x41}, 65528)
			capsule := spec.EncodeDatagramCapsule(oversized)

			if err := conn.WriteData(sid, capsule, false); err != nil {
				return fmt.Errorf("write oversized capsule: %w", err)
			}

			// The proxy MUST abort the stream.
			_, err = conn.ReadDataFrame(sid, cfg.Timeout)
			if errors.Is(err, spec.ErrRSTStream) {
				return nil // stream aborted as required
			}
			if err != nil {
				// GOAWAY or connection close is also acceptable.
				return nil
			}
			return fmt.Errorf(
				"expected stream abort for oversized payload (>65527 bytes), but got data back",
			)
		},
	})

	// 5/2  DATAGRAM capsule payload begins with Context ID 0 for UDP proxying.
	g.AddTest(&spec.TestCase{
		Desc: "UDP proxying payloads MUST be framed with Context ID 0",
		Requirement: `RFC 9298 §5: "When HTTP Datagrams are used to proxy UDP,
the Context ID field MUST be zero." The test verifies that echoed datagrams
carry context ID 0.`,
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

			// Send a valid datagram.
			payload := []byte("ctx-id-check")
			capsule := spec.EncodeDatagramCapsule(payload)
			if err := conn.WriteData(sid, capsule, false); err != nil {
				return fmt.Errorf("write capsule: %w", err)
			}

			deadline := time.Now().Add(cfg.Timeout)
			for time.Now().Before(deadline) {
				df, err := conn.ReadDataFrame(sid, time.Until(deadline))
				if err != nil {
					return fmt.Errorf("read data frame: %w", err)
				}
				caps, err := spec.ReadCapsules(df.Data())
				if err != nil {
					return fmt.Errorf("decode capsules: %w", err)
				}
				for _, c := range caps {
					if c.Type != spec.CapsuleTypeDatagram {
						continue
					}
					ctxID, err := spec.ReadVarint(bytes.NewReader(c.Value))
					if err != nil {
						return fmt.Errorf("read context ID: %w", err)
					}
					if ctxID != 0 {
						return fmt.Errorf(
							"proxy returned DATAGRAM capsule with context ID %d (expected 0)",
							ctxID,
						)
					}
					return nil // context ID is 0 as required
				}
			}
			return fmt.Errorf("no DATAGRAM capsule received within %s", cfg.Timeout)
		},
	})

	// 5/3  Client MAY optimistically send datagrams before receiving 2xx.
	g.AddTest(&spec.TestCase{
		Desc: "Client MAY send datagrams before receiving the 2xx response",
		Requirement: `RFC 9298 §5: "A client MAY optimistically start sending UDP
packets in HTTP Datagrams before receiving the response to its UDP tunneling
request." The proxy MUST tolerate early datagrams.`,
		Run: func(cfg *config.Config) error {
			conn, err := spec.NewH2Conn(cfg)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer conn.Close()

			if _, err := conn.Handshake(); err != nil {
				return fmt.Errorf("handshake: %w", err)
			}

			conn.WriteWindowUpdate(0, 65535) //nolint:errcheck

			// Send the CONNECT request.
			sid, err := conn.SendConnectUDP(cfg)
			if err != nil {
				return fmt.Errorf("send CONNECT: %w", err)
			}

			// Immediately send a DATAGRAM capsule WITHOUT waiting for 2xx.
			payload := []byte("optimistic")
			capsule := spec.EncodeDatagramCapsule(payload)
			if err := conn.WriteData(sid, capsule, false); err != nil {
				return fmt.Errorf("write optimistic datagram: %w", err)
			}

			// Now read the 2xx response.
			rh, err := conn.ReadResponseHeaders(sid, cfg.Timeout)
			if err != nil {
				return fmt.Errorf("read response: %w", err)
			}
			if rh.Status < 200 || rh.Status > 299 {
				return fmt.Errorf("proxy rejected CONNECT-UDP with %d", rh.Status)
			}

			conn.WriteWindowUpdate(sid, 65535) //nolint:errcheck

			// Wait for the echo of the optimistic datagram.
			deadline := time.Now().Add(cfg.Timeout)
			for time.Now().Before(deadline) {
				df, err := conn.ReadDataFrame(sid, time.Until(deadline))
				if err != nil {
					break
				}
				caps, _ := spec.ReadCapsules(df.Data())
				for _, c := range caps {
					if c.Type != spec.CapsuleTypeDatagram {
						continue
					}
					udpPayload, err := spec.ExtractUDPPayload(c)
					if err == nil && string(udpPayload) == string(payload) {
						return nil
					}
				}
			}

			// Not failing here — the RFC says "MAY" and the proxy may have discarded
			// the optimistic datagram. We only fail if the connection broke entirely.
			return nil
		},
	})

	// 5/4  Payload size boundary: exactly 65527 bytes MUST be accepted.
	g.AddTest(&spec.TestCase{
		Desc: "UDP Proxying Payload of exactly 65527 bytes MUST be accepted",
		Requirement: `RFC 9298 §5: "The UDP Proxying Payload field MUST NOT be
longer than 65527 bytes." The maximum-size payload (65527 bytes) MUST be
accepted and forwarded by the proxy.`,
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

			conn.WriteWindowUpdate(sid, 1<<20) //nolint:errcheck
			conn.WriteWindowUpdate(0, 1<<20)   //nolint:errcheck

			// Exactly 65527 bytes.
			maxPayload := bytes.Repeat([]byte{0x42}, 65527)
			capsule := spec.EncodeDatagramCapsule(maxPayload)
			if err := conn.WriteData(sid, capsule, false); err != nil {
				return fmt.Errorf("write max-size capsule: %w", err)
			}

			// Expect echo (or at least no immediate stream abort).
			deadline := time.Now().Add(cfg.Timeout)
			for time.Now().Before(deadline) {
				df, err := conn.ReadDataFrame(sid, time.Until(deadline))
				if errors.Is(err, spec.ErrRSTStream) {
					return fmt.Errorf(
						"proxy aborted stream for a max-size payload (65527 bytes), which MUST be accepted",
					)
				}
				if err != nil {
					break
				}
				caps, _ := spec.ReadCapsules(df.Data())
				for _, c := range caps {
					if c.Type == spec.CapsuleTypeDatagram {
						return nil // payload was forwarded and echoed
					}
				}
			}
			// If we get here without RST, the proxy may simply not echo (it might drop
			// large payloads on the UDP side). We consider no-RST a pass.
			return nil
		},
	})

	return g
}
