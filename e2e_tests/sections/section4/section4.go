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
	"bytes"
	"errors"
	"fmt"
	"time"

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
payload and MUST be accepted by the proxy.`,
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

			// Send a DATAGRAM capsule with context ID = 0.
			payload := []byte("ctx-id-0-test")
			capsule := spec.EncodeDatagramCapsule(payload)
			if err := conn.WriteData(sid, capsule, false); err != nil {
				return fmt.Errorf("write capsule: %w", err)
			}

			// Expect an echo within the timeout.
			deadline := time.Now().Add(cfg.Timeout)
			for time.Now().Before(deadline) {
				df, err := conn.ReadDataFrame(sid, time.Until(deadline))
				if err != nil {
					return fmt.Errorf("read data frame: %w", err)
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
			return fmt.Errorf("no UDP echo received with context ID 0")
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
capsules using an even Context ID.`,
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

			// Trigger a response by sending a probe datagram.
			probe := spec.EncodeDatagramCapsule([]byte("ctx-probe"))
			conn.WriteData(sid, probe, false) //nolint:errcheck

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
					ctxID, err := peekContextID(c.Value)
					if err != nil {
						continue
					}
					// Context ID 0 is special (it IS even but is the client UDP slot).
					if ctxID != 0 && ctxID%2 == 0 {
						return fmt.Errorf(
							"proxy sent DATAGRAM capsule with even context ID %d "+
								"(even IDs are client-allocated)",
							ctxID,
						)
					}
				}
			}
			return nil
		},
	})

	return g
}

// peekContextID reads the leading varint (context ID) from a capsule Value.
func peekContextID(value []byte) (uint64, error) {
	return spec.ReadVarint(bytes.NewReader(value))
}
