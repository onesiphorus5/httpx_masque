// Package spec – Capsule Protocol (RFC 9297) encoding/decoding.
//
// Wire format of a Capsule:
//
//	Capsule Type   (QUIC varint)
//	Capsule Length (QUIC varint)
//	Capsule Value  (bytes, length as above)
//
// The DATAGRAM capsule (type 0x00) carries an HTTP Datagram Payload.
// For UDP proxying (RFC 9298 §5) the payload begins with Context ID 0:
//
//	Context ID     (QUIC varint, value 0 for UDP proxying)
//	UDP Payload    (remaining bytes)
package spec

import (
	"bytes"
	"fmt"
	"io"
)

// Well-known capsule type values.
const (
	// CapsuleTypeDatagram is the DATAGRAM capsule type (RFC 9297 §3.5).
	CapsuleTypeDatagram uint64 = 0x00

	// ContextIDUDPProxy is the Context ID used for UDP proxying payloads
	// (RFC 9298 §4 – even IDs are client-allocated; 0 is the first one).
	ContextIDUDPProxy uint64 = 0x00
)

// Capsule holds a decoded capsule.
type Capsule struct {
	Type  uint64
	Value []byte
}

// EncodeCapsule encodes a single capsule into wire format.
func EncodeCapsule(capsuleType uint64, value []byte) []byte {
	var b []byte
	b = AppendVarint(b, capsuleType)
	b = AppendVarint(b, uint64(len(value)))
	b = append(b, value...)
	return b
}

// EncodeDatagramCapsule builds a DATAGRAM capsule (type 0x00) carrying a
// UDP proxying payload with context ID 0.
func EncodeDatagramCapsule(udpPayload []byte) []byte {
	var value []byte
	value = AppendVarint(value, ContextIDUDPProxy)
	value = append(value, udpPayload...)
	return EncodeCapsule(CapsuleTypeDatagram, value)
}

// EncodeDatagramCapsuleWithContextID builds a DATAGRAM capsule with an
// arbitrary context ID – used for negative tests.
func EncodeDatagramCapsuleWithContextID(contextID uint64, payload []byte) []byte {
	var value []byte
	value = AppendVarint(value, contextID)
	value = append(value, payload...)
	return EncodeCapsule(CapsuleTypeDatagram, value)
}

// ReadCapsule reads exactly one capsule from r.
func ReadCapsule(r io.Reader) (*Capsule, error) {
	t, err := ReadVarint(r)
	if err != nil {
		return nil, fmt.Errorf("capsule type: %w", err)
	}
	l, err := ReadVarint(r)
	if err != nil {
		return nil, fmt.Errorf("capsule length: %w", err)
	}
	if l > 1<<20 { // 1 MiB sanity cap
		return nil, fmt.Errorf("capsule length %d too large", l)
	}
	value := make([]byte, l)
	if _, err := io.ReadFull(r, value); err != nil {
		return nil, fmt.Errorf("capsule value: %w", err)
	}
	return &Capsule{Type: t, Value: value}, nil
}

// ReadCapsules reads all capsules from b (a DATA-frame body).
func ReadCapsules(b []byte) ([]*Capsule, error) {
	r := bytes.NewReader(b)
	var caps []*Capsule
	for r.Len() > 0 {
		c, err := ReadCapsule(r)
		if err != nil {
			return caps, err
		}
		caps = append(caps, c)
	}
	return caps, nil
}

// ExtractUDPPayload extracts the UDP payload from the Value field of a
// DATAGRAM capsule by stripping the leading Context ID varint.
// Returns an error if the context ID is not ContextIDUDPProxy.
func ExtractUDPPayload(c *Capsule) ([]byte, error) {
	if c.Type != CapsuleTypeDatagram {
		return nil, fmt.Errorf("capsule type %d is not DATAGRAM (0x00)", c.Type)
	}
	r := bytes.NewReader(c.Value)
	ctxID, err := ReadVarint(r)
	if err != nil {
		return nil, fmt.Errorf("reading context ID: %w", err)
	}
	if ctxID != ContextIDUDPProxy {
		return nil, fmt.Errorf("unexpected context ID %d (want 0)", ctxID)
	}
	payload := make([]byte, r.Len())
	copy(payload, c.Value[VarintLen(ctxID):])
	return payload, nil
}
