// Package spec – variable-length integer encoding as defined by RFC 9000 §16.
// Used for encoding capsule types/lengths (RFC 9297) and context IDs (RFC 9298).
package spec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ErrVarintOverflow is returned when a varint exceeds 62 usable bits.
var ErrVarintOverflow = errors.New("varint overflow")

// AppendVarint appends the QUIC variable-length encoding of v to b.
func AppendVarint(b []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(b, byte(v))
	case v <= 16383:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v <= 1073741823:
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], uint32(v)|0x80000000)
		return append(b, buf[:]...)
	default:
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], v|0xC000000000000000)
		return append(b, buf[:]...)
	}
}

// ReadVarint reads one QUIC variable-length integer from r.
func ReadVarint(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	prefix := first[0] >> 6
	length := 1 << prefix // 1, 2, 4, or 8 bytes total

	buf := make([]byte, length)
	buf[0] = first[0] & 0x3f
	if length > 1 {
		if _, err := io.ReadFull(r, buf[1:]); err != nil {
			return 0, err
		}
	}

	switch length {
	case 1:
		return uint64(buf[0]), nil
	case 2:
		return uint64(binary.BigEndian.Uint16(buf)), nil
	case 4:
		return uint64(binary.BigEndian.Uint32(buf)), nil
	case 8:
		return binary.BigEndian.Uint64(buf), nil
	}
	return 0, fmt.Errorf("impossible varint length %d", length)
}

// VarintLen returns the encoded byte length of v.
func VarintLen(v uint64) int {
	switch {
	case v <= 63:
		return 1
	case v <= 16383:
		return 2
	case v <= 1073741823:
		return 4
	default:
		return 8
	}
}
