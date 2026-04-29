package domain

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

var (
	ErrEmptyCanonicalPayload   = errors.New("empty canonical payload")
	ErrInvalidCanonicalPayload = errors.New("invalid canonical payload protobuf wire")
)

// CanonicalObjectBytes encodes the ObjectEnvelope protobuf fields that participate in object_id.
// ObjectID, Pow, source peer, and local metadata are intentionally excluded.
func CanonicalObjectBytes(envelope ObjectEnvelope) ([]byte, error) {
	if len(envelope.Payload) == 0 {
		return nil, ErrEmptyCanonicalPayload
	}

	var buf bytes.Buffer
	writeProtoString(&buf, 2, string(envelope.ObjectType))
	writeProtoString(&buf, 3, envelope.ProtocolVersion)
	writeProtoString(&buf, 4, envelope.NetworkID)
	writeProtoString(&buf, 5, string(envelope.Scope))
	writeProtoString(&buf, 6, envelope.ScopeID)
	writeProtoBytes(&buf, 7, envelope.Payload)
	writeProtoInt64(&buf, 9, envelope.CreatedAt)
	return buf.Bytes(), nil
}

// ValidateCanonicalPayloadWire checks the envelope-level protobuf wire constraints available before payload schemas exist.
func ValidateCanonicalPayloadWire(payload []byte) error {
	if len(payload) == 0 {
		return ErrEmptyCanonicalPayload
	}
	var lastFieldNumber uint64
	for len(payload) > 0 {
		key, n, err := consumeProtoVarint(payload)
		if err != nil {
			return fmt.Errorf("field key: %w", err)
		}
		if key == 0 {
			return fmt.Errorf("field key: %w", ErrInvalidCanonicalPayload)
		}
		payload = payload[n:]

		fieldNumber := key >> 3
		wireType := key & 0x7
		if fieldNumber == 0 {
			return fmt.Errorf("field number: %w", ErrInvalidCanonicalPayload)
		}
		if fieldNumber < lastFieldNumber {
			return fmt.Errorf("field order: %w", ErrInvalidCanonicalPayload)
		}
		lastFieldNumber = fieldNumber

		switch wireType {
		case 0:
			value, n, err := consumeProtoVarint(payload)
			if err != nil {
				return fmt.Errorf("varint value: %w", err)
			}
			if value == 0 {
				return fmt.Errorf("varint default value: %w", ErrInvalidCanonicalPayload)
			}
			payload = payload[n:]
		case 1:
			if len(payload) < 8 {
				return io.ErrUnexpectedEOF
			}
			payload = payload[8:]
		case 2:
			length, n, err := consumeProtoVarint(payload)
			if err != nil {
				return fmt.Errorf("length-delimited size: %w", err)
			}
			payload = payload[n:]
			if length > uint64(len(payload)) {
				return io.ErrUnexpectedEOF
			}
			if length == 0 {
				return fmt.Errorf("length-delimited default value: %w", ErrInvalidCanonicalPayload)
			}
			payload = payload[int(length):]
		case 5:
			if len(payload) < 4 {
				return io.ErrUnexpectedEOF
			}
			payload = payload[4:]
		default:
			return fmt.Errorf("wire type %d: %w", wireType, ErrInvalidCanonicalPayload)
		}
	}
	return nil
}

func writeProtoString(buf *bytes.Buffer, fieldNumber uint64, value string) {
	if value == "" {
		return
	}
	writeProtoBytes(buf, fieldNumber, []byte(value))
}

func writeProtoBytes(buf *bytes.Buffer, fieldNumber uint64, value []byte) {
	if len(value) == 0 {
		return
	}
	writeProtoVarint(buf, fieldNumber<<3|2)
	writeProtoVarint(buf, uint64(len(value)))
	buf.Write(value)
}

func writeProtoInt64(buf *bytes.Buffer, fieldNumber uint64, value int64) {
	if value == 0 {
		return
	}
	writeProtoVarint(buf, fieldNumber<<3)
	writeProtoVarint(buf, uint64(value))
}

func writeProtoVarint(buf *bytes.Buffer, value uint64) {
	for value >= 0x80 {
		buf.WriteByte(byte(value) | 0x80)
		value >>= 7
	}
	buf.WriteByte(byte(value))
}

func consumeProtoVarint(b []byte) (uint64, int, error) {
	var value uint64
	for i, c := range b {
		if i == 10 {
			return 0, 0, ErrInvalidCanonicalPayload
		}
		if i == 9 && c > 1 {
			return 0, 0, ErrInvalidCanonicalPayload
		}
		value |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			if i > 0 && c == 0 {
				return 0, 0, ErrInvalidCanonicalPayload
			}
			return value, i + 1, nil
		}
	}
	return 0, 0, io.ErrUnexpectedEOF
}
