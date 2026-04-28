package domain

import (
	"encoding/hex"
	"errors"
	"testing"
)

func TestCanonicalObjectBytesUsesDocumentedEnvelopeFields(t *testing.T) {
	envelope := canonicalTestEnvelope()
	envelope.ObjectID = "ignored-object-id"
	envelope.Pow = []byte("ignored-pow")

	got, err := CanonicalObjectBytes(envelope)
	if err != nil {
		t.Fatalf("CanonicalObjectBytes() error = %v", err)
	}

	wantHex := "1211416e6f6e796d6f7573456c656374696f6e1a0276312207746573746e65742a076e6574776f726b3a0a0a08656c656374696f6e4880d095ffbc31"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("CanonicalObjectBytes() = %x; want %x", got, want)
	}
}

func TestCanonicalObjectBytesExcludesObjectIDAndPoW(t *testing.T) {
	envelope := canonicalTestEnvelope()
	base, err := CanonicalObjectBytes(envelope)
	if err != nil {
		t.Fatalf("CanonicalObjectBytes() error = %v", err)
	}

	envelope.ObjectID = "other-object-id"
	envelope.Pow = []byte("other-pow")
	got, err := CanonicalObjectBytes(envelope)
	if err != nil {
		t.Fatalf("CanonicalObjectBytes() error = %v", err)
	}
	if string(got) != string(base) {
		t.Fatalf("CanonicalObjectBytes() changed after object_id/pow change: %x != %x", got, base)
	}
}

func TestCanonicalObjectBytesIncludesEnvelopeFields(t *testing.T) {
	envelope := canonicalTestEnvelope()
	base, err := CanonicalObjectBytes(envelope)
	if err != nil {
		t.Fatalf("CanonicalObjectBytes() error = %v", err)
	}

	envelope.NetworkID = "othernet"
	got, err := CanonicalObjectBytes(envelope)
	if err != nil {
		t.Fatalf("CanonicalObjectBytes() error = %v", err)
	}
	if string(got) == string(base) {
		t.Fatalf("CanonicalObjectBytes() did not change after network_id change")
	}
}

func TestCanonicalObjectBytesIncludesScopeID(t *testing.T) {
	envelope := canonicalTestEnvelope()
	envelope.ObjectType = ObjectTypeBlindTokenRequest
	envelope.Scope = ScopeElectionID
	envelope.ScopeID = "election-1"
	base, err := CanonicalObjectBytes(envelope)
	if err != nil {
		t.Fatalf("CanonicalObjectBytes() error = %v", err)
	}

	envelope.ScopeID = "election-2"
	got, err := CanonicalObjectBytes(envelope)
	if err != nil {
		t.Fatalf("CanonicalObjectBytes() error = %v", err)
	}
	if string(got) == string(base) {
		t.Fatalf("CanonicalObjectBytes() did not change after scope_id change")
	}
}

func TestValidateCanonicalPayloadWire(t *testing.T) {
	if err := ValidateCanonicalPayloadWire([]byte{0x0a, 0x08, 'e', 'l', 'e', 'c', 't', 'i', 'o', 'n'}); err != nil {
		t.Fatalf("ValidateCanonicalPayloadWire() error = %v", err)
	}

	if err := ValidateCanonicalPayloadWire([]byte("not-protobuf")); !errors.Is(err, ErrInvalidCanonicalPayload) {
		t.Fatalf("ValidateCanonicalPayloadWire() error = %v; want %v", err, ErrInvalidCanonicalPayload)
	}

	outOfOrderFields := []byte{0x18, 0x01, 0x10, 0x01}
	if err := ValidateCanonicalPayloadWire(outOfOrderFields); !errors.Is(err, ErrInvalidCanonicalPayload) {
		t.Fatalf("ValidateCanonicalPayloadWire() error = %v; want %v", err, ErrInvalidCanonicalPayload)
	}
}

func canonicalTestEnvelope() ObjectEnvelope {
	return ObjectEnvelope{
		ObjectID:        "object-id",
		ObjectType:      ObjectTypeAnonymousElection,
		ProtocolVersion: "v1",
		NetworkID:       "testnet",
		Scope:           ScopeNetwork,
		Payload:         []byte{0x0a, 0x08, 'e', 'l', 'e', 'c', 't', 'i', 'o', 'n'},
		Pow:             []byte("pow"),
		CreatedAt:       1700000000000,
	}
}
