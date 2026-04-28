package validation

import (
	"errors"
	"testing"
	"time"

	"librevote/internal/crypto"
	"librevote/internal/domain"
)

func TestValidateEnvelopeAcceptsValidEnvelope(t *testing.T) {
	envelope := validEnvelope(t)

	result, err := ValidateEnvelope(envelope, validEnvelopeConfig())
	if err != nil {
		t.Fatalf("ValidateEnvelope() error = %v", err)
	}
	if !result.Accepted {
		t.Fatalf("Accepted = false; outcome = %+v", result.Outcome)
	}
	if result.Outcome.ObjectID != envelope.ObjectID {
		t.Fatalf("Outcome.ObjectID = %q; want %q", result.Outcome.ObjectID, envelope.ObjectID)
	}
	if result.Outcome.Status != "" {
		t.Fatalf("Outcome.Status = %q; want empty until later validation stages", result.Outcome.Status)
	}
}

func TestValidateEnvelopeRejectsShapeFailure(t *testing.T) {
	envelope := validEnvelope(t)
	envelope.Payload = nil

	assertEnvelopeInvalid(t, envelope, validEnvelopeConfig(), ErrorEnvelopeShape)
}

func TestValidateEnvelopeRejectsWrongNetwork(t *testing.T) {
	envelope := validEnvelope(t)
	envelope.NetworkID = "othernet"
	envelope.ObjectID = objectIDForEnvelope(t, envelope)

	assertEnvelopeInvalid(t, envelope, validEnvelopeConfig(), ErrorEnvelopeNetwork)
}

func TestValidateEnvelopeRejectsUnsupportedProtocolVersion(t *testing.T) {
	envelope := validEnvelope(t)
	envelope.ProtocolVersion = "v2"
	envelope.ObjectID = objectIDForEnvelope(t, envelope)

	assertEnvelopeInvalid(t, envelope, validEnvelopeConfig(), ErrorEnvelopeProtocolVersion)
}

func TestValidateEnvelopeRejectsObjectIDMismatch(t *testing.T) {
	envelope := validEnvelope(t)
	envelope.ObjectID = "0000000000000000000000000000000000000000000000000000000000000000"

	assertEnvelopeInvalid(t, envelope, validEnvelopeConfig(), ErrorEnvelopeObjectID)
}

func TestValidateEnvelopeRejectsInvalidCanonicalPayloadWire(t *testing.T) {
	envelope := validEnvelope(t)
	envelope.Payload = []byte("not-protobuf")
	envelope.ObjectID = objectIDForEnvelope(t, envelope)

	assertEnvelopeInvalid(t, envelope, validEnvelopeConfig(), ErrorEnvelopePayload)
}

func TestValidateEnvelopeRejectsInvalidObjectPoW(t *testing.T) {
	envelope := validEnvelope(t)
	cfg := validEnvelopeConfig()
	cfg.ObjectPoWDifficulty = 255

	assertEnvelopeInvalid(t, envelope, cfg, ErrorEnvelopeObjectPoW)
}

func TestValidateEnvelopeRejectsCreatedAtOutsideClockSkew(t *testing.T) {
	envelope := validEnvelope(t)
	cfg := validEnvelopeConfig()
	cfg.MaxClockSkew = time.Minute
	cfg.Now = func() time.Time { return time.UnixMilli(envelope.CreatedAt).Add(2 * time.Minute) }

	assertEnvelopeInvalid(t, envelope, cfg, ErrorEnvelopeCreatedAtClockSkew)
}

func TestValidateEnvelopeRejectsInvalidConfig(t *testing.T) {
	envelope := validEnvelope(t)
	cfg := validEnvelopeConfig()
	cfg.NetworkID = ""

	_, err := ValidateEnvelope(envelope, cfg)
	if !errors.Is(err, ErrEnvelopeConfigNetworkID) {
		t.Fatalf("ValidateEnvelope() error = %v; want %v", err, ErrEnvelopeConfigNetworkID)
	}
}

func assertEnvelopeInvalid(t *testing.T, envelope domain.ObjectEnvelope, cfg EnvelopeConfig, wantCode string) {
	t.Helper()

	result, err := ValidateEnvelope(envelope, cfg)
	if err != nil {
		t.Fatalf("ValidateEnvelope() error = %v", err)
	}
	if result.Accepted {
		t.Fatalf("Accepted = true; want false")
	}
	if result.Outcome.Status != StatusInvalid {
		t.Fatalf("Status = %q; want %q", result.Outcome.Status, StatusInvalid)
	}
	if result.Outcome.ShouldRepublish {
		t.Fatalf("ShouldRepublish = true; want false")
	}
	if result.Outcome.ValidationErrorCode != wantCode {
		t.Fatalf("ValidationErrorCode = %q; want %q", result.Outcome.ValidationErrorCode, wantCode)
	}
	if result.Outcome.ValidationErrorReason == "" {
		t.Fatalf("ValidationErrorReason is empty")
	}
}

func validEnvelopeConfig() EnvelopeConfig {
	return EnvelopeConfig{
		NetworkID:       "testnet",
		ProtocolVersion: "v1",
	}
}

func validEnvelope(t *testing.T) domain.ObjectEnvelope {
	t.Helper()

	envelope := domain.ObjectEnvelope{
		ObjectType:      domain.ObjectTypeAnonymousElection,
		ProtocolVersion: "v1",
		NetworkID:       "testnet",
		Scope:           domain.ScopeNetwork,
		Payload:         []byte{0x0a, 0x08, 'e', 'l', 'e', 'c', 't', 'i', 'o', 'n'},
		Pow:             []byte("nonce"),
		CreatedAt:       1700000000000,
	}
	envelope.ObjectID = objectIDForEnvelope(t, envelope)
	return envelope
}

func objectIDForEnvelope(t *testing.T, envelope domain.ObjectEnvelope) string {
	t.Helper()

	canonicalBytes, err := domain.CanonicalObjectBytes(envelope)
	if err != nil {
		t.Fatalf("CanonicalObjectBytes() error = %v", err)
	}
	objectID, err := crypto.ObjectID(canonicalBytes)
	if err != nil {
		t.Fatalf("ObjectID() error = %v", err)
	}
	return objectID.String()
}
