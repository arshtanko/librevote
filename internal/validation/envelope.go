package validation

import (
	"errors"
	"fmt"
	"time"

	"librevote/internal/crypto"
	"librevote/internal/domain"
)

const (
	ErrorEnvelopeShape              = "envelope_shape"
	ErrorEnvelopeNetwork            = "envelope_network"
	ErrorEnvelopeProtocolVersion    = "envelope_protocol_version"
	ErrorEnvelopePayload            = "envelope_payload"
	ErrorEnvelopeObjectID           = "envelope_object_id"
	ErrorEnvelopeObjectPoW          = "envelope_object_pow"
	ErrorEnvelopeCreatedAtClockSkew = "envelope_created_at_clock_skew"
)

var (
	ErrEnvelopeConfigNetworkID       = errors.New("network_id is required")
	ErrEnvelopeConfigProtocolVersion = errors.New("protocol_version is required")
)

// EnvelopeConfig contains local deterministic envelope validation settings.
type EnvelopeConfig struct {
	NetworkID           string
	ProtocolVersion     string
	ObjectPoWDifficulty uint8
	MaxClockSkew        time.Duration
	Now                 func() time.Time
}

// EnvelopeResult reports whether envelope validation accepted the object for later stages.
// Failed envelope validation maps directly to an invalid validation outcome.
type EnvelopeResult struct {
	Accepted bool
	Outcome  Outcome
}

// ValidateEnvelope performs deterministic ObjectEnvelope validation only.
func ValidateEnvelope(envelope domain.ObjectEnvelope, cfg EnvelopeConfig) (EnvelopeResult, error) {
	if cfg.NetworkID == "" {
		return EnvelopeResult{}, ErrEnvelopeConfigNetworkID
	}
	if cfg.ProtocolVersion == "" {
		return EnvelopeResult{}, ErrEnvelopeConfigProtocolVersion
	}

	if err := domain.ValidateEnvelopeShape(envelope); err != nil {
		return invalidEnvelope(envelope.ObjectID, ErrorEnvelopeShape, err), nil
	}
	if envelope.NetworkID != cfg.NetworkID {
		return invalidEnvelope(envelope.ObjectID, ErrorEnvelopeNetwork, fmt.Errorf("network_id %q does not match local network %q", envelope.NetworkID, cfg.NetworkID)), nil
	}
	if envelope.ProtocolVersion != cfg.ProtocolVersion {
		return invalidEnvelope(envelope.ObjectID, ErrorEnvelopeProtocolVersion, fmt.Errorf("protocol_version %q is not supported", envelope.ProtocolVersion)), nil
	}
	if err := domain.ValidateCanonicalPayloadWire(envelope.Payload); err != nil {
		return invalidEnvelope(envelope.ObjectID, ErrorEnvelopePayload, err), nil
	}

	objectID, err := recomputeObjectID(envelope)
	if err != nil {
		return invalidEnvelope(envelope.ObjectID, ErrorEnvelopeObjectID, err), nil
	}
	if envelope.ObjectID != objectID.String() {
		return invalidEnvelope(envelope.ObjectID, ErrorEnvelopeObjectID, fmt.Errorf("object_id does not match canonical object bytes")), nil
	}

	powValid, err := crypto.ValidatePoW(crypto.DomainObjectPoW, objectID, cfg.ObjectPoWDifficulty, envelope.Pow)
	if err != nil {
		return invalidEnvelope(envelope.ObjectID, ErrorEnvelopeObjectPoW, err), nil
	}
	if !powValid {
		return invalidEnvelope(envelope.ObjectID, ErrorEnvelopeObjectPoW, fmt.Errorf("object pow does not satisfy difficulty %d", cfg.ObjectPoWDifficulty)), nil
	}

	if err := validateCreatedAtClockSkew(envelope.CreatedAt, cfg); err != nil {
		return invalidEnvelope(envelope.ObjectID, ErrorEnvelopeCreatedAtClockSkew, err), nil
	}

	return EnvelopeResult{Accepted: true, Outcome: Outcome{ObjectID: envelope.ObjectID}}, nil
}

func invalidEnvelope(objectID, code string, err error) EnvelopeResult {
	outcome := NewOutcome(objectID, StatusInvalid)
	outcome.ValidationErrorCode = code
	outcome.ValidationErrorReason = err.Error()
	return EnvelopeResult{Outcome: outcome}
}

func recomputeObjectID(envelope domain.ObjectEnvelope) (crypto.Digest, error) {
	canonicalBytes, err := domain.CanonicalObjectBytes(envelope)
	if err != nil {
		return crypto.Digest{}, fmt.Errorf("canonical object bytes: %w", err)
	}
	return crypto.ObjectID(canonicalBytes)
}

func validateCreatedAtClockSkew(createdAt int64, cfg EnvelopeConfig) error {
	if cfg.MaxClockSkew <= 0 {
		return nil
	}

	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	created := time.UnixMilli(createdAt)
	delta := now().Sub(created)
	if delta < 0 {
		delta = -delta
	}
	if delta > cfg.MaxClockSkew {
		return fmt.Errorf("created_at outside max clock skew")
	}
	return nil
}
