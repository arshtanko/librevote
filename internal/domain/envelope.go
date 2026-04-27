package domain

import "fmt"

// ObjectEnvelope carries immutable domain object bytes with routing metadata.
type ObjectEnvelope struct {
	ObjectID        string
	ObjectType      ObjectType
	ProtocolVersion string
	NetworkID       string
	Scope           Scope
	ScopeID         string
	Payload         []byte
	Pow             []byte
	CreatedAt       int64
}

// ValidateEnvelopeShape performs cheap ObjectEnvelope shape checks only.
func ValidateEnvelopeShape(envelope ObjectEnvelope) error {
	if envelope.ObjectID == "" {
		return fmt.Errorf("object_id is required")
	}
	if !KnownObjectType(envelope.ObjectType) {
		return fmt.Errorf("unknown object_type %q", envelope.ObjectType)
	}
	if envelope.ProtocolVersion == "" {
		return fmt.Errorf("protocol_version is required")
	}
	if envelope.NetworkID == "" {
		return fmt.Errorf("network_id is required")
	}
	if err := ValidateScopeForObjectType(envelope.ObjectType, envelope.Scope, envelope.ScopeID); err != nil {
		return fmt.Errorf("invalid scope: %w", err)
	}
	if len(envelope.Payload) == 0 {
		return fmt.Errorf("payload is required")
	}
	if len(envelope.Pow) == 0 {
		return fmt.Errorf("pow is required")
	}
	if envelope.CreatedAt <= 0 {
		return fmt.Errorf("created_at must be greater than zero")
	}
	return nil
}
