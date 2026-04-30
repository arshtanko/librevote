package validation

import (
	"context"
	"errors"
	"fmt"

	"librevote/internal/domain"
)

const (
	ErrorStructuralPayload           = "structural_payload"
	ErrorStructuralUnsupportedObject = "structural_unsupported_object_type"
)

var ErrStructuralContextualValidator = errors.New("contextual validator is required")

// ContextualValidator runs validation stages that require already-known domain
// objects or derived state. StructuralValidator delegates to it only after the
// schema-independent structural checks succeed.
type ContextualValidator interface {
	ValidateContext(context.Context, domain.ObjectEnvelope) (Outcome, error)
}

// StructuralValidator implements Runner's DomainValidator stage. It performs
// deterministic structural checks that are possible before generated payload
// structs exist, then delegates contextual status assignment.
type StructuralValidator struct {
	contextual ContextualValidator
	checks     map[domain.ObjectType]structuralCheck
}

type structuralCheck func(domain.ObjectEnvelope) error

// NewStructuralValidator creates a structural domain validator. A contextual
// delegate is required so structural success is not incorrectly recorded as
// contextual validity.
func NewStructuralValidator(contextual ContextualValidator) (*StructuralValidator, error) {
	if contextual == nil {
		return nil, ErrStructuralContextualValidator
	}
	return &StructuralValidator{
		contextual: contextual,
		checks:     defaultStructuralChecks(),
	}, nil
}

// ValidateDomain validates structural payload shape and delegates contextual
// validation. Missing dependencies are reported only by the contextual stage,
// where real dependency identities can be derived from decoded payloads.
func (v *StructuralValidator) ValidateDomain(ctx context.Context, envelope domain.ObjectEnvelope) (Outcome, error) {
	if v == nil || v.contextual == nil {
		return Outcome{}, ErrStructuralContextualValidator
	}

	checks := v.checks
	if checks == nil {
		checks = defaultStructuralChecks()
	}
	check, ok := checks[envelope.ObjectType]
	if !ok {
		return invalidStructural(envelope.ObjectID, ErrorStructuralUnsupportedObject, fmt.Errorf("unsupported object_type %q", envelope.ObjectType)), nil
	}
	if err := check(envelope); err != nil {
		return invalidStructural(envelope.ObjectID, ErrorStructuralPayload, err), nil
	}

	return v.contextual.ValidateContext(ctx, envelope)
}

func defaultStructuralChecks() map[domain.ObjectType]structuralCheck {
	check := validateCanonicalPayloadWire
	typed := validateTypedPayloadShape
	return map[domain.ObjectType]structuralCheck{
		domain.ObjectTypeTrusteeSelectionElection: typed,
		domain.ObjectTypeTrusteeNomination:        typed,
		domain.ObjectTypeTrusteeVote:              typed,
		domain.ObjectTypeTrusteeSelectionResult:   typed,
		domain.ObjectTypeTrusteeConsent:           typed,
		domain.ObjectTypeAnonymousElection:        typed,
		domain.ObjectTypeTallyKeyContribution:     typed,
		domain.ObjectTypeTallyKeySet:              typed,
		domain.ObjectTypeBlindTokenRequest:        check,
		domain.ObjectTypeBlindTokenIssue:          check,
		domain.ObjectTypeAnonymousBallot:          check,
		domain.ObjectTypeTallyDecryptionShare:     check,
		domain.ObjectTypeTallyResult:              check,
	}
}

func validateTypedPayloadShape(envelope domain.ObjectEnvelope) error {
	if err := domain.ValidatePayloadShape(envelope.ObjectType, envelope.Payload); err != nil {
		return fmt.Errorf("payload shape: %w", err)
	}
	return nil
}

func validateCanonicalPayloadWire(envelope domain.ObjectEnvelope) error {
	if err := domain.ValidateCanonicalPayloadWire(envelope.Payload); err != nil {
		return fmt.Errorf("canonical payload wire: %w", err)
	}
	return nil
}

func invalidStructural(objectID, code string, err error) Outcome {
	outcome := NewOutcome(objectID, StatusInvalid)
	outcome.ValidationErrorCode = code
	outcome.ValidationErrorReason = err.Error()
	return outcome
}
