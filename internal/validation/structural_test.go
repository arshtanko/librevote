package validation

import (
	"context"
	"errors"
	"testing"

	"librevote/internal/domain"
)

func TestNewStructuralValidatorRequiresContextualValidator(t *testing.T) {
	_, err := NewStructuralValidator(nil)
	if !errors.Is(err, ErrStructuralContextualValidator) {
		t.Fatalf("NewStructuralValidator() error = %v, want %v", err, ErrStructuralContextualValidator)
	}
}

func TestStructuralValidatorDelegatesAfterStructuralSuccess(t *testing.T) {
	envelope := validEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeBlindTokenIssue
	envelope.Scope = domain.ScopeElectionID
	envelope.ScopeID = "election-1"
	delegate := &recordingContextualValidator{
		outcome: NewOutcome(envelope.ObjectID, StatusValid),
	}
	validator, err := NewStructuralValidator(delegate)
	if err != nil {
		t.Fatalf("NewStructuralValidator() error = %v", err)
	}

	outcome, err := validator.ValidateDomain(context.Background(), envelope)
	if err != nil {
		t.Fatalf("ValidateDomain() error = %v", err)
	}
	if !delegate.called || delegate.envelope.ObjectID != envelope.ObjectID {
		t.Fatalf("contextual validator was not called with envelope")
	}
	if outcome.Status != StatusValid || !outcome.ShouldRepublish {
		t.Fatalf("outcome = %+v, want delegated valid outcome", outcome)
	}
}

func TestStructuralValidatorRejectsMalformedPayloadBeforeContextualDelegation(t *testing.T) {
	envelope := validEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeBlindTokenIssue
	envelope.Scope = domain.ScopeElectionID
	envelope.ScopeID = "election-1"
	envelope.Payload = []byte("not-protobuf")
	delegate := &recordingContextualValidator{}
	validator, err := NewStructuralValidator(delegate)
	if err != nil {
		t.Fatalf("NewStructuralValidator() error = %v", err)
	}

	outcome, err := validator.ValidateDomain(context.Background(), envelope)
	if err != nil {
		t.Fatalf("ValidateDomain() error = %v", err)
	}
	if delegate.called {
		t.Fatal("contextual validator was called after structural failure")
	}
	if outcome.Status != StatusInvalid || outcome.ValidationErrorCode != ErrorStructuralPayload || outcome.ShouldRepublish {
		t.Fatalf("outcome = %+v, want structural invalid", outcome)
	}
}

func TestStructuralValidatorRejectsUnsupportedObjectType(t *testing.T) {
	envelope := validEnvelope(t)
	envelope.ObjectType = domain.ObjectType("UnknownObject")
	delegate := &recordingContextualValidator{}
	validator, err := NewStructuralValidator(delegate)
	if err != nil {
		t.Fatalf("NewStructuralValidator() error = %v", err)
	}

	outcome, err := validator.ValidateDomain(context.Background(), envelope)
	if err != nil {
		t.Fatalf("ValidateDomain() error = %v", err)
	}
	if delegate.called {
		t.Fatal("contextual validator was called for unsupported type")
	}
	if outcome.Status != StatusInvalid || outcome.ValidationErrorCode != ErrorStructuralUnsupportedObject {
		t.Fatalf("outcome = %+v, want unsupported object type invalid", outcome)
	}
}

func TestStructuralValidatorDoesNotInventDependencies(t *testing.T) {
	envelope := validEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeBlindTokenIssue
	envelope.Scope = domain.ScopeElectionID
	envelope.ScopeID = "election-1"
	delegate := &recordingContextualValidator{
		outcome: NewOutcome(envelope.ObjectID, StatusPendingDependencies),
	}
	delegate.outcome.Dependencies = []Dependency{{Type: "TrusteeSelectionResult", ID: "result-1"}}
	validator, err := NewStructuralValidator(delegate)
	if err != nil {
		t.Fatalf("NewStructuralValidator() error = %v", err)
	}

	outcome, err := validator.ValidateDomain(context.Background(), envelope)
	if err != nil {
		t.Fatalf("ValidateDomain() error = %v", err)
	}
	if outcome.Status != StatusPendingDependencies || len(outcome.Dependencies) != 1 || outcome.Dependencies[0].ID != "result-1" {
		t.Fatalf("outcome = %+v, want contextual dependency unchanged", outcome)
	}
}

type recordingContextualValidator struct {
	called   bool
	envelope domain.ObjectEnvelope
	outcome  Outcome
	err      error
}

func (v *recordingContextualValidator) ValidateContext(_ context.Context, envelope domain.ObjectEnvelope) (Outcome, error) {
	v.called = true
	v.envelope = envelope
	return v.outcome, v.err
}
