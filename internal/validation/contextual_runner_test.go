package validation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"librevote/internal/domain"
	"librevote/internal/storage"
	"librevote/internal/validation"
)

func TestContextualValidatorRunnerPersistsMissingDependencyRows(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	validator := newStructuralContextualRunner(t, store, validation.WithContextualRule(domain.ObjectTypeBlindTokenIssue,
		func(context.Context, domain.ObjectEnvelope) (validation.ContextualRuleResult, error) {
			return validation.ContextualRuleResult{
				Status: validation.StatusValid,
				RequiredDependencies: []validation.RequiredDependency{
					validation.RequireObject("blind_token_request", "request-1", validation.StatusValid),
				},
			}, nil
		}))
	envelope := runnerValidEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeBlindTokenIssue
	envelope.Scope = domain.ScopeElectionID
	envelope.ScopeID = "election-1"
	envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)

	result, err := validator.IngestAndValidate(ctx, envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if result.Outcome.Status != validation.StatusPendingDependencies || result.Outcome.ShouldRepublish {
		t.Fatalf("outcome = %+v, want pending without republish", result.Outcome)
	}
	deps, err := store.Dependencies(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 1 || deps[0] != (storage.Dependency{Type: "blind_token_request", ID: "request-1"}) {
		t.Fatalf("dependencies = %+v", deps)
	}
}

func TestContextualValidatorRunnerAcceptsPresentDependency(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	ingestDependency(t, store, "request-1", domain.ValidationStatusValid)
	runner := newStructuralContextualRunner(t, store, validation.WithContextualRule(domain.ObjectTypeBlindTokenIssue,
		func(context.Context, domain.ObjectEnvelope) (validation.ContextualRuleResult, error) {
			return validation.ContextualRuleResult{
				Status: validation.StatusValid,
				RequiredDependencies: []validation.RequiredDependency{
					validation.RequireObject("blind_token_request", "request-1", validation.StatusValid),
				},
			}, nil
		}))
	envelope := runnerValidEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeBlindTokenIssue
	envelope.Scope = domain.ScopeElectionID
	envelope.ScopeID = "election-1"
	envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)

	result, err := runner.IngestAndValidate(ctx, envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if result.Outcome.Status != validation.StatusValid || !result.Outcome.ShouldRepublish {
		t.Fatalf("outcome = %+v, want valid", result.Outcome)
	}
	deps, err := store.Dependencies(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 0 {
		t.Fatalf("dependencies = %+v, want none", deps)
	}
}

func TestContextualValidatorRunnerDoesNotPersistUnsupportedObjectType(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	runner := newStructuralContextualRunner(t, store)
	envelope := runnerValidEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeTallyKeyContribution
	envelope.Scope = domain.ScopeElectionID
	envelope.ScopeID = "election-1"
	envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)

	_, err := runner.IngestAndValidate(ctx, envelope)
	if !errors.Is(err, validation.ErrContextualRuleUnsupported) {
		t.Fatalf("IngestAndValidate() error = %v, want %v", err, validation.ErrContextualRuleUnsupported)
	}
	if _, err := store.InvalidObjectRecord(ctx, envelope.ObjectID); err == nil {
		t.Fatal("InvalidObjectRecord() succeeded for unsupported object, want no destructive invalid record")
	}
	deps, err := store.Dependencies(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 0 {
		t.Fatalf("dependencies = %+v, want none", deps)
	}
}

func TestContextualValidatorRunnerRejectsInvalidRecordedDependency(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	invalidEnvelope := runnerValidEnvelope(t)
	invalidEnvelope.ObjectID = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := store.IngestObject(ctx, storage.IngestObjectInput{
		ObjectID:               invalidEnvelope.ObjectID,
		ObjectType:             string(invalidEnvelope.ObjectType),
		NetworkID:              invalidEnvelope.NetworkID,
		Scope:                  string(invalidEnvelope.Scope),
		ScopeID:                invalidEnvelope.ScopeID,
		CreatedAt:              invalidEnvelope.CreatedAt,
		ObjectPoW:              invalidEnvelope.Pow,
		PayloadBytes:           invalidEnvelope.Payload,
		ValidationStatus:       domain.ValidationStatusInvalid,
		ValidationErrorCode:    validation.ErrorEnvelopeObjectID,
		ValidationErrorMessage: "bad object id",
		ValidatorVersion:       validation.ValidatorVersionEnvelopeRunner,
		SeenAt:                 1700000000000,
		CheckedAt:              1700000000000,
	}); err != nil {
		t.Fatalf("IngestObject() invalid dependency error = %v", err)
	}
	runner := newStructuralContextualRunner(t, store, validation.WithContextualRule(domain.ObjectTypeBlindTokenIssue,
		func(context.Context, domain.ObjectEnvelope) (validation.ContextualRuleResult, error) {
			return validation.ContextualRuleResult{
				Status: validation.StatusValid,
				RequiredDependencies: []validation.RequiredDependency{
					validation.RequireObject("blind_token_request", invalidEnvelope.ObjectID, validation.StatusValid),
				},
			}, nil
		}))
	envelope := runnerValidEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeBlindTokenIssue
	envelope.Scope = domain.ScopeElectionID
	envelope.ScopeID = "election-1"
	envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)

	result, err := runner.IngestAndValidate(ctx, envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if result.Outcome.Status != validation.StatusInvalid || result.Outcome.ValidationErrorCode != validation.ErrorContextualDependencyStatus {
		t.Fatalf("outcome = %+v, want invalid dependency rejection", result.Outcome)
	}
}

func newStructuralContextualRunner(t *testing.T, store *storage.Store, opts ...validation.ContextualOption) *validation.Runner {
	t.Helper()
	contextual, err := validation.NewContextualValidator(store, opts...)
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}
	structural, err := validation.NewStructuralValidator(contextual)
	if err != nil {
		t.Fatalf("NewStructuralValidator() error = %v", err)
	}
	runner, err := validation.NewRunner(validation.RunnerConfig{
		Envelope:         runnerEnvelopeConfig(),
		Store:            store,
		DomainValidator:  structural,
		ValidatorVersion: validation.ValidatorVersionEnvelopeRunner,
		Now:              func() time.Time { return time.UnixMilli(1700000001000) },
	})
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	return runner
}

func ingestDependency(t *testing.T, store *storage.Store, objectID string, status domain.ValidationStatus) {
	t.Helper()
	_, err := store.IngestObject(context.Background(), storage.IngestObjectInput{
		ObjectID:         objectID,
		ObjectType:       string(domain.ObjectTypeBlindTokenRequest),
		ProtocolVersion:  1,
		NetworkID:        "testnet",
		Scope:            string(domain.ScopeElectionID),
		ScopeID:          "election-1",
		CreatedAt:        1700000000000,
		ObjectPoW:        []byte("nonce"),
		PayloadBytes:     []byte{0x0a, 0x08, 'r', 'e', 'q', 'u', 'e', 's', 't', '1'},
		ValidationStatus: status,
		ValidatorVersion: validation.ValidatorVersionEnvelopeRunner,
		SeenAt:           1700000000000,
		CheckedAt:        1700000000000,
	})
	if err != nil {
		t.Fatalf("IngestObject() dependency error = %v", err)
	}
}
