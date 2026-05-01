package validation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"librevote/internal/crypto"
	"librevote/internal/domain"
	"librevote/internal/storage"
	"librevote/internal/validation"
)

func TestRunnerIngestAndValidatePersistsAcceptedEnvelopeAsPending(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	runner := newTestRunner(t, store)
	envelope := runnerPendingDependencyEnvelope(t)

	result, err := runner.IngestAndValidate(ctx, envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if !result.EnvelopeAccepted || !result.Persistence.Inserted {
		t.Fatalf("result = %+v, want accepted inserted envelope", result)
	}
	if result.Outcome.Status != validation.StatusPendingDependencies {
		t.Fatalf("status = %q, want %q", result.Outcome.Status, validation.StatusPendingDependencies)
	}
	if result.Outcome.ShouldRepublish || result.Outcome.ShouldRecomputeState || len(result.Outcome.ConflictKeys) != 0 {
		t.Fatalf("unexpected side-effect flags in outcome: %+v", result.Outcome)
	}

	record, err := store.ValidationRecord(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() error = %v", err)
	}
	if record.ValidationStatus != string(validation.StatusPendingDependencies) || record.ValidatorVersion != validation.ValidatorVersionEnvelopeRunner {
		t.Fatalf("validation record = %+v", record)
	}
	if record.ValidationErrorCode != "" || record.ValidationErrorMessage != "" {
		t.Fatalf("accepted envelope has validation error fields: %+v", record)
	}

	meta, err := store.ObjectMetadata(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() error = %v", err)
	}
	if !meta.PayloadRetained {
		t.Fatal("payload_retained = false, want true for pending envelope")
	}
	payload, err := store.Payload(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("Payload() error = %v", err)
	}
	if string(payload) != string(envelope.Payload) {
		t.Fatalf("payload = %x, want %x", payload, envelope.Payload)
	}

	deps, err := store.Dependencies(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 1 || deps[0].Type != "election" || deps[0].ID != "election-1" {
		t.Fatalf("dependencies = %+v", deps)
	}

	if _, err := store.InvalidObjectRecord(ctx, envelope.ObjectID); err == nil {
		t.Fatal("InvalidObjectRecord() succeeded for accepted envelope, want error")
	}
}

func TestRunnerIngestAndValidateRecordsMalformedEnvelopeInvalid(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	runner := newTestRunner(t, store)
	envelope := runnerValidEnvelope(t)
	envelope.ObjectType = ""
	envelope.ObjectID = "1111111111111111111111111111111111111111111111111111111111111111"

	result, err := runner.IngestAndValidate(ctx, envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if result.EnvelopeAccepted || !result.Persistence.InvalidRecorded {
		t.Fatalf("result = %+v, want invalid recorded", result)
	}
	if result.Outcome.ValidationErrorCode != validation.ErrorEnvelopeShape {
		t.Fatalf("outcome = %+v", result.Outcome)
	}
	if _, err := store.InvalidObjectRecord(ctx, envelope.ObjectID); err != nil {
		t.Fatalf("InvalidObjectRecord() error = %v", err)
	}
}

func TestRunnerIngestAndValidatePersistsEnvelopeFailureAsInvalid(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	runner := newTestRunner(t, store)
	envelope := runnerValidEnvelope(t)
	envelope.ObjectID = "0000000000000000000000000000000000000000000000000000000000000000"

	result, err := runner.IngestAndValidate(ctx, envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if result.EnvelopeAccepted || !result.Persistence.InvalidRecorded {
		t.Fatalf("result = %+v, want invalid recorded", result)
	}
	if result.Outcome.Status != validation.StatusInvalid || result.Outcome.ValidationErrorCode != validation.ErrorEnvelopeObjectID {
		t.Fatalf("outcome = %+v", result.Outcome)
	}

	if _, err := store.ObjectMetadata(ctx, envelope.ObjectID); err == nil {
		t.Fatal("ObjectMetadata() succeeded for invalid envelope, want error")
	}
	if _, err := store.Payload(ctx, envelope.ObjectID); err == nil {
		t.Fatal("Payload() succeeded for invalid envelope, want error")
	}
	invalid, err := store.InvalidObjectRecord(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("InvalidObjectRecord() error = %v", err)
	}
	if invalid.ValidationErrorCode != validation.ErrorEnvelopeObjectID || invalid.SeenCount != 1 {
		t.Fatalf("invalid record = %+v", invalid)
	}
}

func TestRunnerIngestAndValidateReacquiresEvictedPendingPayload(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	runner := newTestRunner(t, store)
	envelope := runnerValidEnvelope(t)

	if _, err := runner.IngestAndValidate(ctx, envelope); err != nil {
		t.Fatalf("initial IngestAndValidate() error = %v", err)
	}
	if err := store.EvictPendingPayload(ctx, envelope.ObjectID, 1700000002000, validation.ValidatorVersionEnvelopeRunner); err != nil {
		t.Fatalf("EvictPendingPayload() error = %v", err)
	}
	meta, err := store.ObjectMetadata(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() after eviction error = %v", err)
	}
	if meta.PayloadRetained {
		t.Fatal("payload retained after eviction, want false")
	}

	result, err := runner.IngestAndValidate(ctx, envelope)
	if err != nil {
		t.Fatalf("reacquire IngestAndValidate() error = %v", err)
	}
	if !result.Persistence.Reacquired || !result.Persistence.Updated {
		t.Fatalf("persistence = %+v, want reacquired updated", result.Persistence)
	}
	meta, err = store.ObjectMetadata(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() after reacquire error = %v", err)
	}
	if !meta.PayloadRetained {
		t.Fatal("payload_retained = false after reacquire, want true")
	}
	record, err := store.ValidationRecord(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() after reacquire error = %v", err)
	}
	if record.ValidationStatus != string(validation.StatusPendingDependencies) {
		t.Fatalf("status after reacquire = %q", record.ValidationStatus)
	}
}

func TestRunnerRejectsConfigErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  validation.RunnerConfig
		want error
	}{
		{
			name: "missing store",
			cfg: validation.RunnerConfig{
				Envelope:         runnerEnvelopeConfig(),
				ValidatorVersion: validation.ValidatorVersionEnvelopeRunner,
			},
			want: validation.ErrRunnerConfigStore,
		},
		{
			name: "missing validator version",
			cfg: validation.RunnerConfig{
				Envelope:        runnerEnvelopeConfig(),
				Store:           fakeStore{},
				DomainValidator: fakeDomainValidator{},
			},
			want: validation.ErrRunnerConfigValidatorVersion,
		},
		{
			name: "missing domain validator",
			cfg: validation.RunnerConfig{
				Envelope:         runnerEnvelopeConfig(),
				Store:            fakeStore{},
				ValidatorVersion: validation.ValidatorVersionEnvelopeRunner,
			},
			want: validation.ErrRunnerConfigDomainValidator,
		},
		{
			name: "missing network id",
			cfg: validation.RunnerConfig{
				Envelope:         validation.EnvelopeConfig{ProtocolVersion: "v1"},
				Store:            fakeStore{},
				DomainValidator:  fakeDomainValidator{},
				ValidatorVersion: validation.ValidatorVersionEnvelopeRunner,
			},
			want: validation.ErrEnvelopeConfigNetworkID,
		},
		{
			name: "missing protocol version",
			cfg: validation.RunnerConfig{
				Envelope:         validation.EnvelopeConfig{NetworkID: "testnet"},
				Store:            fakeStore{},
				DomainValidator:  fakeDomainValidator{},
				ValidatorVersion: validation.ValidatorVersionEnvelopeRunner,
			},
			want: validation.ErrEnvelopeConfigProtocolVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validation.NewRunner(tt.cfg)
			if !errors.Is(err, tt.want) {
				t.Fatalf("NewRunner() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestRunnerDoesNotEmitNetworkTallyOrRevalidationSideEffects(t *testing.T) {
	store := &capturingStore{}
	runner, err := validation.NewRunner(validation.RunnerConfig{
		Envelope:         runnerEnvelopeConfig(),
		Store:            store,
		DomainValidator:  fakeDomainValidator{},
		ValidatorVersion: validation.ValidatorVersionEnvelopeRunner,
		Now:              func() time.Time { return time.UnixMilli(1700000001000) },
	})
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}

	result, err := runner.IngestAndValidate(context.Background(), runnerValidEnvelope(t))
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if result.Outcome.ShouldRepublish || result.Outcome.ShouldRecomputeState || len(result.Outcome.ConflictKeys) != 0 {
		t.Fatalf("outcome has unsupported side effects: %+v", result.Outcome)
	}
	if !store.called {
		t.Fatal("store was not called")
	}
	if store.input.SeenAt != 1700000001000 || store.input.CheckedAt != 1700000001000 {
		t.Fatalf("persistence input = %+v", store.input)
	}
}

func TestRunnerIntegratesStructuralValidatorAndContextualDelegate(t *testing.T) {
	envelope := runnerValidEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeBlindTokenIssue
	envelope.Scope = domain.ScopeElectionID
	envelope.ScopeID = "election-1"
	envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)
	contextual := &runnerContextualValidator{
		outcome: validation.NewOutcome(envelope.ObjectID, validation.StatusValid),
	}
	structural, err := validation.NewStructuralValidator(contextual)
	if err != nil {
		t.Fatalf("NewStructuralValidator() error = %v", err)
	}
	store := &capturingStore{}
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

	result, err := runner.IngestAndValidate(context.Background(), envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if !result.EnvelopeAccepted || !contextual.called || contextual.envelope.ObjectID != envelope.ObjectID {
		t.Fatalf("runner did not pass accepted envelope through structural/contextual validation")
	}
	if result.Outcome.Status != validation.StatusValid || !result.Outcome.ShouldRepublish {
		t.Fatalf("outcome = %+v, want delegated valid outcome", result.Outcome)
	}
	if store.outcome.Status != validation.StatusValid {
		t.Fatalf("persisted outcome = %+v, want delegated valid outcome", store.outcome)
	}
}

func TestRunnerWithStructuralValidatorDoesNotMarkValidWithoutContextualStatus(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	envelope := runnerValidEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeBlindTokenIssue
	envelope.Scope = domain.ScopeElectionID
	envelope.ScopeID = "election-1"
	envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)
	contextual := &runnerContextualValidator{
		outcome: validation.NewOutcome(envelope.ObjectID, validation.StatusPendingDependencies),
	}
	contextual.outcome.Dependencies = []validation.Dependency{{Type: "TrusteeSelectionResult", ID: "result-1"}}
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

	result, err := runner.IngestAndValidate(ctx, envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if result.Outcome.Status != validation.StatusPendingDependencies || result.Outcome.ShouldRepublish {
		t.Fatalf("outcome = %+v, want pending without republish", result.Outcome)
	}
	record, err := store.ValidationRecord(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() error = %v", err)
	}
	if record.ValidationStatus != string(validation.StatusPendingDependencies) {
		t.Fatalf("validation status = %q, want pending", record.ValidationStatus)
	}
}

func TestRunnerWithStructuralValidatorPersistsDelegatedValidOutcome(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	envelope := runnerValidEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeBlindTokenIssue
	envelope.Scope = domain.ScopeElectionID
	envelope.ScopeID = "election-1"
	envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)
	contextual := &runnerContextualValidator{
		outcome: validation.NewOutcome(envelope.ObjectID, validation.StatusValid),
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

	result, err := runner.IngestAndValidate(ctx, envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if result.Outcome.Status != validation.StatusValid || !result.Outcome.ShouldRepublish {
		t.Fatalf("outcome = %+v, want delegated valid republish-eligible outcome", result.Outcome)
	}
	record, err := store.ValidationRecord(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() error = %v", err)
	}
	if record.ValidationStatus != string(validation.StatusValid) {
		t.Fatalf("validation status = %q, want valid", record.ValidationStatus)
	}
	deps, err := store.Dependencies(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 0 {
		t.Fatalf("dependencies = %+v, want none for valid outcome", deps)
	}
}

func TestRunnerPersistsWorkerFacingOutcomeFlags(t *testing.T) {
	store := openTestStore(t)
	envelope := runnerValidEnvelope(t)
	runner, err := validation.NewRunner(validation.RunnerConfig{
		Envelope: runnerEnvelopeConfig(),
		Store:    store,
		DomainValidator: staticDomainValidator{outcome: validation.Outcome{
			ObjectID:             envelope.ObjectID,
			Status:               validation.StatusPendingDependencies,
			Dependencies:         []validation.Dependency{{Type: "election", ID: "election-1"}},
			ConflictKeys:         []validation.ConflictKey{{Group: "g", Key: "k"}},
			AffectedScope:        validation.AffectedScope{Scope: domain.ScopeElectionID, ScopeID: "election-1"},
			ShouldRecomputeState: true,
		}},
		ValidatorVersion: validation.ValidatorVersionEnvelopeRunner,
		Now:              func() time.Time { return time.UnixMilli(1700000001000) },
	})
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}

	result, err := runner.IngestAndValidate(context.Background(), envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if result.Outcome.AffectedScope.Scope != domain.ScopeElectionID || !result.Outcome.ShouldRecomputeState {
		t.Fatalf("outcome = %+v, want worker-facing flags preserved", result.Outcome)
	}
	meta, err := store.ValidationOutcomeMetadata(context.Background(), envelope.ObjectID)
	if err != nil {
		t.Fatalf("ValidationOutcomeMetadata() error = %v", err)
	}
	if meta.AffectedScope != result.Outcome.AffectedScope || !meta.ShouldRecomputeState {
		t.Fatalf("metadata = %+v, want persisted outcome flags", meta)
	}
}

func TestRunnerRejectsMismatchedDomainOutcomeObjectID(t *testing.T) {
	runner, err := validation.NewRunner(validation.RunnerConfig{
		Envelope: runnerEnvelopeConfig(),
		Store:    fakeStore{},
		DomainValidator: staticDomainValidator{outcome: validation.NewOutcome(
			"other-object", validation.StatusPendingDependencies,
		)},
		ValidatorVersion: validation.ValidatorVersionEnvelopeRunner,
		Now:              func() time.Time { return time.UnixMilli(1700000001000) },
	})
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}

	_, err = runner.IngestAndValidate(context.Background(), runnerValidEnvelope(t))
	if !errors.Is(err, validation.ErrRunnerOutcomeObjectID) {
		t.Fatalf("IngestAndValidate() error = %v, want %v", err, validation.ErrRunnerOutcomeObjectID)
	}
}

type fakeStore struct{}

func (fakeStore) PersistEnvelopeValidationOutcome(context.Context, domain.ObjectEnvelope, validation.Outcome, validation.PersistenceInput) (validation.PersistenceResult, error) {
	return validation.PersistenceResult{}, nil
}

type fakeDomainValidator struct{}

func (fakeDomainValidator) ValidateDomain(_ context.Context, envelope domain.ObjectEnvelope) (validation.Outcome, error) {
	outcome := validation.NewOutcome(envelope.ObjectID, validation.StatusPendingDependencies)
	outcome.Dependencies = []validation.Dependency{{Type: "election", ID: "election-1"}}
	return outcome, nil
}

type staticDomainValidator struct {
	outcome validation.Outcome
}

func (v staticDomainValidator) ValidateDomain(context.Context, domain.ObjectEnvelope) (validation.Outcome, error) {
	return v.outcome, nil
}

type runnerContextualValidator struct {
	called   bool
	envelope domain.ObjectEnvelope
	outcome  validation.Outcome
}

func (v *runnerContextualValidator) ValidateContext(_ context.Context, envelope domain.ObjectEnvelope) (validation.Outcome, error) {
	v.called = true
	v.envelope = envelope
	return v.outcome, nil
}

type capturingStore struct {
	called  bool
	outcome validation.Outcome
	input   validation.PersistenceInput
}

func (s *capturingStore) PersistEnvelopeValidationOutcome(_ context.Context, _ domain.ObjectEnvelope, outcome validation.Outcome, input validation.PersistenceInput) (validation.PersistenceResult, error) {
	s.called = true
	s.outcome = outcome
	s.input = input
	return validation.PersistenceResult{Inserted: true}, nil
}

func openTestStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.Open(context.Background(), storage.Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("storage.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("store.Close() error = %v", err)
		}
	})
	return store
}

func newTestRunner(t *testing.T, store *storage.Store) *validation.Runner {
	t.Helper()
	runner, err := validation.NewRunner(validation.RunnerConfig{
		Envelope:         runnerEnvelopeConfig(),
		Store:            store,
		DomainValidator:  fakeDomainValidator{},
		ValidatorVersion: validation.ValidatorVersionEnvelopeRunner,
		Now:              func() time.Time { return time.UnixMilli(1700000001000) },
	})
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	return runner
}

func runnerPendingDependencyEnvelope(t *testing.T) domain.ObjectEnvelope {
	t.Helper()
	envelope := runnerValidEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeBlindTokenRequest
	envelope.Scope = domain.ScopeElectionID
	envelope.ScopeID = "election-1"
	envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)
	return envelope
}

func runnerEnvelopeConfig() validation.EnvelopeConfig {
	return validation.EnvelopeConfig{
		NetworkID:       "testnet",
		ProtocolVersion: "v1",
	}
}

func runnerValidEnvelope(t *testing.T) domain.ObjectEnvelope {
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
	envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)
	return envelope
}

func runnerObjectIDForEnvelope(t *testing.T, envelope domain.ObjectEnvelope) string {
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
