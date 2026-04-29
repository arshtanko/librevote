package validation_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"librevote/internal/domain"
	"librevote/internal/storage"
	"librevote/internal/validation"
)

func TestRunnerRevalidateObjectIDUpdatesValidationStatus(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	pendingRunner := newTestRunner(t, store)
	envelope := runnerPendingDependencyEnvelope(t)

	if _, err := pendingRunner.IngestAndValidate(ctx, envelope); err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}

	validRunner := newStaticRevalidationRunner(t, store, validation.NewOutcome(envelope.ObjectID, validation.StatusValid))
	result, err := validRunner.RevalidateObjectID(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("RevalidateObjectID() error = %v", err)
	}
	if !result.EnvelopeAccepted || result.Outcome.Status != validation.StatusValid || !result.Outcome.ShouldRepublish {
		t.Fatalf("result = %+v, want accepted valid republish-eligible", result)
	}

	record, err := store.ValidationRecord(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() error = %v", err)
	}
	if record.ValidationStatus != string(validation.StatusValid) || record.ValidatorVersion != "revalidator-v1" || record.LastCheckedAt != 1700000005000 {
		t.Fatalf("validation record = %+v", record)
	}
	deps, err := store.Dependencies(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 0 {
		t.Fatalf("dependencies = %+v, want cleared", deps)
	}
}

func TestRunnerRevalidateObjectIDMissingObject(t *testing.T) {
	store := openTestStore(t)
	runner := newStaticRevalidationRunner(t, store, validation.NewOutcome("missing", validation.StatusValid))

	_, err := runner.RevalidateObjectID(context.Background(), "missing")
	if !errors.Is(err, storage.ErrRevalidationObjectNotFound) {
		t.Fatalf("RevalidateObjectID() error = %v, want %v", err, storage.ErrRevalidationObjectNotFound)
	}
}

func TestRunnerRevalidateObjectIDPendingPayloadEvictedRequiresReacquire(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	runner := newTestRunner(t, store)
	envelope := runnerPendingDependencyEnvelope(t)

	if _, err := runner.IngestAndValidate(ctx, envelope); err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if err := store.EvictPendingPayload(ctx, envelope.ObjectID, 1700000002000, validation.ValidatorVersionEnvelopeRunner); err != nil {
		t.Fatalf("EvictPendingPayload() error = %v", err)
	}

	_, err := runner.RevalidateObjectID(ctx, envelope.ObjectID)
	if !errors.Is(err, storage.ErrRevalidationPayloadEvicted) {
		t.Fatalf("RevalidateObjectID() error = %v, want %v", err, storage.ErrRevalidationPayloadEvicted)
	}
	record, err := store.ValidationRecord(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() error = %v", err)
	}
	if record.ValidationStatus != string(validation.StatusPendingPayloadEvicted) {
		t.Fatalf("status = %q, want pending_payload_evicted", record.ValidationStatus)
	}
	if _, err := store.Payload(ctx, envelope.ObjectID); err == nil {
		t.Fatal("Payload() succeeded for evicted object, want no retained payload")
	}
}

func TestRunnerRevalidateObjectIDDoesNotLoadInvalidRecords(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	envelope := runnerValidEnvelope(t)
	envelope.ObjectID = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := store.IngestObject(ctx, storage.IngestObjectInput{
		ObjectID:               envelope.ObjectID,
		ObjectType:             string(envelope.ObjectType),
		NetworkID:              envelope.NetworkID,
		Scope:                  string(envelope.Scope),
		ScopeID:                envelope.ScopeID,
		CreatedAt:              envelope.CreatedAt,
		ObjectPoW:              envelope.Pow,
		PayloadBytes:           envelope.Payload,
		ValidationStatus:       domain.ValidationStatusInvalid,
		ValidationErrorCode:    validation.ErrorEnvelopeObjectID,
		ValidationErrorMessage: "bad object id",
		ValidatorVersion:       validation.ValidatorVersionEnvelopeRunner,
		SeenAt:                 1700000000000,
		CheckedAt:              1700000000000,
	}); err != nil {
		t.Fatalf("IngestObject(invalid) error = %v", err)
	}

	runner := newStaticRevalidationRunner(t, store, validation.NewOutcome(envelope.ObjectID, validation.StatusValid))
	_, err := runner.RevalidateObjectID(ctx, envelope.ObjectID)
	if !errors.Is(err, storage.ErrRevalidationInvalidObject) {
		t.Fatalf("RevalidateObjectID() error = %v, want %v", err, storage.ErrRevalidationInvalidObject)
	}
}

func TestRunnerRevalidateObjectIDPreservesDomainAndSourceBoundaries(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	runner := newTestRunner(t, store)
	envelope := runnerPendingDependencyEnvelope(t)
	envelope.Pow = []byte("original-pow")
	envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)

	if _, err := runner.IngestAndValidate(ctx, envelope); err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if err := store.RecordObjectSource(ctx, envelope.ObjectID, "peer-1", 1700000003000); err != nil {
		t.Fatalf("RecordObjectSource() error = %v", err)
	}
	beforeMeta, err := store.ObjectMetadata(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() before error = %v", err)
	}
	beforePayload, err := store.Payload(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("Payload() before error = %v", err)
	}
	beforeSources, err := store.ObjectSources(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("ObjectSources() before error = %v", err)
	}

	validRunner := newStaticRevalidationRunner(t, store, validation.NewOutcome(envelope.ObjectID, validation.StatusValid))
	if _, err := validRunner.RevalidateObjectID(ctx, envelope.ObjectID); err != nil {
		t.Fatalf("RevalidateObjectID() error = %v", err)
	}

	afterMeta, err := store.ObjectMetadata(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() after error = %v", err)
	}
	afterPayload, err := store.Payload(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("Payload() after error = %v", err)
	}
	afterSources, err := store.ObjectSources(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("ObjectSources() after error = %v", err)
	}

	if beforeMeta.ObjectID != afterMeta.ObjectID || beforeMeta.ObjectType != afterMeta.ObjectType || beforeMeta.NetworkID != afterMeta.NetworkID || beforeMeta.Scope != afterMeta.Scope || beforeMeta.ScopeID != afterMeta.ScopeID || beforeMeta.CreatedAt != afterMeta.CreatedAt || !bytes.Equal(beforeMeta.ObjectPoW, afterMeta.ObjectPoW) || !bytes.Equal(beforeMeta.PayloadHash, afterMeta.PayloadHash) {
		t.Fatalf("domain metadata changed: before=%+v after=%+v", beforeMeta, afterMeta)
	}
	if !bytes.Equal(beforePayload, afterPayload) {
		t.Fatal("payload bytes changed during revalidation")
	}
	if len(afterSources) != len(beforeSources) || afterSources[0] != beforeSources[0] {
		t.Fatalf("source metadata changed: before=%+v after=%+v", beforeSources, afterSources)
	}
}

func newStaticRevalidationRunner(t *testing.T, store *storage.Store, outcome validation.Outcome) *validation.Runner {
	t.Helper()
	runner, err := validation.NewRunner(validation.RunnerConfig{
		Envelope:         runnerEnvelopeConfig(),
		Store:            store,
		DomainValidator:  staticDomainValidator{outcome: outcome},
		ValidatorVersion: "revalidator-v1",
		Now:              func() time.Time { return time.UnixMilli(1700000005000) },
	})
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	return runner
}
