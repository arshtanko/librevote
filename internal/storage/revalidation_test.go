package storage

import (
	"context"
	"errors"
	"slices"
	"testing"

	"librevote/internal/domain"
	"librevote/internal/validation"
)

func TestRevalidationPlannerWithStorageListsWaitingObjects(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	objectB := defaultIngestInput("planner-waiting-b", domain.ValidationStatusPendingDependencies)
	objectB.Dependencies = []Dependency{{Type: "election", ID: "election-1"}}
	if _, err := store.IngestObject(ctx, objectB); err != nil {
		t.Fatalf("IngestObject(objectB) error = %v", err)
	}

	objectA := defaultIngestInput("planner-waiting-a", domain.ValidationStatusPendingDependencies)
	objectA.Dependencies = []Dependency{
		{Type: "election", ID: "election-1"},
		{Type: "election", ID: "election-1"},
		{Type: "tally_key_set", ID: "tks-1"},
	}
	if _, err := store.IngestObject(ctx, objectA); err != nil {
		t.Fatalf("IngestObject(objectA) error = %v", err)
	}

	validInput := defaultIngestInput("planner-valid", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, validInput); err != nil {
		t.Fatalf("IngestObject(validInput) error = %v", err)
	}

	planner := validation.RevalidationPlanner{Store: store}
	plan, err := planner.CandidatesForDependencyChange(ctx, validation.Dependency{Type: "election", ID: "election-1"})
	if err != nil {
		t.Fatalf("CandidatesForDependencyChange() error = %v", err)
	}
	want := []string{"planner-waiting-a", "planner-waiting-b"}
	if !slices.Equal(plan.ObjectIDs, want) {
		t.Fatalf("ObjectIDs = %+v, want %+v", plan.ObjectIDs, want)
	}

	missing, err := planner.CandidatesForDependencyChange(ctx, validation.Dependency{Type: "blind_token_request", ID: "request-1"})
	if err != nil {
		t.Fatalf("CandidatesForDependencyChange(missing) error = %v", err)
	}
	if len(missing.ObjectIDs) != 0 {
		t.Fatalf("missing dependency ObjectIDs = %+v, want empty", missing.ObjectIDs)
	}
}

func TestLoadRetainedObjectEnvelopeReconstructsEnvelope(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("load-retained", domain.ValidationStatusPendingDependencies)
	input.ObjectPoW = []byte{0xaa, 0xbb}
	input.Dependencies = []Dependency{{Type: "election", ID: "election-1"}}
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}

	envelope, err := store.LoadRetainedObjectEnvelope(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("LoadRetainedObjectEnvelope() error = %v", err)
	}
	if envelope.ObjectID != input.ObjectID || envelope.ObjectType != domain.ObjectType(input.ObjectType) || envelope.ProtocolVersion != "v1" || envelope.NetworkID != input.NetworkID || envelope.Scope != domain.Scope(input.Scope) || envelope.ScopeID != input.ScopeID || envelope.CreatedAt != input.CreatedAt {
		t.Fatalf("envelope metadata = %+v, input = %+v", envelope, input)
	}
	if !slices.Equal(envelope.Pow, input.ObjectPoW) || !slices.Equal(envelope.Payload, input.PayloadBytes) {
		t.Fatalf("envelope bytes = pow %x payload %x", envelope.Pow, envelope.Payload)
	}
}

func TestLoadRetainedObjectEnvelopeExplicitNonRevalidatableErrors(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	if _, err := store.LoadRetainedObjectEnvelope(ctx, "missing"); !errors.Is(err, ErrRevalidationObjectNotFound) {
		t.Fatalf("missing error = %v, want %v", err, ErrRevalidationObjectNotFound)
	}

	invalid := defaultIngestInput("load-invalid", domain.ValidationStatusInvalid)
	invalid.ValidationErrorCode = "bad_envelope"
	if _, err := store.IngestObject(ctx, invalid); err != nil {
		t.Fatalf("IngestObject(invalid) error = %v", err)
	}
	if _, err := store.LoadRetainedObjectEnvelope(ctx, invalid.ObjectID); !errors.Is(err, ErrRevalidationInvalidObject) {
		t.Fatalf("invalid error = %v, want %v", err, ErrRevalidationInvalidObject)
	}

	evicted := defaultIngestInput("load-evicted", domain.ValidationStatusPendingDependencies)
	evicted.Dependencies = []Dependency{{Type: "election", ID: "election-1"}}
	if _, err := store.IngestObject(ctx, evicted); err != nil {
		t.Fatalf("IngestObject(evicted) error = %v", err)
	}
	if err := store.EvictPendingPayload(ctx, evicted.ObjectID, 4000, "v2"); err != nil {
		t.Fatalf("EvictPendingPayload() error = %v", err)
	}
	if _, err := store.LoadRetainedObjectEnvelope(ctx, evicted.ObjectID); !errors.Is(err, ErrRevalidationPayloadEvicted) {
		t.Fatalf("evicted error = %v, want %v", err, ErrRevalidationPayloadEvicted)
	}

	missingPayload := defaultIngestInput("load-missing-payload", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, missingPayload); err != nil {
		t.Fatalf("IngestObject(missingPayload) error = %v", err)
	}
	if _, err := store.db.ExecContext(ctx, "DELETE FROM object_payloads WHERE object_id = ?", missingPayload.ObjectID); err != nil {
		t.Fatalf("delete payload error = %v", err)
	}
	if _, err := store.LoadRetainedObjectEnvelope(ctx, missingPayload.ObjectID); !errors.Is(err, ErrRevalidationPayloadMissing) {
		t.Fatalf("missing payload error = %v, want %v", err, ErrRevalidationPayloadMissing)
	}
	if _, err := store.IngestObject(ctx, missingPayload); err != nil {
		t.Fatalf("reacquire missing payload error = %v", err)
	}
	if _, err := store.LoadRetainedObjectEnvelope(ctx, missingPayload.ObjectID); err != nil {
		t.Fatalf("LoadRetainedObjectEnvelope() after reacquire error = %v", err)
	}
}

func TestRevalidateRetainedObjectRejectsMismatchedOutcomeObjectID(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("revalidate-mismatch", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}

	_, err = store.RevalidateRetainedObject(ctx, input.ObjectID, validation.PersistenceInput{ValidatorVersion: "v2", CheckedAt: 5000}, func(domain.ObjectEnvelope) (validation.RevalidationResult, error) {
		return validation.RevalidationResult{Outcome: validation.NewOutcome("other-object", validation.StatusValid)}, nil
	})
	if !errors.Is(err, validation.ErrRunnerOutcomeObjectID) {
		t.Fatalf("RevalidateRetainedObject() error = %v, want %v", err, validation.ErrRunnerOutcomeObjectID)
	}
}

func TestRevalidationPlannerRepublishAndReacquireStatusDecisions(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	tests := []struct {
		objectID  string
		status    validation.Status
		republish bool
		reacquire bool
	}{
		{"planner-pending-evicted", validation.StatusPendingPayloadEvicted, false, true},
		{"planner-invalid", validation.StatusInvalid, false, false},
		{"planner-valid", validation.StatusValid, true, false},
		{"planner-valid-tally", validation.StatusValidForTally, true, false},
		{"planner-conflicted", validation.StatusValidButConflicted, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.status.String(), func(t *testing.T) {
			input := defaultIngestInput(tt.objectID, domain.ValidationStatusValid)
			if _, err := store.IngestObject(ctx, input); err != nil {
				t.Fatalf("IngestObject() error = %v", err)
			}
			if tt.status != validation.StatusValid {
				outcome := validation.Outcome{ObjectID: tt.objectID, Status: tt.status}
				if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{Outcome: outcome, ValidatorVersion: "v2", CheckedAt: 4000}); err != nil {
					t.Fatalf("ApplyValidationOutcome() error = %v", err)
				}
			}

			status, ok, err := store.ValidationStatus(ctx, tt.objectID)
			if err != nil {
				t.Fatalf("ValidationStatus() error = %v", err)
			}
			if !ok || status != tt.status {
				t.Fatalf("ValidationStatus() = %q, %v; want %q, true", status, ok, tt.status)
			}

			plan, err := validation.PlanRepublishForStatus(status)
			if err != nil {
				t.Fatalf("PlanRepublishForStatus() error = %v", err)
			}
			if plan.ShouldRepublish != tt.republish || plan.ShouldReacquirePayload != tt.reacquire {
				t.Fatalf("PlanRepublishForStatus() = %+v, want republish=%v reacquire=%v", plan, tt.republish, tt.reacquire)
			}
		})
	}
}
