package storage

import (
	"context"
	"slices"
	"testing"

	"librevote/internal/domain"
	"librevote/internal/validation"
)

func TestRepublishEligibleObjectsListsOnlyDocumentedStatuses(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	validB := defaultIngestInput("worklist-valid-b", domain.ValidationStatusValid)
	validB.CreatedAt = 30
	if _, err := store.IngestObject(ctx, validB); err != nil {
		t.Fatalf("IngestObject(validB) error = %v", err)
	}

	validForTally := defaultIngestInput("worklist-valid-tally", domain.ValidationStatusValidForTally)
	validForTally.CreatedAt = 20
	if _, err := store.IngestObject(ctx, validForTally); err != nil {
		t.Fatalf("IngestObject(validForTally) error = %v", err)
	}

	conflicted := defaultIngestInput("worklist-conflicted", domain.ValidationStatusValidButConflicted)
	conflicted.CreatedAt = 20
	if _, err := store.IngestObject(ctx, conflicted); err != nil {
		t.Fatalf("IngestObject(conflicted) error = %v", err)
	}

	pending := defaultIngestInput("worklist-pending", domain.ValidationStatusPendingDependencies)
	pending.Dependencies = []Dependency{{Type: "election", ID: "election-1"}}
	if _, err := store.IngestObject(ctx, pending); err != nil {
		t.Fatalf("IngestObject(pending) error = %v", err)
	}

	evicted := defaultIngestInput("worklist-evicted", domain.ValidationStatusPendingDependencies)
	evicted.Dependencies = []Dependency{{Type: "election", ID: "election-2"}}
	if _, err := store.IngestObject(ctx, evicted); err != nil {
		t.Fatalf("IngestObject(evicted) error = %v", err)
	}
	if err := store.EvictPendingPayload(ctx, evicted.ObjectID, 4000, "v2"); err != nil {
		t.Fatalf("EvictPendingPayload() error = %v", err)
	}

	invalid := defaultIngestInput("worklist-invalid", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, invalid); err != nil {
		t.Fatalf("IngestObject(invalid) error = %v", err)
	}
	if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{
		Outcome:          validation.Outcome{ObjectID: invalid.ObjectID, Status: validation.StatusInvalid},
		ValidatorVersion: "v2",
		CheckedAt:        5000,
	}); err != nil {
		t.Fatalf("ApplyValidationOutcome(invalid) error = %v", err)
	}

	got, err := store.RepublishEligibleObjects(ctx)
	if err != nil {
		t.Fatalf("RepublishEligibleObjects() error = %v", err)
	}
	wantIDs := []string{"worklist-conflicted", "worklist-valid-tally", "worklist-valid-b"}
	if !slices.Equal(worklistObjectIDs(got), wantIDs) {
		t.Fatalf("RepublishEligibleObjects() ids = %+v, want %+v", worklistObjectIDs(got), wantIDs)
	}

	for _, item := range got {
		if !item.ValidationStatus.RepublishEligible() {
			t.Fatalf("republish item has status %q", item.ValidationStatus)
		}
		if !item.ShouldRepublish {
			t.Fatalf("republish item missing persisted flag: %+v", item)
		}
		if item.ObjectID == evicted.ObjectID || item.ObjectID == invalid.ObjectID || item.ObjectID == pending.ObjectID {
			t.Fatalf("non-republishable object listed: %+v", item)
		}
	}
}

func TestRecomputeStateObjectsListsPersistedOutcomeFlags(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	flagged := defaultIngestInput("worklist-recompute", domain.ValidationStatusValid)
	flagged.AffectedScope = validation.AffectedScope{Scope: domain.ScopeElectionID, ScopeID: "election-1"}
	flagged.ShouldRecomputeState = true
	if _, err := store.IngestObject(ctx, flagged); err != nil {
		t.Fatalf("IngestObject(flagged) error = %v", err)
	}

	unflagged := defaultIngestInput("worklist-no-recompute", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, unflagged); err != nil {
		t.Fatalf("IngestObject(unflagged) error = %v", err)
	}

	got, err := store.RecomputeStateObjects(ctx)
	if err != nil {
		t.Fatalf("RecomputeStateObjects() error = %v", err)
	}
	if len(got) != 1 || got[0].ObjectID != flagged.ObjectID || got[0].AffectedScope != flagged.AffectedScope || !got[0].ShouldRecomputeState {
		t.Fatalf("RecomputeStateObjects() = %+v, want only flagged object", got)
	}
}

func TestPayloadReacquireObjectsListsEvictedPendingWithoutPayload(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	evictedB := defaultIngestInput("worklist-reacquire-b", domain.ValidationStatusPendingDependencies)
	evictedB.CreatedAt = 30
	evictedB.Dependencies = []Dependency{{Type: "election", ID: "election-1"}}
	if _, err := store.IngestObject(ctx, evictedB); err != nil {
		t.Fatalf("IngestObject(evictedB) error = %v", err)
	}
	if err := store.EvictPendingPayload(ctx, evictedB.ObjectID, 4000, "v2"); err != nil {
		t.Fatalf("EvictPendingPayload(evictedB) error = %v", err)
	}

	evictedA := defaultIngestInput("worklist-reacquire-a", domain.ValidationStatusPendingDependencies)
	evictedA.CreatedAt = 20
	evictedA.Dependencies = []Dependency{{Type: "election", ID: "election-2"}}
	if _, err := store.IngestObject(ctx, evictedA); err != nil {
		t.Fatalf("IngestObject(evictedA) error = %v", err)
	}
	if err := store.EvictPendingPayload(ctx, evictedA.ObjectID, 5000, "v2"); err != nil {
		t.Fatalf("EvictPendingPayload(evictedA) error = %v", err)
	}

	valid := defaultIngestInput("worklist-reacquire-valid", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, valid); err != nil {
		t.Fatalf("IngestObject(valid) error = %v", err)
	}

	invalid := defaultIngestInput("worklist-reacquire-invalid", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, invalid); err != nil {
		t.Fatalf("IngestObject(invalid) error = %v", err)
	}
	if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{
		Outcome:          validation.Outcome{ObjectID: invalid.ObjectID, Status: validation.StatusInvalid},
		ValidatorVersion: "v2",
		CheckedAt:        6000,
	}); err != nil {
		t.Fatalf("ApplyValidationOutcome(invalid) error = %v", err)
	}

	got, err := store.PayloadReacquireObjects(ctx)
	if err != nil {
		t.Fatalf("PayloadReacquireObjects() error = %v", err)
	}
	wantIDs := []string{"worklist-reacquire-a", "worklist-reacquire-b"}
	if !slices.Equal(worklistObjectIDs(got), wantIDs) {
		t.Fatalf("PayloadReacquireObjects() ids = %+v, want %+v", worklistObjectIDs(got), wantIDs)
	}

	for _, item := range got {
		if item.ValidationStatus != validation.StatusPendingPayloadEvicted {
			t.Fatalf("reacquire item status = %q, want %q", item.ValidationStatus, validation.StatusPendingPayloadEvicted)
		}
		if item.PayloadRetained {
			t.Fatalf("reacquire item retained payload: %+v", item)
		}
	}

	input := evictedA
	input.ValidationStatus = domain.ValidationStatusValid
	input.Dependencies = nil
	input.SeenAt = 7000
	input.CheckedAt = 8000
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("reacquire IngestObject() error = %v", err)
	}

	got, err = store.PayloadReacquireObjects(ctx)
	if err != nil {
		t.Fatalf("PayloadReacquireObjects() after reacquire error = %v", err)
	}
	wantIDs = []string{"worklist-reacquire-b"}
	if !slices.Equal(worklistObjectIDs(got), wantIDs) {
		t.Fatalf("PayloadReacquireObjects() after reacquire ids = %+v, want %+v", worklistObjectIDs(got), wantIDs)
	}
}

func worklistObjectIDs(items []WorklistObject) []string {
	ids := make([]string, len(items))
	for i, item := range items {
		ids[i] = item.ObjectID
	}
	return ids
}
