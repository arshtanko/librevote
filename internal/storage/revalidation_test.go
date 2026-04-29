package storage

import (
	"context"
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
