package validation

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

type fakeRevalidationStore struct {
	objectIDs []string
	err       error
	got       Dependency
}

func (s *fakeRevalidationStore) ObjectsWaitingOnValidationDependency(_ context.Context, dependency Dependency) ([]string, error) {
	s.got = dependency
	if s.err != nil {
		return nil, s.err
	}
	return slices.Clone(s.objectIDs), nil
}

func TestRevalidationPlannerCandidatesForDependencyChange(t *testing.T) {
	store := &fakeRevalidationStore{objectIDs: []string{"object-a", "object-b"}}
	planner := RevalidationPlanner{Store: store}

	plan, err := planner.CandidatesForDependencyChange(context.Background(), Dependency{Type: "election", ID: "election-1"})
	if err != nil {
		t.Fatalf("CandidatesForDependencyChange() error = %v", err)
	}
	if !slices.Equal(plan.ObjectIDs, []string{"object-a", "object-b"}) {
		t.Fatalf("ObjectIDs = %+v, want object-a/object-b", plan.ObjectIDs)
	}
	if store.got != (Dependency{Type: "election", ID: "election-1"}) {
		t.Fatalf("dependency passed to store = %+v", store.got)
	}
}

func TestRevalidationPlannerRejectsIncompleteInput(t *testing.T) {
	tests := []struct {
		name    string
		planner RevalidationPlanner
		dep     Dependency
		wantErr string
	}{
		{name: "missing store", dep: Dependency{Type: "election", ID: "election-1"}, wantErr: "store"},
		{name: "missing type", planner: RevalidationPlanner{Store: &fakeRevalidationStore{}}, dep: Dependency{ID: "election-1"}, wantErr: "dependency type and id"},
		{name: "missing id", planner: RevalidationPlanner{Store: &fakeRevalidationStore{}}, dep: Dependency{Type: "election"}, wantErr: "dependency type and id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.planner.CandidatesForDependencyChange(context.Background(), tt.dep)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("CandidatesForDependencyChange() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestRevalidationPlannerPropagatesStoreError(t *testing.T) {
	wantErr := errors.New("storage read failed")
	planner := RevalidationPlanner{Store: &fakeRevalidationStore{err: wantErr}}

	_, err := planner.CandidatesForDependencyChange(context.Background(), Dependency{Type: "election", ID: "election-1"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("CandidatesForDependencyChange() error = %v, want %v", err, wantErr)
	}
}

func TestPlanRepublishForStatusUsesOnlyDocumentedStatuses(t *testing.T) {
	tests := []struct {
		status    Status
		republish bool
		reacquire bool
	}{
		{StatusPendingDependencies, false, false},
		{StatusPendingPayloadEvicted, false, true},
		{StatusValid, true, false},
		{StatusValidForTally, true, false},
		{StatusValidButConflicted, true, false},
		{StatusInvalid, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.status.String(), func(t *testing.T) {
			plan, err := PlanRepublishForStatus(tt.status)
			if err != nil {
				t.Fatalf("PlanRepublishForStatus() error = %v", err)
			}
			if plan.ShouldRepublish != tt.republish || plan.ShouldReacquirePayload != tt.reacquire {
				t.Fatalf("PlanRepublishForStatus() = %+v, want republish=%v reacquire=%v", plan, tt.republish, tt.reacquire)
			}
		})
	}
}

func TestPlanRepublishForStatusRejectsUndocumentedStatus(t *testing.T) {
	if _, err := PlanRepublishForStatus(Status("stale")); err == nil || !strings.Contains(err.Error(), "unknown validation status") {
		t.Fatalf("PlanRepublishForStatus(stale) error = %v, want unknown status error", err)
	}
}
