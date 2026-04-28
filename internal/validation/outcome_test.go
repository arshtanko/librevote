package validation

import (
	"testing"

	"librevote/internal/domain"
)

func TestNewOutcomeDerivesRepublishEligibility(t *testing.T) {
	tests := []struct {
		status Status
		want   bool
	}{
		{StatusValid, true},
		{StatusValidForTally, true},
		{StatusValidButConflicted, true},
		{StatusPendingDependencies, false},
		{StatusPendingPayloadEvicted, false},
		{StatusInvalid, false},
	}

	for _, tt := range tests {
		t.Run(tt.status.String(), func(t *testing.T) {
			outcome := NewOutcome("object-1", tt.status)
			if outcome.ObjectID != "object-1" {
				t.Fatalf("ObjectID = %q; want object-1", outcome.ObjectID)
			}
			if outcome.Status != tt.status {
				t.Fatalf("Status = %q; want %q", outcome.Status, tt.status)
			}
			if outcome.ShouldRepublish != tt.want {
				t.Fatalf("ShouldRepublish = %v; want %v", outcome.ShouldRepublish, tt.want)
			}
		})
	}
}

func TestOutcomeCarriesDocumentedData(t *testing.T) {
	outcome := NewOutcome("object-1", StatusPendingDependencies)
	outcome.ValidationErrorCode = "missing_dependency"
	outcome.ValidationErrorReason = "referenced election is not retained"
	outcome.Dependencies = []Dependency{{Type: "AnonymousElection", ID: "election-1"}}
	outcome.ConflictKeys = []ConflictKey{{Group: "anonymous_ballot_conflict_key", Key: "election-1|nullifier-1"}}
	outcome.AffectedScope = AffectedScope{Scope: domain.ScopeElectionID, ScopeID: "election-1"}
	outcome.ShouldRecomputeState = true

	if len(outcome.Dependencies) != 1 || outcome.Dependencies[0].ID != "election-1" {
		t.Fatalf("Dependencies = %+v; want election dependency", outcome.Dependencies)
	}
	if len(outcome.ConflictKeys) != 1 || outcome.ConflictKeys[0].Group != "anonymous_ballot_conflict_key" {
		t.Fatalf("ConflictKeys = %+v; want ballot conflict key", outcome.ConflictKeys)
	}
	if outcome.AffectedScope.Scope != domain.ScopeElectionID || outcome.AffectedScope.ScopeID != "election-1" {
		t.Fatalf("AffectedScope = %+v; want election scope", outcome.AffectedScope)
	}
	if !outcome.ShouldRecomputeState {
		t.Fatal("ShouldRecomputeState = false; want true")
	}
}
