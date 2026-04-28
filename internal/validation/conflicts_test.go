package validation

import (
	"reflect"
	"testing"
)

func TestClassifyConflictsSingletonNoOp(t *testing.T) {
	outcomes := []Outcome{
		conflictOutcome("object-1", StatusValid, ConflictKey{Group: "trustee_vote_conflict_key", Key: "selection-1|voter-1"}),
	}

	classified := ClassifyConflicts(outcomes)
	if len(classified) != 1 {
		t.Fatalf("len(classified) = %d; want 1", len(classified))
	}
	if classified[0].Status != StatusValid || !classified[0].ShouldRepublish {
		t.Fatalf("classified[0] = %+v; want valid republishable singleton", classified[0])
	}
	if outcomes[0].Status != StatusValid {
		t.Fatalf("input status mutated to %q", outcomes[0].Status)
	}
}

func TestClassifyConflictsMarksAllDistinctValidMembers(t *testing.T) {
	key := ConflictKey{Group: "anonymous_ballot_conflict_key", Key: "election-1|nullifier-1"}
	outcomes := []Outcome{
		conflictOutcome("object-b", StatusValid, key),
		conflictOutcome("object-a", StatusValid, key),
	}

	classified := ClassifyConflicts(outcomes)
	assertStatuses(t, classified, map[string]Status{
		"object-a": StatusValidButConflicted,
		"object-b": StatusValidButConflicted,
	})
	if classified[0].ObjectID != "object-a" || classified[1].ObjectID != "object-b" {
		t.Fatalf("classified order = %q, %q; want object_id order", classified[0].ObjectID, classified[1].ObjectID)
	}
}

func TestClassifyConflictsValidForTallyBecomesConflicted(t *testing.T) {
	key := ConflictKey{Group: "anonymous_ballot_conflict_key", Key: "election-1|nullifier-1"}
	outcomes := []Outcome{
		conflictOutcome("ballot-1", StatusValidForTally, key),
		conflictOutcome("ballot-2", StatusValid, key),
	}

	classified := ClassifyConflicts(outcomes)
	assertStatuses(t, classified, map[string]Status{
		"ballot-1": StatusValidButConflicted,
		"ballot-2": StatusValidButConflicted,
	})
}

func TestClassifyConflictsDoesNotUpgradeInvalidOrPending(t *testing.T) {
	key := ConflictKey{Group: "blind_token_request_conflict_key", Key: "election-1|voter-1"}
	outcomes := []Outcome{
		conflictOutcome("invalid-1", StatusInvalid, key),
		conflictOutcome("pending-1", StatusPendingDependencies, key),
		conflictOutcome("pending-2", StatusPendingPayloadEvicted, key),
		conflictOutcome("valid-1", StatusValid, key),
	}

	classified := ClassifyConflicts(outcomes)
	assertStatuses(t, classified, map[string]Status{
		"invalid-1": StatusInvalid,
		"pending-1": StatusPendingDependencies,
		"pending-2": StatusPendingPayloadEvicted,
		"valid-1":   StatusValid,
	})
}

func TestClassifyConflictsUsesDistinctObjectIDs(t *testing.T) {
	key := ConflictKey{Group: "trustee_consent_conflict_key", Key: "election-1|trustee-1"}
	outcomes := []Outcome{
		conflictOutcome("object-1", StatusValid, key),
		conflictOutcome("object-1", StatusValid, key),
	}

	classified := ClassifyConflicts(outcomes)
	for _, outcome := range classified {
		if outcome.Status != StatusValid {
			t.Fatalf("duplicate object_id outcome = %+v; want valid", outcome)
		}
	}
}

func TestClassifyConflictsDeepCopiesSliceFields(t *testing.T) {
	key := ConflictKey{Group: "trustee_vote_conflict_key", Key: "selection-1|voter-1"}
	outcomes := []Outcome{conflictOutcome("object-1", StatusValid, key)}
	outcomes[0].Dependencies = []Dependency{{Type: "dep", ID: "dep-1"}}

	classified := ClassifyConflicts(outcomes)
	classified[0].ConflictKeys[0].Key = "changed"
	classified[0].Dependencies[0].ID = "changed"

	if outcomes[0].ConflictKeys[0].Key != key.Key {
		t.Fatalf("input conflict key mutated to %q", outcomes[0].ConflictKeys[0].Key)
	}
	if outcomes[0].Dependencies[0].ID != "dep-1" {
		t.Fatalf("input dependency mutated to %q", outcomes[0].Dependencies[0].ID)
	}
}

func TestClassifyConflictsOrdersDuplicateObjectIDsDeterministically(t *testing.T) {
	key := ConflictKey{Group: "trustee_consent_conflict_key", Key: "election-1|trustee-1"}
	first := []Outcome{
		conflictOutcome("object-1", StatusValid, key),
		conflictOutcome("object-1", StatusPendingDependencies, key),
	}
	second := []Outcome{
		conflictOutcome("object-1", StatusPendingDependencies, key),
		conflictOutcome("object-1", StatusValid, key),
	}

	classifiedFirst := ClassifyConflicts(first)
	classifiedSecond := ClassifyConflicts(second)
	if !reflect.DeepEqual(classifiedFirst, classifiedSecond) {
		t.Fatalf("classification differs for duplicate object ids:\nfirst=%+v\nsecond=%+v", classifiedFirst, classifiedSecond)
	}
}

func TestClassifyConflictsDeterministicResults(t *testing.T) {
	key := ConflictKey{Group: "tally_decryption_share_conflict_key", Key: "election-1|tally-hash|trustee-1"}
	first := []Outcome{
		conflictOutcome("object-c", StatusValid, ConflictKey{Group: "other", Key: "singleton"}),
		conflictOutcome("object-b", StatusValid, key),
		conflictOutcome("object-a", StatusValidForTally, key),
	}
	second := []Outcome{
		conflictOutcome("object-a", StatusValidForTally, key),
		conflictOutcome("object-c", StatusValid, ConflictKey{Group: "other", Key: "singleton"}),
		conflictOutcome("object-b", StatusValid, key),
	}

	classifiedFirst := ClassifyConflicts(first)
	classifiedSecond := ClassifyConflicts(second)
	if !reflect.DeepEqual(classifiedFirst, classifiedSecond) {
		t.Fatalf("classification differs:\nfirst=%+v\nsecond=%+v", classifiedFirst, classifiedSecond)
	}
	assertStatuses(t, classifiedFirst, map[string]Status{
		"object-a": StatusValidButConflicted,
		"object-b": StatusValidButConflicted,
		"object-c": StatusValid,
	})
}

func conflictOutcome(objectID string, status Status, keys ...ConflictKey) Outcome {
	outcome := NewOutcome(objectID, status)
	outcome.ConflictKeys = keys
	return outcome
}

func assertStatuses(t *testing.T, outcomes []Outcome, want map[string]Status) {
	t.Helper()
	if len(outcomes) != len(want) {
		t.Fatalf("len(outcomes) = %d; want %d", len(outcomes), len(want))
	}
	for _, outcome := range outcomes {
		if outcome.Status != want[outcome.ObjectID] {
			t.Fatalf("status for %q = %q; want %q", outcome.ObjectID, outcome.Status, want[outcome.ObjectID])
		}
	}
}
