package storage

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"librevote/internal/domain"
	"librevote/internal/validation"
)

func TestConflictMetadataAPIsPersistAndQueryDeterministically(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("conflict-api", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}

	conflicts := []ConflictMetadata{
		{ObjectID: input.ObjectID, Group: "trustee_vote_conflict_key", Key: "selection-1|voter-1"},
		{ObjectID: input.ObjectID, Group: "anonymous_ballot_conflict_key", Key: "election-1|nullifier-1"},
	}
	if err := store.ReplaceConflictMetadata(ctx, input.ObjectID, conflicts); err != nil {
		t.Fatalf("ReplaceConflictMetadata() error = %v", err)
	}

	got, err := store.ConflictMetadataForObject(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ConflictMetadataForObject() error = %v", err)
	}
	if len(got) != 2 || got[0].Group != "anonymous_ballot_conflict_key" || got[1].Group != "trustee_vote_conflict_key" {
		t.Fatalf("conflict metadata = %+v", got)
	}

	objectIDs, err := store.ObjectsInConflictGroup(ctx, conflicts[0].Group, conflicts[0].Key)
	if err != nil {
		t.Fatalf("ObjectsInConflictGroup() error = %v", err)
	}
	if len(objectIDs) != 1 || objectIDs[0] != input.ObjectID {
		t.Fatalf("conflict group object ids = %+v", objectIDs)
	}
}

func TestConflictMetadataAPIsRejectInvalidInput(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	if err := store.ReplaceConflictMetadata(ctx, "", nil); err == nil {
		t.Fatal("ReplaceConflictMetadata() succeeded without object_id, want error")
	}
	if err := store.ReplaceConflictMetadata(ctx, "object-1", []ConflictMetadata{{Group: "", Key: "key-1"}}); err == nil {
		t.Fatal("ReplaceConflictMetadata() succeeded without conflict group, want error")
	}
	if err := store.ReplaceConflictMetadata(ctx, "object-1", []ConflictMetadata{{ObjectID: "other-object", Group: "group-1", Key: "key-1"}}); err == nil {
		t.Fatal("ReplaceConflictMetadata() succeeded with mismatched conflict object_id, want error")
	}
	if _, err := store.ConflictMetadataForObject(ctx, ""); err == nil {
		t.Fatal("ConflictMetadataForObject() succeeded without object_id, want error")
	}
	if _, err := store.ObjectsInConflictGroup(ctx, "", "key-1"); err == nil {
		t.Fatal("ObjectsInConflictGroup() succeeded without group, want error")
	}
}

func TestReplaceConflictMetadataRejectsNonUsableValidationStatuses(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	tests := []struct {
		name   string
		status domain.ValidationStatus
		mutate func(*IngestObjectInput)
	}{
		{
			name:   "pending dependencies",
			status: domain.ValidationStatusPendingDependencies,
			mutate: func(input *IngestObjectInput) {
				input.Dependencies = []Dependency{{Type: "election", ID: "election-1"}}
			},
		},
		{
			name:   "pending payload evicted",
			status: domain.ValidationStatusPendingDependencies,
			mutate: func(input *IngestObjectInput) {
				input.Dependencies = []Dependency{{Type: "election", ID: "election-1"}}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := defaultIngestInput("conflict-non-usable-"+strings.ReplaceAll(tc.name, " ", "-"), tc.status)
			if tc.mutate != nil {
				tc.mutate(&input)
			}
			if _, err := store.IngestObject(ctx, input); err != nil {
				t.Fatalf("IngestObject() error = %v", err)
			}
			if tc.name == "pending payload evicted" {
				if err := store.EvictPendingPayload(ctx, input.ObjectID, 4000, "v2"); err != nil {
					t.Fatalf("EvictPendingPayload() error = %v", err)
				}
			}

			err := store.ReplaceConflictMetadata(ctx, input.ObjectID, []ConflictMetadata{{Group: "group-1", Key: "key-1"}})
			if err == nil {
				t.Fatal("ReplaceConflictMetadata() succeeded for non-usable status, want error")
			}
			if !strings.Contains(err.Error(), "requires usable validation status") {
				t.Fatalf("ReplaceConflictMetadata() error = %v, want usable status error", err)
			}
			conflicts, err := store.ConflictMetadataForObject(ctx, input.ObjectID)
			if err != nil {
				t.Fatalf("ConflictMetadataForObject() error = %v", err)
			}
			if len(conflicts) != 0 {
				t.Fatalf("conflicts = %+v, want none", conflicts)
			}
		})
	}
}

func TestReplaceConflictMetadataRejectsInvalidValidationStatus(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("conflict-invalid-existing", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}
	outcome := validation.Outcome{ObjectID: input.ObjectID, Status: validation.StatusInvalid, ValidationErrorCode: "bad"}
	if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{Outcome: outcome, ValidatorVersion: "v2", CheckedAt: 4000}); err != nil {
		t.Fatalf("ApplyValidationOutcome() error = %v", err)
	}

	err = store.ReplaceConflictMetadata(ctx, input.ObjectID, []ConflictMetadata{{Group: "group-1", Key: "key-1"}})
	if err == nil {
		t.Fatal("ReplaceConflictMetadata() succeeded for invalid status, want error")
	}
	if !strings.Contains(err.Error(), "requires usable validation status") {
		t.Fatalf("ReplaceConflictMetadata() error = %v, want usable status error", err)
	}
	conflicts, err := store.ConflictMetadataForObject(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ConflictMetadataForObject() error = %v", err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("conflicts = %+v, want none", conflicts)
	}
}

func TestConflictMetadataPreservesObjectPayloadPowAndSourceMetadata(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("conflict-api-preserve", domain.ValidationStatusValid)
	input.ObjectPoW = []byte{0xcc, 0xdd}
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}
	if err := store.RecordObjectSource(ctx, input.ObjectID, "peer-1", 3500); err != nil {
		t.Fatalf("RecordObjectSource() error = %v", err)
	}

	beforeMeta, err := store.ObjectMetadata(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() before error = %v", err)
	}
	beforePayload, err := store.Payload(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Payload() before error = %v", err)
	}
	beforeSources, err := store.ObjectSources(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectSources() before error = %v", err)
	}

	conflicts := []ConflictMetadata{{Group: "anonymous_ballot_conflict_key", Key: "election-1|nullifier-1"}}
	if err := store.ReplaceConflictMetadata(ctx, input.ObjectID, conflicts); err != nil {
		t.Fatalf("ReplaceConflictMetadata() error = %v", err)
	}

	afterMeta, err := store.ObjectMetadata(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() after error = %v", err)
	}
	afterPayload, err := store.Payload(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Payload() after error = %v", err)
	}
	afterSources, err := store.ObjectSources(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectSources() after error = %v", err)
	}

	if beforeMeta.ObjectID != afterMeta.ObjectID || beforeMeta.PayloadRetained != afterMeta.PayloadRetained || !bytes.Equal(beforeMeta.ObjectPoW, afterMeta.ObjectPoW) || !bytes.Equal(beforeMeta.PayloadHash, afterMeta.PayloadHash) {
		t.Fatalf("object metadata mutated: before=%+v after=%+v", beforeMeta, afterMeta)
	}
	if !bytes.Equal(beforePayload, afterPayload) {
		t.Fatal("payload mutated")
	}
	if len(afterSources) != len(beforeSources) || afterSources[0] != beforeSources[0] {
		t.Fatalf("source metadata mutated: before=%+v after=%+v", beforeSources, afterSources)
	}
}

func TestConflictClassificationMarksWholeGroupConflictedAndRepublishEligible(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	key := ConflictMetadata{Group: "trustee_consent_conflict_key", Key: "election-1|trustee-1"}
	first := defaultIngestInput("conflict-group-1", domain.ValidationStatusValid)
	first.ConflictKeys = []ConflictMetadata{key}
	if _, err := store.IngestObject(ctx, first); err != nil {
		t.Fatalf("first IngestObject() error = %v", err)
	}
	second := defaultIngestInput("conflict-group-2", domain.ValidationStatusValid)
	second.ConflictKeys = []ConflictMetadata{key}
	if _, err := store.IngestObject(ctx, second); err != nil {
		t.Fatalf("second IngestObject() error = %v", err)
	}

	for _, objectID := range []string{first.ObjectID, second.ObjectID} {
		record, err := store.ValidationRecord(ctx, objectID)
		if err != nil {
			t.Fatalf("ValidationRecord(%s) error = %v", objectID, err)
		}
		status, err := validation.ParseStatus(record.ValidationStatus)
		if err != nil {
			t.Fatalf("ParseStatus(%s) error = %v", record.ValidationStatus, err)
		}
		if status != validation.StatusValidButConflicted || !status.RepublishEligible() {
			t.Fatalf("status for %s = %s, republish=%v; want valid_but_conflicted republish-eligible", objectID, status, status.RepublishEligible())
		}
	}
}

func TestApplyValidationOutcomeMarksExistingObjectsWithSameConflictKeyConflicted(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	first := defaultIngestInput("outcome-conflict-group-1", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, first); err != nil {
		t.Fatalf("first IngestObject() error = %v", err)
	}
	second := defaultIngestInput("outcome-conflict-group-2", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, second); err != nil {
		t.Fatalf("second IngestObject() error = %v", err)
	}

	key := validation.ConflictKey{Group: "trustee_vote_conflict_key", Key: "selection-1|voter-1"}
	for i, objectID := range []string{first.ObjectID, second.ObjectID} {
		outcome := validation.Outcome{ObjectID: objectID, Status: validation.StatusValid, ConflictKeys: []validation.ConflictKey{key}}
		if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{Outcome: outcome, ValidatorVersion: "v2", CheckedAt: int64(5000 + i)}); err != nil {
			t.Fatalf("ApplyValidationOutcome(%s) error = %v", objectID, err)
		}
	}

	for _, objectID := range []string{first.ObjectID, second.ObjectID} {
		record, err := store.ValidationRecord(ctx, objectID)
		if err != nil {
			t.Fatalf("ValidationRecord(%s) error = %v", objectID, err)
		}
		if record.ValidationStatus != validation.StatusValidButConflicted.String() {
			t.Fatalf("status for %s = %q, want valid_but_conflicted", objectID, record.ValidationStatus)
		}
	}
}

func TestReplaceConflictMetadataMarksExistingObjectsWithSameConflictKeyConflicted(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	first := defaultIngestInput("replace-conflict-group-1", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, first); err != nil {
		t.Fatalf("first IngestObject() error = %v", err)
	}
	second := defaultIngestInput("replace-conflict-group-2", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, second); err != nil {
		t.Fatalf("second IngestObject() error = %v", err)
	}

	key := ConflictMetadata{Group: "trustee_vote_conflict_key", Key: "selection-1|voter-1"}
	for _, objectID := range []string{first.ObjectID, second.ObjectID} {
		if err := store.ReplaceConflictMetadata(ctx, objectID, []ConflictMetadata{key}); err != nil {
			t.Fatalf("ReplaceConflictMetadata(%s) error = %v", objectID, err)
		}
	}

	for _, objectID := range []string{first.ObjectID, second.ObjectID} {
		record, err := store.ValidationRecord(ctx, objectID)
		if err != nil {
			t.Fatalf("ValidationRecord(%s) error = %v", objectID, err)
		}
		if record.ValidationStatus != validation.StatusValidButConflicted.String() {
			t.Fatalf("status for %s = %q, want valid_but_conflicted", objectID, record.ValidationStatus)
		}
	}
}

func TestReplaceConflictMetadataClearingOneObjectRestoresSingletonSurvivor(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	key := ConflictMetadata{Group: "anonymous_ballot_conflict_key", Key: "election-1|nullifier-1"}
	first := defaultIngestInput("replace-conflict-survivor-1", domain.ValidationStatusValidForTally)
	if _, err := store.IngestObject(ctx, first); err != nil {
		t.Fatalf("first IngestObject() error = %v", err)
	}
	second := defaultIngestInput("replace-conflict-survivor-2", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, second); err != nil {
		t.Fatalf("second IngestObject() error = %v", err)
	}

	for _, objectID := range []string{first.ObjectID, second.ObjectID} {
		if err := store.ReplaceConflictMetadata(ctx, objectID, []ConflictMetadata{key}); err != nil {
			t.Fatalf("ReplaceConflictMetadata(%s) add error = %v", objectID, err)
		}
	}
	if err := store.ReplaceConflictMetadata(ctx, second.ObjectID, nil); err != nil {
		t.Fatalf("ReplaceConflictMetadata() clear error = %v", err)
	}

	survivorRecord, err := store.ValidationRecord(ctx, first.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() survivor error = %v", err)
	}
	if survivorRecord.ValidationStatus != validation.StatusValidForTally.String() {
		t.Fatalf("survivor status = %q, want valid_for_tally", survivorRecord.ValidationStatus)
	}
	clearedRecord, err := store.ValidationRecord(ctx, second.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() cleared error = %v", err)
	}
	if clearedRecord.ValidationStatus != validation.StatusValid.String() {
		t.Fatalf("cleared status = %q, want valid", clearedRecord.ValidationStatus)
	}
	conflicts, err := store.ConflictMetadataForObject(ctx, second.ObjectID)
	if err != nil {
		t.Fatalf("ConflictMetadataForObject() cleared error = %v", err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("cleared object conflicts = %+v, want none", conflicts)
	}
}

func TestReplaceConflictMetadataDoesNotRestoreObjectStillConflictedThroughOtherKey(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	removedKey := ConflictMetadata{Group: "anonymous_ballot_conflict_key", Key: "election-1|nullifier-1"}
	remainingKey := ConflictMetadata{Group: "trustee_vote_conflict_key", Key: "selection-1|voter-1"}
	first := defaultIngestInput("replace-conflict-retained-1", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, first); err != nil {
		t.Fatalf("first IngestObject() error = %v", err)
	}
	second := defaultIngestInput("replace-conflict-retained-2", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, second); err != nil {
		t.Fatalf("second IngestObject() error = %v", err)
	}
	third := defaultIngestInput("replace-conflict-retained-3", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, third); err != nil {
		t.Fatalf("third IngestObject() error = %v", err)
	}

	if err := store.ReplaceConflictMetadata(ctx, first.ObjectID, []ConflictMetadata{removedKey, remainingKey}); err != nil {
		t.Fatalf("ReplaceConflictMetadata(first) add error = %v", err)
	}
	if err := store.ReplaceConflictMetadata(ctx, second.ObjectID, []ConflictMetadata{removedKey}); err != nil {
		t.Fatalf("ReplaceConflictMetadata(second) add error = %v", err)
	}
	if err := store.ReplaceConflictMetadata(ctx, third.ObjectID, []ConflictMetadata{remainingKey}); err != nil {
		t.Fatalf("ReplaceConflictMetadata(third) add error = %v", err)
	}

	if err := store.ReplaceConflictMetadata(ctx, first.ObjectID, []ConflictMetadata{remainingKey}); err != nil {
		t.Fatalf("ReplaceConflictMetadata(first) replace error = %v", err)
	}

	record, err := store.ValidationRecord(ctx, first.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() first error = %v", err)
	}
	if record.ValidationStatus != validation.StatusValidButConflicted.String() {
		t.Fatalf("first status = %q, want valid_but_conflicted", record.ValidationStatus)
	}
}

func TestConflictClassificationRestoresSingletonSurvivorBaseStatus(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	key := ConflictMetadata{Group: "anonymous_ballot_conflict_key", Key: "election-1|nullifier-1"}
	first := defaultIngestInput("conflict-survivor-1", domain.ValidationStatusValidForTally)
	first.ConflictKeys = []ConflictMetadata{key}
	if _, err := store.IngestObject(ctx, first); err != nil {
		t.Fatalf("first IngestObject() error = %v", err)
	}
	second := defaultIngestInput("conflict-survivor-2", domain.ValidationStatusValid)
	second.ConflictKeys = []ConflictMetadata{key}
	if _, err := store.IngestObject(ctx, second); err != nil {
		t.Fatalf("second IngestObject() error = %v", err)
	}

	invalid := validation.Outcome{ObjectID: second.ObjectID, Status: validation.StatusInvalid, ValidationErrorCode: "bad"}
	if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{Outcome: invalid, ValidatorVersion: "v2", CheckedAt: 5000}); err != nil {
		t.Fatalf("ApplyValidationOutcome() invalid error = %v", err)
	}

	record, err := store.ValidationRecord(ctx, first.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() survivor error = %v", err)
	}
	if record.ValidationStatus != validation.StatusValidForTally.String() {
		t.Fatalf("survivor status = %q, want valid_for_tally", record.ValidationStatus)
	}
	conflicts, err := store.ConflictMetadataForObject(ctx, second.ObjectID)
	if err != nil {
		t.Fatalf("ConflictMetadataForObject() invalidated error = %v", err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("invalidated object conflicts = %+v, want none", conflicts)
	}
}

func TestSingletonConflictKeyRemainsValid(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("conflict-singleton", domain.ValidationStatusValid)
	input.ConflictKeys = []ConflictMetadata{{Group: "tally_key_contribution_conflict_key", Key: "election-1|trustee-1"}}
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}
	record, err := store.ValidationRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() error = %v", err)
	}
	if record.ValidationStatus != string(validation.StatusValid) {
		t.Fatalf("status = %q, want valid", record.ValidationStatus)
	}
}

func TestConflictKeyRowsRemovedWhenOutcomeBecomesUnusable(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("conflict-stale", domain.ValidationStatusValid)
	input.ConflictKeys = []ConflictMetadata{{Group: "trustee_consent_conflict_key", Key: "election-1|trustee-1"}}
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}

	outcome := validation.Outcome{ObjectID: input.ObjectID, Status: validation.StatusPendingDependencies}
	outcome.Dependencies = []validation.Dependency{{Type: "election", ID: "election-1"}}
	if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{Outcome: outcome, ValidatorVersion: "v2", CheckedAt: 5000}); err != nil {
		t.Fatalf("ApplyValidationOutcome() pending error = %v", err)
	}
	conflicts, err := store.ConflictMetadataForObject(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ConflictMetadataForObject() pending error = %v", err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("conflicts after pending outcome = %+v", conflicts)
	}

	outcome = validation.Outcome{ObjectID: input.ObjectID, Status: validation.StatusInvalid, ValidationErrorCode: "bad"}
	if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{Outcome: outcome, ValidatorVersion: "v3", CheckedAt: 6000}); err != nil {
		t.Fatalf("ApplyValidationOutcome() invalid error = %v", err)
	}
	conflicts, err = store.ConflictMetadataForObject(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ConflictMetadataForObject() invalid error = %v", err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("conflicts after invalid outcome = %+v", conflicts)
	}
}
