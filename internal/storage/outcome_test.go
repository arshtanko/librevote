package storage

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"librevote/internal/domain"
	"librevote/internal/validation"
)

func TestApplyValidationOutcomeInvalidDropsPayloadAndRecordsError(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("outcome-invalid", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}

	outcome := validation.NewOutcome(input.ObjectID, validation.StatusInvalid)
	outcome.ValidationErrorCode = "bad_signature"
	outcome.ValidationErrorReason = "signature verification failed"
	if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{Outcome: outcome, ValidatorVersion: "v2", CheckedAt: 4000}); err != nil {
		t.Fatalf("ApplyValidationOutcome() error = %v", err)
	}

	meta, err := store.ObjectMetadata(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() error = %v", err)
	}
	if meta.PayloadRetained {
		t.Fatal("payload_retained = true, want false")
	}
	if _, err := store.Payload(ctx, input.ObjectID); err == nil {
		t.Fatal("Payload() succeeded for invalid outcome, want error")
	}

	record, err := store.ValidationRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() error = %v", err)
	}
	if record.ValidationStatus != string(validation.StatusInvalid) || record.ValidationErrorCode != "bad_signature" || record.ValidationErrorMessage != "signature verification failed" || record.ValidatorVersion != "v2" || record.LastCheckedAt != 4000 {
		t.Fatalf("validation record = %+v", record)
	}

	invalid, err := store.InvalidObjectRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("InvalidObjectRecord() error = %v", err)
	}
	if invalid.ValidationErrorCode != "bad_signature" || invalid.SeenCount != 1 {
		t.Fatalf("invalid record = %+v", invalid)
	}
}

func TestApplyValidationOutcomePendingDependenciesReplacesDependencyRows(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("outcome-pending", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}

	outcome := validation.NewOutcome(input.ObjectID, validation.StatusPendingDependencies)
	outcome.Dependencies = []validation.Dependency{
		{Type: "election", ID: "election-1"},
		{Type: "tally_key_set", ID: "tks-1"},
	}
	if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{Outcome: outcome, ValidatorVersion: "v2", CheckedAt: 5000}); err != nil {
		t.Fatalf("ApplyValidationOutcome() error = %v", err)
	}

	record, err := store.ValidationRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() error = %v", err)
	}
	if record.ValidationStatus != string(validation.StatusPendingDependencies) {
		t.Fatalf("status = %q, want %q", record.ValidationStatus, validation.StatusPendingDependencies)
	}

	deps, err := store.Dependencies(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("dependency count = %d, want 2", len(deps))
	}
	want := map[string]string{"election": "election-1", "tally_key_set": "tks-1"}
	for _, dep := range deps {
		if want[dep.Type] != dep.ID {
			t.Fatalf("unexpected dependency %+v", dep)
		}
	}

	outcome = validation.Outcome{ObjectID: input.ObjectID, Status: validation.StatusValid}
	if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{Outcome: outcome, ValidatorVersion: "v3", CheckedAt: 6000}); err != nil {
		t.Fatalf("second ApplyValidationOutcome() error = %v", err)
	}
	deps, err = store.Dependencies(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() after valid error = %v", err)
	}
	if len(deps) != 0 {
		t.Fatalf("dependencies after valid outcome = %+v", deps)
	}
}

func TestApplyValidationOutcomePersistsConflictKeys(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("outcome-conflict", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}

	outcome := validation.Outcome{ObjectID: input.ObjectID, Status: validation.StatusValid}
	outcome.ConflictKeys = []validation.ConflictKey{{Group: "anonymous_ballot_conflict_key", Key: "election-1|nullifier-1"}}
	if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{Outcome: outcome, ValidatorVersion: "v2", CheckedAt: 7000}); err != nil {
		t.Fatalf("ApplyValidationOutcome() error = %v", err)
	}
	conflicts, err := store.ConflictMetadataForObject(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ConflictMetadataForObject() error = %v", err)
	}
	if len(conflicts) != 1 || conflicts[0].Group != outcome.ConflictKeys[0].Group || conflicts[0].Key != outcome.ConflictKeys[0].Key {
		t.Fatalf("conflicts = %+v", conflicts)
	}
}

func TestApplyValidationOutcomeRejectsUnsupportedScopeAndFlags(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("outcome-unsupported", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*validation.Outcome)
		wantErr string
	}{
		{
			name: "affected scope",
			mutate: func(outcome *validation.Outcome) {
				outcome.AffectedScope = validation.AffectedScope{Scope: domain.ScopeElectionID, ScopeID: "election-1"}
			},
			wantErr: "affected scope",
		},
		{
			name: "should republish",
			mutate: func(outcome *validation.Outcome) {
				outcome.ShouldRepublish = true
			},
			wantErr: "republish flag",
		},
		{
			name: "should recompute state",
			mutate: func(outcome *validation.Outcome) {
				outcome.ShouldRecomputeState = true
			},
			wantErr: "recompute-state flag",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcome := validation.Outcome{ObjectID: input.ObjectID, Status: validation.StatusValid}
			tt.mutate(&outcome)
			if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{Outcome: outcome, ValidatorVersion: "v2", CheckedAt: 7000}); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ApplyValidationOutcome() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestApplyValidationOutcomePreservesObjectPayloadPowAndSourceMetadata(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("outcome-preserve", domain.ValidationStatusPendingDependencies)
	input.ObjectPoW = []byte{0xaa, 0xbb}
	input.Dependencies = []Dependency{{Type: "election", ID: "election-1"}}
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

	outcome := validation.Outcome{ObjectID: input.ObjectID, Status: validation.StatusValid}
	if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{Outcome: outcome, ValidatorVersion: "v2", CheckedAt: 8000}); err != nil {
		t.Fatalf("ApplyValidationOutcome() error = %v", err)
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

func TestApplyValidationOutcomeRejectsMissingObjectID(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	outcome := validation.NewOutcome("", validation.StatusValid)
	if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{Outcome: outcome, ValidatorVersion: "v1", CheckedAt: 1000}); err == nil {
		t.Fatal("ApplyValidationOutcome() succeeded without object_id, want error")
	}
}

func TestApplyValidationOutcomeRejectsMissingExistingObjectRow(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	outcome := validation.Outcome{ObjectID: "missing-object", Status: validation.StatusValid}
	if err := store.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{Outcome: outcome, ValidatorVersion: "v1", CheckedAt: 1000}); err == nil || !strings.Contains(err.Error(), "object not found") {
		t.Fatalf("ApplyValidationOutcome() error = %v, want object not found", err)
	}
}
