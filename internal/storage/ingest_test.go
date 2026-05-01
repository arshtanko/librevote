package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"librevote/internal/domain"
)

func defaultIngestInput(objectID string, status domain.ValidationStatus) IngestObjectInput {
	return IngestObjectInput{
		ObjectID:         objectID,
		ObjectType:       string(domain.ObjectTypeAnonymousElection),
		ProtocolVersion:  1,
		NetworkID:        "testnet",
		Scope:            string(domain.ScopeNetwork),
		ScopeID:          "",
		CreatedAt:        1000,
		ObjectPoW:        []byte{0x01},
		PayloadBytes:     []byte("payload-" + objectID),
		ValidationStatus: status,
		ValidatorVersion: "v1",
		SeenAt:           2000,
		CheckedAt:        3000,
	}
}

func TestValidIngestRetainsPayloadAndValidationRecord(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("obj-valid-1", domain.ValidationStatusValid)
	res, err := store.IngestObject(ctx, input)
	if err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}
	if !res.Inserted {
		t.Fatalf("expected Inserted=true, got %+v", res)
	}

	meta, err := store.ObjectMetadata(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() error = %v", err)
	}
	if meta.ObjectType != input.ObjectType {
		t.Fatalf("object_type = %q, want %q", meta.ObjectType, input.ObjectType)
	}
	if meta.PayloadSize != len(input.PayloadBytes) {
		t.Fatalf("payload_size = %d, want %d", meta.PayloadSize, len(input.PayloadBytes))
	}
	wantHash := sha256.Sum256(input.PayloadBytes)
	if !bytes.Equal(meta.PayloadHash, wantHash[:]) {
		t.Fatalf("payload_hash mismatch")
	}
	if !meta.PayloadRetained {
		t.Fatalf("payload_retained = false, want true")
	}

	payload, err := store.Payload(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Payload() error = %v", err)
	}
	if !bytes.Equal(payload, input.PayloadBytes) {
		t.Fatalf("payload bytes mismatch")
	}

	vr, err := store.ValidationRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() error = %v", err)
	}
	if vr.ValidationStatus != string(domain.ValidationStatusValid) {
		t.Fatalf("validation_status = %q, want %q", vr.ValidationStatus, domain.ValidationStatusValid)
	}
	if vr.ValidatorVersion != input.ValidatorVersion {
		t.Fatalf("validator_version = %q, want %q", vr.ValidatorVersion, input.ValidatorVersion)
	}
}

func TestPendingDependenciesRequiresAndStoresDependencies(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	// Missing dependencies should fail.
	input := defaultIngestInput("obj-pending-1", domain.ValidationStatusPendingDependencies)
	input.Dependencies = nil
	_, err = store.IngestObject(ctx, input)
	if err == nil {
		t.Fatal("IngestObject() succeeded without dependencies, want error")
	}

	// With dependencies should succeed.
	input.Dependencies = []Dependency{
		{Type: "election", ID: "election-1"},
		{Type: "tally_key_set", ID: "tks-1"},
	}
	res, err := store.IngestObject(ctx, input)
	if err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}
	if !res.Inserted {
		t.Fatalf("expected Inserted=true, got %+v", res)
	}

	deps, err := store.Dependencies(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("dependency count = %d, want 2", len(deps))
	}
	want := map[string]string{"election": "election-1", "tally_key_set": "tks-1"}
	for _, d := range deps {
		if want[d.Type] != d.ID {
			t.Fatalf("unexpected dependency %+v", d)
		}
	}
}

func TestInvalidStoresInvalidObjectRecordsOnly(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("obj-invalid-1", domain.ValidationStatusInvalid)
	input.ValidationErrorCode = "ERR_SYNTAX"
	res, err := store.IngestObject(ctx, input)
	if err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}
	if !res.InvalidRecorded || res.Inserted || res.Duplicate {
		t.Fatalf("unexpected result %+v", res)
	}

	// No objects row.
	_, err = store.ObjectMetadata(ctx, input.ObjectID)
	if err == nil {
		t.Fatal("ObjectMetadata() succeeded for invalid object, want error")
	}

	// No validation record.
	_, err = store.ValidationRecord(ctx, input.ObjectID)
	if err == nil {
		t.Fatal("ValidationRecord() succeeded for invalid object, want error")
	}

	// No payload.
	_, err = store.Payload(ctx, input.ObjectID)
	if err == nil {
		t.Fatal("Payload() succeeded for invalid object, want error")
	}

	// Invalid record exists.
	ir, err := store.InvalidObjectRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("InvalidObjectRecord() error = %v", err)
	}
	if ir.ObjectType != input.ObjectType {
		t.Fatalf("object_type = %q, want %q", ir.ObjectType, input.ObjectType)
	}
	if ir.SeenCount != 1 {
		t.Fatalf("seen_count = %d, want 1", ir.SeenCount)
	}
	if ir.ValidationErrorCode != "ERR_SYNTAX" {
		t.Fatalf("validation_error_code = %q, want ERR_SYNTAX", ir.ValidationErrorCode)
	}
}

func TestInvalidRepeatIncrementsSeenCount(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("obj-invalid-repeat", domain.ValidationStatusInvalid)
	input.ValidationErrorCode = "ERR_FIRST"
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("first ingest error = %v", err)
	}

	input.SeenAt = 2500
	input.ValidationErrorCode = "ERR_SECOND"
	res, err := store.IngestObject(ctx, input)
	if err != nil {
		t.Fatalf("second ingest error = %v", err)
	}
	if !res.InvalidRecorded || !res.Duplicate {
		t.Fatalf("expected InvalidRecorded=true and Duplicate=true, got %+v", res)
	}

	ir, err := store.InvalidObjectRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("InvalidObjectRecord() error = %v", err)
	}
	if ir.SeenCount != 2 {
		t.Fatalf("seen_count = %d, want 2", ir.SeenCount)
	}
	if ir.LastSeenAt != 2500 {
		t.Fatalf("last_seen_at = %d, want 2500", ir.LastSeenAt)
	}
	if ir.ValidationErrorCode != "ERR_SECOND" {
		t.Fatalf("validation_error_code = %q, want ERR_SECOND", ir.ValidationErrorCode)
	}
}

func TestDuplicateMatchingPayloadUpdatesLastSeenAt(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("obj-dup-1", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("first ingest error = %v", err)
	}

	input.SeenAt = 5000
	input.CheckedAt = 6000
	res, err := store.IngestObject(ctx, input)
	if err != nil {
		t.Fatalf("second ingest error = %v", err)
	}
	if !res.Duplicate || res.Inserted {
		t.Fatalf("expected Duplicate=true, got %+v", res)
	}

	meta, err := store.ObjectMetadata(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() error = %v", err)
	}
	if meta.LastSeenAt != 5000 {
		t.Fatalf("last_seen_at = %d, want 5000", meta.LastSeenAt)
	}

	// Payload bytes must remain unchanged.
	payload, err := store.Payload(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Payload() error = %v", err)
	}
	if !bytes.Equal(payload, []byte("payload-obj-dup-1")) {
		t.Fatalf("payload bytes were overwritten")
	}
}

func TestDuplicateMismatchedPayloadReturnsErrPayloadMismatch(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("obj-mismatch-1", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("first ingest error = %v", err)
	}

	input.PayloadBytes = []byte("different-payload")
	_, err = store.IngestObject(ctx, input)
	if !errors.Is(err, ErrPayloadMismatch) {
		t.Fatalf("error = %v, want ErrPayloadMismatch", err)
	}
}

func TestPendingEvictionRemovesPayloadAndReacquireRestores(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("obj-evict-1", domain.ValidationStatusPendingDependencies)
	input.Dependencies = []Dependency{{Type: "election", ID: "election-1"}}
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("first ingest error = %v", err)
	}

	// Evict payload.
	if err := store.EvictPendingPayload(ctx, input.ObjectID, 4000, "v2"); err != nil {
		t.Fatalf("EvictPendingPayload() error = %v", err)
	}

	// Verify payload removed.
	meta, err := store.ObjectMetadata(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() error = %v", err)
	}
	if meta.PayloadRetained {
		t.Fatal("payload_retained = true after eviction")
	}

	_, err = store.Payload(ctx, input.ObjectID)
	if err == nil {
		t.Fatal("Payload() succeeded after eviction, want error")
	}

	vr, err := store.ValidationRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() error = %v", err)
	}
	if vr.ValidationStatus != string(domain.ValidationStatusPendingPayloadEvicted) {
		t.Fatalf("status = %q, want %q", vr.ValidationStatus, domain.ValidationStatusPendingPayloadEvicted)
	}

	deps, err := store.Dependencies(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 0 {
		t.Fatalf("dependency count = %d after eviction, want 0", len(deps))
	}

	// Reacquire with matching payload.
	input.ValidationStatus = domain.ValidationStatusValid
	input.Dependencies = nil
	input.SeenAt = 5000
	input.CheckedAt = 6000
	res, err := store.IngestObject(ctx, input)
	if err != nil {
		t.Fatalf("reacquire ingest error = %v", err)
	}
	if !res.Reacquired {
		t.Fatalf("expected Reacquired=true, got %+v", res)
	}

	meta, err = store.ObjectMetadata(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() after reacquire error = %v", err)
	}
	if !meta.PayloadRetained {
		t.Fatal("payload_retained = false after reacquire")
	}

	payload, err := store.Payload(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Payload() after reacquire error = %v", err)
	}
	if !bytes.Equal(payload, input.PayloadBytes) {
		t.Fatalf("payload bytes mismatch after reacquire")
	}

	vr, err = store.ValidationRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() after reacquire error = %v", err)
	}
	if vr.ValidationStatus != string(domain.ValidationStatusValid) {
		t.Fatalf("status = %q after reacquire, want %q", vr.ValidationStatus, domain.ValidationStatusValid)
	}
}

func TestTransactionFailureLeavesNoPartialRows(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	// Install a trigger that will abort any insert into validation_records.
	triggerSQL := `
	CREATE TRIGGER test_abort_validation_insert
	AFTER INSERT ON validation_records
	BEGIN
		SELECT RAISE(ABORT, 'simulated validation failure');
	END;`
	if _, err := store.db.ExecContext(ctx, triggerSQL); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	input := defaultIngestObjectInput("obj-tx-fail-1", domain.ValidationStatusValid)
	_, err = store.IngestObject(ctx, input)
	if err == nil {
		t.Fatal("IngestObject() succeeded, want error from trigger")
	}

	// Verify no partial rows remain.
	_, err = store.ObjectMetadata(ctx, input.ObjectID)
	if err == nil {
		t.Fatal("ObjectMetadata() succeeded after failed transaction, want error")
	}
	_, err = store.Payload(ctx, input.ObjectID)
	if err == nil {
		t.Fatal("Payload() succeeded after failed transaction, want error")
	}

	// Clean up trigger for cleanliness (not strictly required).
	if _, err := store.db.ExecContext(ctx, "DROP TRIGGER test_abort_validation_insert"); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
}

func TestDependencyReplacementAndRemoval(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	// Ingest as pending with two dependencies.
	input := defaultIngestInput("obj-deps-1", domain.ValidationStatusPendingDependencies)
	input.Dependencies = []Dependency{
		{Type: "election", ID: "election-1"},
		{Type: "trustee_selection", ID: "ts-1"},
	}
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("first ingest error = %v", err)
	}

	// Re-ingestion of a pending object with updated dependencies replaces them
	// so that the latest validation outcome is reflected.
	input.Dependencies = []Dependency{
		{Type: "election", ID: "election-2"},
	}
	res, err := store.IngestObject(ctx, input)
	if err != nil {
		t.Fatalf("second ingest error = %v", err)
	}
	if !res.Reacquired || !res.Updated {
		t.Fatalf("expected Reacquired=true and Updated=true, got %+v", res)
	}

	deps, err := store.Dependencies(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("dependency count after update = %d, want 1", len(deps))
	}
	if deps[0].Type != "election" || deps[0].ID != "election-2" {
		t.Fatalf("dependencies not updated: %+v", deps)
	}

	// Evict and reacquire as valid: dependencies should be removed.
	if err := store.EvictPendingPayload(ctx, input.ObjectID, 4000, "v2"); err != nil {
		t.Fatalf("EvictPendingPayload() error = %v", err)
	}
	input.ValidationStatus = domain.ValidationStatusValid
	input.Dependencies = nil
	input.SeenAt = 5000
	input.CheckedAt = 6000
	res, err = store.IngestObject(ctx, input)
	if err != nil {
		t.Fatalf("reacquire ingest error = %v", err)
	}
	if !res.Reacquired || !res.Updated {
		t.Fatalf("expected Reacquired=true and Updated=true, got %+v", res)
	}

	deps, err = store.Dependencies(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() after removal error = %v", err)
	}
	if len(deps) != 0 {
		t.Fatalf("dependency count = %d after removal, want 0", len(deps))
	}
}

func TestEvictPendingPayloadFailsForMissingObject(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	err = store.EvictPendingPayload(ctx, "missing-object", 1000, "v1")
	if err == nil {
		t.Fatal("EvictPendingPayload() succeeded for missing object, want error")
	}
}

func TestIngestObjectInputValidation(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	tests := []struct {
		name  string
		input IngestObjectInput
	}{
		{
			name: "missing object_id",
			input: func() IngestObjectInput {
				i := defaultIngestInput("x", domain.ValidationStatusValid)
				i.ObjectID = ""
				return i
			}(),
		},
		{
			name: "missing object_type",
			input: func() IngestObjectInput {
				i := defaultIngestInput("x", domain.ValidationStatusValid)
				i.ObjectType = ""
				return i
			}(),
		},
		{
			name: "missing network_id",
			input: func() IngestObjectInput {
				i := defaultIngestInput("x", domain.ValidationStatusValid)
				i.NetworkID = ""
				return i
			}(),
		},
		{
			name: "missing validator_version",
			input: func() IngestObjectInput {
				i := defaultIngestInput("x", domain.ValidationStatusValid)
				i.ValidatorVersion = ""
				return i
			}(),
		},
		{
			name: "zero seen_at",
			input: func() IngestObjectInput {
				i := defaultIngestInput("x", domain.ValidationStatusValid)
				i.SeenAt = 0
				return i
			}(),
		},
		{
			name: "zero checked_at",
			input: func() IngestObjectInput {
				i := defaultIngestInput("x", domain.ValidationStatusValid)
				i.CheckedAt = 0
				return i
			}(),
		},
		{
			name: "direct pending_payload_evicted",
			input: func() IngestObjectInput {
				i := defaultIngestInput("x", domain.ValidationStatusPendingPayloadEvicted)
				return i
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.IngestObject(ctx, tt.input)
			if err == nil {
				t.Fatal("IngestObject() succeeded, want error")
			}
		})
	}
}

func TestEvictPendingPayloadRejectsFinalStatuses(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	for _, status := range []domain.ValidationStatus{
		domain.ValidationStatusValid,
		domain.ValidationStatusValidForTally,
		domain.ValidationStatusValidButConflicted,
	} {
		objectID := fmt.Sprintf("obj-evict-final-%s", status)
		input := defaultIngestInput(objectID, status)
		if _, err := store.IngestObject(ctx, input); err != nil {
			t.Fatalf("IngestObject(%s) error = %v", status, err)
		}

		err := store.EvictPendingPayload(ctx, objectID, 4000, "v2")
		if !errors.Is(err, ErrNotPending) {
			t.Fatalf("EvictPendingPayload(%s) error = %v, want ErrNotPending", status, err)
		}

		meta, err := store.ObjectMetadata(ctx, objectID)
		if err != nil {
			t.Fatalf("ObjectMetadata(%s) error = %v", status, err)
		}
		if !meta.PayloadRetained {
			t.Fatalf("payload_retained = false after rejected eviction for %s", status)
		}
		if _, err := store.Payload(ctx, objectID); err != nil {
			t.Fatalf("Payload(%s) after rejected eviction error = %v", status, err)
		}
	}
}

func TestPendingObjectTransitionsToValidOnReingest(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("obj-dup-metadata", domain.ValidationStatusPendingDependencies)
	input.Dependencies = []Dependency{{Type: "election", ID: "election-1"}}
	input.ValidationErrorCode = "FIRST"
	input.ValidationErrorMessage = "first"
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("first ingest error = %v", err)
	}

	input.ValidationStatus = domain.ValidationStatusValid
	input.ValidationErrorCode = "SECOND"
	input.ValidationErrorMessage = "second"
	input.ValidatorVersion = "v2"
	input.Dependencies = nil
	input.SeenAt = 5000
	input.CheckedAt = 6000
	res, err := store.IngestObject(ctx, input)
	if err != nil {
		t.Fatalf("second ingest error = %v", err)
	}
	if !res.Reacquired || !res.Updated {
		t.Fatalf("expected Reacquired=true and Updated=true for pending->valid transition, got %+v", res)
	}

	vr, err := store.ValidationRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() error = %v", err)
	}
	if vr.ValidationStatus != string(domain.ValidationStatusValid) ||
		vr.ValidationErrorCode != "SECOND" ||
		vr.ValidationErrorMessage != "second" ||
		vr.ValidatorVersion != "v2" ||
		vr.LastCheckedAt != 6000 {
		t.Fatalf("validation record not updated on pending->valid transition: %+v", vr)
	}

	deps, err := store.Dependencies(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 0 {
		t.Fatalf("dependencies should be removed after becoming valid: %+v", deps)
	}
}

func TestValidForTallyAndValidButConflictedRetainPayload(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	for _, status := range []domain.ValidationStatus{
		domain.ValidationStatusValidForTally,
		domain.ValidationStatusValidButConflicted,
	} {
		objectID := fmt.Sprintf("obj-%s-1", status)
		input := defaultIngestInput(objectID, status)
		res, err := store.IngestObject(ctx, input)
		if err != nil {
			t.Fatalf("IngestObject(%s) error = %v", status, err)
		}
		if !res.Inserted {
			t.Fatalf("expected Inserted=true for %s, got %+v", status, res)
		}

		meta, err := store.ObjectMetadata(ctx, objectID)
		if err != nil {
			t.Fatalf("ObjectMetadata(%s) error = %v", status, err)
		}
		if !meta.PayloadRetained {
			t.Fatalf("payload_retained = false for %s", status)
		}

		payload, err := store.Payload(ctx, objectID)
		if err != nil {
			t.Fatalf("Payload(%s) error = %v", status, err)
		}
		if !bytes.Equal(payload, input.PayloadBytes) {
			t.Fatalf("payload mismatch for %s", status)
		}
	}
}

func TestReacquireWithDifferentStatus(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("obj-reacquire-status", domain.ValidationStatusPendingDependencies)
	input.Dependencies = []Dependency{{Type: "election", ID: "election-1"}}
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("first ingest error = %v", err)
	}

	if err := store.EvictPendingPayload(ctx, input.ObjectID, 4000, "v2"); err != nil {
		t.Fatalf("EvictPendingPayload() error = %v", err)
	}

	input.ValidationStatus = domain.ValidationStatusValidButConflicted
	input.Dependencies = nil
	input.SeenAt = 5000
	input.CheckedAt = 6000
	res, err := store.IngestObject(ctx, input)
	if err != nil {
		t.Fatalf("reacquire ingest error = %v", err)
	}
	if !res.Reacquired || !res.Updated {
		t.Fatalf("expected Reacquired=true and Updated=true, got %+v", res)
	}
}

func TestInvalidTransitionFromPendingObject(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("obj-pending-to-invalid", domain.ValidationStatusPendingDependencies)
	input.Dependencies = []Dependency{{Type: "election", ID: "election-1"}}
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("first ingest error = %v", err)
	}

	input.ValidationStatus = domain.ValidationStatusInvalid
	input.ValidationErrorCode = "ERR_BAD_SIG"
	res, err := store.IngestObject(ctx, input)
	if err != nil {
		t.Fatalf("invalid transition error = %v", err)
	}
	if !res.InvalidRecorded || !res.Updated {
		t.Fatalf("expected InvalidRecorded=true and Updated=true, got %+v", res)
	}

	_, err = store.ObjectMetadata(ctx, input.ObjectID)
	if err == nil {
		t.Fatal("ObjectMetadata() succeeded after invalid transition, want error")
	}
	_, err = store.Payload(ctx, input.ObjectID)
	if err == nil {
		t.Fatal("Payload() succeeded after invalid transition, want error")
	}
	deps, err := store.Dependencies(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() after invalid transition error = %v", err)
	}
	if len(deps) != 0 {
		t.Fatalf("dependencies remain after invalid transition: %+v", deps)
	}
	ir, err := store.InvalidObjectRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("InvalidObjectRecord() error = %v", err)
	}
	if ir.SeenCount != 1 {
		t.Fatalf("seen_count = %d, want 1", ir.SeenCount)
	}
}

func TestInvalidDuplicateForFinalObjectDoesNotMutateRetainedObject(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("obj-valid-invalid-duplicate", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("first ingest error = %v", err)
	}

	input.ValidationStatus = domain.ValidationStatusInvalid
	input.ValidationErrorCode = "ERR_BAD_SIG"
	input.SeenAt = 5000
	res, err := store.IngestObject(ctx, input)
	if err != nil {
		t.Fatalf("duplicate invalid ingest error = %v", err)
	}
	if !res.Duplicate || res.InvalidRecorded || res.Updated {
		t.Fatalf("expected duplicate without invalid transition, got %+v", res)
	}

	meta, err := store.ObjectMetadata(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() after duplicate invalid ingest error = %v", err)
	}
	if !meta.PayloadRetained || meta.LastSeenAt != 5000 {
		t.Fatalf("metadata after duplicate invalid ingest = %+v", meta)
	}
	vr, err := store.ValidationRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() after duplicate invalid ingest error = %v", err)
	}
	if vr.ValidationStatus != string(domain.ValidationStatusValid) {
		t.Fatalf("validation_status = %q, want %q", vr.ValidationStatus, domain.ValidationStatusValid)
	}
	if _, err := store.InvalidObjectRecord(ctx, input.ObjectID); err == nil {
		t.Fatal("InvalidObjectRecord() succeeded after duplicate invalid ingest, want error")
	}
}

func TestIngestObjectWithDeadline(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("obj-deadline", domain.ValidationStatusValid)
	res, err := store.IngestObjectWithDeadline(ctx, input, 5*time.Second)
	if err != nil {
		t.Fatalf("IngestObjectWithDeadline() error = %v", err)
	}
	if !res.Inserted {
		t.Fatalf("expected Inserted=true, got %+v", res)
	}
}

func defaultIngestObjectInput(objectID string, status domain.ValidationStatus) IngestObjectInput {
	return defaultIngestInput(objectID, status)
}
