package storage

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"librevote/internal/domain"
)

func TestDependenciesListsPersistedRowsInDeterministicOrder(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("deps-list-object", domain.ValidationStatusPendingDependencies)
	input.Dependencies = []Dependency{
		{Type: "tally_key_set", ID: "tks-2"},
		{Type: "election", ID: "election-2"},
		{Type: "election", ID: "election-1"},
	}
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}

	got, err := store.Dependencies(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	want := []Dependency{
		{Type: "election", ID: "election-1"},
		{Type: "election", ID: "election-2"},
		{Type: "tally_key_set", ID: "tks-2"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Dependencies() = %+v, want %+v", got, want)
	}

	validInput := defaultIngestInput("deps-list-valid-object", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, validInput); err != nil {
		t.Fatalf("valid IngestObject() error = %v", err)
	}
	got, err = store.Dependencies(ctx, validInput.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() for valid object error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Dependencies() for valid object = %+v, want empty", got)
	}
}

func TestDependenciesMissingObjectReturnsEmptyList(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	got, err := store.Dependencies(ctx, "missing-object")
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Dependencies() = %+v, want empty", got)
	}
}

func TestObjectsWaitingOnDependencyListsMatchingObjectsInDeterministicOrder(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	objectB := defaultIngestInput("waiting-object-b", domain.ValidationStatusPendingDependencies)
	objectB.Dependencies = []Dependency{{Type: "election", ID: "election-1"}}
	if _, err := store.IngestObject(ctx, objectB); err != nil {
		t.Fatalf("IngestObject(objectB) error = %v", err)
	}

	objectA := defaultIngestInput("waiting-object-a", domain.ValidationStatusPendingDependencies)
	objectA.Dependencies = []Dependency{
		{Type: "tally_key_set", ID: "tks-1"},
		{Type: "election", ID: "election-1"},
		{Type: "election", ID: "election-1"},
	}
	if _, err := store.IngestObject(ctx, objectA); err != nil {
		t.Fatalf("IngestObject(objectA) error = %v", err)
	}

	validInput := defaultIngestInput("waiting-valid-object", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, validInput); err != nil {
		t.Fatalf("IngestObject(validInput) error = %v", err)
	}

	got, err := store.ObjectsWaitingOnDependency(ctx, Dependency{Type: "election", ID: "election-1"})
	if err != nil {
		t.Fatalf("ObjectsWaitingOnDependency() error = %v", err)
	}
	want := []string{"waiting-object-a", "waiting-object-b"}
	if !slices.Equal(got, want) {
		t.Fatalf("ObjectsWaitingOnDependency() = %+v, want %+v", got, want)
	}

	got, err = store.ObjectsWaitingOnDependency(ctx, Dependency{Type: "blind_token_request", ID: "missing"})
	if err != nil {
		t.Fatalf("ObjectsWaitingOnDependency() missing dependency error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ObjectsWaitingOnDependency() missing dependency = %+v, want empty", got)
	}
}

func TestObjectsWaitingOnDependencyRejectsIncompleteDependency(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	tests := []Dependency{
		{ID: "dependency-1"},
		{Type: "election"},
	}
	for _, tt := range tests {
		_, err := store.ObjectsWaitingOnDependency(ctx, tt)
		if err == nil || !strings.Contains(err.Error(), "dependency type and id") {
			t.Fatalf("ObjectsWaitingOnDependency(%+v) error = %v, want required dependency error", tt, err)
		}
	}
}

func TestDependencyQueriesPreserveObjectAndSourceMetadata(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("deps-preserve-object", domain.ValidationStatusPendingDependencies)
	input.ObjectPoW = []byte{0xaa, 0xbb}
	input.Dependencies = []Dependency{{Type: "election", ID: "election-1"}}
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}
	if err := store.RecordObjectSource(ctx, input.ObjectID, "peer-1", 4000); err != nil {
		t.Fatalf("RecordObjectSource() error = %v", err)
	}

	beforeMeta, err := store.ObjectMetadata(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() before error = %v", err)
	}
	beforeValidation, err := store.ValidationRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() before error = %v", err)
	}
	beforePayload, err := store.Payload(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Payload() before error = %v", err)
	}
	beforeSources, err := store.ObjectSources(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectSources() before error = %v", err)
	}

	if _, err := store.Dependencies(ctx, input.ObjectID); err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if _, err := store.ObjectsWaitingOnDependency(ctx, Dependency{Type: "election", ID: "election-1"}); err != nil {
		t.Fatalf("ObjectsWaitingOnDependency() error = %v", err)
	}

	afterMeta, err := store.ObjectMetadata(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() after error = %v", err)
	}
	afterValidation, err := store.ValidationRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() after error = %v", err)
	}
	afterPayload, err := store.Payload(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Payload() after error = %v", err)
	}
	afterSources, err := store.ObjectSources(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectSources() after error = %v", err)
	}

	if beforeMeta.ObjectID != afterMeta.ObjectID || beforeMeta.LastSeenAt != afterMeta.LastSeenAt || beforeMeta.PayloadRetained != afterMeta.PayloadRetained || !bytes.Equal(beforeMeta.ObjectPoW, afterMeta.ObjectPoW) || !bytes.Equal(beforeMeta.PayloadHash, afterMeta.PayloadHash) {
		t.Fatalf("object metadata mutated: before=%+v after=%+v", beforeMeta, afterMeta)
	}
	if beforeValidation != afterValidation {
		t.Fatalf("validation metadata mutated: before=%+v after=%+v", beforeValidation, afterValidation)
	}
	if !bytes.Equal(beforePayload, afterPayload) {
		t.Fatal("payload mutated")
	}
	if !slices.Equal(beforeSources, afterSources) {
		t.Fatalf("source metadata mutated: before=%+v after=%+v", beforeSources, afterSources)
	}
}
