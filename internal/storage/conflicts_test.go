package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"librevote/internal/domain"
)

func TestConflictMetadataAPIsRejectUnsupportedSchema(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	input := defaultIngestInput("conflict-api-unsupported", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}

	conflicts := []ConflictMetadata{{
		ObjectID: input.ObjectID,
		Group:    "anonymous_ballot_conflict_key",
		Key:      "election-1|nullifier-1",
	}}
	if err := store.ReplaceConflictMetadata(ctx, input.ObjectID, conflicts); !errors.Is(err, ErrConflictMetadataUnsupported) {
		t.Fatalf("ReplaceConflictMetadata() error = %v, want ErrConflictMetadataUnsupported", err)
	}
	if _, err := store.ConflictMetadataForObject(ctx, input.ObjectID); !errors.Is(err, ErrConflictMetadataUnsupported) {
		t.Fatalf("ConflictMetadataForObject() error = %v, want ErrConflictMetadataUnsupported", err)
	}
	if _, err := store.ObjectsInConflictGroup(ctx, conflicts[0].Group, conflicts[0].Key); !errors.Is(err, ErrConflictMetadataUnsupported) {
		t.Fatalf("ObjectsInConflictGroup() error = %v, want ErrConflictMetadataUnsupported", err)
	}
}

func TestConflictMetadataAPIsRejectInvalidInputBeforeUnsupportedSchema(t *testing.T) {
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

func TestConflictMetadataUnsupportedPreservesObjectPayloadPowAndSourceMetadata(t *testing.T) {
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
	if err := store.ReplaceConflictMetadata(ctx, input.ObjectID, conflicts); !errors.Is(err, ErrConflictMetadataUnsupported) {
		t.Fatalf("ReplaceConflictMetadata() error = %v, want ErrConflictMetadataUnsupported", err)
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

func TestConflictMetadataUnsupportedForMissingObject(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	conflicts := []ConflictMetadata{{Group: "trustee_vote_conflict_key", Key: "selection-1|voter-1"}}
	if err := store.ReplaceConflictMetadata(ctx, "missing-object", conflicts); !errors.Is(err, ErrConflictMetadataUnsupported) {
		t.Fatalf("ReplaceConflictMetadata() missing object error = %v, want ErrConflictMetadataUnsupported", err)
	}
}
