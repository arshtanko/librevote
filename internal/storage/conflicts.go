package storage

import (
	"context"
	"errors"
)

// ErrConflictMetadataUnsupported is returned when callers try to use persisted
// conflict metadata APIs with a schema that has no conflict metadata tables.
var ErrConflictMetadataUnsupported = errors.New("conflict metadata storage is unsupported by current schema")

// ConflictMetadata describes one local validation conflict-group membership for
// an object. It is storage metadata around the object log, not domain truth.
type ConflictMetadata struct {
	ObjectID string
	Group    string
	Key      string
}

// ReplaceConflictMetadata would atomically replace persisted conflict metadata
// for an existing object. The current schema has no conflict metadata tables, so
// this API rejects explicitly without mutating object identity, payload, PoW, or
// source metadata.
func (s *Store) ReplaceConflictMetadata(ctx context.Context, objectID string, conflicts []ConflictMetadata) error {
	if objectID == "" {
		return errors.New("object_id is required")
	}
	for _, conflict := range conflicts {
		if conflict.Group == "" || conflict.Key == "" {
			return errors.New("conflict group and key are required")
		}
		if conflict.ObjectID != "" && conflict.ObjectID != objectID {
			return errors.New("conflict object_id must match object_id")
		}
	}
	return ErrConflictMetadataUnsupported
}

// ConflictMetadataForObject would return persisted conflict metadata rows for
// an object in deterministic order. The current schema has no conflict metadata
// tables, so this API rejects explicitly.
func (s *Store) ConflictMetadataForObject(ctx context.Context, objectID string) ([]ConflictMetadata, error) {
	if objectID == "" {
		return nil, errors.New("object_id is required")
	}
	return nil, ErrConflictMetadataUnsupported
}

// ObjectsInConflictGroup would return object ids in a conflict group in
// deterministic order. The current schema has no conflict metadata tables, so
// this API rejects explicitly.
func (s *Store) ObjectsInConflictGroup(ctx context.Context, group, key string) ([]string, error) {
	if group == "" || key == "" {
		return nil, errors.New("conflict group and key are required")
	}
	return nil, ErrConflictMetadataUnsupported
}
