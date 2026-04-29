package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"librevote/internal/domain"
	"librevote/internal/validation"
)

// ValidationStatus returns the locally recorded validation status for objectID.
// The boolean is false when no validation record exists.
func (s *Store) ValidationStatus(ctx context.Context, objectID string) (validation.Status, bool, error) {
	if objectID == "" {
		return "", false, errors.New("object_id is required")
	}
	var raw string
	err := s.db.QueryRowContext(ctx,
		"SELECT validation_status FROM validation_records WHERE object_id = ?",
		objectID).Scan(&raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			var exists int
			err := s.db.QueryRowContext(ctx,
				"SELECT 1 FROM invalid_object_records WHERE object_id = ?",
				objectID).Scan(&exists)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return "", false, nil
				}
				return "", false, fmt.Errorf("read invalid object record: %w", err)
			}
			return validation.StatusInvalid, true, nil
		}
		return "", false, fmt.Errorf("read validation status: %w", err)
	}
	status, err := validation.ParseStatus(raw)
	if err != nil {
		return "", false, err
	}
	return status, true, nil
}

// DependencyStatus resolves contextual dependencies that are identified by
// decoded domain references rather than by object_id alone.
func (s *Store) DependencyStatus(ctx context.Context, dep validation.Dependency) (validation.Status, bool, error) {
	if dep.Type == "" || dep.ID == "" {
		return "", false, errors.New("dependency type and id are required")
	}
	switch dep.Type {
	case "election":
		return s.statusForAnonymousElectionID(ctx, dep.ID)
	case "trustee_selection_result":
		selectionID, resultHash, err := validation.ParseTrusteeSelectionResultDependencyID(dep.ID)
		if err != nil {
			return "", false, err
		}
		return s.statusForTrusteeSelectionResult(ctx, selectionID, resultHash)
	default:
		return s.ValidationStatus(ctx, dep.ID)
	}
}

func (s *Store) statusForAnonymousElectionID(ctx context.Context, electionID string) (validation.Status, bool, error) {
	return s.statusForDecodedPayload(ctx, domain.ObjectTypeAnonymousElection, func(payload []byte) (bool, error) {
		decoded, err := domain.DecodePayload(domain.ObjectTypeAnonymousElection, payload)
		if err != nil {
			return false, err
		}
		election := decoded.(domain.AnonymousElectionPayload)
		return election.ElectionID == electionID, nil
	})
}

func (s *Store) statusForTrusteeSelectionResult(ctx context.Context, selectionID string, resultHash []byte) (validation.Status, bool, error) {
	return s.statusForDecodedPayload(ctx, domain.ObjectTypeTrusteeSelectionResult, func(payload []byte) (bool, error) {
		decoded, err := domain.DecodePayload(domain.ObjectTypeTrusteeSelectionResult, payload)
		if err != nil {
			return false, err
		}
		result := decoded.(domain.TrusteeSelectionResultPayload)
		return result.TrusteeSelectionID == selectionID && bytes.Equal(result.ResultHash, resultHash), nil
	})
}

func (s *Store) statusForDecodedPayload(ctx context.Context, objectType domain.ObjectType, matches func([]byte) (bool, error)) (validation.Status, bool, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT vr.validation_status, op.payload_bytes
		 FROM objects o
		 JOIN validation_records vr ON vr.object_id = o.object_id
		 JOIN object_payloads op ON op.object_id = o.object_id
		 WHERE o.object_type = ?`,
		string(objectType))
	if err != nil {
		return "", false, fmt.Errorf("query %s dependencies: %w", objectType, err)
	}
	defer rows.Close()

	var pendingStatus validation.Status
	foundPending := false
	for rows.Next() {
		var rawStatus string
		var payload []byte
		if err := rows.Scan(&rawStatus, &payload); err != nil {
			return "", false, fmt.Errorf("scan %s dependency: %w", objectType, err)
		}
		ok, err := matches(payload)
		if err != nil {
			return "", false, fmt.Errorf("decode %s dependency: %w", objectType, err)
		}
		if !ok {
			continue
		}
		status, err := validation.ParseStatus(rawStatus)
		if err != nil {
			return "", false, err
		}
		if status.Final() {
			return status, true, nil
		}
		if !foundPending {
			pendingStatus = status
			foundPending = true
		}
	}
	if err := rows.Err(); err != nil {
		return "", false, fmt.Errorf("read %s dependencies: %w", objectType, err)
	}
	if foundPending {
		return pendingStatus, true, nil
	}
	return "", false, nil
}
