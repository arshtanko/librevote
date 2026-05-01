package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"librevote/internal/domain"
	"librevote/internal/validation"
)

// ValidationOutcomeMetadata is local worker-facing metadata persisted from the
// validation outcome. It is separate from domain payload and object identity.
type ValidationOutcomeMetadata struct {
	ObjectID             string
	AffectedScope        validation.AffectedScope
	ShouldRepublish      bool
	ShouldRecomputeState bool
	UpdatedAt            int64
}

func (s *Store) ValidationOutcomeMetadata(ctx context.Context, objectID string) (ValidationOutcomeMetadata, error) {
	var meta ValidationOutcomeMetadata
	var affectedScope string
	var shouldRepublish, shouldRecomputeState int
	err := s.db.QueryRowContext(ctx,
		`SELECT object_id, affected_scope, affected_scope_id,
		        should_republish, should_recompute_state, updated_at
		 FROM validation_outcome_metadata
		 WHERE object_id = ?`,
		objectID).Scan(
		&meta.ObjectID, &affectedScope, &meta.AffectedScope.ScopeID,
		&shouldRepublish, &shouldRecomputeState, &meta.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return meta, fmt.Errorf("validation outcome metadata not found: %w", err)
		}
		return meta, fmt.Errorf("read validation outcome metadata: %w", err)
	}
	meta.AffectedScope.Scope = domain.Scope(affectedScope)
	meta.ShouldRepublish = shouldRepublish == 1
	meta.ShouldRecomputeState = shouldRecomputeState == 1
	return meta, nil
}

func upsertValidationOutcomeMetadata(ctx context.Context, tx *sql.Tx, outcome validation.Outcome, checkedAt int64) error {
	if err := validateOutcomeWorkerMetadata(outcome); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO validation_outcome_metadata
		 (object_id, affected_scope, affected_scope_id,
		  should_republish, should_recompute_state, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(object_id) DO UPDATE SET
		 affected_scope = excluded.affected_scope,
		 affected_scope_id = excluded.affected_scope_id,
		 should_republish = excluded.should_republish,
		 should_recompute_state = excluded.should_recompute_state,
		 updated_at = excluded.updated_at`,
		outcome.ObjectID,
		string(outcome.AffectedScope.Scope),
		outcome.AffectedScope.ScopeID,
		boolInt(outcome.ShouldRepublish),
		boolInt(outcome.ShouldRecomputeState),
		checkedAt,
	); err != nil {
		return fmt.Errorf("upsert validation_outcome_metadata: %w", err)
	}
	return nil
}

func outcomeMetadataFromIngest(input IngestObjectInput) (validation.Outcome, error) {
	status, err := validation.ParseStatus(string(input.ValidationStatus))
	if err != nil {
		return validation.Outcome{}, err
	}
	shouldRepublish := status.RepublishEligible()
	if input.ShouldRepublishSet {
		shouldRepublish = input.ShouldRepublish
	}
	return validation.Outcome{
		ObjectID:             input.ObjectID,
		Status:               status,
		AffectedScope:        input.AffectedScope,
		ShouldRepublish:      shouldRepublish,
		ShouldRecomputeState: input.ShouldRecomputeState,
	}, nil
}

func validateOutcomeWorkerMetadata(outcome validation.Outcome) error {
	if outcome.ShouldRepublish && !outcome.Status.RepublishEligible() {
		return fmt.Errorf("should_republish is not allowed for validation status %q", outcome.Status)
	}
	if !knownAffectedScope(outcome.AffectedScope) {
		return fmt.Errorf("unknown affected scope %q", outcome.AffectedScope.Scope)
	}
	return nil
}

func knownAffectedScope(scope validation.AffectedScope) bool {
	switch scope.Scope {
	case "":
		return scope.ScopeID == ""
	case domain.ScopeNetwork:
		return scope.ScopeID == ""
	case domain.ScopeElectionID, domain.ScopeTrusteeSelectionID:
		return scope.ScopeID != ""
	default:
		return false
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
