package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"librevote/internal/domain"
	"librevote/internal/validation"
)

// ApplyValidationOutcomeInput carries local validation metadata for an existing
// object row. It does not alter domain identity, payload hash, PoW, or source metadata.
type ApplyValidationOutcomeInput struct {
	Outcome          validation.Outcome
	ValidatorVersion string
	CheckedAt        int64
}

// ApplyValidationOutcome persists a validation-layer outcome for an existing object row.
func (s *Store) ApplyValidationOutcome(ctx context.Context, input ApplyValidationOutcomeInput) error {
	if input.Outcome.ObjectID == "" {
		return errors.New("object_id is required")
	}
	if !input.Outcome.Status.Valid() {
		return fmt.Errorf("unknown validation status %q", input.Outcome.Status)
	}
	if input.ValidatorVersion == "" {
		return errors.New("validator_version is required")
	}
	if input.CheckedAt <= 0 {
		return errors.New("checked_at must be greater than zero")
	}
	if err := validateOutcomeWorkerMetadata(input.Outcome); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin validation outcome transaction: %w", err)
	}
	defer tx.Rollback()

	var objectType, networkID, scope, scopeID string
	var firstSeenAt, lastSeenAt int64
	if err := tx.QueryRowContext(ctx,
		`SELECT object_type, network_id, scope, scope_id, first_seen_at, last_seen_at
		 FROM objects WHERE object_id = ?`,
		input.Outcome.ObjectID).Scan(
		&objectType, &networkID, &scope, &scopeID, &firstSeenAt, &lastSeenAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("object not found: %s", input.Outcome.ObjectID)
		}
		return fmt.Errorf("read object metadata: %w", err)
	}

	oldConflicts, err := conflictMetadataForObjectTx(ctx, tx, input.Outcome.ObjectID)
	if err != nil {
		return err
	}

	if err := applyOutcomeRetention(ctx, tx, input.Outcome); err != nil {
		return err
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE validation_records
		 SET validation_status = ?, validation_error_code = ?,
		     validation_error_message = ?, validator_version = ?, last_checked_at = ?
		 WHERE object_id = ?`,
		input.Outcome.Status.String(), input.Outcome.ValidationErrorCode,
		input.Outcome.ValidationErrorReason, input.ValidatorVersion,
		input.CheckedAt, input.Outcome.ObjectID)
	if err != nil {
		return fmt.Errorf("update validation_records: %w", err)
	}
	updated, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("check validation rows affected: %w", err)
	}
	if updated == 0 {
		return fmt.Errorf("validation record not found: %s", input.Outcome.ObjectID)
	}

	if err := replaceDependencies(ctx, tx, input.Outcome.ObjectID, outcomeDomainStatus(input.Outcome.Status), outcomeDependencies(input.Outcome.Dependencies)); err != nil {
		return err
	}
	if err := upsertValidationOutcomeMetadata(ctx, tx, input.Outcome, input.CheckedAt); err != nil {
		return err
	}
	newConflicts := conflictsForOutcome(input.Outcome)
	if err := validateConflictMetadata(input.Outcome.ObjectID, newConflicts); err != nil {
		return err
	}
	if err := replaceConflictMetadataTx(ctx, tx, input.Outcome.ObjectID, newConflicts); err != nil {
		return err
	}
	if err := classifyPersistedConflictsTx(ctx, tx, append(oldConflicts, newConflicts...)); err != nil {
		return err
	}

	if input.Outcome.Status == validation.StatusInvalid {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO invalid_object_records
			 (object_id, object_type, network_id, scope, scope_id,
			  first_seen_at, last_seen_at, seen_count, validation_error_code)
			 VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
			 ON CONFLICT(object_id) DO UPDATE SET
			 last_seen_at = excluded.last_seen_at,
			 seen_count = seen_count + 1,
			 validation_error_code = excluded.validation_error_code`,
			input.Outcome.ObjectID, objectType, networkID, scope, scopeID,
			firstSeenAt, lastSeenAt, input.Outcome.ValidationErrorCode); err != nil {
			return fmt.Errorf("upsert invalid_object_records: %w", err)
		}
	}

	return tx.Commit()
}

func conflictsForOutcome(outcome validation.Outcome) []ConflictMetadata {
	if !persistConflictKeysForStatus(outcome.Status) {
		return nil
	}
	return conflictMetadataFromValidation(outcome.ObjectID, outcome.ConflictKeys)
}

func persistConflictKeysForStatus(status validation.Status) bool {
	switch status {
	case validation.StatusValid, validation.StatusValidForTally, validation.StatusValidButConflicted:
		return true
	default:
		return false
	}
}

func applyOutcomeRetention(ctx context.Context, tx *sql.Tx, outcome validation.Outcome) error {
	switch outcome.Status {
	case validation.StatusInvalid, validation.StatusPendingPayloadEvicted:
		if _, err := tx.ExecContext(ctx,
			"DELETE FROM object_payloads WHERE object_id = ?",
			outcome.ObjectID); err != nil {
			return fmt.Errorf("delete object_payloads: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			"UPDATE objects SET payload_retained = 0 WHERE object_id = ?",
			outcome.ObjectID); err != nil {
			return fmt.Errorf("update payload_retained: %w", err)
		}
	}
	return nil
}

func outcomeDependencies(deps []validation.Dependency) []Dependency {
	if len(deps) == 0 {
		return nil
	}
	out := make([]Dependency, len(deps))
	for i, dep := range deps {
		out[i] = Dependency{Type: dep.Type, ID: dep.ID}
	}
	return out
}

func outcomeDomainStatus(status validation.Status) domain.ValidationStatus {
	return domain.ValidationStatus(status.String())
}
