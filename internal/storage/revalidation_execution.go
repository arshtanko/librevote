package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"librevote/internal/domain"
	"librevote/internal/validation"
)

var (
	ErrRevalidationObjectNotFound   = errors.New("revalidation object not found")
	ErrRevalidationInvalidObject    = errors.New("invalid object is not revalidatable without reacquire")
	ErrRevalidationPayloadMissing   = errors.New("revalidation payload is missing")
	ErrRevalidationPayloadEvicted   = errors.New("pending payload was evicted and must be reacquired")
	ErrRevalidationInvalidObjectRow = errors.New("stored object row is not a valid domain envelope")
	ErrRevalidationValidationRecord = errors.New("stored validation record is invalid")
)

// LoadRetainedObjectEnvelope reconstructs a domain ObjectEnvelope only when the
// object row has retained payload bytes and a revalidatable validation status.
func (s *Store) LoadRetainedObjectEnvelope(ctx context.Context, objectID string) (domain.ObjectEnvelope, error) {
	if objectID == "" {
		return domain.ObjectEnvelope{}, errors.New("object_id is required")
	}

	var invalidExists int
	err := s.db.QueryRowContext(ctx,
		"SELECT 1 FROM invalid_object_records WHERE object_id = ?",
		objectID).Scan(&invalidExists)
	if err == nil {
		return domain.ObjectEnvelope{}, ErrRevalidationInvalidObject
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.ObjectEnvelope{}, fmt.Errorf("read invalid object record: %w", err)
	}

	var envelope domain.ObjectEnvelope
	var protocolVersion int
	var objectType, scope, status string
	var payloadRetained int
	row := s.db.QueryRowContext(ctx,
		`SELECT o.object_id, o.object_type, o.protocol_version, o.network_id,
		        o.scope, o.scope_id, o.object_pow, o.created_at,
		        o.payload_retained, vr.validation_status
		 FROM objects o
		 JOIN validation_records vr ON vr.object_id = o.object_id
		 WHERE o.object_id = ?`,
		objectID)
	if err := row.Scan(
		&envelope.ObjectID, &objectType, &protocolVersion, &envelope.NetworkID,
		&scope, &envelope.ScopeID, &envelope.Pow, &envelope.CreatedAt,
		&payloadRetained, &status,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ObjectEnvelope{}, ErrRevalidationObjectNotFound
		}
		return domain.ObjectEnvelope{}, fmt.Errorf("read object for revalidation: %w", err)
	}

	validationStatus, err := validation.ParseStatus(status)
	if err != nil {
		return domain.ObjectEnvelope{}, fmt.Errorf("%w: %v", ErrRevalidationValidationRecord, err)
	}
	switch validationStatus {
	case validation.StatusPendingPayloadEvicted:
		return domain.ObjectEnvelope{}, ErrRevalidationPayloadEvicted
	case validation.StatusInvalid:
		return domain.ObjectEnvelope{}, ErrRevalidationInvalidObject
	}
	if payloadRetained == 0 {
		return domain.ObjectEnvelope{}, ErrRevalidationPayloadMissing
	}

	envelope.ObjectType = domain.ObjectType(objectType)
	envelope.Scope = domain.Scope(scope)
	envelope.ProtocolVersion = fmt.Sprintf("v%d", protocolVersion)
	if err := domain.ValidateScopeForObjectType(envelope.ObjectType, envelope.Scope, envelope.ScopeID); err != nil {
		return domain.ObjectEnvelope{}, fmt.Errorf("%w: %v", ErrRevalidationInvalidObjectRow, err)
	}
	if protocolVersion <= 0 {
		return domain.ObjectEnvelope{}, fmt.Errorf("%w: protocol_version must be greater than zero", ErrRevalidationInvalidObjectRow)
	}

	payload, err := s.Payload(ctx, objectID)
	if err != nil {
		return domain.ObjectEnvelope{}, fmt.Errorf("%w: %v", ErrRevalidationPayloadMissing, err)
	}
	envelope.Payload = payload
	envelope.Pow = cloneBytes(envelope.Pow)
	return envelope, nil
}

// RevalidateRetainedObject loads a retained object and persists only the outcome
// produced from that loaded envelope.
func (s *Store) RevalidateRetainedObject(ctx context.Context, objectID string, input validation.PersistenceInput, validate func(domain.ObjectEnvelope) (validation.RevalidationResult, error)) (validation.RevalidationResult, error) {
	envelope, err := s.LoadRetainedObjectEnvelope(ctx, objectID)
	if err != nil {
		return validation.RevalidationResult{}, err
	}
	result, err := validate(envelope)
	if err != nil {
		return validation.RevalidationResult{}, err
	}
	if result.Outcome.ObjectID != envelope.ObjectID {
		return validation.RevalidationResult{}, validation.ErrRunnerOutcomeObjectID
	}
	if err := s.persistRevalidationOutcome(ctx, result.Outcome, input); err != nil {
		return validation.RevalidationResult{}, err
	}
	return result, nil
}

func (s *Store) persistRevalidationOutcome(ctx context.Context, outcome validation.Outcome, input validation.PersistenceInput) error {
	stored := outcome
	stored.ShouldRepublish = false
	return s.ApplyValidationOutcome(ctx, ApplyValidationOutcomeInput{
		Outcome:          stored,
		ValidatorVersion: input.ValidatorVersion,
		CheckedAt:        input.CheckedAt,
	})
}
