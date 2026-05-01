package storage

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"librevote/internal/domain"
	"librevote/internal/validation"
)

// PersistEnvelopeValidationOutcome adapts the validation runner's envelope-stage
// outcome to the object log and validation metadata schema.
func (s *Store) PersistEnvelopeValidationOutcome(ctx context.Context, envelope domain.ObjectEnvelope, outcome validation.Outcome, input validation.PersistenceInput) (validation.PersistenceResult, error) {
	if input.ValidatorVersion == "" {
		return validation.PersistenceResult{}, errors.New("validator_version is required")
	}
	if input.SeenAt <= 0 {
		return validation.PersistenceResult{}, errors.New("seen_at must be greater than zero")
	}
	if input.CheckedAt <= 0 {
		return validation.PersistenceResult{}, errors.New("checked_at must be greater than zero")
	}
	if !outcome.Status.Valid() {
		return validation.PersistenceResult{}, fmt.Errorf("unknown validation status %q", outcome.Status)
	}
	if outcome.AffectedScope.Scope != "" || outcome.AffectedScope.ScopeID != "" {
		return validation.PersistenceResult{}, errors.New("affected scope is not supported by envelope persistence")
	}
	if outcome.ShouldRecomputeState {
		return validation.PersistenceResult{}, errors.New("recompute flag is not supported by envelope persistence")
	}

	var protocolVersion int
	if outcome.Status != validation.StatusInvalid {
		var err error
		protocolVersion, err = protocolVersionNumber(envelope.ProtocolVersion)
		if err != nil {
			return validation.PersistenceResult{}, err
		}
	}

	result, err := s.IngestObject(ctx, IngestObjectInput{
		ObjectID:               outcome.ObjectID,
		ObjectType:             string(envelope.ObjectType),
		ProtocolVersion:        protocolVersion,
		NetworkID:              envelope.NetworkID,
		Scope:                  string(envelope.Scope),
		ScopeID:                envelope.ScopeID,
		CreatedAt:              envelope.CreatedAt,
		ObjectPoW:              envelope.Pow,
		PayloadBytes:           envelope.Payload,
		ValidationStatus:       domain.ValidationStatus(outcome.Status.String()),
		ValidationErrorCode:    outcome.ValidationErrorCode,
		ValidationErrorMessage: outcome.ValidationErrorReason,
		ValidatorVersion:       input.ValidatorVersion,
		Dependencies:           runnerDependencies(outcome.Dependencies),
		ConflictKeys:           conflictMetadataFromValidation(outcome.ObjectID, outcome.ConflictKeys),
		SeenAt:                 input.SeenAt,
		CheckedAt:              input.CheckedAt,
	})
	if err != nil {
		return validation.PersistenceResult{}, err
	}

	return validation.PersistenceResult{
		Inserted:        result.Inserted,
		Updated:         result.Updated,
		Duplicate:       result.Duplicate,
		Reacquired:      result.Reacquired,
		InvalidRecorded: result.InvalidRecorded,
	}, nil
}

func protocolVersionNumber(version string) (int, error) {
	value, ok := strings.CutPrefix(version, "v")
	if !ok || value == "" {
		return 0, fmt.Errorf("unsupported protocol_version %q", version)
	}
	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("unsupported protocol_version %q", version)
	}
	return n, nil
}

func runnerDependencies(deps []validation.Dependency) []Dependency {
	if len(deps) == 0 {
		return nil
	}
	out := make([]Dependency, len(deps))
	for i, dep := range deps {
		out[i] = Dependency{Type: dep.Type, ID: dep.ID}
	}
	return out
}
