package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

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
