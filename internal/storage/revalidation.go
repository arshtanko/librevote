package storage

import (
	"context"

	"librevote/internal/validation"
)

// ObjectsWaitingOnValidationDependency adapts storage dependency rows to the
// validation-layer planner API without executing revalidation.
func (s *Store) ObjectsWaitingOnValidationDependency(ctx context.Context, dependency validation.Dependency) ([]string, error) {
	return s.ObjectsWaitingOnDependency(ctx, Dependency{Type: dependency.Type, ID: dependency.ID})
}
