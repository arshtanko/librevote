package validation

import "librevote/internal/domain"

// Dependency records a missing object or derived input required for revalidation.
type Dependency struct {
	Type string
	ID   string
}

// ConflictKey identifies one deterministic conflict group membership for an object.
type ConflictKey struct {
	Group string
	Key   string
}

// AffectedScope identifies the domain scope whose derived state may need recomputation.
type AffectedScope struct {
	Scope   domain.Scope
	ScopeID string
}

// Outcome is the validation-layer result consumed by storage and workers.
type Outcome struct {
	ObjectID              string
	Status                Status
	ValidationErrorCode   string
	ValidationErrorReason string
	Dependencies          []Dependency
	ConflictKeys          []ConflictKey
	AffectedScope         AffectedScope
	ShouldRepublish       bool
	ShouldRecomputeState  bool
}

// NewOutcome builds an outcome with republish eligibility derived from status.
func NewOutcome(objectID string, status Status) Outcome {
	return Outcome{
		ObjectID:        objectID,
		Status:          status,
		ShouldRepublish: status.RepublishEligible(),
	}
}
