package validation

import (
	"context"
	"errors"
	"fmt"
)

// RevalidationCandidateStore is the storage read API needed by workers to plan
// which pending objects should be revalidated after a dependency changes.
type RevalidationCandidateStore interface {
	ObjectsWaitingOnValidationDependency(context.Context, Dependency) ([]string, error)
}

// RevalidationPlanner builds deterministic worker-facing revalidation plans.
// It does not execute validation, recompute derived state, or inspect payloads.
type RevalidationPlanner struct {
	Store RevalidationCandidateStore
}

// RevalidationPlan contains object IDs that should be submitted to a future
// validation worker after a dependency appears or changes status.
type RevalidationPlan struct {
	ObjectIDs []string
}

// RepublishPlan is the status-only worker decision for announcement publication
// and pending payload reacquire. It never authorizes full payload publication.
type RepublishPlan struct {
	ShouldRepublish        bool
	ShouldReacquirePayload bool
}

// CandidatesForDependencyChange lists objects currently waiting on dependency.
func (p RevalidationPlanner) CandidatesForDependencyChange(ctx context.Context, dependency Dependency) (RevalidationPlan, error) {
	if p.Store == nil {
		return RevalidationPlan{}, errors.New("revalidation candidate store is required")
	}
	if dependency.Type == "" || dependency.ID == "" {
		return RevalidationPlan{}, errors.New("dependency type and id are required")
	}

	objectIDs, err := p.Store.ObjectsWaitingOnValidationDependency(ctx, dependency)
	if err != nil {
		return RevalidationPlan{}, err
	}
	return RevalidationPlan{ObjectIDs: objectIDs}, nil
}

// PlanRepublishForStatus derives worker publication and reacquire decisions only
// from documented validation statuses.
func PlanRepublishForStatus(status Status) (RepublishPlan, error) {
	if !status.Valid() {
		return RepublishPlan{}, fmt.Errorf("unknown validation status %q", status)
	}
	return RepublishPlan{
		ShouldRepublish:        status.RepublishEligible(),
		ShouldReacquirePayload: status.PayloadReacquireRequired(),
	}, nil
}
