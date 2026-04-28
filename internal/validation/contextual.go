package validation

import (
	"context"
	"errors"
	"fmt"

	"librevote/internal/domain"
)

const (
	ErrorContextualDependencyStatus = "contextual_dependency_status"
	ErrorContextualUnimplemented    = "contextual_unimplemented"
)

var ErrContextualStore = errors.New("contextual validation store is required")
var ErrContextualRuleUnsupported = errors.New("contextual rule is not implemented")

// ContextualStore is the storage behavior required by contextual validation.
// It is defined where it is consumed so storage remains an implementation detail.
type ContextualStore interface {
	ValidationStatus(context.Context, string) (Status, bool, error)
}

// ContextualRule returns the dependencies and target status for one object type.
// Rules must only use references they can identify without guessing from raw bytes.
type ContextualRule func(context.Context, domain.ObjectEnvelope) (ContextualRuleResult, error)

// RequiredDependency identifies one referenced object and the statuses that make
// it usable by the current rule.
type RequiredDependency struct {
	Dependency
	AcceptableStatuses []Status
}

// ContextualRuleResult is an object-specific contextual rule result before
// storage-backed dependency checks are applied.
type ContextualRuleResult struct {
	Status               Status
	RequiredDependencies []RequiredDependency
}

// ContextualOption customizes ContextualValidator construction.
type ContextualOption func(*DefaultContextualValidator)

// DefaultContextualValidator implements storage-backed contextual validation.
type DefaultContextualValidator struct {
	store ContextualStore
	rules map[domain.ObjectType]ContextualRule
}

// NewContextualValidator creates a contextual validator with conservative
// defaults and optional object-specific rule overrides.
func NewContextualValidator(store ContextualStore, opts ...ContextualOption) (*DefaultContextualValidator, error) {
	if store == nil {
		return nil, ErrContextualStore
	}
	v := &DefaultContextualValidator{
		store: store,
		rules: defaultContextualRules(),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

// WithContextualRule registers or replaces the rule for objectType. Passing nil
// removes the rule and makes the object type unsupported until a rule is added.
func WithContextualRule(objectType domain.ObjectType, rule ContextualRule) ContextualOption {
	return func(v *DefaultContextualValidator) {
		if rule == nil {
			delete(v.rules, objectType)
			return
		}
		v.rules[objectType] = rule
	}
}

// ValidateContext applies the object-specific contextual rule and resolves its
// dependencies using local validation records.
func (v *DefaultContextualValidator) ValidateContext(ctx context.Context, envelope domain.ObjectEnvelope) (Outcome, error) {
	if v == nil || v.store == nil {
		return Outcome{}, ErrContextualStore
	}
	rule := v.rules[envelope.ObjectType]
	if rule == nil {
		return Outcome{}, fmt.Errorf("%w for %s", ErrContextualRuleUnsupported, envelope.ObjectType)
	}

	result, err := rule(ctx, envelope)
	if err != nil {
		return Outcome{}, err
	}
	if !result.Status.Valid() {
		return Outcome{}, fmt.Errorf("contextual rule for %s returned unknown status %q", envelope.ObjectType, result.Status)
	}
	if result.Status == StatusPendingDependencies && len(result.RequiredDependencies) == 0 {
		return Outcome{}, errors.New("pending_dependencies requires at least one contextual dependency")
	}

	missing, rejected, err := v.checkDependencies(ctx, result.RequiredDependencies)
	if err != nil {
		return Outcome{}, err
	}
	if len(rejected) > 0 {
		outcome := NewOutcome(envelope.ObjectID, StatusInvalid)
		outcome.ValidationErrorCode = ErrorContextualDependencyStatus
		outcome.ValidationErrorReason = rejected[0]
		return outcome, nil
	}
	if len(missing) > 0 {
		outcome := NewOutcome(envelope.ObjectID, StatusPendingDependencies)
		outcome.Dependencies = missing
		return outcome, nil
	}

	return NewOutcome(envelope.ObjectID, result.Status), nil
}

func (v *DefaultContextualValidator) checkDependencies(ctx context.Context, deps []RequiredDependency) ([]Dependency, []string, error) {
	var missing []Dependency
	var rejected []string
	seenMissing := make(map[Dependency]struct{})
	for _, dep := range deps {
		if dep.Type == "" || dep.ID == "" {
			return nil, nil, errors.New("dependency type and id are required")
		}
		if len(dep.AcceptableStatuses) == 0 {
			return nil, nil, errors.New("dependency acceptable statuses are required")
		}

		status, exists, err := v.store.ValidationStatus(ctx, dep.ID)
		if err != nil {
			return nil, nil, err
		}
		dependency := dep.Dependency
		if !exists || !status.Final() {
			if _, ok := seenMissing[dependency]; !ok {
				missing = append(missing, dependency)
				seenMissing[dependency] = struct{}{}
			}
			continue
		}
		if !statusAccepted(status, dep.AcceptableStatuses) {
			rejected = append(rejected, fmt.Sprintf("dependency %s/%s has status %s", dep.Type, dep.ID, status))
		}
	}
	return missing, rejected, nil
}

func statusAccepted(status Status, acceptable []Status) bool {
	for _, candidate := range acceptable {
		if status == candidate {
			return true
		}
	}
	return false
}

func defaultContextualRules() map[domain.ObjectType]ContextualRule {
	root := func(_ context.Context, _ domain.ObjectEnvelope) (ContextualRuleResult, error) {
		return ContextualRuleResult{Status: StatusValid}, nil
	}
	return map[domain.ObjectType]ContextualRule{
		domain.ObjectTypeTrusteeSelectionElection: root,
	}
}

// RequireObject builds a storage-backed object_id dependency requirement for
// object-specific rules and tests that can identify a real referenced object.
func RequireObject(dependencyType, objectID string, acceptable ...Status) RequiredDependency {
	return RequiredDependency{
		Dependency:         Dependency{Type: dependencyType, ID: objectID},
		AcceptableStatuses: append([]Status(nil), acceptable...),
	}
}
