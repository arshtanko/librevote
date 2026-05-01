package validation

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

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

type dependencyStatusStore interface {
	DependencyStatus(context.Context, Dependency) (Status, bool, error)
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
	Status                Status
	ValidationErrorCode   string
	ValidationErrorReason string
	RequiredDependencies  []RequiredDependency
	ConflictKeys          []ConflictKey
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
		rules: defaultContextualRules(store),
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

	outcome := NewOutcome(envelope.ObjectID, result.Status)
	outcome.ValidationErrorCode = result.ValidationErrorCode
	outcome.ValidationErrorReason = result.ValidationErrorReason
	outcome.ConflictKeys = append([]ConflictKey(nil), result.ConflictKeys...)
	return outcome, nil
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

		status, exists, err := dependencyStatus(ctx, v.store, dep.Dependency)
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

func dependencyStatus(ctx context.Context, store ContextualStore, dep Dependency) (Status, bool, error) {
	if resolver, ok := store.(dependencyStatusStore); ok {
		return resolver.DependencyStatus(ctx, dep)
	}
	return store.ValidationStatus(ctx, dep.ID)
}

func statusAccepted(status Status, acceptable []Status) bool {
	for _, candidate := range acceptable {
		if status == candidate {
			return true
		}
	}
	return false
}

func defaultContextualRules(store ContextualStore) map[domain.ObjectType]ContextualRule {
	root := func(_ context.Context, _ domain.ObjectEnvelope) (ContextualRuleResult, error) {
		return ContextualRuleResult{Status: StatusValid}, nil
	}
	return map[domain.ObjectType]ContextualRule{
		domain.ObjectTypeTrusteeSelectionElection: root,
		domain.ObjectTypeTrusteeNomination:        contextualTrusteeNomination(store),
		domain.ObjectTypeTrusteeVote:              contextualTrusteeVote(store),
		domain.ObjectTypeTrusteeSelectionResult:   contextualTrusteeSelectionResult(store),
		domain.ObjectTypeAnonymousElection:        contextualAnonymousElection,
		domain.ObjectTypeTrusteeConsent:           contextualTrusteeConsent(store),
		domain.ObjectTypeTallyKeyContribution:     contextualTallyKeyContribution(store),
		domain.ObjectTypeTallyKeySet:              contextualTallyKeySet(store),
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

func contextualAnonymousElection(_ context.Context, envelope domain.ObjectEnvelope) (ContextualRuleResult, error) {
	payload, err := decodePayload[domain.AnonymousElectionPayload](envelope)
	if err != nil {
		return ContextualRuleResult{}, err
	}
	return ContextualRuleResult{
		Status: StatusValid,
		RequiredDependencies: []RequiredDependency{
			RequireObject("trustee_selection_result", TrusteeSelectionResultDependencyID(payload.TrusteeSelectionID, payload.TrusteeSelectionResultHash), StatusValid),
		},
	}, nil
}

func decodePayload[T any](envelope domain.ObjectEnvelope) (T, error) {
	var zero T
	decoded, err := domain.DecodePayload(envelope.ObjectType, envelope.Payload)
	if err != nil {
		return zero, err
	}
	payload, ok := decoded.(T)
	if !ok {
		return zero, fmt.Errorf("decoded %s payload has type %T", envelope.ObjectType, decoded)
	}
	return payload, nil
}

// TrusteeSelectionResultDependencyID deterministically binds a result dependency
// to the trustee selection scope and the referenced preliminary result hash.
func TrusteeSelectionResultDependencyID(trusteeSelectionID string, resultHash []byte) string {
	if trusteeSelectionID == "" || len(resultHash) == 0 {
		return ""
	}
	return trusteeSelectionID + ":" + hex.EncodeToString(resultHash)
}

// ParseTrusteeSelectionResultDependencyID reverses TrusteeSelectionResultDependencyID.
func ParseTrusteeSelectionResultDependencyID(id string) (string, []byte, error) {
	selectionID, resultHashHex, ok := strings.Cut(id, ":")
	if !ok || selectionID == "" || resultHashHex == "" {
		return "", nil, fmt.Errorf("invalid trustee_selection_result dependency id %q", id)
	}
	resultHash, err := hex.DecodeString(resultHashHex)
	if err != nil {
		return "", nil, err
	}
	return selectionID, resultHash, nil
}
