package validation

import (
	"context"
	"errors"
	"testing"

	"librevote/internal/domain"
)

func TestContextualValidatorRootObjectsAreValid(t *testing.T) {
	validator, err := NewContextualValidator(memoryStatusStore{})
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	envelope := domain.ObjectEnvelope{ObjectID: "selection-object", ObjectType: domain.ObjectTypeTrusteeSelectionElection}
	outcome, err := validator.ValidateContext(context.Background(), envelope)
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusValid || !outcome.ShouldRepublish || len(outcome.Dependencies) != 0 {
		t.Fatalf("outcome = %+v, want valid root", outcome)
	}
}

func TestContextualValidatorAnonymousElectionRequiresExplicitRule(t *testing.T) {
	validator, err := NewContextualValidator(memoryStatusStore{})
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	_, err = validator.ValidateContext(context.Background(), domain.ObjectEnvelope{ObjectID: "election-1", ObjectType: domain.ObjectTypeAnonymousElection})
	if !errors.Is(err, ErrContextualRuleUnsupported) {
		t.Fatalf("ValidateContext() error = %v, want %v", err, ErrContextualRuleUnsupported)
	}
}

func TestContextualValidatorMissingDependencyIsPending(t *testing.T) {
	validator, err := NewContextualValidator(memoryStatusStore{}, WithContextualRule(domain.ObjectTypeTrusteeNomination,
		func(context.Context, domain.ObjectEnvelope) (ContextualRuleResult, error) {
			return ContextualRuleResult{
				Status: StatusValid,
				RequiredDependencies: []RequiredDependency{
					RequireObject("trustee_selection", "selection-1", StatusValid),
				},
			}, nil
		}))
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), domain.ObjectEnvelope{ObjectID: "nomination-1", ObjectType: domain.ObjectTypeTrusteeNomination})
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusPendingDependencies || outcome.ShouldRepublish {
		t.Fatalf("outcome = %+v, want pending without republish", outcome)
	}
	if len(outcome.Dependencies) != 1 || outcome.Dependencies[0] != (Dependency{Type: "trustee_selection", ID: "selection-1"}) {
		t.Fatalf("dependencies = %+v", outcome.Dependencies)
	}
}

func TestContextualValidatorPresentDependencyAllowsRuleStatus(t *testing.T) {
	store := memoryStatusStore{"selection-1": StatusValid}
	validator, err := NewContextualValidator(store, WithContextualRule(domain.ObjectTypeTrusteeVote,
		func(context.Context, domain.ObjectEnvelope) (ContextualRuleResult, error) {
			return ContextualRuleResult{
				Status: StatusValidForTally,
				RequiredDependencies: []RequiredDependency{
					RequireObject("trustee_selection", "selection-1", StatusValid),
				},
			}, nil
		}))
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), domain.ObjectEnvelope{ObjectID: "vote-1", ObjectType: domain.ObjectTypeTrusteeVote})
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusValidForTally || !outcome.ShouldRepublish || len(outcome.Dependencies) != 0 {
		t.Fatalf("outcome = %+v, want delegated valid_for_tally", outcome)
	}
}

func TestContextualValidatorDependencyStatusHandling(t *testing.T) {
	tests := []struct {
		name       string
		status     Status
		wantStatus Status
		wantCode   string
	}{
		{name: "pending dependency remains pending", status: StatusPendingDependencies, wantStatus: StatusPendingDependencies},
		{name: "invalid dependency invalidates object", status: StatusInvalid, wantStatus: StatusInvalid, wantCode: ErrorContextualDependencyStatus},
		{name: "conflicted dependency invalidates when not acceptable", status: StatusValidButConflicted, wantStatus: StatusInvalid, wantCode: ErrorContextualDependencyStatus},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, err := NewContextualValidator(memoryStatusStore{"dep-1": tt.status}, WithContextualRule(domain.ObjectTypeBlindTokenIssue,
				func(context.Context, domain.ObjectEnvelope) (ContextualRuleResult, error) {
					return ContextualRuleResult{
						Status: StatusValid,
						RequiredDependencies: []RequiredDependency{
							RequireObject("blind_token_request", "dep-1", StatusValid),
						},
					}, nil
				}))
			if err != nil {
				t.Fatalf("NewContextualValidator() error = %v", err)
			}

			outcome, err := validator.ValidateContext(context.Background(), domain.ObjectEnvelope{ObjectID: "issue-1", ObjectType: domain.ObjectTypeBlindTokenIssue})
			if err != nil {
				t.Fatalf("ValidateContext() error = %v", err)
			}
			if outcome.Status != tt.wantStatus || outcome.ValidationErrorCode != tt.wantCode {
				t.Fatalf("outcome = %+v, want status=%s code=%s", outcome, tt.wantStatus, tt.wantCode)
			}
		})
	}
}

func TestContextualValidatorDoesNotShortcutActivationOrResults(t *testing.T) {
	validator, err := NewContextualValidator(memoryStatusStore{})
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	for _, objectType := range []domain.ObjectType{domain.ObjectTypeTallyKeySet, domain.ObjectTypeTrusteeSelectionResult, domain.ObjectTypeTallyResult} {
		_, err := validator.ValidateContext(context.Background(), domain.ObjectEnvelope{ObjectID: string(objectType) + "-object", ObjectType: objectType})
		if !errors.Is(err, ErrContextualRuleUnsupported) {
			t.Fatalf("ValidateContext(%s) error = %v, want %v", objectType, err, ErrContextualRuleUnsupported)
		}
	}
}

func TestContextualValidatorRejectsBadRules(t *testing.T) {
	validator, err := NewContextualValidator(memoryStatusStore{}, WithContextualRule(domain.ObjectTypeTrusteeNomination,
		func(context.Context, domain.ObjectEnvelope) (ContextualRuleResult, error) {
			return ContextualRuleResult{Status: StatusPendingDependencies}, nil
		}))
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	_, err = validator.ValidateContext(context.Background(), domain.ObjectEnvelope{ObjectID: "nomination-1", ObjectType: domain.ObjectTypeTrusteeNomination})
	if err == nil {
		t.Fatal("ValidateContext() error = nil, want pending without dependency error")
	}
}

func TestContextualValidatorPropagatesStoreErrors(t *testing.T) {
	want := errors.New("boom")
	validator, err := NewContextualValidator(errorStatusStore{err: want}, WithContextualRule(domain.ObjectTypeTrusteeNomination,
		func(context.Context, domain.ObjectEnvelope) (ContextualRuleResult, error) {
			return ContextualRuleResult{
				Status:               StatusValid,
				RequiredDependencies: []RequiredDependency{RequireObject("trustee_selection", "selection-1", StatusValid)},
			}, nil
		}))
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	_, err = validator.ValidateContext(context.Background(), domain.ObjectEnvelope{ObjectID: "nomination-1", ObjectType: domain.ObjectTypeTrusteeNomination})
	if !errors.Is(err, want) {
		t.Fatalf("ValidateContext() error = %v, want %v", err, want)
	}
}

type memoryStatusStore map[string]Status

func (s memoryStatusStore) ValidationStatus(_ context.Context, objectID string) (Status, bool, error) {
	status, ok := s[objectID]
	return status, ok, nil
}

type errorStatusStore struct {
	err error
}

func (s errorStatusStore) ValidationStatus(context.Context, string) (Status, bool, error) {
	return "", false, s.err
}
