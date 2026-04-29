package validation

import (
	"bytes"
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

func TestContextualValidatorAnonymousElectionRequiresResultDependency(t *testing.T) {
	validator, err := NewContextualValidator(memoryStatusStore{})
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), domain.ObjectEnvelope{ObjectID: "election-1", ObjectType: domain.ObjectTypeAnonymousElection, Payload: validAnonymousElectionContextPayload()})
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	resultID := TrusteeSelectionResultDependencyID("selection-1", repeatedContextByte(0x31, 32))
	if outcome.Status != StatusPendingDependencies || len(outcome.Dependencies) != 1 || outcome.Dependencies[0] != (Dependency{Type: "trustee_selection_result", ID: resultID}) {
		t.Fatalf("outcome = %+v, want pending trustee_selection_result dependency", outcome)
	}
}

func TestContextualValidatorTrusteeConsentRequiresExplicitRule(t *testing.T) {
	validator, err := NewContextualValidator(memoryStatusStore{})
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	_, err = validator.ValidateContext(context.Background(), domain.ObjectEnvelope{ObjectID: "consent-1", ObjectType: domain.ObjectTypeTrusteeConsent, Payload: validTrusteeConsentContextPayload()})
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

func sameDependencies(got, want []Dependency) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

type contextPayloadBuilder struct{ bytes.Buffer }

func (b *contextPayloadBuilder) stringField(field uint64, value string) {
	writeContextProtoBytes(&b.Buffer, field, []byte(value))
}

func (b *contextPayloadBuilder) bytesField(field uint64, value []byte) {
	writeContextProtoBytes(&b.Buffer, field, value)
}

func (b *contextPayloadBuilder) intField(field uint64, value int64) {
	writeContextProtoVarint(&b.Buffer, field<<3)
	writeContextProtoVarint(&b.Buffer, uint64(value))
}

func validAnonymousElectionContextPayload() []byte {
	var b contextPayloadBuilder
	b.stringField(1, "election-1")
	b.stringField(2, "testnet")
	b.stringField(3, "Title")
	b.stringField(4, "Description")
	b.stringField(5, "Yes")
	b.stringField(5, "No")
	b.bytesField(6, voterEntryContextPayload())
	b.stringField(7, "selection-1")
	b.bytesField(8, repeatedContextByte(0x31, 32))
	b.intField(9, 2)
	b.intField(10, 3)
	b.stringField(11, domain.EligibilitySchemeBlindTokenV1)
	b.intField(12, 1000)
	b.intField(13, 2000)
	b.intField(14, 3000)
	b.intField(15, 4000)
	b.intField(16, 5000)
	b.bytesField(17, repeatedContextByte(0xaa, 32))
	b.bytesField(18, repeatedContextByte(0xbb, 64))
	return b.Bytes()
}

func validTrusteeConsentContextPayload() []byte {
	var b contextPayloadBuilder
	b.stringField(1, "selection-1")
	b.bytesField(2, repeatedContextByte(0x31, 32))
	b.stringField(3, "election-1")
	b.bytesField(4, repeatedContextByte(0x41, 32))
	b.bytesField(5, repeatedContextByte(0x51, 32))
	b.bytesField(6, repeatedContextByte(0x61, 32))
	b.intField(7, 2)
	b.intField(8, 3)
	b.bytesField(9, repeatedContextByte(0x71, 64))
	return b.Bytes()
}

func voterEntryContextPayload() []byte {
	var b contextPayloadBuilder
	b.stringField(1, "voter-1")
	b.bytesField(2, repeatedContextByte(0x11, 32))
	b.bytesField(3, repeatedContextByte(0x21, 32))
	return b.Bytes()
}

func repeatedContextByte(value byte, size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = value
	}
	return out
}

func writeContextProtoBytes(buf *bytes.Buffer, fieldNumber uint64, value []byte) {
	writeContextProtoVarint(buf, fieldNumber<<3|2)
	writeContextProtoVarint(buf, uint64(len(value)))
	buf.Write(value)
}

func writeContextProtoVarint(buf *bytes.Buffer, value uint64) {
	for value >= 0x80 {
		buf.WriteByte(byte(value) | 0x80)
		value >>= 7
	}
	buf.WriteByte(byte(value))
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
