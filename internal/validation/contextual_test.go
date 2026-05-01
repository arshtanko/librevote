package validation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	lvcrypto "librevote/internal/crypto"
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

	for _, objectType := range []domain.ObjectType{domain.ObjectTypeTallyKeySet, domain.ObjectTypeTallyResult} {
		_, err := validator.ValidateContext(context.Background(), domain.ObjectEnvelope{ObjectID: string(objectType) + "-object", ObjectType: objectType})
		if !errors.Is(err, ErrContextualRuleUnsupported) {
			t.Fatalf("ValidateContext(%s) error = %v, want %v", objectType, err, ErrContextualRuleUnsupported)
		}
	}
}

func TestContextualValidatorTrusteeSelectionResultRecomputesValidResult(t *testing.T) {
	store := trusteeSelectionInputStore{inputs: recomputableTrusteeSelectionInputs(StatusValid, StatusValidForTally)}
	result := recomputedTrusteeSelectionResult(t, store.inputs)
	validator, err := NewContextualValidator(store)
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), trusteeSelectionResultEnvelope(result))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusValid || !outcome.ShouldRepublish {
		t.Fatalf("outcome = %+v, want recomputed valid result", outcome)
	}
}

func TestContextualValidatorTrusteeSelectionResultRejectsMismatch(t *testing.T) {
	store := trusteeSelectionInputStore{inputs: recomputableTrusteeSelectionInputs(StatusValid, StatusValidForTally)}
	result := recomputedTrusteeSelectionResult(t, store.inputs)
	result.ValidVoteCount++
	validator, err := NewContextualValidator(store)
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), trusteeSelectionResultEnvelope(result))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusInvalid || outcome.ValidationErrorCode != ErrorTrusteeSelectionResultMismatch {
		t.Fatalf("outcome = %+v, want mismatch invalid", outcome)
	}
}

func TestContextualValidatorTrusteeSelectionResultRejectsInvalidSignature(t *testing.T) {
	store := trusteeSelectionInputStore{inputs: recomputableTrusteeSelectionInputs(StatusValid, StatusValidForTally)}
	result := recomputedTrusteeSelectionResult(t, store.inputs)
	result.Signature[0] ^= 0xff
	validator, err := NewContextualValidator(store)
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), trusteeSelectionResultEnvelope(result))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusInvalid || outcome.ValidationErrorCode != ErrorTrusteeSelectionResultMismatch {
		t.Fatalf("outcome = %+v, want invalid signature rejection", outcome)
	}
}

func TestContextualValidatorTrusteeSelectionResultRejectsWrongScope(t *testing.T) {
	store := trusteeSelectionInputStore{inputs: recomputableTrusteeSelectionInputs(StatusValid, StatusValidForTally)}
	result := recomputedTrusteeSelectionResult(t, store.inputs)
	validator, err := NewContextualValidator(store)
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}
	envelope := trusteeSelectionResultEnvelope(result)
	envelope.ScopeID = "other-selection"

	outcome, err := validator.ValidateContext(context.Background(), envelope)
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusInvalid || outcome.ValidationErrorCode != ErrorTrusteeSelectionResultMismatch {
		t.Fatalf("outcome = %+v, want invalid scope mismatch", outcome)
	}
}

func TestContextualValidatorTrusteeSelectionResultPendingInputsBlockRecompute(t *testing.T) {
	store := trusteeSelectionInputStore{inputs: recomputableTrusteeSelectionInputs(StatusPendingDependencies, StatusPendingPayloadEvicted)}
	complete := recomputableTrusteeSelectionInputs(StatusValid, StatusValidForTally)
	result := recomputedTrusteeSelectionResult(t, complete)
	validator, err := NewContextualValidator(store)
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), trusteeSelectionResultEnvelope(result))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusPendingDependencies || len(outcome.Dependencies) != 2 {
		t.Fatalf("outcome = %+v, want pending nomination and vote dependencies", outcome)
	}
}

func TestContextualValidatorTrusteeSelectionResultMissingNominationPending(t *testing.T) {
	store := trusteeSelectionInputStore{inputs: recomputableTrusteeSelectionInputs(StatusValid, StatusValidForTally)}
	result := recomputedTrusteeSelectionResult(t, store.inputs)
	store.inputs.Nominations = store.inputs.Nominations[:2]
	validator, err := NewContextualValidator(store)
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), trusteeSelectionResultEnvelope(result))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusPendingDependencies || len(outcome.Dependencies) != 1 || outcome.Dependencies[0].Type != "trustee_nomination" {
		t.Fatalf("outcome = %+v, want pending missing nomination", outcome)
	}
}

func TestContextualValidatorTrusteeSelectionResultExcludesConflictedInputs(t *testing.T) {
	store := trusteeSelectionInputStore{inputs: recomputableTrusteeSelectionInputs(StatusValidButConflicted, StatusValidButConflicted)}
	result := recomputedTrusteeSelectionResult(t, store.inputs)
	validator, err := NewContextualValidator(store)
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), trusteeSelectionResultEnvelope(result))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusValid || result.ValidVoteCount != 1 || result.ConflictedVoteCount != 1 || len(result.CandidateRanking) != 2 {
		t.Fatalf("outcome = %+v result = %+v, want conflicted inputs excluded/counts recomputed", outcome, result)
	}
}

func TestContextualValidatorTrusteeSelectionResultRequiresRecomputeStore(t *testing.T) {
	validator, err := NewContextualValidator(memoryStatusStore{})
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	_, err = validator.ValidateContext(context.Background(), trusteeSelectionResultEnvelope(domain.TrusteeSelectionResultPayload{TrusteeSelectionID: "selection-1"}))
	if !errors.Is(err, ErrContextualRuleUnsupported) {
		t.Fatalf("ValidateContext() error = %v, want unsupported without recompute store", err)
	}
}

func TestContextualValidatorTallyKeySetRecomputesValidActivation(t *testing.T) {
	store := tallyKeySetInputStore{inputs: recomputableTallyKeySetInputs(t)}
	keySet := recomputedTallyKeySet(t, store.inputs)
	validator, err := NewContextualValidator(store)
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), tallyKeySetEnvelope(keySet))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusValid || !outcome.ShouldRepublish {
		t.Fatalf("outcome = %+v, want recomputed valid tally key set", outcome)
	}
}

func TestContextualValidatorTallyKeySetMissingDependencies(t *testing.T) {
	base := recomputableTallyKeySetInputs(t)
	keySet := recomputedTallyKeySet(t, base)
	tests := []struct {
		name       string
		mutate     func(*TallyKeySetInputs)
		dependency string
	}{
		{name: "missing election", mutate: func(in *TallyKeySetInputs) { in.ElectionFound = false }, dependency: "election"},
		{name: "missing result", mutate: func(in *TallyKeySetInputs) { in.ResultFound = false }, dependency: "trustee_selection_result"},
		{name: "missing consent", mutate: func(in *TallyKeySetInputs) { in.Consents = in.Consents[:2] }, dependency: "trustee_consent"},
		{name: "missing contribution", mutate: func(in *TallyKeySetInputs) { in.Contributions = in.Contributions[:2] }, dependency: "tally_key_contribution"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputs := base
			inputs.Consents = append([]TrusteeConsentInput(nil), base.Consents...)
			inputs.Contributions = append([]TallyKeyContributionInput(nil), base.Contributions...)
			tt.mutate(&inputs)
			validator, err := NewContextualValidator(tallyKeySetInputStore{inputs: inputs})
			if err != nil {
				t.Fatalf("NewContextualValidator() error = %v", err)
			}
			outcome, err := validator.ValidateContext(context.Background(), tallyKeySetEnvelope(keySet))
			if err != nil {
				t.Fatalf("ValidateContext() error = %v", err)
			}
			if outcome.Status != StatusPendingDependencies || len(outcome.Dependencies) != 1 || outcome.Dependencies[0].Type != tt.dependency {
				t.Fatalf("outcome = %+v, want pending %s", outcome, tt.dependency)
			}
		})
	}
}

func TestContextualValidatorTallyKeySetRejectsMismatches(t *testing.T) {
	inputs := recomputableTallyKeySetInputs(t)
	tests := []struct {
		name   string
		mutate func(*domain.TallyKeySetPayload)
	}{
		{name: "trustee set", mutate: func(p *domain.TallyKeySetPayload) {
			p.TrusteeSet[0], p.TrusteeSet[1] = p.TrusteeSet[1], p.TrusteeSet[0]
		}},
		{name: "trustee set hash", mutate: func(p *domain.TallyKeySetPayload) { p.TrusteeSetHash[0] ^= 0xff }},
		{name: "consent ids", mutate: func(p *domain.TallyKeySetPayload) { p.TrusteeConsentObjectIDs[0] = "other-consent" }},
		{name: "contribution ids", mutate: func(p *domain.TallyKeySetPayload) { p.TallyKeyContributionObjectIDs[0] = "other-contribution" }},
		{name: "activation hash", mutate: func(p *domain.TallyKeySetPayload) { p.TallyKeySetHash[0] ^= 0xff }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keySet := recomputedTallyKeySet(t, inputs)
			tt.mutate(&keySet)
			validator, err := NewContextualValidator(tallyKeySetInputStore{inputs: inputs})
			if err != nil {
				t.Fatalf("NewContextualValidator() error = %v", err)
			}
			outcome, err := validator.ValidateContext(context.Background(), tallyKeySetEnvelope(keySet))
			if err != nil {
				t.Fatalf("ValidateContext() error = %v", err)
			}
			if outcome.Status != StatusInvalid || outcome.ValidationErrorCode != ErrorTallyKeySetActivationMismatch {
				t.Fatalf("outcome = %+v, want activation mismatch", outcome)
			}
		})
	}
}

func TestContextualValidatorTallyKeySetExcludesConflictedInputs(t *testing.T) {
	inputs := recomputableTallyKeySetInputs(t)
	inputs.Consents[0].Status = StatusValidButConflicted
	keySet := recomputedTallyKeySet(t, recomputableTallyKeySetInputs(t))
	validator, err := NewContextualValidator(tallyKeySetInputStore{inputs: inputs})
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), tallyKeySetEnvelope(keySet))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusPendingDependencies || outcome.Dependencies[0].Type != "trustee_consent" {
		t.Fatalf("outcome = %+v, want conflicted consent excluded from activation", outcome)
	}
}

func TestContextualValidatorTallyKeySetIgnoresUnrelatedPendingActivationInputs(t *testing.T) {
	inputs := recomputableTallyKeySetInputs(t)
	keySet := recomputedTallyKeySet(t, inputs)
	inputs.Consents = append(inputs.Consents, TrusteeConsentInput{ObjectID: "unrelated-pending-consent", Status: StatusPendingDependencies, Payload: domain.TrusteeConsentPayload{TrusteePublicKey: repeatedContextByte(0xee, 32)}})
	inputs.Contributions = append(inputs.Contributions, TallyKeyContributionInput{ObjectID: "unrelated-pending-contribution", Status: StatusPendingDependencies, Payload: domain.TallyKeyContributionPayload{TrusteePublicKey: repeatedContextByte(0xef, 32)}})
	validator, err := NewContextualValidator(tallyKeySetInputStore{inputs: inputs})
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), tallyKeySetEnvelope(keySet))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusValid {
		t.Fatalf("outcome = %+v, want unrelated pending activation inputs ignored", outcome)
	}
}

func TestContextualValidatorTallyKeySetRejectsDuplicateValidActivationInputs(t *testing.T) {
	inputs := recomputableTallyKeySetInputs(t)
	keySet := recomputedTallyKeySet(t, inputs)
	inputs.Consents = append(inputs.Consents, TrusteeConsentInput{ObjectID: "duplicate-consent", Status: StatusValid, Payload: inputs.Consents[0].Payload})
	validator, err := NewContextualValidator(tallyKeySetInputStore{inputs: inputs})
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), tallyKeySetEnvelope(keySet))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusInvalid {
		t.Fatalf("outcome = %+v, want duplicate valid consent rejected", outcome)
	}

	inputs = recomputableTallyKeySetInputs(t)
	keySet = recomputedTallyKeySet(t, inputs)
	inputs.Contributions = append(inputs.Contributions, TallyKeyContributionInput{ObjectID: "duplicate-contribution", Status: StatusValid, Payload: inputs.Contributions[0].Payload})
	validator, err = NewContextualValidator(tallyKeySetInputStore{inputs: inputs})
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}
	outcome, err = validator.ValidateContext(context.Background(), tallyKeySetEnvelope(keySet))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusInvalid {
		t.Fatalf("outcome = %+v, want duplicate valid contribution rejected", outcome)
	}
}

func TestContextualValidatorTallyKeySetRequiresDistinctFinalTrustees(t *testing.T) {
	inputs := recomputableTallyKeySetInputs(t)
	inputs.Result.CandidateRanking[1].TrusteePublicKey = append([]byte(nil), inputs.Result.CandidateRanking[0].TrusteePublicKey...)
	keySet := recomputedTallyKeySet(t, recomputableTallyKeySetInputs(t))
	validator, err := NewContextualValidator(tallyKeySetInputStore{inputs: inputs})
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), tallyKeySetEnvelope(keySet))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusPendingDependencies {
		t.Fatalf("outcome = %+v, want duplicate ranked trustee to prevent distinct final set", outcome)
	}
}

func TestContextualValidatorTrusteeConsentValidatesSignature(t *testing.T) {
	inputs := recomputableTallyKeySetInputs(t)
	validator, err := NewContextualValidator(tallyKeySetInputStore{inputs: inputs})
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), trusteeConsentEnvelope(inputs.Consents[0].Payload))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusValid {
		t.Fatalf("outcome = %+v, want valid consent", outcome)
	}
	wantConsentConflicts := trusteeConsentConflictKeys(inputs.Consents[0].Payload)
	if !sameConflictKeys(outcome.ConflictKeys, wantConsentConflicts) {
		t.Fatalf("consent conflict keys = %+v, want %+v", outcome.ConflictKeys, wantConsentConflicts)
	}

	bad := inputs.Consents[0].Payload
	bad.Signature = append([]byte(nil), bad.Signature...)
	bad.Signature[0] ^= 0xff
	outcome, err = validator.ValidateContext(context.Background(), trusteeConsentEnvelope(bad))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusInvalid {
		t.Fatalf("outcome = %+v, want invalid signature", outcome)
	}
}

func TestContextualValidatorTallyKeyContributionValidatesFinalSetAndSignature(t *testing.T) {
	inputs := recomputableTallyKeySetInputs(t)
	inputs.Consents = append(inputs.Consents, TrusteeConsentInput{ObjectID: "unrelated-pending-consent", Status: StatusPendingDependencies, Payload: domain.TrusteeConsentPayload{TrusteePublicKey: repeatedContextByte(0xee, 32)}})
	validator, err := NewContextualValidator(tallyKeySetInputStore{inputs: inputs})
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}

	outcome, err := validator.ValidateContext(context.Background(), tallyKeyContributionEnvelope(inputs.Contributions[0].Payload))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusValid {
		t.Fatalf("outcome = %+v, want unrelated pending consent ignored", outcome)
	}
	wantContributionConflicts := tallyKeyContributionConflictKeys(inputs.Contributions[0].Payload)
	if !sameConflictKeys(outcome.ConflictKeys, wantContributionConflicts) {
		t.Fatalf("contribution conflict keys = %+v, want %+v", outcome.ConflictKeys, wantContributionConflicts)
	}

	badShares := inputs.Contributions[0].Payload
	badShares.DKGEncryptedShares = append([]domain.DKGEncryptedShare(nil), badShares.DKGEncryptedShares...)
	badShares.DKGEncryptedShares[0].RecipientIndex = 99
	outcome, err = validator.ValidateContext(context.Background(), tallyKeyContributionEnvelope(badShares))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusInvalid {
		t.Fatalf("outcome = %+v, want invalid share binding", outcome)
	}

	badSignature := inputs.Contributions[0].Payload
	badSignature.Signature = append([]byte(nil), badSignature.Signature...)
	badSignature.Signature[0] ^= 0xff
	outcome, err = validator.ValidateContext(context.Background(), tallyKeyContributionEnvelope(badSignature))
	if err != nil {
		t.Fatalf("ValidateContext() error = %v", err)
	}
	if outcome.Status != StatusInvalid {
		t.Fatalf("outcome = %+v, want invalid signature", outcome)
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

func sameConflictKeys(got, want []ConflictKey) bool {
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

type trusteeSelectionInputStore struct {
	inputs TrusteeSelectionInputs
}

func (s trusteeSelectionInputStore) ValidationStatus(context.Context, string) (Status, bool, error) {
	return "", false, nil
}

func (s trusteeSelectionInputStore) TrusteeSelectionInputs(context.Context, string) (TrusteeSelectionInputs, error) {
	return s.inputs, nil
}

type tallyKeySetInputStore struct {
	inputs TallyKeySetInputs
}

func (s tallyKeySetInputStore) ValidationStatus(context.Context, string) (Status, bool, error) {
	return "", false, nil
}

func (s tallyKeySetInputStore) TallyKeySetInputs(context.Context, string, []byte) (TallyKeySetInputs, error) {
	return s.inputs, nil
}

func (s tallyKeySetInputStore) ElectionActivationInputs(context.Context, string) (TallyKeySetInputs, error) {
	return s.inputs, nil
}

func recomputableTallyKeySetInputs(t *testing.T) TallyKeySetInputs {
	t.Helper()
	selectionInputs := recomputableTrusteeSelectionInputs("", StatusValidForTally)
	result := recomputedTrusteeSelectionResult(t, selectionInputs)
	trusteeKeys := map[string]ed25519.PrivateKey{}
	for i := 0; i < domain.TrusteeCountV1; i++ {
		privateKey := ed25519.NewKeyFromSeed(repeatedContextByte(0x30+byte(i), ed25519.SeedSize))
		publicKey := append([]byte(nil), privateKey.Public().(ed25519.PublicKey)...)
		result.CandidateRanking[i].TrusteePublicKey = publicKey
		if i < len(result.InitialSelectedTrustees) {
			result.InitialSelectedTrustees[i].TrusteePublicKey = append([]byte(nil), publicKey...)
		}
		if i < len(result.CandidateScores) {
			result.CandidateScores[i].TrusteePublicKey = append([]byte(nil), publicKey...)
		}
		trusteeKeys[string(publicKey)] = privateKey
	}
	result.ResultHash = ComputeTrusteeSelectionResultHash(result)
	election := domain.AnonymousElectionPayload{
		ElectionID:                 "election-1",
		TrusteeSelectionID:         result.TrusteeSelectionID,
		TrusteeSelectionResultHash: append([]byte(nil), result.ResultHash...),
	}
	consents := make([]TrusteeConsentInput, 0, domain.TrusteeCountV1)
	contributions := make([]TallyKeyContributionInput, 0, domain.TrusteeCountV1)
	for i, candidate := range result.CandidateRanking[:domain.TrusteeCountV1] {
		index := byte(i + 1)
		setupKey := repeatedContextByte(0x80+index, 32)
		consent := domain.TrusteeConsentPayload{
			TrusteeSelectionID:         result.TrusteeSelectionID,
			TrusteeSelectionResultHash: append([]byte(nil), result.ResultHash...),
			ElectionID:                 election.ElectionID,
			ElectionParametersHash:     ComputeElectionParametersHash(election),
			TrusteePublicKey:           append([]byte(nil), candidate.TrusteePublicKey...),
			TrusteeTallySetupPublicKey: setupKey,
			ThresholdT:                 domain.ThresholdV1,
			TrusteeCountN:              domain.TrusteeCountV1,
		}
		consent.Signature = signContextPayload(t, domain.ObjectTypeTrusteeConsent, election.ElectionID, 9, trusteeConsentContextPayload(consent), trusteeKeys[string(candidate.TrusteePublicKey)])
		consents = append(consents, TrusteeConsentInput{
			ObjectID: "consent-" + string(rune('0'+index)),
			Status:   StatusValid,
			Payload:  consent,
		})
	}
	finalSet, _, ok := deriveFinalTrusteeSet(result, consents)
	if !ok {
		t.Fatal("deriveFinalTrusteeSet() failed for fixture")
	}
	for i, trustee := range finalSet {
		index := byte(i + 1)
		contribution := domain.TallyKeyContributionPayload{
			ElectionID:                 election.ElectionID,
			TrusteePublicKey:           append([]byte(nil), trustee.TrusteePublicKey...),
			TrusteeTallySetupPublicKey: append([]byte(nil), trustee.TrusteeTallySetupKey...),
			DKGCommitments: []domain.DKGCommitment{{
				SenderTrusteePublicKey: append([]byte(nil), trustee.TrusteePublicKey...),
				CoefficientIndex:       1,
				Commitment:             repeatedContextByte(0x90+index, 32),
			}},
			DKGEncryptedShares: tallyKeySetShares(trustee.TrusteePublicKey, finalSet),
			SetupProof:         repeatedContextByte(0xa0+index, 32),
		}
		contribution.Signature = signContextPayload(t, domain.ObjectTypeTallyKeyContribution, election.ElectionID, 7, tallyKeyContributionContextPayload(contribution), trusteeKeys[string(trustee.TrusteePublicKey)])
		contributions = append(contributions, TallyKeyContributionInput{
			ObjectID: "contribution-" + string(rune('0'+index)),
			Status:   StatusValid,
			Payload:  contribution,
		})
	}
	return TallyKeySetInputs{
		ElectionFound:  true,
		ElectionStatus: StatusValid,
		Election:       election,
		ResultFound:    true,
		ResultStatus:   StatusValid,
		Result:         result,
		Consents:       consents,
		Contributions:  contributions,
	}
}

func tallyKeySetShares(sender []byte, trustees []domain.TrusteeCandidate) []domain.DKGEncryptedShare {
	shares := make([]domain.DKGEncryptedShare, 0, len(trustees))
	for i, trustee := range trustees {
		index := byte(i + 1)
		setupKeyID, err := lvcrypto.KeyID(lvcrypto.KeyTypeTrusteeTallySetup, trustee.TrusteeTallySetupKey)
		if err != nil {
			panic(err)
		}
		shares = append(shares, domain.DKGEncryptedShare{
			SenderTrusteePublicKey:    append([]byte(nil), sender...),
			RecipientTrusteePublicKey: append([]byte(nil), trustee.TrusteePublicKey...),
			RecipientTallySetupKeyID:  append([]byte(nil), setupKeyID[:]...),
			RecipientIndex:            int64(i + 1),
			EncryptedShare:            repeatedContextByte(0xc0+index, 16),
			ShareEncryptionProof:      repeatedContextByte(0xd0+index, 16),
		})
	}
	return shares
}

func recomputedTallyKeySet(t *testing.T, inputs TallyKeySetInputs) domain.TallyKeySetPayload {
	t.Helper()
	finalSet, consentIDs, ok := deriveFinalTrusteeSet(inputs.Result, inputs.Consents)
	if !ok {
		t.Fatal("deriveFinalTrusteeSet() failed")
	}
	contributionIDs, commitments, setupProofs, contributionIssue, _ := retainedContributionsForTrustees(inputs.Election.ElectionID, finalSet, inputs.Contributions)
	if contributionIssue != "" {
		t.Fatalf("retainedContributionsForTrustees() failed: %s", contributionIssue)
	}
	keySet := domain.TallyKeySetPayload{
		ElectionID:                    inputs.Election.ElectionID,
		TrusteeSelectionResultHash:    append([]byte(nil), inputs.Election.TrusteeSelectionResultHash...),
		TrusteeSet:                    finalSet,
		TrusteeConsentObjectIDs:       consentIDs,
		TallyKeyContributionObjectIDs: contributionIDs,
		TrusteeSetHash:                ComputeTrusteeSetHash(finalSet),
		ThresholdT:                    domain.ThresholdV1,
		TrusteeCountN:                 domain.TrusteeCountV1,
		TrusteeKeyCommitments:         commitments,
		SetupProofs:                   setupProofs,
	}
	keySet.TallyPublicKey = ComputeTallyPublicKey(commitments)
	keySet.TallyKeySetHash = ComputeTallyKeySetHash(keySet.ElectionID, keySet.TrusteeSelectionResultHash, keySet.TrusteeSet, keySet.TrusteeConsentObjectIDs, keySet.TallyKeyContributionObjectIDs, keySet.TrusteeKeyCommitments, keySet.TallyPublicKey)
	privateKey := ed25519.NewKeyFromSeed(repeatedContextByte(0x44, ed25519.SeedSize))
	keySet.ReporterPublicKey = append([]byte(nil), privateKey.Public().(ed25519.PublicKey)...)
	keySet.Signature = signContextPayload(t, domain.ObjectTypeTallyKeySet, keySet.ElectionID, 14, tallyKeySetContextPayload(keySet), privateKey)
	return keySet
}

func tallyKeySetEnvelope(payload domain.TallyKeySetPayload) domain.ObjectEnvelope {
	return domain.ObjectEnvelope{ObjectID: "tally-key-set-1", ObjectType: domain.ObjectTypeTallyKeySet, ProtocolVersion: "1", NetworkID: "testnet", Scope: domain.ScopeElectionID, ScopeID: payload.ElectionID, CreatedAt: 1700000000000, Payload: tallyKeySetContextPayload(payload)}
}

func trusteeConsentEnvelope(payload domain.TrusteeConsentPayload) domain.ObjectEnvelope {
	return domain.ObjectEnvelope{ObjectID: "consent-1", ObjectType: domain.ObjectTypeTrusteeConsent, ProtocolVersion: "1", NetworkID: "testnet", Scope: domain.ScopeElectionID, ScopeID: payload.ElectionID, CreatedAt: 1700000000000, Payload: trusteeConsentContextPayload(payload)}
}

func tallyKeyContributionEnvelope(payload domain.TallyKeyContributionPayload) domain.ObjectEnvelope {
	return domain.ObjectEnvelope{ObjectID: "contribution-1", ObjectType: domain.ObjectTypeTallyKeyContribution, ProtocolVersion: "1", NetworkID: "testnet", Scope: domain.ScopeElectionID, ScopeID: payload.ElectionID, CreatedAt: 1700000000000, Payload: tallyKeyContributionContextPayload(payload)}
}

func signContextPayload(t *testing.T, objectType domain.ObjectType, electionID string, signatureField uint64, payload []byte, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	signedPayload, err := payloadWithoutField(payload, signatureField)
	if err != nil {
		t.Fatalf("payloadWithoutField() error = %v", err)
	}
	digest, err := lvcrypto.SigningDigest(lvcrypto.SigningContext{Domain: signingDomainForObjectType(objectType), ProtocolVersion: "1", NetworkID: "testnet", ObjectType: objectType, Scope: domain.ScopeElectionID, ScopeID: electionID, CreatedAt: 1700000000000}, signedPayload)
	if err != nil {
		t.Fatalf("SigningDigest() error = %v", err)
	}
	return ed25519.Sign(privateKey, digest[:])
}

func signingDomainForObjectType(objectType domain.ObjectType) lvcrypto.Domain {
	switch objectType {
	case domain.ObjectTypeTrusteeConsent:
		return lvcrypto.DomainTrusteeConsentSign
	case domain.ObjectTypeTallyKeyContribution:
		return lvcrypto.DomainTallyKeyContributionSign
	case domain.ObjectTypeTallyKeySet:
		return lvcrypto.DomainTallyKeySetSign
	default:
		panic("unexpected signing object type")
	}
}

func trusteeConsentContextPayload(payload domain.TrusteeConsentPayload) []byte {
	var b contextPayloadBuilder
	b.stringField(1, payload.TrusteeSelectionID)
	b.bytesField(2, payload.TrusteeSelectionResultHash)
	b.stringField(3, payload.ElectionID)
	b.bytesField(4, payload.ElectionParametersHash)
	b.bytesField(5, payload.TrusteePublicKey)
	b.bytesField(6, payload.TrusteeTallySetupPublicKey)
	b.intField(7, payload.ThresholdT)
	b.intField(8, payload.TrusteeCountN)
	b.bytesField(9, payload.Signature)
	return b.Bytes()
}

func tallyKeyContributionContextPayload(payload domain.TallyKeyContributionPayload) []byte {
	var b contextPayloadBuilder
	b.stringField(1, payload.ElectionID)
	b.bytesField(2, payload.TrusteePublicKey)
	b.bytesField(3, payload.TrusteeTallySetupPublicKey)
	for _, commitment := range payload.DKGCommitments {
		b.bytesField(4, dkgCommitmentContextPayload(commitment))
	}
	for _, share := range payload.DKGEncryptedShares {
		b.bytesField(5, dkgEncryptedShareContextPayload(share))
	}
	b.bytesField(6, payload.SetupProof)
	b.bytesField(7, payload.Signature)
	return b.Bytes()
}

func dkgCommitmentContextPayload(payload domain.DKGCommitment) []byte {
	var b contextPayloadBuilder
	b.bytesField(1, payload.SenderTrusteePublicKey)
	b.intField(2, payload.CoefficientIndex)
	b.bytesField(3, payload.Commitment)
	return b.Bytes()
}

func dkgEncryptedShareContextPayload(payload domain.DKGEncryptedShare) []byte {
	var b contextPayloadBuilder
	b.bytesField(1, payload.SenderTrusteePublicKey)
	b.bytesField(2, payload.RecipientTrusteePublicKey)
	b.bytesField(3, payload.RecipientTallySetupKeyID)
	b.intField(4, payload.RecipientIndex)
	b.bytesField(5, payload.EncryptedShare)
	b.bytesField(6, payload.ShareEncryptionProof)
	return b.Bytes()
}

func tallyKeySetContextPayload(payload domain.TallyKeySetPayload) []byte {
	var b contextPayloadBuilder
	b.stringField(1, payload.ElectionID)
	b.bytesField(2, payload.TrusteeSelectionResultHash)
	for _, trustee := range payload.TrusteeSet {
		b.bytesField(3, trusteeCandidateWithSetupContextPayload(trustee))
	}
	for _, objectID := range payload.TrusteeConsentObjectIDs {
		b.stringField(4, objectID)
	}
	for _, objectID := range payload.TallyKeyContributionObjectIDs {
		b.stringField(5, objectID)
	}
	b.bytesField(6, payload.TrusteeSetHash)
	b.intField(7, payload.ThresholdT)
	b.intField(8, payload.TrusteeCountN)
	b.bytesField(9, payload.TallyPublicKey)
	for _, commitment := range payload.TrusteeKeyCommitments {
		b.bytesField(10, commitment)
	}
	for _, proof := range payload.SetupProofs {
		b.bytesField(11, proof)
	}
	b.bytesField(12, payload.TallyKeySetHash)
	b.bytesField(13, payload.ReporterPublicKey)
	b.bytesField(14, payload.Signature)
	return b.Bytes()
}

func trusteeCandidateWithSetupContextPayload(candidate domain.TrusteeCandidate) []byte {
	var b contextPayloadBuilder
	b.bytesField(1, candidate.TrusteePublicKey)
	b.bytesField(2, candidate.BlindTokenPublicKey)
	b.bytesField(3, candidate.TrusteeTallySetupKey)
	return b.Bytes()
}

func recomputableTrusteeSelectionInputs(conflictedNominationStatus Status, conflictedVoteStatus Status) TrusteeSelectionInputs {
	nominations := []TrusteeSelectionNominationInput{
		{ObjectID: "nomination-1", Status: StatusValid, Payload: trusteeNominationPayload(1)},
		{ObjectID: "nomination-2", Status: StatusValid, Payload: trusteeNominationPayload(2)},
		{ObjectID: "nomination-3", Status: conflictedNominationStatus, Payload: trusteeNominationPayload(3)},
	}
	if conflictedNominationStatus == "" {
		nominations[2].Status = StatusValid
	}
	votes := []TrusteeSelectionVoteInput{
		{ObjectID: "vote-1", Status: StatusValidForTally, Payload: trusteeVotePayload(1, 1, 2)},
		{ObjectID: "vote-2", Status: conflictedVoteStatus, Payload: trusteeVotePayload(2, 3)},
	}
	return TrusteeSelectionInputs{ElectionFound: true, ElectionStatus: StatusValid, Nominations: nominations, Votes: votes}
}

func recomputedTrusteeSelectionResult(t *testing.T, inputs TrusteeSelectionInputs) domain.TrusteeSelectionResultPayload {
	t.Helper()
	valid := make(map[string]domain.TrusteeNominationPayload)
	for _, nomination := range inputs.Nominations {
		if nomination.Status == StatusValid {
			valid[string(nomination.Payload.CandidatePublicKey)] = nomination.Payload
		}
	}
	result, err := RecomputeTrusteeSelectionResult("selection-1", valid, inputs.Votes)
	if err != nil {
		t.Fatalf("RecomputeTrusteeSelectionResult() error = %v", err)
	}
	privateKey := ed25519.NewKeyFromSeed(repeatedContextByte(0x33, ed25519.SeedSize))
	result.ReporterPublicKey = append([]byte(nil), privateKey.Public().(ed25519.PublicKey)...)
	digest := lvcrypto.Hash(lvcrypto.DomainTrusteeSelectionResultSign, result.ResultHash)
	result.Signature = ed25519.Sign(privateKey, digest[:])
	return result
}

func trusteeSelectionResultEnvelope(result domain.TrusteeSelectionResultPayload) domain.ObjectEnvelope {
	return domain.ObjectEnvelope{ObjectID: "result-1", ObjectType: domain.ObjectTypeTrusteeSelectionResult, Scope: domain.ScopeTrusteeSelectionID, ScopeID: result.TrusteeSelectionID, Payload: trusteeSelectionResultContextPayload(result)}
}

func trusteeSelectionResultContextPayload(result domain.TrusteeSelectionResultPayload) []byte {
	var b contextPayloadBuilder
	b.stringField(1, result.TrusteeSelectionID)
	for _, candidate := range result.CandidateRanking {
		b.bytesField(2, trusteeCandidateContextPayload(candidate))
	}
	for _, candidate := range result.InitialSelectedTrustees {
		b.bytesField(3, trusteeCandidateContextPayload(candidate))
	}
	b.intField(4, result.ThresholdT)
	b.intField(5, result.TrusteeCountN)
	for _, score := range result.CandidateScores {
		b.bytesField(6, candidateScoreContextPayload(score))
	}
	if result.ConflictedVoteCount != 0 {
		b.intField(7, result.ConflictedVoteCount)
	}
	if result.ValidVoteCount != 0 {
		b.intField(8, result.ValidVoteCount)
	}
	b.bytesField(9, result.ResultHash)
	b.bytesField(10, result.ReporterPublicKey)
	b.bytesField(11, result.Signature)
	return b.Bytes()
}

func trusteeCandidateContextPayload(candidate domain.TrusteeCandidate) []byte {
	var b contextPayloadBuilder
	b.bytesField(1, candidate.TrusteePublicKey)
	b.bytesField(2, candidate.BlindTokenPublicKey)
	return b.Bytes()
}

func candidateScoreContextPayload(score domain.CandidateScore) []byte {
	var b contextPayloadBuilder
	b.bytesField(1, score.TrusteePublicKey)
	if score.Score != 0 {
		b.intField(2, score.Score)
	}
	return b.Bytes()
}

func trusteeNominationPayload(index byte) domain.TrusteeNominationPayload {
	return domain.TrusteeNominationPayload{
		TrusteeSelectionID:           "selection-1",
		CandidatePublicKey:           repeatedContextByte(0x50+index, 32),
		CandidateBlindTokenPublicKey: repeatedContextByte(0x60+index, 32),
		Signature:                    repeatedContextByte(0x70+index, 64),
	}
}

func trusteeVotePayload(voter byte, selected ...byte) domain.TrusteeVotePayload {
	keys := make([][]byte, 0, len(selected))
	for _, candidate := range selected {
		keys = append(keys, repeatedContextByte(0x50+candidate, 32))
	}
	return domain.TrusteeVotePayload{
		TrusteeSelectionID:    "selection-1",
		VoterPublicKey:        repeatedContextByte(0x10+voter, 32),
		SelectedCandidateKeys: keys,
		Signature:             repeatedContextByte(0x20+voter, 64),
	}
}

type errorStatusStore struct {
	err error
}

func (s errorStatusStore) ValidationStatus(context.Context, string) (Status, bool, error) {
	return "", false, s.err
}
