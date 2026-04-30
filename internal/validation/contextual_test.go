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

type trusteeSelectionInputStore struct {
	inputs TrusteeSelectionInputs
}

func (s trusteeSelectionInputStore) ValidationStatus(context.Context, string) (Status, bool, error) {
	return "", false, nil
}

func (s trusteeSelectionInputStore) TrusteeSelectionInputs(context.Context, string) (TrusteeSelectionInputs, error) {
	return s.inputs, nil
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
	result, err := recomputeTrusteeSelectionResult("selection-1", valid, inputs.Votes)
	if err != nil {
		t.Fatalf("recomputeTrusteeSelectionResult() error = %v", err)
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
