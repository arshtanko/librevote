package validation_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"librevote/internal/domain"
	"librevote/internal/storage"
	"librevote/internal/validation"
)

func TestContextualValidatorRunnerPersistsMissingDependencyRows(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	validator := newStructuralContextualRunner(t, store, validation.WithContextualRule(domain.ObjectTypeBlindTokenIssue,
		func(context.Context, domain.ObjectEnvelope) (validation.ContextualRuleResult, error) {
			return validation.ContextualRuleResult{
				Status: validation.StatusValid,
				RequiredDependencies: []validation.RequiredDependency{
					validation.RequireObject("blind_token_request", "request-1", validation.StatusValid),
				},
			}, nil
		}))
	envelope := runnerValidEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeBlindTokenIssue
	envelope.Scope = domain.ScopeElectionID
	envelope.ScopeID = "election-1"
	envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)

	result, err := validator.IngestAndValidate(ctx, envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if result.Outcome.Status != validation.StatusPendingDependencies || result.Outcome.ShouldRepublish {
		t.Fatalf("outcome = %+v, want pending without republish", result.Outcome)
	}
	deps, err := store.Dependencies(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 1 || deps[0] != (storage.Dependency{Type: "blind_token_request", ID: "request-1"}) {
		t.Fatalf("dependencies = %+v", deps)
	}
}

func TestContextualValidatorRunnerAnonymousElectionMissingResultPersistsDependency(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	runner := newStructuralContextualRunner(t, store)
	envelope := runnerAnonymousElectionEnvelope(t)

	result, err := runner.IngestAndValidate(ctx, envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if result.Outcome.Status != validation.StatusPendingDependencies || result.Outcome.ShouldRepublish {
		t.Fatalf("outcome = %+v, want pending without republish", result.Outcome)
	}
	deps, err := store.Dependencies(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	wantID := validation.TrusteeSelectionResultDependencyID("selection-1", repeatedRunnerByte(0x31, 32))
	if len(deps) != 1 || deps[0] != (storage.Dependency{Type: "trustee_selection_result", ID: wantID}) {
		t.Fatalf("dependencies = %+v", deps)
	}
}

func TestContextualValidatorRunnerAnonymousElectionAcceptsPresentResult(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	ingestTypedDependency(t, store, "result-object", domain.ObjectTypeTrusteeSelectionResult, domain.ScopeTrusteeSelectionID, "selection-1", validTrusteeSelectionResultRunnerPayload())
	runner := newStructuralContextualRunner(t, store)
	envelope := runnerAnonymousElectionEnvelope(t)

	result, err := runner.IngestAndValidate(ctx, envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if result.Outcome.Status != validation.StatusValid || !result.Outcome.ShouldRepublish {
		t.Fatalf("outcome = %+v, want valid", result.Outcome)
	}
	deps, err := store.Dependencies(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 0 {
		t.Fatalf("dependencies = %+v, want none", deps)
	}
}

func TestContextualValidatorRunnerTrusteeConsentPersistsMissingElectionDependency(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	runner := newStructuralContextualRunner(t, store)
	envelope := runnerTrusteeConsentEnvelope(t)

	result, err := runner.IngestAndValidate(ctx, envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if result.Outcome.Status != validation.StatusPendingDependencies || result.Outcome.ShouldRepublish {
		t.Fatalf("outcome = %+v, want pending without republish", result.Outcome)
	}
	deps, err := store.Dependencies(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 1 || deps[0] != (storage.Dependency{Type: "election", ID: "election-1"}) {
		t.Fatalf("dependencies = %+v", deps)
	}
}

func TestContextualValidatorRunnerAcceptsPresentDependency(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	ingestDependency(t, store, "request-1", domain.ValidationStatusValid)
	runner := newStructuralContextualRunner(t, store, validation.WithContextualRule(domain.ObjectTypeBlindTokenIssue,
		func(context.Context, domain.ObjectEnvelope) (validation.ContextualRuleResult, error) {
			return validation.ContextualRuleResult{
				Status: validation.StatusValid,
				RequiredDependencies: []validation.RequiredDependency{
					validation.RequireObject("blind_token_request", "request-1", validation.StatusValid),
				},
			}, nil
		}))
	envelope := runnerValidEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeBlindTokenIssue
	envelope.Scope = domain.ScopeElectionID
	envelope.ScopeID = "election-1"
	envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)

	result, err := runner.IngestAndValidate(ctx, envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if result.Outcome.Status != validation.StatusValid || !result.Outcome.ShouldRepublish {
		t.Fatalf("outcome = %+v, want valid", result.Outcome)
	}
	deps, err := store.Dependencies(ctx, envelope.ObjectID)
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 0 {
		t.Fatalf("dependencies = %+v, want none", deps)
	}
}

func TestContextualValidatorRunnerDoesNotPersistUnsupportedObjectType(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name       string
		objectType domain.ObjectType
		scope      domain.Scope
		scopeID    string
		payload    []byte
	}{
		{name: "blind token issue", objectType: domain.ObjectTypeBlindTokenIssue, scope: domain.ScopeElectionID, scopeID: "election-1", payload: []byte{0x0a, 0x08, 'e', 'l', 'e', 'c', 't', 'i', 'o', 'n'}},
		{name: "tally result", objectType: domain.ObjectTypeTallyResult, scope: domain.ScopeElectionID, scopeID: "election-1", payload: []byte{0x0a, 0x08, 'e', 'l', 'e', 'c', 't', 'i', 'o', 'n'}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := openTestStore(t)
			runner := newStructuralContextualRunner(t, store)
			envelope := runnerValidEnvelope(t)
			envelope.ObjectType = tt.objectType
			envelope.Scope = tt.scope
			envelope.ScopeID = tt.scopeID
			envelope.Payload = tt.payload
			envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)

			_, err := runner.IngestAndValidate(ctx, envelope)
			if !errors.Is(err, validation.ErrContextualRuleUnsupported) {
				t.Fatalf("IngestAndValidate() error = %v, want %v", err, validation.ErrContextualRuleUnsupported)
			}
			if _, err := store.InvalidObjectRecord(ctx, envelope.ObjectID); err == nil {
				t.Fatal("InvalidObjectRecord() succeeded for unsupported object, want no destructive invalid record")
			}
			deps, err := store.Dependencies(ctx, envelope.ObjectID)
			if err != nil {
				t.Fatalf("Dependencies() error = %v", err)
			}
			if len(deps) != 0 {
				t.Fatalf("dependencies = %+v, want none", deps)
			}
		})
	}
}

func TestContextualValidatorRunnerRejectsInvalidRecordedDependency(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	invalidEnvelope := runnerValidEnvelope(t)
	invalidEnvelope.ObjectID = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := store.IngestObject(ctx, storage.IngestObjectInput{
		ObjectID:               invalidEnvelope.ObjectID,
		ObjectType:             string(invalidEnvelope.ObjectType),
		NetworkID:              invalidEnvelope.NetworkID,
		Scope:                  string(invalidEnvelope.Scope),
		ScopeID:                invalidEnvelope.ScopeID,
		CreatedAt:              invalidEnvelope.CreatedAt,
		ObjectPoW:              invalidEnvelope.Pow,
		PayloadBytes:           invalidEnvelope.Payload,
		ValidationStatus:       domain.ValidationStatusInvalid,
		ValidationErrorCode:    validation.ErrorEnvelopeObjectID,
		ValidationErrorMessage: "bad object id",
		ValidatorVersion:       validation.ValidatorVersionEnvelopeRunner,
		SeenAt:                 1700000000000,
		CheckedAt:              1700000000000,
	}); err != nil {
		t.Fatalf("IngestObject() invalid dependency error = %v", err)
	}
	runner := newStructuralContextualRunner(t, store, validation.WithContextualRule(domain.ObjectTypeBlindTokenIssue,
		func(context.Context, domain.ObjectEnvelope) (validation.ContextualRuleResult, error) {
			return validation.ContextualRuleResult{
				Status: validation.StatusValid,
				RequiredDependencies: []validation.RequiredDependency{
					validation.RequireObject("blind_token_request", invalidEnvelope.ObjectID, validation.StatusValid),
				},
			}, nil
		}))
	envelope := runnerValidEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeBlindTokenIssue
	envelope.Scope = domain.ScopeElectionID
	envelope.ScopeID = "election-1"
	envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)

	result, err := runner.IngestAndValidate(ctx, envelope)
	if err != nil {
		t.Fatalf("IngestAndValidate() error = %v", err)
	}
	if result.Outcome.Status != validation.StatusInvalid || result.Outcome.ValidationErrorCode != validation.ErrorContextualDependencyStatus {
		t.Fatalf("outcome = %+v, want invalid dependency rejection", result.Outcome)
	}
}

func newStructuralContextualRunner(t *testing.T, store *storage.Store, opts ...validation.ContextualOption) *validation.Runner {
	t.Helper()
	contextual, err := validation.NewContextualValidator(store, opts...)
	if err != nil {
		t.Fatalf("NewContextualValidator() error = %v", err)
	}
	structural, err := validation.NewStructuralValidator(contextual)
	if err != nil {
		t.Fatalf("NewStructuralValidator() error = %v", err)
	}
	runner, err := validation.NewRunner(validation.RunnerConfig{
		Envelope:         runnerEnvelopeConfig(),
		Store:            store,
		DomainValidator:  structural,
		ValidatorVersion: validation.ValidatorVersionEnvelopeRunner,
		Now:              func() time.Time { return time.UnixMilli(1700000001000) },
	})
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	return runner
}

func ingestDependency(t *testing.T, store *storage.Store, objectID string, status domain.ValidationStatus) {
	t.Helper()
	_, err := store.IngestObject(context.Background(), storage.IngestObjectInput{
		ObjectID:         objectID,
		ObjectType:       string(domain.ObjectTypeBlindTokenRequest),
		ProtocolVersion:  1,
		NetworkID:        "testnet",
		Scope:            string(domain.ScopeElectionID),
		ScopeID:          "election-1",
		CreatedAt:        1700000000000,
		ObjectPoW:        []byte("nonce"),
		PayloadBytes:     []byte{0x0a, 0x08, 'r', 'e', 'q', 'u', 'e', 's', 't', '1'},
		ValidationStatus: status,
		ValidatorVersion: validation.ValidatorVersionEnvelopeRunner,
		SeenAt:           1700000000000,
		CheckedAt:        1700000000000,
	})
	if err != nil {
		t.Fatalf("IngestObject() dependency error = %v", err)
	}
}

func runnerAnonymousElectionEnvelope(t *testing.T) domain.ObjectEnvelope {
	t.Helper()
	envelope := runnerValidEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeAnonymousElection
	envelope.Scope = domain.ScopeNetwork
	envelope.ScopeID = ""
	envelope.Payload = validAnonymousElectionRunnerPayload()
	envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)
	return envelope
}

func runnerTrusteeConsentEnvelope(t *testing.T) domain.ObjectEnvelope {
	t.Helper()
	envelope := runnerValidEnvelope(t)
	envelope.ObjectType = domain.ObjectTypeTrusteeConsent
	envelope.Scope = domain.ScopeElectionID
	envelope.ScopeID = "election-1"
	envelope.Payload = validTrusteeConsentRunnerPayload()
	envelope.ObjectID = runnerObjectIDForEnvelope(t, envelope)
	return envelope
}

func ingestTypedDependency(t *testing.T, store *storage.Store, objectID string, objectType domain.ObjectType, scope domain.Scope, scopeID string, payload []byte) {
	t.Helper()
	_, err := store.IngestObject(context.Background(), storage.IngestObjectInput{
		ObjectID:         objectID,
		ObjectType:       string(objectType),
		ProtocolVersion:  1,
		NetworkID:        "testnet",
		Scope:            string(scope),
		ScopeID:          scopeID,
		CreatedAt:        1700000000000,
		ObjectPoW:        []byte("nonce"),
		PayloadBytes:     payload,
		ValidationStatus: domain.ValidationStatusValid,
		ValidatorVersion: validation.ValidatorVersionEnvelopeRunner,
		SeenAt:           1700000000000,
		CheckedAt:        1700000000000,
	})
	if err != nil {
		t.Fatalf("IngestObject(%s) dependency error = %v", objectType, err)
	}
}

type runnerPayloadBuilder struct{ bytes.Buffer }

func (b *runnerPayloadBuilder) stringField(field uint64, value string) {
	writeRunnerProtoBytes(&b.Buffer, field, []byte(value))
}

func (b *runnerPayloadBuilder) bytesField(field uint64, value []byte) {
	writeRunnerProtoBytes(&b.Buffer, field, value)
}

func (b *runnerPayloadBuilder) intField(field uint64, value int64) {
	writeRunnerProtoVarint(&b.Buffer, field<<3)
	writeRunnerProtoVarint(&b.Buffer, uint64(value))
}

func validAnonymousElectionRunnerPayload() []byte {
	var b runnerPayloadBuilder
	b.stringField(1, "election-1")
	b.stringField(2, "testnet")
	b.stringField(3, "Title")
	b.stringField(4, "Description")
	b.stringField(5, "Yes")
	b.stringField(5, "No")
	b.bytesField(6, voterEntryRunnerPayload())
	b.stringField(7, "selection-1")
	b.bytesField(8, repeatedRunnerByte(0x31, 32))
	b.intField(9, 2)
	b.intField(10, 3)
	b.stringField(11, domain.EligibilitySchemeBlindTokenV1)
	b.intField(12, 1000)
	b.intField(13, 2000)
	b.intField(14, 3000)
	b.intField(15, 4000)
	b.intField(16, 5000)
	b.bytesField(17, repeatedRunnerByte(0xaa, 32))
	b.bytesField(18, repeatedRunnerByte(0xbb, 64))
	return b.Bytes()
}

func validTrusteeConsentRunnerPayload() []byte {
	var b runnerPayloadBuilder
	b.stringField(1, "selection-1")
	b.bytesField(2, repeatedRunnerByte(0x31, 32))
	b.stringField(3, "election-1")
	b.bytesField(4, repeatedRunnerByte(0x41, 32))
	b.bytesField(5, repeatedRunnerByte(0x51, 32))
	b.bytesField(6, repeatedRunnerByte(0x61, 32))
	b.intField(7, 2)
	b.intField(8, 3)
	b.bytesField(9, repeatedRunnerByte(0x71, 64))
	return b.Bytes()
}

func validTrusteeSelectionResultRunnerPayload() []byte {
	var b runnerPayloadBuilder
	b.stringField(1, "selection-1")
	for i := 1; i <= 3; i++ {
		b.bytesField(2, trusteeCandidateRunnerPayload(byte(i)))
	}
	for i := 1; i <= 3; i++ {
		b.bytesField(3, trusteeCandidateRunnerPayload(byte(i)))
	}
	b.intField(4, 2)
	b.intField(5, 3)
	for i := 1; i <= 3; i++ {
		b.bytesField(6, candidateScoreRunnerPayload(byte(i), int64(i)))
	}
	b.intField(7, 1)
	b.intField(8, 2)
	b.bytesField(9, repeatedRunnerByte(0x31, 32))
	b.bytesField(10, repeatedRunnerByte(0x33, 32))
	b.bytesField(11, repeatedRunnerByte(0x34, 64))
	return b.Bytes()
}

func validTallyKeySetRunnerPayload() []byte {
	var b runnerPayloadBuilder
	b.stringField(1, "election-1")
	b.bytesField(2, repeatedRunnerByte(0x31, 32))
	for i := 1; i <= 3; i++ {
		b.bytesField(3, trusteeCandidateWithSetupRunnerPayload(byte(i)))
	}
	for i := 1; i <= 3; i++ {
		b.stringField(4, string(rune('a'+i)))
	}
	for i := 1; i <= 3; i++ {
		b.stringField(5, string(rune('x'+i)))
	}
	b.bytesField(6, repeatedRunnerByte(0x42, 32))
	b.intField(7, 2)
	b.intField(8, 3)
	b.bytesField(9, repeatedRunnerByte(0x43, 32))
	for i := 1; i <= 3; i++ {
		b.bytesField(10, repeatedRunnerByte(0x70+byte(i), 32))
	}
	for i := 1; i <= 3; i++ {
		b.bytesField(11, repeatedRunnerByte(0x80+byte(i), 64))
	}
	b.bytesField(12, repeatedRunnerByte(0x44, 32))
	b.bytesField(13, repeatedRunnerByte(0x45, 32))
	b.bytesField(14, repeatedRunnerByte(0x46, 64))
	return b.Bytes()
}

func voterEntryRunnerPayload() []byte {
	var b runnerPayloadBuilder
	b.stringField(1, "voter-1")
	b.bytesField(2, repeatedRunnerByte(0x11, 32))
	b.bytesField(3, repeatedRunnerByte(0x21, 32))
	return b.Bytes()
}

func trusteeCandidateRunnerPayload(index byte) []byte {
	var b runnerPayloadBuilder
	b.bytesField(1, repeatedRunnerByte(0x50+index, 32))
	b.bytesField(2, repeatedRunnerByte(0x60+index, 32))
	return b.Bytes()
}

func trusteeCandidateWithSetupRunnerPayload(index byte) []byte {
	var b runnerPayloadBuilder
	b.bytesField(1, repeatedRunnerByte(0x50+index, 32))
	b.bytesField(2, repeatedRunnerByte(0x60+index, 32))
	b.bytesField(3, repeatedRunnerByte(0x90+index, 32))
	return b.Bytes()
}

func candidateScoreRunnerPayload(index byte, score int64) []byte {
	var b runnerPayloadBuilder
	b.bytesField(1, repeatedRunnerByte(0x50+index, 32))
	b.intField(2, score)
	return b.Bytes()
}

func repeatedRunnerByte(value byte, size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = value
	}
	return out
}

func writeRunnerProtoBytes(buf *bytes.Buffer, fieldNumber uint64, value []byte) {
	writeRunnerProtoVarint(buf, fieldNumber<<3|2)
	writeRunnerProtoVarint(buf, uint64(len(value)))
	buf.Write(value)
}

func writeRunnerProtoVarint(buf *bytes.Buffer, value uint64) {
	for value >= 0x80 {
		buf.WriteByte(byte(value) | 0x80)
		value >>= 7
	}
	buf.WriteByte(byte(value))
}
