package storage

import (
	"bytes"
	"context"
	"testing"

	"librevote/internal/domain"
	"librevote/internal/validation"
)

func TestTrusteeSelectionInputsEnumeratesRetainedValidationInputs(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer store.Close()

	ingestTrusteeSelectionInput(t, store, "selection-object", domain.ObjectTypeTrusteeSelectionElection, domain.ScopeNetwork, "", trusteeSelectionElectionStoragePayload(), domain.ValidationStatusValid)
	ingestTrusteeSelectionInput(t, store, "nomination-valid", domain.ObjectTypeTrusteeNomination, domain.ScopeTrusteeSelectionID, "selection-1", trusteeNominationStoragePayload(1), domain.ValidationStatusValid)
	ingestTrusteeSelectionInput(t, store, "nomination-conflicted", domain.ObjectTypeTrusteeNomination, domain.ScopeTrusteeSelectionID, "selection-1", trusteeNominationStoragePayload(2), domain.ValidationStatusValidButConflicted)
	ingestTrusteeSelectionInput(t, store, "vote-valid", domain.ObjectTypeTrusteeVote, domain.ScopeTrusteeSelectionID, "selection-1", trusteeVoteStoragePayload(1, 1), domain.ValidationStatusValidForTally)
	ingestTrusteeSelectionInput(t, store, "vote-conflicted", domain.ObjectTypeTrusteeVote, domain.ScopeTrusteeSelectionID, "selection-1", trusteeVoteStoragePayload(2, 2), domain.ValidationStatusValidButConflicted)

	inputs, err := store.TrusteeSelectionInputs(ctx, "selection-1")
	if err != nil {
		t.Fatalf("TrusteeSelectionInputs() error = %v", err)
	}
	if !inputs.ElectionFound || inputs.ElectionStatus != validation.StatusValid {
		t.Fatalf("election = found %v status %s", inputs.ElectionFound, inputs.ElectionStatus)
	}
	if len(inputs.Nominations) != 2 || len(inputs.Votes) != 2 {
		t.Fatalf("input counts = nominations %d votes %d", len(inputs.Nominations), len(inputs.Votes))
	}
	foundStatuses := map[validation.Status]bool{}
	for _, nomination := range inputs.Nominations {
		foundStatuses[nomination.Status] = true
	}
	if !foundStatuses[validation.StatusValid] || !foundStatuses[validation.StatusValidButConflicted] {
		t.Fatalf("nomination statuses = %+v", foundStatuses)
	}
	var validVote validation.TrusteeSelectionVoteInput
	for _, vote := range inputs.Votes {
		if vote.Status == validation.StatusValidForTally {
			validVote = vote
		}
	}
	if len(validVote.Payload.SelectedCandidateKeys) != 1 || !bytes.Equal(validVote.Payload.SelectedCandidateKeys[0], repeatedStorageByte(0x51, 32)) {
		t.Fatalf("decoded valid vote = %+v", validVote.Payload)
	}
}

func TestTallyKeySetInputsEnumeratesRetainedActivationInputs(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer store.Close()

	ingestTrusteeSelectionInput(t, store, "election-object", domain.ObjectTypeAnonymousElection, domain.ScopeNetwork, "", anonymousElectionStoragePayload(), domain.ValidationStatusValid)
	ingestTrusteeSelectionInput(t, store, "result-object", domain.ObjectTypeTrusteeSelectionResult, domain.ScopeTrusteeSelectionID, "selection-1", trusteeSelectionResultStoragePayload(), domain.ValidationStatusValid)
	ingestTrusteeSelectionInput(t, store, "consent-valid", domain.ObjectTypeTrusteeConsent, domain.ScopeElectionID, "election-1", trusteeConsentStoragePayload(1), domain.ValidationStatusValid)
	ingestTrusteeSelectionInput(t, store, "consent-conflicted", domain.ObjectTypeTrusteeConsent, domain.ScopeElectionID, "election-1", trusteeConsentStoragePayload(2), domain.ValidationStatusValidButConflicted)
	ingestTrusteeSelectionInput(t, store, "contribution-valid", domain.ObjectTypeTallyKeyContribution, domain.ScopeElectionID, "election-1", tallyKeyContributionStoragePayload(1), domain.ValidationStatusValid)
	ingestTrusteeSelectionInput(t, store, "contribution-conflicted", domain.ObjectTypeTallyKeyContribution, domain.ScopeElectionID, "election-1", tallyKeyContributionStoragePayload(2), domain.ValidationStatusValidButConflicted)
	ingestTrusteeSelectionInput(t, store, "other-consent", domain.ObjectTypeTrusteeConsent, domain.ScopeElectionID, "other-election", trusteeConsentStoragePayload(3), domain.ValidationStatusValid)

	inputs, err := store.TallyKeySetInputs(ctx, "election-1", repeatedStorageByte(0x32, 32))
	if err != nil {
		t.Fatalf("TallyKeySetInputs() error = %v", err)
	}
	if !inputs.ElectionFound || inputs.ElectionStatus != validation.StatusValid || inputs.Election.TrusteeSelectionID != "selection-1" {
		t.Fatalf("election input = found %v status %s payload %+v", inputs.ElectionFound, inputs.ElectionStatus, inputs.Election)
	}
	if !inputs.ResultFound || inputs.ResultStatus != validation.StatusValid || len(inputs.Result.CandidateRanking) != domain.TrusteeCountV1 {
		t.Fatalf("result input = found %v status %s payload %+v", inputs.ResultFound, inputs.ResultStatus, inputs.Result)
	}
	if len(inputs.Consents) != 2 || len(inputs.Contributions) != 2 {
		t.Fatalf("input counts = consents %d contributions %d", len(inputs.Consents), len(inputs.Contributions))
	}
	foundContributionStatuses := map[validation.Status]bool{}
	for _, contribution := range inputs.Contributions {
		foundContributionStatuses[contribution.Status] = true
	}
	if !foundContributionStatuses[validation.StatusValid] || !foundContributionStatuses[validation.StatusValidButConflicted] {
		t.Fatalf("contribution statuses = %+v", foundContributionStatuses)
	}
}

func ingestTrusteeSelectionInput(t *testing.T, store *Store, objectID string, objectType domain.ObjectType, scope domain.Scope, scopeID string, payload []byte, status domain.ValidationStatus) {
	t.Helper()
	_, err := store.IngestObject(context.Background(), IngestObjectInput{
		ObjectID:         objectID,
		ObjectType:       string(objectType),
		ProtocolVersion:  1,
		NetworkID:        "testnet",
		Scope:            string(scope),
		ScopeID:          scopeID,
		CreatedAt:        1700000000000,
		ObjectPoW:        []byte("nonce"),
		PayloadBytes:     payload,
		ValidationStatus: status,
		ValidatorVersion: validation.ValidatorVersionEnvelopeRunner,
		SeenAt:           1700000000000,
		CheckedAt:        1700000000000,
	})
	if err != nil {
		t.Fatalf("IngestObject(%s) error = %v", objectID, err)
	}
}

type storagePayloadBuilder struct{ bytes.Buffer }

func (b *storagePayloadBuilder) stringField(field uint64, value string) {
	writeStorageProtoBytes(&b.Buffer, field, []byte(value))
}

func (b *storagePayloadBuilder) bytesField(field uint64, value []byte) {
	writeStorageProtoBytes(&b.Buffer, field, value)
}

func (b *storagePayloadBuilder) intField(field uint64, value int64) {
	writeStorageProtoVarint(&b.Buffer, field<<3)
	writeStorageProtoVarint(&b.Buffer, uint64(value))
}

func trusteeSelectionElectionStoragePayload() []byte {
	var b storagePayloadBuilder
	b.stringField(1, "selection-1")
	b.stringField(2, "testnet")
	b.stringField(3, "Trustees")
	b.stringField(4, "Trustee selection")
	b.bytesField(5, voterEntryStoragePayload(1))
	b.intField(6, 1000)
	b.intField(7, 2000)
	b.intField(8, 3000)
	b.intField(9, 4000)
	b.intField(10, 5000)
	b.intField(11, 6000)
	b.intField(12, 3)
	b.intField(13, 2)
	b.intField(14, 3)
	b.bytesField(15, repeatedStorageByte(0xaa, 32))
	b.bytesField(16, repeatedStorageByte(0xbb, 64))
	return b.Bytes()
}

func voterEntryStoragePayload(index byte) []byte {
	var b storagePayloadBuilder
	b.stringField(1, "voter-1")
	b.bytesField(2, repeatedStorageByte(0x10+index, 32))
	b.bytesField(3, repeatedStorageByte(0x20+index, 32))
	return b.Bytes()
}

func trusteeNominationStoragePayload(index byte) []byte {
	var b storagePayloadBuilder
	b.stringField(1, "selection-1")
	b.bytesField(2, repeatedStorageByte(0x50+index, 32))
	b.bytesField(3, repeatedStorageByte(0x60+index, 32))
	b.stringField(4, "peer-1")
	b.stringField(5, "statement")
	b.bytesField(6, repeatedStorageByte(0x70+index, 64))
	return b.Bytes()
}

func trusteeVoteStoragePayload(voter byte, selected ...byte) []byte {
	var b storagePayloadBuilder
	b.stringField(1, "selection-1")
	b.bytesField(2, repeatedStorageByte(0x10+voter, 32))
	for _, candidate := range selected {
		b.bytesField(3, repeatedStorageByte(0x50+candidate, 32))
	}
	b.bytesField(4, repeatedStorageByte(0x20+voter, 64))
	return b.Bytes()
}

func anonymousElectionStoragePayload() []byte {
	var b storagePayloadBuilder
	b.stringField(1, "election-1")
	b.stringField(2, "testnet")
	b.stringField(3, "Title")
	b.stringField(4, "Description")
	b.stringField(5, "Yes")
	b.stringField(5, "No")
	b.bytesField(6, voterEntryStoragePayload(1))
	b.stringField(7, "selection-1")
	b.bytesField(8, repeatedStorageByte(0x32, 32))
	b.intField(9, 2)
	b.intField(10, 3)
	b.stringField(11, domain.EligibilitySchemeBlindTokenV1)
	b.intField(12, 1000)
	b.intField(13, 2000)
	b.intField(14, 3000)
	b.intField(15, 4000)
	b.intField(16, 5000)
	b.bytesField(17, repeatedStorageByte(0xaa, 32))
	b.bytesField(18, repeatedStorageByte(0xbb, 64))
	return b.Bytes()
}

func trusteeSelectionResultStoragePayload() []byte {
	var b storagePayloadBuilder
	b.stringField(1, "selection-1")
	for i := 1; i <= domain.TrusteeCountV1; i++ {
		b.bytesField(2, trusteeCandidateStoragePayload(byte(i), false))
	}
	for i := 1; i <= domain.TrusteeCountV1; i++ {
		b.bytesField(3, trusteeCandidateStoragePayload(byte(i), false))
	}
	b.intField(4, 2)
	b.intField(5, 3)
	for i := 1; i <= domain.TrusteeCountV1; i++ {
		b.bytesField(6, candidateScoreStoragePayload(byte(i), int64(i)))
	}
	b.intField(8, 1)
	b.bytesField(9, repeatedStorageByte(0x32, 32))
	b.bytesField(10, repeatedStorageByte(0x33, 32))
	b.bytesField(11, repeatedStorageByte(0x34, 64))
	return b.Bytes()
}

func trusteeConsentStoragePayload(index byte) []byte {
	var b storagePayloadBuilder
	b.stringField(1, "selection-1")
	b.bytesField(2, repeatedStorageByte(0x32, 32))
	b.stringField(3, "election-1")
	b.bytesField(4, repeatedStorageByte(0x41, 32))
	b.bytesField(5, repeatedStorageByte(0x50+index, 32))
	b.bytesField(6, repeatedStorageByte(0x80+index, 32))
	b.intField(7, 2)
	b.intField(8, 3)
	b.bytesField(9, repeatedStorageByte(0x70+index, 64))
	return b.Bytes()
}

func tallyKeyContributionStoragePayload(index byte) []byte {
	var b storagePayloadBuilder
	b.stringField(1, "election-1")
	b.bytesField(2, repeatedStorageByte(0x50+index, 32))
	b.bytesField(3, repeatedStorageByte(0x80+index, 32))
	b.bytesField(4, dkgCommitmentStoragePayload(index))
	for i := 1; i <= domain.TrusteeCountV1; i++ {
		b.bytesField(5, dkgShareStoragePayload(index, byte(i)))
	}
	b.bytesField(6, repeatedStorageByte(0xa0+index, 32))
	b.bytesField(7, repeatedStorageByte(0xb0+index, 64))
	return b.Bytes()
}

func trusteeCandidateStoragePayload(index byte, includeSetup bool) []byte {
	var b storagePayloadBuilder
	b.bytesField(1, repeatedStorageByte(0x50+index, 32))
	b.bytesField(2, repeatedStorageByte(0x60+index, 32))
	if includeSetup {
		b.bytesField(3, repeatedStorageByte(0x80+index, 32))
	}
	return b.Bytes()
}

func candidateScoreStoragePayload(index byte, score int64) []byte {
	var b storagePayloadBuilder
	b.bytesField(1, repeatedStorageByte(0x50+index, 32))
	b.intField(2, score)
	return b.Bytes()
}

func dkgCommitmentStoragePayload(index byte) []byte {
	var b storagePayloadBuilder
	b.bytesField(1, repeatedStorageByte(0x50+index, 32))
	b.intField(2, 1)
	b.bytesField(3, repeatedStorageByte(0x90+index, 32))
	return b.Bytes()
}

func dkgShareStoragePayload(sender, recipient byte) []byte {
	var b storagePayloadBuilder
	b.bytesField(1, repeatedStorageByte(0x50+sender, 32))
	b.bytesField(2, repeatedStorageByte(0x50+recipient, 32))
	b.bytesField(3, repeatedStorageByte(0x80+recipient, 32))
	b.intField(4, int64(recipient))
	b.bytesField(5, repeatedStorageByte(0xc0+recipient, 16))
	b.bytesField(6, repeatedStorageByte(0xd0+recipient, 16))
	return b.Bytes()
}

func repeatedStorageByte(value byte, size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = value
	}
	return out
}

func writeStorageProtoBytes(buf *bytes.Buffer, fieldNumber uint64, value []byte) {
	writeStorageProtoVarint(buf, fieldNumber<<3|2)
	writeStorageProtoVarint(buf, uint64(len(value)))
	buf.Write(value)
}

func writeStorageProtoVarint(buf *bytes.Buffer, value uint64) {
	for value >= 0x80 {
		buf.WriteByte(byte(value) | 0x80)
		value >>= 7
	}
	buf.WriteByte(byte(value))
}
