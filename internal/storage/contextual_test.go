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
