package domain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestDecodeAnonymousElectionExtractsReferences(t *testing.T) {
	payload := validAnonymousElectionPayloadFixture()
	decoded, err := DecodePayload(ObjectTypeAnonymousElection, payload)
	if err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}
	election := decoded.(AnonymousElectionPayload)

	if election.ElectionID != "election-1" || election.TrusteeSelectionID != "selection-1" {
		t.Fatalf("decoded ids = %q/%q", election.ElectionID, election.TrusteeSelectionID)
	}
	if !bytes.Equal(election.TrusteeSelectionResultHash, repeatedByte(0x31, hashSize)) {
		t.Fatalf("trustee_selection_result_hash = %x", election.TrusteeSelectionResultHash)
	}
	if election.EligibilityScheme != EligibilitySchemeBlindTokenV1 {
		t.Fatalf("eligibility_scheme = %q", election.EligibilityScheme)
	}

	wantHex := "0a0a656c656374696f6e2d311207746573746e65741a055469746c65220b4465736372697074696f6e2a035965732a024e6f324d0a07766f7465722d31122011111111111111111111111111111111111111111111111111111111111111111a2021212121212121212121212121212121212121212121212121212121212121213a0b73656c656374696f6e2d3142203131313131313131313131313131313131313131313131313131313131313131480250035a0e626c696e645f746f6b656e5f763160e80768d00f70b81778a01f800188278a0120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa920140bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if got := hex.EncodeToString(payload); got != wantHex {
		t.Fatalf("fixture hex changed:\n got %s\nwant %s", got, wantHex)
	}
}

func TestValidatePayloadShapeRejectsAnonymousElectionStructuralErrors(t *testing.T) {
	if err := ValidatePayloadShape(ObjectTypeAnonymousElection, validAnonymousElectionPayloadFixture()); err != nil {
		t.Fatalf("ValidatePayloadShape() error = %v", err)
	}

	duplicateOption := validAnonymousElectionPayloadFixture(func(b *payloadBuilder) {
		b.reset()
		writeAnonymousElectionPayload(b, []string{"Yes", "Yes"}, EligibilitySchemeBlindTokenV1, []VoterEntry{validVoterEntry(1)})
	})
	if err := ValidatePayloadShape(ObjectTypeAnonymousElection, duplicateOption); err == nil {
		t.Fatal("ValidatePayloadShape() error = nil, want duplicate option rejection")
	}

	unknownScheme := validAnonymousElectionPayloadFixture(func(b *payloadBuilder) {
		b.reset()
		writeAnonymousElectionPayload(b, []string{"Yes", "No"}, "public_key_v1", []VoterEntry{validVoterEntry(1)})
	})
	if err := ValidatePayloadShape(ObjectTypeAnonymousElection, unknownScheme); err == nil {
		t.Fatal("ValidatePayloadShape() error = nil, want eligibility scheme rejection")
	}
}

func TestDecodePayloadRejectsUnknownAndMalformedFields(t *testing.T) {
	payload := validAnonymousElectionPayloadFixture()
	payload = append(payload, 0x98, 0x06, 0x01) // field 99 varint
	_, err := DecodePayload(ObjectTypeAnonymousElection, payload)
	if !errors.Is(err, ErrUnknownPayloadField) {
		t.Fatalf("DecodePayload() error = %v, want %v", err, ErrUnknownPayloadField)
	}

	_, err = DecodePayload(ObjectTypeAnonymousElection, []byte{0x0a, 0xff})
	if !errors.Is(err, ErrInvalidCanonicalPayload) && err == nil {
		t.Fatalf("DecodePayload() error = %v, want malformed protobuf error", err)
	}
}

func TestDecodePayloadRejectsExplicitDefaultRepresentations(t *testing.T) {
	defaultString := validAnonymousElectionPayloadFixture(func(b *payloadBuilder) {
		b.reset()
		b.stringField(1, "election-1")
		writeProtoVarint(&b.Buffer, 2<<3|2)
		writeProtoVarint(&b.Buffer, 0)
	})
	_, err := DecodePayload(ObjectTypeAnonymousElection, defaultString)
	if !errors.Is(err, ErrInvalidCanonicalPayload) {
		t.Fatalf("DecodePayload() empty string error = %v, want %v", err, ErrInvalidCanonicalPayload)
	}

	defaultInt := validAnonymousElectionPayloadFixture(func(b *payloadBuilder) {
		b.reset()
		b.stringField(1, "election-1")
		b.stringField(2, "testnet")
		writeProtoVarint(&b.Buffer, 9<<3)
		writeProtoVarint(&b.Buffer, 0)
	})
	_, err = DecodePayload(ObjectTypeAnonymousElection, defaultInt)
	if !errors.Is(err, ErrInvalidCanonicalPayload) {
		t.Fatalf("DecodePayload() zero int error = %v, want %v", err, ErrInvalidCanonicalPayload)
	}
}

func TestValidateTallyKeySetRejectsDuplicateTrustees(t *testing.T) {
	payload := validTallyKeySetPayloadFixture(true)
	if err := ValidatePayloadShape(ObjectTypeTallyKeySet, payload); err == nil {
		t.Fatal("ValidatePayloadShape() error = nil, want duplicate trustee rejection")
	}
}

func TestDecodeTrusteeConsentExtractsDependencyFields(t *testing.T) {
	payload := validTrusteeConsentPayloadFixture()
	decoded, err := DecodePayload(ObjectTypeTrusteeConsent, payload)
	if err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}
	consent := decoded.(TrusteeConsentPayload)
	if consent.TrusteeSelectionID != "selection-1" || consent.ElectionID != "election-1" {
		t.Fatalf("decoded ids = %q/%q", consent.TrusteeSelectionID, consent.ElectionID)
	}
	if !bytes.Equal(consent.TrusteeSelectionResultHash, repeatedByte(0x31, hashSize)) {
		t.Fatalf("trustee_selection_result_hash = %x", consent.TrusteeSelectionResultHash)
	}
}

func TestDecodeTrusteeSelectionResultIncludesResultFields(t *testing.T) {
	payload := validTrusteeSelectionResultPayloadFixture()
	decoded, err := DecodePayload(ObjectTypeTrusteeSelectionResult, payload)
	if err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}
	result := decoded.(TrusteeSelectionResultPayload)
	if len(result.CandidateRanking) != TrusteeCountV1 || len(result.InitialSelectedTrustees) != TrusteeCountV1 || len(result.CandidateScores) != TrusteeCountV1 {
		t.Fatalf("decoded result counts = ranking %d selected %d scores %d", len(result.CandidateRanking), len(result.InitialSelectedTrustees), len(result.CandidateScores))
	}
	if result.ConflictedVoteCount != 1 || result.ValidVoteCount != 2 {
		t.Fatalf("decoded vote counts = %d/%d", result.ConflictedVoteCount, result.ValidVoteCount)
	}
	if !bytes.Equal(result.ResultHash, repeatedByte(0x32, hashSize)) {
		t.Fatalf("result_hash = %x", result.ResultHash)
	}
}

func TestDecodeTrusteeSelectionResultRejectsPreliminaryTallySetupKey(t *testing.T) {
	payload := validTrusteeSelectionResultPayloadFixture(func(b *payloadBuilder) {
		b.reset()
		b.stringField(1, "selection-1")
		b.bytesField(2, trusteeCandidatePayload(1, true))
	})
	_, err := DecodePayload(ObjectTypeTrusteeSelectionResult, payload)
	if !errors.Is(err, ErrUnknownPayloadField) {
		t.Fatalf("DecodePayload() error = %v, want %v", err, ErrUnknownPayloadField)
	}
}

func TestDecodePayloadRejectsNestedNonCanonicalOrdering(t *testing.T) {
	var nested payloadBuilder
	nested.bytesField(2, repeatedByte(0x61, 32))
	nested.bytesField(1, repeatedByte(0x51, ed25519PublicKeySize))
	var b payloadBuilder
	b.stringField(1, "selection-1")
	b.bytesField(2, nested.Bytes())
	_, err := DecodePayload(ObjectTypeTrusteeSelectionResult, b.Bytes())
	if !errors.Is(err, ErrInvalidCanonicalPayload) {
		t.Fatalf("DecodePayload() error = %v, want %v", err, ErrInvalidCanonicalPayload)
	}
}

func TestValidateTallyKeySetRequiresActivationData(t *testing.T) {
	payload := validTallyKeySetPayloadFixture(false, func(b *payloadBuilder) {
		b.reset()
		writeTallyKeySetPayload(b, false, false)
	})
	if err := ValidatePayloadShape(ObjectTypeTallyKeySet, payload); err == nil {
		t.Fatal("ValidatePayloadShape() error = nil, want missing commitments/proofs rejection")
	}
}

type payloadBuilder struct{ bytes.Buffer }

func (b *payloadBuilder) reset() { b.Buffer.Reset() }

func (b *payloadBuilder) stringField(field uint64, value string) {
	writeProtoString(&b.Buffer, field, value)
}
func (b *payloadBuilder) bytesField(field uint64, value []byte) {
	writeProtoBytes(&b.Buffer, field, value)
}
func (b *payloadBuilder) intField(field uint64, value int64) {
	writeProtoInt64(&b.Buffer, field, value)
}

func validAnonymousElectionPayloadFixture(opts ...func(*payloadBuilder)) []byte {
	var b payloadBuilder
	writeAnonymousElectionPayload(&b, []string{"Yes", "No"}, EligibilitySchemeBlindTokenV1, []VoterEntry{validVoterEntry(1)})
	for _, opt := range opts {
		opt(&b)
	}
	return append([]byte(nil), b.Bytes()...)
}

func writeAnonymousElectionPayload(b *payloadBuilder, options []string, scheme string, voters []VoterEntry) {
	b.stringField(1, "election-1")
	b.stringField(2, "testnet")
	b.stringField(3, "Title")
	b.stringField(4, "Description")
	for _, option := range options {
		b.stringField(5, option)
	}
	for _, voter := range voters {
		b.bytesField(6, voterEntryPayload(voter))
	}
	b.stringField(7, "selection-1")
	b.bytesField(8, repeatedByte(0x31, hashSize))
	b.intField(9, ThresholdV1)
	b.intField(10, TrusteeCountV1)
	b.stringField(11, scheme)
	b.intField(12, 1000)
	b.intField(13, 2000)
	b.intField(14, 3000)
	b.intField(15, 4000)
	b.intField(16, 5000)
	b.bytesField(17, repeatedByte(0xaa, ed25519PublicKeySize))
	b.bytesField(18, repeatedByte(0xbb, ed25519SignatureSize))
}

func validTrusteeConsentPayloadFixture() []byte {
	var b payloadBuilder
	b.stringField(1, "selection-1")
	b.bytesField(2, repeatedByte(0x31, hashSize))
	b.stringField(3, "election-1")
	b.bytesField(4, repeatedByte(0x41, hashSize))
	b.bytesField(5, repeatedByte(0x51, ed25519PublicKeySize))
	b.bytesField(6, repeatedByte(0x61, 32))
	b.intField(7, ThresholdV1)
	b.intField(8, TrusteeCountV1)
	b.bytesField(9, repeatedByte(0x71, ed25519SignatureSize))
	return b.Bytes()
}

func validTrusteeSelectionResultPayloadFixture(opts ...func(*payloadBuilder)) []byte {
	var b payloadBuilder
	b.stringField(1, "selection-1")
	for i := 1; i <= TrusteeCountV1; i++ {
		b.bytesField(2, trusteeCandidatePayload(byte(i), false))
	}
	for i := 1; i <= TrusteeCountV1; i++ {
		b.bytesField(3, trusteeCandidatePayload(byte(i), false))
	}
	b.intField(4, ThresholdV1)
	b.intField(5, TrusteeCountV1)
	for i := 1; i <= TrusteeCountV1; i++ {
		b.bytesField(6, candidateScorePayload(byte(i), int64(i)))
	}
	b.intField(7, 1)
	b.intField(8, 2)
	b.bytesField(9, repeatedByte(0x32, hashSize))
	b.bytesField(10, repeatedByte(0x33, ed25519PublicKeySize))
	b.bytesField(11, repeatedByte(0x34, ed25519SignatureSize))
	for _, opt := range opts {
		opt(&b)
	}
	return b.Bytes()
}

func validTallyKeySetPayloadFixture(duplicateTrustee bool, opts ...func(*payloadBuilder)) []byte {
	var b payloadBuilder
	writeTallyKeySetPayload(&b, duplicateTrustee, true)
	for _, opt := range opts {
		opt(&b)
	}
	return b.Bytes()
}

func writeTallyKeySetPayload(b *payloadBuilder, duplicateTrustee bool, includeActivationData bool) {
	b.stringField(1, "election-1")
	b.bytesField(2, repeatedByte(0x31, hashSize))
	for i := 1; i <= TrusteeCountV1; i++ {
		trusteeIndex := byte(i)
		if duplicateTrustee && i == 3 {
			trusteeIndex = 1
		}
		b.bytesField(3, trusteeCandidatePayload(trusteeIndex, true))
	}
	for i := 1; i <= TrusteeCountV1; i++ {
		b.stringField(4, string(rune('a'+i)))
	}
	for i := 1; i <= TrusteeCountV1; i++ {
		b.stringField(5, string(rune('x'+i)))
	}
	b.bytesField(6, repeatedByte(0x42, hashSize))
	b.intField(7, ThresholdV1)
	b.intField(8, TrusteeCountV1)
	b.bytesField(9, repeatedByte(0x43, 32))
	if includeActivationData {
		for i := 1; i <= TrusteeCountV1; i++ {
			b.bytesField(10, repeatedByte(0x70+byte(i), 32))
		}
		for i := 1; i <= TrusteeCountV1; i++ {
			b.bytesField(11, repeatedByte(0x80+byte(i), 64))
		}
	}
	b.bytesField(12, repeatedByte(0x44, hashSize))
	b.bytesField(13, repeatedByte(0x45, ed25519PublicKeySize))
	b.bytesField(14, repeatedByte(0x46, ed25519SignatureSize))
}

func validVoterEntry(index byte) VoterEntry {
	return VoterEntry{VoterID: "voter-1", VoterSigningPublicKey: repeatedByte(0x10+index, ed25519PublicKeySize), VoterEncryptionPublicKey: repeatedByte(0x20+index, 32)}
}

func voterEntryPayload(entry VoterEntry) []byte {
	var b payloadBuilder
	b.stringField(1, entry.VoterID)
	b.bytesField(2, entry.VoterSigningPublicKey)
	b.bytesField(3, entry.VoterEncryptionPublicKey)
	return b.Bytes()
}

func trusteeCandidatePayload(index byte, tallySetup bool) []byte {
	var b payloadBuilder
	b.bytesField(1, repeatedByte(0x50+index, ed25519PublicKeySize))
	b.bytesField(2, repeatedByte(0x60+index, 32))
	if tallySetup {
		b.bytesField(3, repeatedByte(0x70+index, 32))
	}
	return b.Bytes()
}

func candidateScorePayload(index byte, score int64) []byte {
	var b payloadBuilder
	b.bytesField(1, repeatedByte(0x50+index, ed25519PublicKeySize))
	b.intField(2, score)
	return b.Bytes()
}

func repeatedByte(value byte, size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = value
	}
	return out
}
