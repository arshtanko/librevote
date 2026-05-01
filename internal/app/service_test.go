package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"librevote/internal/app"
	"librevote/internal/domain"
	"librevote/internal/validation"
)

type testKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return testKey{pub: pub, priv: priv}
}

func TestTrusteeSelectionHappyPath(t *testing.T) {
	ctx := context.Background()
	svc, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()

	creator := newTestKey(t)
	voter := newTestKey(t)

	electionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: "ts-1",
		NetworkID:          "testnet",
		Title:              "Test Trustee Selection",
		Description:        "Select trustees",
		VoterAllowlist: []domain.VoterEntry{
			{VoterID: "v-1", VoterSigningPublicKey: voter.pub, VoterEncryptionPublicKey: make([]byte, 32)},
		},
		NominationStartsAt: 1000,
		NominationEndsAt:   2000,
		VotingStartsAt:     3000,
		VotingEndsAt:       4000,
		ConsentStartsAt:    5000,
		ConsentEndsAt:      6000,
		TrusteeCountN:      domain.TrusteeCountV1,
		ThresholdT:         domain.ThresholdV1,
		MaxChoicesPerVote:  domain.MaxChoicesPerVoteV1,
	}
	_, err = svc.CreateTrusteeSelectionElection(ctx, electionPayload, creator.priv, 500)
	if err != nil {
		t.Fatalf("CreateTrusteeSelectionElection() error = %v", err)
	}

	candidate1 := newTestKey(t)
	candidate2 := newTestKey(t)
	candidate3 := newTestKey(t)
	blind1 := randomBytes(t, 32)
	blind2 := randomBytes(t, 32)
	blind3 := randomBytes(t, 32)

	nomWindow := int64(1500)
	candidates := []struct {
		key   testKey
		blind []byte
	}{
		{candidate1, blind1},
		{candidate2, blind2},
		{candidate3, blind3},
	}
	for i, c := range candidates {
		nom := domain.TrusteeNominationPayload{
			TrusteeSelectionID:           "ts-1",
			CandidatePublicKey:           c.key.pub,
			CandidateBlindTokenPublicKey: c.blind,
			CandidateNodePeerID:          "peer-1",
			Statement:                    "I will serve as trustee",
		}
		env, err := svc.CreateTrusteeNomination(ctx, nom, c.key.priv, nomWindow)
		if err != nil {
			t.Fatalf("CreateTrusteeNomination(%d) error = %v", i, err)
		}
		t.Logf("nomination %d: %s", i, env.ObjectID)
	}

	voteWindow := int64(3500)
	votePayload := domain.TrusteeVotePayload{
		TrusteeSelectionID:    "ts-1",
		VoterPublicKey:        voter.pub,
		SelectedCandidateKeys: [][]byte{candidate1.pub},
	}
	voteEnv, err := svc.CreateTrusteeVote(ctx, votePayload, voter.priv, voteWindow)
	if err != nil {
		t.Fatalf("CreateTrusteeVote() error = %v", err)
	}
	t.Logf("vote: %s", voteEnv.ObjectID)

	reporter := newTestKey(t)
	resultEnv, err := svc.BuildTrusteeSelectionResult(ctx, "ts-1", reporter.pub, reporter.priv)
	if err != nil {
		t.Fatalf("BuildTrusteeSelectionResult() error = %v", err)
	}
	t.Logf("result: %s", resultEnv.ObjectID)

	assertStatus(t, ctx, svc, voteEnv.ObjectID, validation.StatusValidForTally)
	assertStatus(t, ctx, svc, resultEnv.ObjectID, validation.StatusValid)

	for _, env := range []domain.ObjectEnvelope{voteEnv, resultEnv} {
		t.Logf("  %s: %s", env.ObjectType, env.ObjectID)
	}
}

func TestCreateTrusteeVoteRejectsZeroCandidates(t *testing.T) {
	ctx := context.Background()
	svc, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()

	creator := newTestKey(t)
	voter := newTestKey(t)

	electionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: "ts-1",
		NetworkID:          "testnet",
		Title:              "Test Election",
		Description:        "Desc",
		VoterAllowlist: []domain.VoterEntry{
			{VoterID: "v-1", VoterSigningPublicKey: voter.pub, VoterEncryptionPublicKey: make([]byte, 32)},
		},
		NominationStartsAt: 1000,
		NominationEndsAt:   2000,
		VotingStartsAt:     3000,
		VotingEndsAt:       4000,
		ConsentStartsAt:    5000,
		ConsentEndsAt:      6000,
		TrusteeCountN:      domain.TrusteeCountV1,
		ThresholdT:         domain.ThresholdV1,
		MaxChoicesPerVote:  domain.MaxChoicesPerVoteV1,
	}
	_, err = svc.CreateTrusteeSelectionElection(ctx, electionPayload, creator.priv, 500)
	if err != nil {
		t.Fatalf("CreateTrusteeSelectionElection() error = %v", err)
	}

	votePayload := domain.TrusteeVotePayload{
		TrusteeSelectionID:    "ts-1",
		VoterPublicKey:        voter.pub,
		SelectedCandidateKeys: nil,
	}
	_, err = svc.CreateTrusteeVote(ctx, votePayload, voter.priv, 3500)
	if err == nil {
		t.Fatal("CreateTrusteeVote() with zero candidates: expected error, got nil")
	}
	t.Logf("rejected zero-candidate vote: %v", err)
}

func assertStatus(t *testing.T, ctx context.Context, svc *app.Service, objectID string, want validation.Status) {
	t.Helper()
	status, found, err := svc.ValidationStatus(ctx, objectID)
	if err != nil {
		t.Fatalf("ValidationStatus(%s) error = %v", objectID, err)
	}
	if !found {
		t.Fatalf("ValidationStatus(%s) not found", objectID)
	}
	if status != want {
		t.Fatalf("ValidationStatus(%s) = %s, want %s", objectID, status, want)
	}
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random bytes: %v", err)
	}
	return b
}
