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

func TestActivationHappyPath(t *testing.T) {
	ctx := context.Background()
	svc, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()

	creator := newTestKey(t)
	voter := newTestKey(t)

	electionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: "ts-act-1",
		NetworkID:          "testnet",
		Title:              "Activation Test",
		Description:        "Activation happy path",
		VoterAllowlist: []domain.VoterEntry{
			{VoterID: "v-1", VoterSigningPublicKey: voter.pub, VoterEncryptionPublicKey: make([]byte, 32)},
		},
		NominationStartsAt: 1000, NominationEndsAt: 2000,
		VotingStartsAt: 3000, VotingEndsAt: 4000,
		ConsentStartsAt: 5000, ConsentEndsAt: 6000,
		TrusteeCountN: domain.TrusteeCountV1, ThresholdT: domain.ThresholdV1,
		MaxChoicesPerVote: domain.MaxChoicesPerVoteV1,
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

	candidates := []struct {
		key   testKey
		blind []byte
	}{
		{candidate1, blind1}, {candidate2, blind2}, {candidate3, blind3},
	}
	for _, c := range candidates {
		nom := domain.TrusteeNominationPayload{
			TrusteeSelectionID:           "ts-act-1",
			CandidatePublicKey:           c.key.pub,
			CandidateBlindTokenPublicKey: c.blind,
			CandidateNodePeerID:          "peer-1",
			Statement:                    "I will serve as trustee",
		}
		_, err := svc.CreateTrusteeNomination(ctx, nom, c.key.priv, 1500)
		if err != nil {
			t.Fatalf("CreateTrusteeNomination() error = %v", err)
		}
	}

	votePayload := domain.TrusteeVotePayload{
		TrusteeSelectionID:    "ts-act-1",
		VoterPublicKey:        voter.pub,
		SelectedCandidateKeys: [][]byte{candidate1.pub, candidate2.pub, candidate3.pub},
	}
	voteEnv, err := svc.CreateTrusteeVote(ctx, votePayload, voter.priv, 3500)
	if err != nil {
		t.Fatalf("CreateTrusteeVote() error = %v", err)
	}
	t.Logf("vote: %s", voteEnv.ObjectID)

	reporter := newTestKey(t)
	resultEnv, err := svc.BuildTrusteeSelectionResult(ctx, "ts-act-1", reporter.pub, reporter.priv)
	if err != nil {
		t.Fatalf("BuildTrusteeSelectionResult() error = %v", err)
	}
	t.Logf("result: %s", resultEnv.ObjectID)

	anonPayload := domain.AnonymousElectionPayload{
		ElectionID:                 "an-1",
		NetworkID:                  "testnet",
		Title:                      "Anonymous Election",
		Description:                "MVP test election",
		Options:                    []string{"yes", "no"},
		VoterAllowlist:             []domain.VoterEntry{{VoterID: "v-1", VoterSigningPublicKey: voter.pub, VoterEncryptionPublicKey: make([]byte, 32)}},
		TrusteeSelectionID:         "ts-act-1",
		TrusteeSelectionResultHash: resultEnv.Payload[:0],
		ThresholdT:                 domain.ThresholdV1,
		TrusteeCountN:              domain.TrusteeCountV1,
		EligibilityScheme:          domain.EligibilitySchemeBlindTokenV1,
		IssuanceStartsAt:           7000, IssuanceEndsAt: 8000,
		VotingStartsAt: 9000, VotingEndsAt: 10000,
		TallyStartsAt: 11000,
	}

	resultPayload, err := domain.DecodePayload(domain.ObjectTypeTrusteeSelectionResult, resultEnv.Payload)
	if err != nil {
		t.Fatalf("DecodePayload result: %v", err)
	}
	result := resultPayload.(domain.TrusteeSelectionResultPayload)
	anonPayload.TrusteeSelectionResultHash = result.ResultHash

	anonEnv, err := svc.CreateAnonymousElection(ctx, anonPayload, creator.priv, 6000)
	if err != nil {
		t.Fatalf("CreateAnonymousElection() error = %v", err)
	}
	t.Logf("election: %s", anonEnv.ObjectID)
	assertStatus(t, ctx, svc, anonEnv.ObjectID, validation.StatusValid)

	electionHash := validation.ComputeElectionParametersHash(anonPayload)

	trusteeKeys := []testKey{candidate1, candidate2, candidate3}
	tallySetupKeys := [][]byte{randomBytes(t, 32), randomBytes(t, 32), randomBytes(t, 32)}

	for i, tk := range trusteeKeys {
		consentPayload := domain.TrusteeConsentPayload{
			TrusteeSelectionID:         "ts-act-1",
			TrusteeSelectionResultHash: result.ResultHash,
			ElectionID:                 "an-1",
			ElectionParametersHash:     electionHash,
			TrusteePublicKey:           tk.pub,
			TrusteeTallySetupPublicKey: tallySetupKeys[i],
			ThresholdT:                 domain.ThresholdV1,
			TrusteeCountN:              domain.TrusteeCountV1,
		}
		env, err := svc.CreateTrusteeConsent(ctx, consentPayload, tk.priv, 5500)
		if err != nil {
			t.Fatalf("CreateTrusteeConsent(%d) error = %v", i, err)
		}
		t.Logf("consent %d: %s", i, env.ObjectID)
		assertStatus(t, ctx, svc, env.ObjectID, validation.StatusValid)
	}

	finalTrustees, err := svc.FinalTrusteeSet(ctx, "an-1")
	if err != nil {
		t.Fatalf("FinalTrusteeSet() error = %v", err)
	}
	if len(finalTrustees) != 3 {
		t.Fatalf("FinalTrusteeSet() returned %d trustees, want 3", len(finalTrustees))
	}

	for i, tk := range trusteeKeys {
		env, err := svc.CreateTallyKeyContribution(ctx, "an-1", tk.pub, tallySetupKeys[i], finalTrustees, tk.priv, 8000)
		if err != nil {
			t.Fatalf("CreateTallyKeyContribution(%d) error = %v", i, err)
		}
		t.Logf("contribution %d: %s", i, env.ObjectID)
		assertStatus(t, ctx, svc, env.ObjectID, validation.StatusValid)
	}

	keySetEnv, err := svc.BuildTallyKeySet(ctx, "an-1", reporter.pub, reporter.priv)
	if err != nil {
		t.Fatalf("BuildTallyKeySet() error = %v", err)
	}
	t.Logf("key set: %s", keySetEnv.ObjectID)
	assertStatus(t, ctx, svc, keySetEnv.ObjectID, validation.StatusValid)
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random bytes: %v", err)
	}
	return b
}
