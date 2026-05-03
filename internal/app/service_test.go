package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"librevote/internal/app"
	"librevote/internal/crypto"
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

func TestStartMVPElectionForVotersCreatesExplicitEligibleVoters(t *testing.T) {
	ctx := context.Background()
	svc, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()

	status, err := svc.StartMVPElectionForVoters(ctx, []string{"peer-b", "peer-a", "peer-b"})
	if err != nil {
		t.Fatalf("StartMVPElectionForVoters() error = %v", err)
	}

	want := []string{"peer-a", "peer-b"}
	if !stringSlicesEqual(status.VoterIDs, want) {
		t.Fatalf("signable voter_ids = %v, want %v", status.VoterIDs, want)
	}
	if !stringSlicesEqual(status.EligibleVoterIDs, want) {
		t.Fatalf("eligible_voter_ids = %v, want %v", status.EligibleVoterIDs, want)
	}
}

func TestElectionStatusForLocalVoterUsesPeerVoterID(t *testing.T) {
	ctx := context.Background()
	svc, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()
	if _, err := svc.StartMVPElectionForVoters(ctx, []string{"peer-local", "peer-other"}); err != nil {
		t.Fatalf("StartMVPElectionForVoters() error = %v", err)
	}

	status, err := svc.ElectionStatusForLocalVoter(ctx, "peer-local")
	if err != nil {
		t.Fatalf("ElectionStatusForLocalVoter() error = %v", err)
	}
	if status.LocalVoterID != "peer-local" || !status.LocalVoterSignable || status.LocalVoterVoted {
		t.Fatalf("local voter status = %+v", status)
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

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
		VoterAllowlist:             []domain.VoterEntry{{VoterID: "voter-1", VoterSigningPublicKey: voter.pub, VoterEncryptionPublicKey: make([]byte, 32)}},
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

func TestBallotCastAndTallyHappyPath(t *testing.T) {
	ctx := context.Background()
	svc, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()

	creator := newTestKey(t)
	voter := newTestKey(t)

	electionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: "ts-bt-1",
		NetworkID:          "testnet",
		Title:              "Ballot Test Election",
		Description:        "Test",
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

	candidates := []struct {
		key   testKey
		blind []byte
	}{
		{candidate1, randomBytes(t, 32)},
		{candidate2, randomBytes(t, 32)},
		{candidate3, randomBytes(t, 32)},
	}
	for _, c := range candidates {
		nom := domain.TrusteeNominationPayload{
			TrusteeSelectionID:           "ts-bt-1",
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
		TrusteeSelectionID:    "ts-bt-1",
		VoterPublicKey:        voter.pub,
		SelectedCandidateKeys: [][]byte{candidate1.pub, candidate2.pub, candidate3.pub},
	}
	_, err = svc.CreateTrusteeVote(ctx, votePayload, voter.priv, 3500)
	if err != nil {
		t.Fatalf("CreateTrusteeVote() error = %v", err)
	}

	reporter := newTestKey(t)
	resultEnv, err := svc.BuildTrusteeSelectionResult(ctx, "ts-bt-1", reporter.pub, reporter.priv)
	if err != nil {
		t.Fatalf("BuildTrusteeSelectionResult() error = %v", err)
	}
	resultPayload, _ := domain.DecodePayload(domain.ObjectTypeTrusteeSelectionResult, resultEnv.Payload)
	result := resultPayload.(domain.TrusteeSelectionResultPayload)
	voter2Key := newTestKey(t)
	voter3Key := newTestKey(t)

	anonPayload := domain.AnonymousElectionPayload{
		ElectionID:  "an-bt-1",
		NetworkID:   "testnet",
		Title:       "Ballot Election",
		Description: "Test",
		Options:     []string{"yes", "no", "maybe"},
		VoterAllowlist: []domain.VoterEntry{
			{VoterID: "voter-1", VoterSigningPublicKey: voter.pub, VoterEncryptionPublicKey: make([]byte, 32)},
			{VoterID: "voter-2", VoterSigningPublicKey: voter2Key.pub, VoterEncryptionPublicKey: randomBytes(t, 32)},
			{VoterID: "voter-3", VoterSigningPublicKey: voter3Key.pub, VoterEncryptionPublicKey: randomBytes(t, 32)},
		},
		TrusteeSelectionID:         "ts-bt-1",
		TrusteeSelectionResultHash: result.ResultHash,
		ThresholdT:                 domain.ThresholdV1,
		TrusteeCountN:              domain.TrusteeCountV1,
		EligibilityScheme:          domain.EligibilitySchemeBlindTokenV1,
		IssuanceStartsAt:           7000, IssuanceEndsAt: 8000,
		VotingStartsAt: 9000, VotingEndsAt: 10000,
		TallyStartsAt: 11000,
	}
	_, err = svc.CreateAnonymousElection(ctx, anonPayload, creator.priv, 6000)
	if err != nil {
		t.Fatalf("CreateAnonymousElection() error = %v", err)
	}

	electionHash := validation.ComputeElectionParametersHash(anonPayload)
	trusteeKeys := []testKey{candidate1, candidate2, candidate3}
	tallySetupKeys := [][]byte{randomBytes(t, 32), randomBytes(t, 32), randomBytes(t, 32)}

	for i, tk := range trusteeKeys {
		consentPayload := domain.TrusteeConsentPayload{
			TrusteeSelectionID:         "ts-bt-1",
			TrusteeSelectionResultHash: result.ResultHash,
			ElectionID:                 "an-bt-1",
			ElectionParametersHash:     electionHash,
			TrusteePublicKey:           tk.pub,
			TrusteeTallySetupPublicKey: tallySetupKeys[i],
			ThresholdT:                 domain.ThresholdV1,
			TrusteeCountN:              domain.TrusteeCountV1,
		}
		_, err := svc.CreateTrusteeConsent(ctx, consentPayload, tk.priv, 5500)
		if err != nil {
			t.Fatalf("CreateTrusteeConsent(%d) error = %v", i, err)
		}
	}

	finalTrustees, err := svc.FinalTrusteeSet(ctx, "an-bt-1")
	if err != nil {
		t.Fatalf("FinalTrusteeSet() error = %v", err)
	}

	for i, tk := range trusteeKeys {
		_, err := svc.CreateTallyKeyContribution(ctx, "an-bt-1", tk.pub, tallySetupKeys[i], finalTrustees, tk.priv, 8000)
		if err != nil {
			t.Fatalf("CreateTallyKeyContribution(%d) error = %v", i, err)
		}
	}

	tksEnv, err := svc.BuildTallyKeySet(ctx, "an-bt-1", reporter.pub, reporter.priv)
	if err != nil {
		t.Fatalf("BuildTallyKeySet() error = %v", err)
	}
	assertStatus(t, ctx, svc, tksEnv.ObjectID, validation.StatusValid)

	ballotEnv1, err := svc.CastBallot(ctx, "an-bt-1", "voter-1", "yes", voter.priv, 9500)
	if err != nil {
		t.Fatalf("CastBallot(voter-1:yes) error = %v", err)
	}
	assertStatus(t, ctx, svc, ballotEnv1.ObjectID, validation.StatusValidForTally)
	t.Logf("ballot voter-1:yes = %s", ballotEnv1.ObjectID)

	ballotEnv2, err := svc.CastBallot(ctx, "an-bt-1", "voter-2", "no", voter2Key.priv, 9600)
	if err != nil {
		t.Fatalf("CastBallot(voter-2:no) error = %v", err)
	}
	assertStatus(t, ctx, svc, ballotEnv2.ObjectID, validation.StatusValidForTally)
	t.Logf("ballot voter-2:no = %s", ballotEnv2.ObjectID)

	ballotEnv3, err := svc.CastBallot(ctx, "an-bt-1", "voter-3", "maybe", voter3Key.priv, 9700)
	if err != nil {
		t.Fatalf("CastBallot(voter-3:maybe) error = %v", err)
	}
	assertStatus(t, ctx, svc, ballotEnv3.ObjectID, validation.StatusValidForTally)

	tallyEnv, err := svc.BuildTallyResult(ctx, "an-bt-1", reporter.pub, reporter.priv, 12000)
	if err != nil {
		t.Fatalf("BuildTallyResult() error = %v", err)
	}
	assertStatus(t, ctx, svc, tallyEnv.ObjectID, validation.StatusValid)
	t.Logf("tally result: %s", tallyEnv.ObjectID)

	inputs, err := svc.GetTallyComputationInputs(ctx, "an-bt-1")
	if err != nil {
		t.Fatalf("GetTallyComputationInputs() error = %v", err)
	}
	computed := validation.ComputeLocalTallyResultForService("an-bt-1", inputs.TallyKeySetHash, inputs.RetainedBallots, inputs.Election.Options)
	if computed.ValidBallotCount != 3 {
		t.Fatalf("valid_ballot_count = %d, want 3", computed.ValidBallotCount)
	}
	if computed.ConflictedBallotCount != 0 {
		t.Fatalf("conflicted_ballot_count = %d, want 0", computed.ConflictedBallotCount)
	}
	expectedCounts := map[string]int64{"yes": 1, "no": 1, "maybe": 1}
	for _, r := range computed.OptionResults {
		if expectedCounts[r.Option] != r.Count {
			t.Fatalf("option %s: count = %d, want %d", r.Option, r.Count, expectedCounts[r.Option])
		}
	}
}

func TestBallotDuplicateConflict(t *testing.T) {
	ctx := context.Background()
	svc, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()

	creator := newTestKey(t)
	voter := newTestKey(t)

	electionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: "ts-dc-1",
		NetworkID:          "testnet",
		Title:              "Duplicate Test",
		Description:        "Test",
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
	for _, c := range []testKey{candidate1, candidate2, candidate3} {
		nom := domain.TrusteeNominationPayload{
			TrusteeSelectionID:           "ts-dc-1",
			CandidatePublicKey:           c.pub,
			CandidateBlindTokenPublicKey: randomBytes(t, 32),
			CandidateNodePeerID:          "peer-1",
			Statement:                    "I will serve",
		}
		_, err := svc.CreateTrusteeNomination(ctx, nom, c.priv, 1500)
		if err != nil {
			t.Fatalf("CreateTrusteeNomination() error = %v", err)
		}
	}

	_, err = svc.CreateTrusteeVote(ctx, domain.TrusteeVotePayload{
		TrusteeSelectionID:    "ts-dc-1",
		VoterPublicKey:        voter.pub,
		SelectedCandidateKeys: [][]byte{candidate1.pub, candidate2.pub, candidate3.pub},
	}, voter.priv, 3500)
	if err != nil {
		t.Fatalf("CreateTrusteeVote() error = %v", err)
	}

	reporter := newTestKey(t)
	resultEnv, _ := svc.BuildTrusteeSelectionResult(ctx, "ts-dc-1", reporter.pub, reporter.priv)
	resultPayload, _ := domain.DecodePayload(domain.ObjectTypeTrusteeSelectionResult, resultEnv.Payload)
	result := resultPayload.(domain.TrusteeSelectionResultPayload)

	anonPayload := domain.AnonymousElectionPayload{
		ElectionID:                 "an-dc-1",
		NetworkID:                  "testnet",
		Title:                      "Duplicate Test",
		Description:                "Test",
		Options:                    []string{"yes", "no"},
		VoterAllowlist:             []domain.VoterEntry{{VoterID: "voter-1", VoterSigningPublicKey: voter.pub, VoterEncryptionPublicKey: make([]byte, 32)}},
		TrusteeSelectionID:         "ts-dc-1",
		TrusteeSelectionResultHash: result.ResultHash,
		ThresholdT:                 domain.ThresholdV1,
		TrusteeCountN:              domain.TrusteeCountV1,
		EligibilityScheme:          domain.EligibilitySchemeBlindTokenV1,
		IssuanceStartsAt:           7000, IssuanceEndsAt: 8000,
		VotingStartsAt: 9000, VotingEndsAt: 10000,
		TallyStartsAt: 11000,
	}
	_, err = svc.CreateAnonymousElection(ctx, anonPayload, creator.priv, 6000)
	if err != nil {
		t.Fatalf("CreateAnonymousElection() error = %v", err)
	}

	electionHash := validation.ComputeElectionParametersHash(anonPayload)
	trusteeKeys := []testKey{candidate1, candidate2, candidate3}
	tallySetupKeys := [][]byte{randomBytes(t, 32), randomBytes(t, 32), randomBytes(t, 32)}
	for i, tk := range trusteeKeys {
		_, err := svc.CreateTrusteeConsent(ctx, domain.TrusteeConsentPayload{
			TrusteeSelectionID:         "ts-dc-1",
			TrusteeSelectionResultHash: result.ResultHash,
			ElectionID:                 "an-dc-1",
			ElectionParametersHash:     electionHash,
			TrusteePublicKey:           tk.pub,
			TrusteeTallySetupPublicKey: tallySetupKeys[i],
			ThresholdT:                 domain.ThresholdV1,
			TrusteeCountN:              domain.TrusteeCountV1,
		}, tk.priv, 5500)
		if err != nil {
			t.Fatalf("CreateTrusteeConsent(%d) error = %v", i, err)
		}
	}

	finalTrustees, _ := svc.FinalTrusteeSet(ctx, "an-dc-1")
	for i, tk := range trusteeKeys {
		_, err := svc.CreateTallyKeyContribution(ctx, "an-dc-1", tk.pub, tallySetupKeys[i], finalTrustees, tk.priv, 8000)
		if err != nil {
			t.Fatalf("CreateTallyKeyContribution(%d) error = %v", i, err)
		}
	}

	_, err = svc.BuildTallyKeySet(ctx, "an-dc-1", reporter.pub, reporter.priv)
	if err != nil {
		t.Fatalf("BuildTallyKeySet() error = %v", err)
	}

	ballot1, err := svc.CastBallot(ctx, "an-dc-1", "voter-1", "yes", voter.priv, 9500)
	if err != nil {
		t.Fatalf("CastBallot(1) error = %v", err)
	}
	assertStatus(t, ctx, svc, ballot1.ObjectID, validation.StatusValidForTally)
	t.Logf("ballot 1: %s", ballot1.ObjectID)

	ballot2, err := svc.CastBallot(ctx, "an-dc-1", "voter-1", "no", voter.priv, 9501)
	if err != nil {
		t.Fatalf("CastBallot(2) error = %v", err)
	}
	t.Logf("ballot 2: %s", ballot2.ObjectID)

	status1, _, _ := svc.ValidationStatus(ctx, ballot1.ObjectID)
	status2, _, _ := svc.ValidationStatus(ctx, ballot2.ObjectID)
	if status1 != validation.StatusValidButConflicted && status2 != validation.StatusValidButConflicted {
		t.Fatalf("expected both ballots to be valid_but_conflicted, got %s and %s", status1, status2)
	}
	t.Logf("ballot statuses after conflict: %s, %s", status1, status2)

	inputs, err := svc.GetTallyComputationInputs(ctx, "an-dc-1")
	if err != nil {
		t.Fatalf("GetTallyComputationInputs() error = %v", err)
	}
	computed := validation.ComputeLocalTallyResultForService("an-dc-1", inputs.TallyKeySetHash, inputs.RetainedBallots, inputs.Election.Options)
	if computed.ValidBallotCount != 0 {
		t.Fatalf("valid_ballot_count = %d, want 0 (all conflicted)", computed.ValidBallotCount)
	}
	if computed.ConflictedBallotCount != 2 {
		t.Fatalf("conflicted_ballot_count = %d, want 2", computed.ConflictedBallotCount)
	}
}

func TestTallyResultMismatchRejection(t *testing.T) {
	ctx := context.Background()
	svc, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()

	creator := newTestKey(t)
	voter := newTestKey(t)

	electionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: "ts-rej-1",
		NetworkID:          "testnet",
		Title:              "Rejection Test",
		Description:        "Test rejection of mismatched tally result",
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
	for _, c := range []testKey{candidate1, candidate2, candidate3} {
		nom := domain.TrusteeNominationPayload{
			TrusteeSelectionID:           "ts-rej-1",
			CandidatePublicKey:           c.pub,
			CandidateBlindTokenPublicKey: randomBytes(t, 32),
			CandidateNodePeerID:          "peer-1",
			Statement:                    "I will serve",
		}
		_, err := svc.CreateTrusteeNomination(ctx, nom, c.priv, 1500)
		if err != nil {
			t.Fatalf("CreateTrusteeNomination() error = %v", err)
		}
	}

	_, err = svc.CreateTrusteeVote(ctx, domain.TrusteeVotePayload{
		TrusteeSelectionID:    "ts-rej-1",
		VoterPublicKey:        voter.pub,
		SelectedCandidateKeys: [][]byte{candidate1.pub, candidate2.pub, candidate3.pub},
	}, voter.priv, 3500)
	if err != nil {
		t.Fatalf("CreateTrusteeVote() error = %v", err)
	}

	reporter := newTestKey(t)
	resultEnv, _ := svc.BuildTrusteeSelectionResult(ctx, "ts-rej-1", reporter.pub, reporter.priv)
	resultPayload, _ := domain.DecodePayload(domain.ObjectTypeTrusteeSelectionResult, resultEnv.Payload)
	result := resultPayload.(domain.TrusteeSelectionResultPayload)

	anonPayload := domain.AnonymousElectionPayload{
		ElectionID:                 "an-rej-1",
		NetworkID:                  "testnet",
		Title:                      "Rejection Test",
		Description:                "Test",
		Options:                    []string{"yes", "no"},
		VoterAllowlist:             []domain.VoterEntry{{VoterID: "voter-1", VoterSigningPublicKey: voter.pub, VoterEncryptionPublicKey: make([]byte, 32)}},
		TrusteeSelectionID:         "ts-rej-1",
		TrusteeSelectionResultHash: result.ResultHash,
		ThresholdT:                 domain.ThresholdV1,
		TrusteeCountN:              domain.TrusteeCountV1,
		EligibilityScheme:          domain.EligibilitySchemeBlindTokenV1,
		IssuanceStartsAt:           7000, IssuanceEndsAt: 8000,
		VotingStartsAt: 9000, VotingEndsAt: 10000,
		TallyStartsAt: 11000,
	}
	_, err = svc.CreateAnonymousElection(ctx, anonPayload, creator.priv, 6000)
	if err != nil {
		t.Fatalf("CreateAnonymousElection() error = %v", err)
	}

	electionHash := validation.ComputeElectionParametersHash(anonPayload)
	trusteeKeys := []testKey{candidate1, candidate2, candidate3}
	tallySetupKeys := [][]byte{randomBytes(t, 32), randomBytes(t, 32), randomBytes(t, 32)}
	for i, tk := range trusteeKeys {
		_, err := svc.CreateTrusteeConsent(ctx, domain.TrusteeConsentPayload{
			TrusteeSelectionID:         "ts-rej-1",
			TrusteeSelectionResultHash: result.ResultHash,
			ElectionID:                 "an-rej-1",
			ElectionParametersHash:     electionHash,
			TrusteePublicKey:           tk.pub,
			TrusteeTallySetupPublicKey: tallySetupKeys[i],
			ThresholdT:                 domain.ThresholdV1,
			TrusteeCountN:              domain.TrusteeCountV1,
		}, tk.priv, 5500)
		if err != nil {
			t.Fatalf("CreateTrusteeConsent(%d) error = %v", i, err)
		}
	}

	finalTrustees, _ := svc.FinalTrusteeSet(ctx, "an-rej-1")
	for i, tk := range trusteeKeys {
		_, err := svc.CreateTallyKeyContribution(ctx, "an-rej-1", tk.pub, tallySetupKeys[i], finalTrustees, tk.priv, 8000)
		if err != nil {
			t.Fatalf("CreateTallyKeyContribution(%d) error = %v", i, err)
		}
	}

	tksEnv, err := svc.BuildTallyKeySet(ctx, "an-rej-1", reporter.pub, reporter.priv)
	if err != nil {
		t.Fatalf("BuildTallyKeySet() error = %v", err)
	}
	assertStatus(t, ctx, svc, tksEnv.ObjectID, validation.StatusValid)

	_, err = svc.CastBallot(ctx, "an-rej-1", "voter-1", "yes", voter.priv, 9500)
	if err != nil {
		t.Fatalf("CastBallot() error = %v", err)
	}

	inputs, err := svc.GetTallyComputationInputs(ctx, "an-rej-1")
	if err != nil {
		t.Fatalf("GetTallyComputationInputs() error = %v", err)
	}
	computed := validation.ComputeLocalTallyResultForService("an-rej-1", inputs.TallyKeySetHash, inputs.RetainedBallots, inputs.Election.Options)
	computed.ReporterPublicKey = reporter.pub

	unsigned := computed
	unsigned.Signature = nil
	unsignedPayload := domain.EncodeTallyResultPayload(unsigned)
	createdAt := int64(12000)
	digest, err := crypto.SigningDigest(crypto.SigningContext{
		Domain:          crypto.DomainTallyResultSign,
		ProtocolVersion: "v1",
		NetworkID:       "testnet",
		ObjectType:      domain.ObjectTypeTallyResult,
		Scope:           domain.ScopeElectionID,
		ScopeID:         "an-rej-1",
		CreatedAt:       createdAt,
	}, unsignedPayload)
	if err != nil {
		t.Fatalf("SigningDigest() error = %v", err)
	}
	sig, err := crypto.SignEd25519(reporter.priv, digest)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}

	mismatchedPayload := computed
	mismatchedPayload.ResultHash = make([]byte, 32)
	mismatchedPayload.ValidBallotCount = 999
	mismatchedPayload.Signature = sig

	mismatchedEncoded := domain.EncodeTallyResultPayload(mismatchedPayload)
	mismatchedEnvelope := domain.ObjectEnvelope{
		ObjectType:      domain.ObjectTypeTallyResult,
		ProtocolVersion: "v1",
		NetworkID:       "testnet",
		Scope:           domain.ScopeElectionID,
		ScopeID:         "an-rej-1",
		Payload:         mismatchedEncoded,
		Pow:             []byte("mvp-nonce"),
		CreatedAt:       createdAt,
	}
	canonicalBytes, err := domain.CanonicalObjectBytes(mismatchedEnvelope)
	if err != nil {
		t.Fatalf("CanonicalObjectBytes() error = %v", err)
	}
	objectID, err := crypto.ObjectID(canonicalBytes)
	if err != nil {
		t.Fatalf("ObjectID() error = %v", err)
	}
	mismatchedEnvelope.ObjectID = objectID.String()

	ingestResult, err := svc.IngestEnvelope(ctx, mismatchedEnvelope)
	if err != nil {
		t.Fatalf("IngestEnvelope() error = %v", err)
	}
	if ingestResult.Outcome.Status != validation.StatusInvalid {
		t.Fatalf("expected invalid tally result, got status %s", ingestResult.Outcome.Status)
	}
	t.Logf("mismatched tally result rejected: %s", ingestResult.Outcome.Status)
}
