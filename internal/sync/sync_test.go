package sync_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"librevote/internal/app"
	"librevote/internal/domain"
	"librevote/internal/sync"
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

func TestSyncTrusteeSelectionHappyPath(t *testing.T) {
	ctx := context.Background()

	svcA, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node A: %v", err)
	}
	defer svcA.Close()

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
	electionEnv, err := svcA.CreateTrusteeSelectionElection(ctx, electionPayload, creator.priv, 500)
	if err != nil {
		t.Fatalf("CreateTrusteeSelectionElection: %v", err)
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
	var nominationIDs []string
	for _, c := range candidates {
		nom := domain.TrusteeNominationPayload{
			TrusteeSelectionID:           "ts-1",
			CandidatePublicKey:           c.key.pub,
			CandidateBlindTokenPublicKey: c.blind,
			CandidateNodePeerID:          "peer-1",
			Statement:                    "I will serve as trustee",
		}
		env, err := svcA.CreateTrusteeNomination(ctx, nom, c.key.priv, nomWindow)
		if err != nil {
			t.Fatalf("CreateTrusteeNomination: %v", err)
		}
		nominationIDs = append(nominationIDs, env.ObjectID)
	}

	voteWindow := int64(3500)
	votePayload := domain.TrusteeVotePayload{
		TrusteeSelectionID:    "ts-1",
		VoterPublicKey:        voter.pub,
		SelectedCandidateKeys: [][]byte{candidate1.pub},
	}
	voteEnv, err := svcA.CreateTrusteeVote(ctx, votePayload, voter.priv, voteWindow)
	if err != nil {
		t.Fatalf("CreateTrusteeVote: %v", err)
	}

	reporter := newTestKey(t)
	resultEnv, err := svcA.BuildTrusteeSelectionResult(ctx, "ts-1", reporter.pub, reporter.priv)
	if err != nil {
		t.Fatalf("BuildTrusteeSelectionResult: %v", err)
	}

	assertStatus(t, ctx, svcA, electionEnv.ObjectID, validation.StatusValid)
	assertStatus(t, ctx, svcA, voteEnv.ObjectID, validation.StatusValidForTally)
	assertStatus(t, ctx, svcA, resultEnv.ObjectID, validation.StatusValid)

	svcB, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node B: %v", err)
	}
	defer svcB.Close()

	for _, id := range append([]string{electionEnv.ObjectID, voteEnv.ObjectID, resultEnv.ObjectID}, nominationIDs...) {
		_, found, err := svcB.ValidationStatus(ctx, id)
		if err != nil {
			t.Fatalf("ValidationStatus B(%s): %v", id, err)
		}
		if found {
			t.Fatalf("node B should not have object %s yet", id)
		}
	}

	transport := sync.NewStaticPeerTransport(map[string]sync.StoreQuerier{
		"node-a": svcA,
		"node-b": svcB,
	})

	result, err := sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeNetwork), "", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Sync network scope: result=%+v err=%v", result, err)
	}

	result, err = sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeTrusteeSelectionID), "ts-1", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Sync trustee_selection_id scope: result=%+v err=%v", result, err)
	}

	assertStatus(t, ctx, svcB, voteEnv.ObjectID, validation.StatusValidForTally)
	assertStatus(t, ctx, svcB, resultEnv.ObjectID, validation.StatusValid)
	for _, id := range nominationIDs {
		assertStatus(t, ctx, svcB, id, validation.StatusValid)
	}

	result, err = sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeNetwork), "", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Repeat network scope sync: result=%+v err=%v", result, err)
	}
	result, err = sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeTrusteeSelectionID), "ts-1", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Repeat trustee_selection_id scope sync: result=%+v err=%v", result, err)
	}
	assertStatus(t, ctx, svcB, voteEnv.ObjectID, validation.StatusValidForTally)

	t.Logf("election: %s", electionEnv.ObjectID)
	for i, id := range nominationIDs {
		t.Logf("nomination %d: %s", i, id)
	}
	t.Logf("vote: %s", voteEnv.ObjectID)
	t.Logf("result: %s", resultEnv.ObjectID)
}

func TestSyncExcludesInvalidAndUnservableObjects(t *testing.T) {
	ctx := context.Background()

	svcA, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node A: %v", err)
	}
	defer svcA.Close()

	creator := newTestKey(t)
	voter := newTestKey(t)

	electionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: "ts-exclude",
		NetworkID:          "testnet",
		Title:              "Test",
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
	_, err = svcA.CreateTrusteeSelectionElection(ctx, electionPayload, creator.priv, 500)
	if err != nil {
		t.Fatalf("CreateTrusteeSelectionElection: %v", err)
	}

	candidate := newTestKey(t)
	nom := domain.TrusteeNominationPayload{
		TrusteeSelectionID:           "ts-exclude",
		CandidatePublicKey:           candidate.pub,
		CandidateBlindTokenPublicKey: randomBytes(t, 32),
		CandidateNodePeerID:          "peer-1",
		Statement:                    "Trustee",
	}
	_, err = svcA.CreateTrusteeNomination(ctx, nom, candidate.priv, 1500)
	if err != nil {
		t.Fatalf("CreateTrusteeNomination: %v", err)
	}

	svcB, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node B: %v", err)
	}
	defer svcB.Close()

	transport := sync.NewStaticPeerTransport(map[string]sync.StoreQuerier{
		"node-a": svcA,
		"node-b": svcB,
	})

	refs, err := svcA.ListServableObjectRefs(ctx, string(domain.ScopeTrusteeSelectionID), "ts-exclude", nil)
	if err != nil {
		t.Fatalf("ListServableObjectRefs: %v", err)
	}
	if len(refs) == 0 {
		t.Fatal("expected at least one servable object ref")
	}

	for _, ref := range refs {
		env, err := svcA.LoadObjectEnvelope(ctx, ref.ObjectID)
		if err != nil {
			t.Fatalf("LoadObjectEnvelope(%s): %v", ref.ObjectID, err)
		}
		if env.ObjectID != ref.ObjectID {
			t.Fatalf("mismatched object ID: %s != %s", env.ObjectID, ref.ObjectID)
		}
	}

	_, err = svcA.LoadObjectEnvelope(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent object")
	}

	badEnvelope := domain.ObjectEnvelope{
		ObjectID:        "bogus-id",
		ObjectType:      domain.ObjectTypeTrusteeVote,
		ProtocolVersion: "v1",
		NetworkID:       "wrong-net",
		Scope:           domain.ScopeTrusteeSelectionID,
		ScopeID:         "ts-exclude",
		Payload:         []byte("not-valid"),
		Pow:             []byte("nonce"),
		CreatedAt:       3500,
	}
	_, err = svcA.IngestEnvelope(ctx, badEnvelope)
	if err != nil {
		t.Logf("expected ingest error for bad envelope: %v", err)
	}

	refsAfterBad, err := svcA.ListServableObjectRefs(ctx, string(domain.ScopeTrusteeSelectionID), "ts-exclude", nil)
	if err != nil {
		t.Fatalf("ListServableObjectRefs after bad: %v", err)
	}
	for _, ref := range refsAfterBad {
		if ref.ObjectID == "bogus-id" {
			t.Fatal("invalid object should not appear in servable refs")
		}
	}

	_ = transport
}

func TestSyncRepeatedIdempotent(t *testing.T) {
	ctx := context.Background()

	svcA, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node A: %v", err)
	}
	defer svcA.Close()

	creator := newTestKey(t)
	voter := newTestKey(t)

	electionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: "ts-idem",
		NetworkID:          "testnet",
		Title:              "Idempotent Test",
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
	electionEnv, err := svcA.CreateTrusteeSelectionElection(ctx, electionPayload, creator.priv, 500)
	if err != nil {
		t.Fatalf("CreateTrusteeSelectionElection: %v", err)
	}

	candidate := newTestKey(t)
	nom := domain.TrusteeNominationPayload{
		TrusteeSelectionID:           "ts-idem",
		CandidatePublicKey:           candidate.pub,
		CandidateBlindTokenPublicKey: randomBytes(t, 32),
		CandidateNodePeerID:          "peer-1",
		Statement:                    "Trustee",
	}
	nomEnv, err := svcA.CreateTrusteeNomination(ctx, nom, candidate.priv, 1500)
	if err != nil {
		t.Fatalf("CreateTrusteeNomination: %v", err)
	}

	svcB, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node B: %v", err)
	}
	defer svcB.Close()

	transport := sync.NewStaticPeerTransport(map[string]sync.StoreQuerier{
		"node-a": svcA,
		"node-b": svcB,
	})

	result, err := sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeNetwork), "", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("First network sync: result=%+v err=%v", result, err)
	}
	result, err = sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeTrusteeSelectionID), "ts-idem", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("First scoped sync: result=%+v err=%v", result, err)
	}
	assertStatus(t, ctx, svcB, electionEnv.ObjectID, validation.StatusValid)
	assertStatus(t, ctx, svcB, nomEnv.ObjectID, validation.StatusValid)

	result, err = sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeNetwork), "", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Second network sync: result=%+v err=%v", result, err)
	}
	result, err = sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeTrusteeSelectionID), "ts-idem", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Second scoped sync: result=%+v err=%v", result, err)
	}

	result, err = sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeNetwork), "", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Third network sync: result=%+v err=%v", result, err)
	}
	result, err = sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeTrusteeSelectionID), "ts-idem", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Third scoped sync: result=%+v err=%v", result, err)
	}

	assertStatus(t, ctx, svcB, electionEnv.ObjectID, validation.StatusValid)
	assertStatus(t, ctx, svcB, nomEnv.ObjectID, validation.StatusValid)
}

func TestSyncEvictedPayloadExcludedFromServableRefs(t *testing.T) {
	ctx := context.Background()

	svcA, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node A: %v", err)
	}
	defer svcA.Close()

	creator := newTestKey(t)
	voter := newTestKey(t)

	electionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: "ts-evict",
		NetworkID:          "testnet",
		Title:              "Evict Test",
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
	_, err = svcA.CreateTrusteeSelectionElection(ctx, electionPayload, creator.priv, 500)
	if err != nil {
		t.Fatalf("CreateTrusteeSelectionElection: %v", err)
	}

	candidate := newTestKey(t)
	nom := domain.TrusteeNominationPayload{
		TrusteeSelectionID:           "ts-evict",
		CandidatePublicKey:           candidate.pub,
		CandidateBlindTokenPublicKey: randomBytes(t, 32),
		CandidateNodePeerID:          "peer-1",
		Statement:                    "Trustee",
	}
	nomEnv, err := svcA.CreateTrusteeNomination(ctx, nom, candidate.priv, 1500)
	if err != nil {
		t.Fatalf("CreateTrusteeNomination: %v", err)
	}

	assertStatus(t, ctx, svcA, nomEnv.ObjectID, validation.StatusValid)

	refsBefore, err := svcA.ListServableObjectRefs(ctx, string(domain.ScopeTrusteeSelectionID), "ts-evict", nil)
	if err != nil {
		t.Fatalf("ListServableObjectRefs before: %v", err)
	}
	foundBefore := false
	for _, ref := range refsBefore {
		if ref.ObjectID == nomEnv.ObjectID {
			foundBefore = true
			break
		}
	}
	if !foundBefore {
		t.Fatal("valid nomination should be servable")
	}

	err = svcA.EvictPendingPayload(ctx, nomEnv.ObjectID, 5000, "test")
	if err == nil {
		t.Fatal("expected EvictPendingPayload to fail for non-pending valid object")
	}
	t.Logf("evict non-pending rejected as expected: %v", err)

	refsAfter, err := svcA.ListServableObjectRefs(ctx, string(domain.ScopeTrusteeSelectionID), "ts-evict", nil)
	if err != nil {
		t.Fatalf("ListServableObjectRefs after: %v", err)
	}
	foundAfter := false
	for _, ref := range refsAfter {
		if ref.ObjectID == nomEnv.ObjectID {
			foundAfter = true
			break
		}
	}
	if !foundAfter {
		t.Fatal("valid object should remain servable after failed eviction")
	}

	svcB, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node B: %v", err)
	}
	defer svcB.Close()

	transport := sync.NewStaticPeerTransport(map[string]sync.StoreQuerier{
		"node-a": svcA,
		"node-b": svcB,
	})

	result, err := sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeNetwork), "", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Sync network scope: result=%+v err=%v", result, err)
	}
	result, err = sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeTrusteeSelectionID), "ts-evict", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Sync scoped: result=%+v err=%v", result, err)
	}

	refsBServed, err := svcB.ListServableObjectRefs(ctx, string(domain.ScopeTrusteeSelectionID), "ts-evict", nil)
	if err != nil {
		t.Fatalf("ListServableObjectRefs on B: %v", err)
	}
	foundB := false
	for _, ref := range refsBServed {
		if ref.ObjectID == nomEnv.ObjectID {
			foundB = true
			break
		}
	}
	if !foundB {
		t.Fatal("valid nomination should be servable on B after sync")
	}
}

func TestSyncPendingObjectTransitionsToValid(t *testing.T) {
	ctx := context.Background()

	svcA, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node A: %v", err)
	}
	defer svcA.Close()

	creator := newTestKey(t)
	voter := newTestKey(t)

	electionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: "ts-pending",
		NetworkID:          "testnet",
		Title:              "Pending Test",
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
	electionEnv, err := svcA.CreateTrusteeSelectionElection(ctx, electionPayload, creator.priv, 500)
	if err != nil {
		t.Fatalf("CreateTrusteeSelectionElection: %v", err)
	}

	candidate1 := newTestKey(t)
	candidate2 := newTestKey(t)
	nom1Env, err := svcA.CreateTrusteeNomination(ctx, domain.TrusteeNominationPayload{
		TrusteeSelectionID:           "ts-pending",
		CandidatePublicKey:           candidate1.pub,
		CandidateBlindTokenPublicKey: randomBytes(t, 32),
		CandidateNodePeerID:          "peer-1",
		Statement:                    "Trustee 1",
	}, candidate1.priv, 1500)
	if err != nil {
		t.Fatalf("CreateTrusteeNomination 1: %v", err)
	}
	nom2Env, err := svcA.CreateTrusteeNomination(ctx, domain.TrusteeNominationPayload{
		TrusteeSelectionID:           "ts-pending",
		CandidatePublicKey:           candidate2.pub,
		CandidateBlindTokenPublicKey: randomBytes(t, 32),
		CandidateNodePeerID:          "peer-1",
		Statement:                    "Trustee 2",
	}, candidate2.priv, 1500)
	if err != nil {
		t.Fatalf("CreateTrusteeNomination 2: %v", err)
	}

	votePayload := domain.TrusteeVotePayload{
		TrusteeSelectionID:    "ts-pending",
		VoterPublicKey:        voter.pub,
		SelectedCandidateKeys: [][]byte{candidate1.pub},
	}
	voteEnv, err := svcA.CreateTrusteeVote(ctx, votePayload, voter.priv, 3500)
	if err != nil {
		t.Fatalf("CreateTrusteeVote: %v", err)
	}

	reporter := newTestKey(t)
	resultEnv, err := svcA.BuildTrusteeSelectionResult(ctx, "ts-pending", reporter.pub, reporter.priv)
	if err != nil {
		t.Fatalf("BuildTrusteeSelectionResult: %v", err)
	}

	svcB, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node B: %v", err)
	}
	defer svcB.Close()

	transport := sync.NewStaticPeerTransport(map[string]sync.StoreQuerier{
		"node-a": svcA,
		"node-b": svcB,
	})

	result, err := sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeTrusteeSelectionID), "ts-pending", []string{string(domain.ObjectTypeTrusteeVote)}, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Sync vote only: result=%+v err=%v", result, err)
	}

	status, found, err := svcB.ValidationStatus(ctx, voteEnv.ObjectID)
	if err != nil {
		t.Fatalf("ValidationStatus(vote): %v", err)
	}
	if !found {
		t.Fatal("vote should be stored on B")
	}
	if status != validation.StatusPendingDependencies {
		t.Fatalf("vote status = %s, want pending_dependencies (election and nominations not yet synced)", status)
	}
	t.Logf("vote is pending as expected: %s", status)

	_, found, err = svcB.ValidationStatus(ctx, nom1Env.ObjectID)
	if err != nil {
		t.Fatalf("ValidationStatus(nom1): %v", err)
	}
	if found {
		t.Fatal("nomination should not be on B yet")
	}

	result, err = sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeNetwork), "", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Sync network scope: result=%+v err=%v", result, err)
	}
	assertStatus(t, ctx, svcB, electionEnv.ObjectID, validation.StatusValid)

	status, found, err = svcB.ValidationStatus(ctx, voteEnv.ObjectID)
	if err != nil {
		t.Fatalf("ValidationStatus(vote) after election sync: %v", err)
	}
	if !found {
		t.Fatal("vote should still be stored")
	}
	if status != validation.StatusPendingDependencies {
		t.Fatalf("vote status after election sync = %s, still expect pending (nominations missing)", status)
	}

	result, err = sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeTrusteeSelectionID), "ts-pending", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Second scoped sync: result=%+v err=%v", result, err)
	}

	assertStatus(t, ctx, svcB, nom1Env.ObjectID, validation.StatusValid)
	assertStatus(t, ctx, svcB, nom2Env.ObjectID, validation.StatusValid)
	assertStatus(t, ctx, svcB, voteEnv.ObjectID, validation.StatusValidForTally)
	assertStatus(t, ctx, svcB, resultEnv.ObjectID, validation.StatusValid)
}

func TestSyncResultCounts(t *testing.T) {
	ctx := context.Background()

	svcA, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node A: %v", err)
	}
	defer svcA.Close()

	creator := newTestKey(t)
	voter := newTestKey(t)

	electionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: "ts-count",
		NetworkID:          "testnet",
		Title:              "Count Test",
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
	_, err = svcA.CreateTrusteeSelectionElection(ctx, electionPayload, creator.priv, 500)
	if err != nil {
		t.Fatalf("CreateTrusteeSelectionElection: %v", err)
	}

	svcB, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node B: %v", err)
	}
	defer svcB.Close()

	transport := sync.NewStaticPeerTransport(map[string]sync.StoreQuerier{
		"node-a": svcA,
		"node-b": svcB,
	})

	result, err := sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeNetwork), "", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("First sync: result=%+v err=%v", result, err)
	}
	if result.Fetched == 0 {
		t.Fatal("expected Fetched > 0 on first sync")
	}
	if result.Ingested == 0 {
		t.Fatal("expected Ingested > 0 on first sync")
	}
	if result.Fetched != result.Ingested {
		t.Fatalf("Fetched=%d Ingested=%d: all fetched should be ingested", result.Fetched, result.Ingested)
	}

	result, err = sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeNetwork), "", nil, []string{"node-a"})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Second sync: result=%+v err=%v", result, err)
	}
	if result.Fetched > 0 || result.Ingested > 0 {
		t.Fatalf("Second sync should not fetch/ingest anything: Fetched=%d Ingested=%d", result.Fetched, result.Ingested)
	}

	result, err = sync.Sync(ctx, transport, svcB, svcB, string(domain.ScopeNetwork), "", nil, []string{"nonexistent-peer"})
	if err == nil {
		t.Fatal("expected non-nil error from sync with bad peer")
	}
	if len(result.Errors) == 0 {
		t.Fatal("expected result.Errors from sync with bad peer")
	}
	t.Logf("bad peer sync errors: %v", result.Errors)
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
