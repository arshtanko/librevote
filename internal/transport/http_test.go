package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"librevote/internal/app"
	"librevote/internal/domain"
	"librevote/internal/sync"
	"librevote/internal/transport"
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

func TestHTTPServerClientSyncTrusteeSelection(t *testing.T) {
	ctx := context.Background()

	svcA, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node A: %v", err)
	}
	defer svcA.Close()

	creator := newTestKey(t)
	voter := newTestKey(t)

	electionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: "ts-http",
		NetworkID:          "testnet",
		Title:              "HTTP Sync Test",
		Description:        "Test HTTP transport sync",
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
	candidates := []struct {
		key   testKey
		blind []byte
	}{
		{candidate1, randomBytes(t, 32)},
		{candidate2, randomBytes(t, 32)},
		{candidate3, randomBytes(t, 32)},
	}
	var nominationIDs []string
	for _, c := range candidates {
		nom := domain.TrusteeNominationPayload{
			TrusteeSelectionID:           "ts-http",
			CandidatePublicKey:           c.key.pub,
			CandidateBlindTokenPublicKey: c.blind,
			CandidateNodePeerID:          "peer-1",
			Statement:                    "I will serve as trustee",
		}
		env, err := svcA.CreateTrusteeNomination(ctx, nom, c.key.priv, 1500)
		if err != nil {
			t.Fatalf("CreateTrusteeNomination: %v", err)
		}
		nominationIDs = append(nominationIDs, env.ObjectID)
	}

	votePayload := domain.TrusteeVotePayload{
		TrusteeSelectionID:    "ts-http",
		VoterPublicKey:        voter.pub,
		SelectedCandidateKeys: [][]byte{candidate1.pub},
	}
	voteEnv, err := svcA.CreateTrusteeVote(ctx, votePayload, voter.priv, 3500)
	if err != nil {
		t.Fatalf("CreateTrusteeVote: %v", err)
	}

	reporter := newTestKey(t)
	resultEnv, err := svcA.BuildTrusteeSelectionResult(ctx, "ts-http", reporter.pub, reporter.priv)
	if err != nil {
		t.Fatalf("BuildTrusteeSelectionResult: %v", err)
	}

	assertStatus(t, ctx, svcA, electionEnv.ObjectID, validation.StatusValid)
	assertStatus(t, ctx, svcA, voteEnv.ObjectID, validation.StatusValidForTally)
	assertStatus(t, ctx, svcA, resultEnv.ObjectID, validation.StatusValid)

	server := transport.NewServer(svcA, "testnet")
	testServer := httptest.NewServer(server.Handler())
	defer testServer.Close()

	svcB, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node B: %v", err)
	}
	defer svcB.Close()

	httpTransport := transport.NewHTTPTransportWithClient(testServer.Client())

	result, err := sync.Sync(ctx, httpTransport, svcB, svcB, string(domain.ScopeNetwork), "", nil, []string{testServer.URL})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Sync network scope: result=%+v err=%v", result, err)
	}

	result, err = sync.Sync(ctx, httpTransport, svcB, svcB, string(domain.ScopeTrusteeSelectionID), "ts-http", nil, []string{testServer.URL})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Sync trustee_selection_id scope: result=%+v err=%v", result, err)
	}

	assertStatus(t, ctx, svcB, electionEnv.ObjectID, validation.StatusValid)
	assertStatus(t, ctx, svcB, voteEnv.ObjectID, validation.StatusValidForTally)
	assertStatus(t, ctx, svcB, resultEnv.ObjectID, validation.StatusValid)
	for _, id := range nominationIDs {
		assertStatus(t, ctx, svcB, id, validation.StatusValid)
	}

	t.Logf("election: %s", electionEnv.ObjectID)
	t.Logf("vote: %s", voteEnv.ObjectID)
	t.Logf("result: %s", resultEnv.ObjectID)
}

func TestHTTPEndpointsExcludeInvalidObjects(t *testing.T) {
	ctx := context.Background()

	svc, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer svc.Close()

	server := transport.NewServer(svc, "testnet")
	testServer := httptest.NewServer(server.Handler())
	defer testServer.Close()

	httpTransport := transport.NewHTTPTransportWithClient(testServer.Client())

	refs, err := httpTransport.Inventory(ctx, testServer.URL, string(domain.ScopeNetwork), "", nil)
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("empty store should have 0 refs, got %d", len(refs))
	}

	_, err = httpTransport.GetObject(ctx, testServer.URL, "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent object")
	}
	if !strings.Contains(err.Error(), "get-object failed") {
		t.Fatalf("unexpected error for nonexistent: %v", err)
	}

	badEnvelope := domain.ObjectEnvelope{
		ObjectID:        "bogus-invalid",
		ObjectType:      domain.ObjectTypeTrusteeVote,
		ProtocolVersion: "v1",
		NetworkID:       "wrong-net",
		Scope:           domain.ScopeTrusteeSelectionID,
		ScopeID:         "ts-bad",
		Payload:         []byte("not-valid"),
		Pow:             []byte("nonce"),
		CreatedAt:       3500,
	}
	_, err = svc.IngestEnvelope(ctx, badEnvelope)
	if err != nil {
		t.Logf("expected ingest error: %v", err)
	}

	refsAfter, err := httpTransport.Inventory(ctx, testServer.URL, string(domain.ScopeNetwork), "", nil)
	if err != nil {
		t.Fatalf("Inventory after bad ingest: %v", err)
	}
	for _, ref := range refsAfter {
		if ref.ObjectID == "bogus-invalid" {
			t.Fatal("invalid object should not appear in inventory")
		}
	}

	_, err = httpTransport.GetObject(ctx, testServer.URL, "bogus-invalid")
	if err == nil {
		t.Fatal("expected error when fetching invalid object")
	}
}

func TestHTTPTransportMultiplePeers(t *testing.T) {
	ctx := context.Background()

	svcA, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node A: %v", err)
	}
	defer svcA.Close()

	creator := newTestKey(t)
	voter := newTestKey(t)

	electionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: "ts-multi",
		NetworkID:          "testnet",
		Title:              "Multi Peer",
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
	nomPayload := domain.TrusteeNominationPayload{
		TrusteeSelectionID:           "ts-multi",
		CandidatePublicKey:           candidate.pub,
		CandidateBlindTokenPublicKey: randomBytes(t, 32),
		CandidateNodePeerID:          "peer-1",
		Statement:                    "Trustee",
	}
	nomEnv, err := svcA.CreateTrusteeNomination(ctx, nomPayload, candidate.priv, 1500)
	if err != nil {
		t.Fatalf("CreateTrusteeNomination: %v", err)
	}

	server := transport.NewServer(svcA, "testnet")
	testServer := httptest.NewServer(server.Handler())
	defer testServer.Close()

	svcB, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node B: %v", err)
	}
	defer svcB.Close()

	httpTransport := transport.NewHTTPTransportWithClient(testServer.Client())

	result, err := sync.Sync(ctx, httpTransport, svcB, svcB, string(domain.ScopeNetwork), "", nil, []string{testServer.URL, testServer.URL})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Sync network scope: result=%+v err=%v", result, err)
	}

	assertStatus(t, ctx, svcB, electionEnv.ObjectID, validation.StatusValid)

	result, err = sync.Sync(ctx, httpTransport, svcB, svcB, string(domain.ScopeTrusteeSelectionID), "ts-multi", nil, []string{testServer.URL})
	if err != nil || len(result.Errors) > 0 {
		t.Fatalf("Sync scoped: result=%+v err=%v", result, err)
	}

	assertStatus(t, ctx, svcB, nomEnv.ObjectID, validation.StatusValid)

	t.Logf("sync fetched=%d ingested=%d", result.Fetched, result.Ingested)
}

func TestHTTPEndpointsMethodNotAllowed(t *testing.T) {
	svc, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer svc.Close()

	handler := transport.NewServer(svc, "testnet").Handler()

	for _, tt := range []struct {
		method string
		path   string
	}{
		{"POST", "/inventory"},
		{"POST", "/object/abc"},
		{"PUT", "/inventory"},
		{"DELETE", "/object/abc"},
	} {
		t.Run(fmt.Sprintf("%s %s", tt.method, tt.path), func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s: %d, want %d", tt.method, tt.path, w.Code, http.StatusMethodNotAllowed)
			}
		})
	}
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
