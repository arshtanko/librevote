package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	nethttp "net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"librevote/internal/app"
	"librevote/internal/domain"
	"librevote/internal/gossip"
	"librevote/internal/sync"
	"librevote/internal/validation"

	ma "github.com/multiformats/go-multiaddr"
)

func generateTestKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func generateTestElectionPayload(selectionID string, creatorPub ed25519.PublicKey) domain.TrusteeSelectionElectionPayload {
	return domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: selectionID,
		NetworkID:          "testnet",
		Title:              "Test Election",
		Description:        "Test",
		VoterAllowlist: []domain.VoterEntry{
			{VoterID: "v-1", VoterSigningPublicKey: creatorPub, VoterEncryptionPublicKey: make([]byte, 32)},
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
}

func multiaddrFromStr(t *testing.T, s string) ma.Multiaddr {
	t.Helper()
	maddr, err := ma.NewMultiaddr(s)
	if err != nil {
		t.Fatalf("parse multiaddr %q: %v", s, err)
	}
	return maddr
}

func TestNodeStartStopBasic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dir := t.TempDir()
	svc, err := app.Open(dir, "testnet")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	svc.Close()

	config := app.NodeStartConfig{
		DataDir:        dir,
		NetworkID:      "testnet",
		HTTPListenAddr: "127.0.0.1:0",
		KeyPath:        filepath.Join(dir, "node.key"),
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
	}

	ns, err := app.NewNodeStart(ctx, config, t.Logf)
	if err != nil {
		t.Fatalf("NewNodeStart: %v", err)
	}

	if err := ns.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	if err := ns.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestNodeStartHTTPAccessible(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dir := t.TempDir()
	svc, err := app.Open(dir, "testnet")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	svc.Close()

	config := app.NodeStartConfig{
		DataDir:        dir,
		NetworkID:      "testnet",
		HTTPListenAddr: "127.0.0.1:0",
		KeyPath:        filepath.Join(dir, "node.key"),
	}

	ns, err := app.NewNodeStart(ctx, config, t.Logf)
	if err != nil {
		t.Fatalf("NewNodeStart: %v", err)
	}

	if err := ns.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer ns.Stop()

	time.Sleep(200 * time.Millisecond)

	testServer := httptest.NewServer(nil)
	testServer.Config.Handler = nil
	testServer.Close()

	resp, err := nethttp.Get("http://" + ns.Addr() + "/inventory?scope=network")
	if err != nil {
		t.Fatalf("GET inventory: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != nethttp.StatusOK {
		t.Fatalf("inventory status = %d, want 200", resp.StatusCode)
	}
}

func TestNodeStartExtraHandlerPreservesSyncEndpoints(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dir := t.TempDir()
	svc, err := app.Open(dir, "testnet")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	svc.Close()

	config := app.NodeStartConfig{
		DataDir:        dir,
		NetworkID:      "testnet",
		HTTPListenAddr: "127.0.0.1:0",
		KeyPath:        filepath.Join(dir, "node.key"),
	}

	ns, err := app.NewNodeStart(ctx, config, t.Logf)
	if err != nil {
		t.Fatalf("NewNodeStart: %v", err)
	}
	ns.SetExtraHTTPHandler(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.URL.Path != "/" {
			nethttp.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "extra handler")
	}))

	if err := ns.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer ns.Stop()

	resp, err := nethttp.Get("http://" + ns.Addr() + "/")
	if err != nil {
		t.Fatalf("GET extra: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "extra handler" {
		t.Fatalf("extra body = %q", string(body))
	}

	resp, err = nethttp.Get("http://" + ns.Addr() + "/inventory?scope=network")
	if err != nil {
		t.Fatalf("GET inventory: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != nethttp.StatusOK {
		t.Fatalf("inventory status = %d, want 200", resp.StatusCode)
	}
}

func TestNodeStartConfigDefaults(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	svc, err := app.Open(dir, "testnet")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	svc.Close()

	config := app.NodeStartConfig{
		DataDir:   dir,
		NetworkID: "testnet",
	}

	ns, err := app.NewNodeStart(ctx, config, nil)
	if err != nil {
		t.Fatalf("NewNodeStart: %v", err)
	}
	ns.Stop()
}

func TestNodeStartInvalidConfig(t *testing.T) {
	ctx := context.Background()

	_, err := app.NewNodeStart(ctx, app.NodeStartConfig{}, nil)
	if err == nil {
		t.Fatal("expected error for empty config")
	}

	_, err = app.NewNodeStart(ctx, app.NodeStartConfig{DataDir: "/tmp"}, nil)
	if err == nil {
		t.Fatal("expected error for missing network ID")
	}
	_ = err
}

func TestPublishInventory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dir := t.TempDir()
	svc, err := app.Open(dir, "testnet")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	creatorPub, creatorPriv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	electionPayload := generateTestElectionPayload("ts-pub", creatorPub)
	_, err = svc.CreateTrusteeSelectionElection(ctx, electionPayload, creatorPriv, 500)
	if err != nil {
		t.Fatalf("CreateTrusteeSelectionElection: %v", err)
	}
	svc.Close()

	config := app.NodeStartConfig{
		DataDir:        dir,
		NetworkID:      "testnet",
		HTTPListenAddr: "127.0.0.1:0",
		KeyPath:        filepath.Join(dir, "node.key"),
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
	}

	ns, err := app.NewNodeStart(ctx, config, t.Logf)
	if err != nil {
		t.Fatalf("NewNodeStart: %v", err)
	}

	if err := ns.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer ns.Stop()

	time.Sleep(500 * time.Millisecond)

	refs, err := ns.Service().ListServableObjectRefs(ctx, "network", "", nil)
	if err != nil {
		t.Fatalf("list refs: %v", err)
	}
	if len(refs) == 0 {
		t.Fatal("expected at least one network-scoped object")
	}
	t.Logf("network objects: %d", len(refs))

	scopes, err := ns.Service().ListServableScopes(ctx)
	if err != nil {
		t.Fatalf("list scopes: %v", err)
	}
	if len(scopes) == 0 {
		t.Fatal("expected at least one scope pair")
	}
	t.Logf("servable scopes: %d", len(scopes))
	for _, sp := range scopes {
		t.Logf("  scope=%s scope_id=%q", sp.Scope, sp.ScopeID)
	}
}

func TestPublishInventoryCrossScope(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	svc, err := app.Open(dir, "testnet")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	creatorPub, creatorPriv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	electionPayload := generateTestElectionPayload("ts-xscope", creatorPub)
	_, err = svc.CreateTrusteeSelectionElection(ctx, electionPayload, creatorPriv, 500)
	if err != nil {
		t.Fatalf("CreateTrusteeSelectionElection: %v", err)
	}

	candidatePub, candidatePriv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate candidate key: %v", err)
	}
	nomPayload := domain.TrusteeNominationPayload{
		TrusteeSelectionID:           "ts-xscope",
		CandidatePublicKey:           candidatePub,
		CandidateBlindTokenPublicKey: make([]byte, 32),
		CandidateNodePeerID:          "peer-x",
		Statement:                    "Candidate",
	}
	_, err = svc.CreateTrusteeNomination(ctx, nomPayload, candidatePriv, 1500)
	if err != nil {
		t.Fatalf("CreateTrusteeNomination: %v", err)
	}
	svc.Close()

	config := app.NodeStartConfig{
		DataDir:        dir,
		NetworkID:      "testnet",
		HTTPListenAddr: "127.0.0.1:0",
		KeyPath:        filepath.Join(dir, "node.key"),
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
	}

	ns, err := app.NewNodeStart(ctx, config, t.Logf)
	if err != nil {
		t.Fatalf("NewNodeStart: %v", err)
	}
	if err := ns.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer ns.Stop()

	time.Sleep(500 * time.Millisecond)

	scopes, err := ns.Service().ListServableScopes(ctx)
	if err != nil {
		t.Fatalf("list scopes: %v", err)
	}
	if len(scopes) < 2 {
		t.Fatalf("expected at least 2 scopes (network + trustee_selection_id), got %d", len(scopes))
	}

	hasNetwork := false
	hasTrusteeScope := false
	for _, sp := range scopes {
		if sp.Scope == "network" && sp.ScopeID == "" {
			hasNetwork = true
		}
		if sp.Scope == "trustee_selection_id" && sp.ScopeID == "ts-xscope" {
			hasTrusteeScope = true
		}
	}
	if !hasNetwork {
		t.Fatal("expected network scope in servable scopes")
	}
	if !hasTrusteeScope {
		t.Fatal("expected trustee_selection_id scope in servable scopes")
	}

	refsNetwork, _ := ns.Service().ListServableObjectRefs(ctx, "network", "", nil)
	refsTrustee, _ := ns.Service().ListServableObjectRefs(ctx, "trustee_selection_id", "ts-xscope", nil)
	t.Logf("network refs: %d, trustee_selection_id refs: %d", len(refsNetwork), len(refsTrustee))
	if len(refsTrustee) == 0 {
		t.Fatal("expected trustee_selection_id scoped objects")
	}
}

func TestAdvertisedHTTPFromActualPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dir := t.TempDir()
	svc, err := app.Open(dir, "testnet")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	svc.Close()

	config := app.NodeStartConfig{
		DataDir:        dir,
		NetworkID:      "testnet",
		HTTPListenAddr: "127.0.0.1:0",
		KeyPath:        filepath.Join(dir, "node.key"),
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
	}

	ns, err := app.NewNodeStart(ctx, config, t.Logf)
	if err != nil {
		t.Fatalf("NewNodeStart: %v", err)
	}
	if err := ns.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer ns.Stop()

	time.Sleep(200 * time.Millisecond)

	actualAddr := ns.Addr()
	if actualAddr == "" || actualAddr == "127.0.0.1:0" {
		t.Fatalf("actual HTTP addr should be a concrete bound port, got %q", actualAddr)
	}
	t.Logf("HTTP bound addr: %s", actualAddr)

	resp, err := nethttp.Get("http://" + actualAddr + "/inventory?scope=network")
	if err != nil {
		t.Fatalf("GET inventory: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != nethttp.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", resp.StatusCode)
	}
}

func TestDiscoveryHTTPURLUsed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	dirA := t.TempDir()
	dirB := t.TempDir()

	for _, d := range []string{dirA, dirB} {
		svc, err := app.Open(d, "testnet")
		if err != nil {
			t.Fatalf("Open %s: %v", d, err)
		}
		svc.Close()
	}

	svcA, err := app.Open(dirA, "testnet")
	if err != nil {
		t.Fatalf("Open svcA: %v", err)
	}
	creatorPub, creatorPriv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	electionPayload := generateTestElectionPayload("ts-disc", creatorPub)
	env, err := svcA.CreateTrusteeSelectionElection(ctx, electionPayload, creatorPriv, 500)
	if err != nil {
		t.Fatalf("CreateTrusteeSelectionElection: %v", err)
	}
	t.Logf("Node A election object: %s", env.ObjectID)
	svcA.Close()

	configA := app.NodeStartConfig{
		DataDir:        dirA,
		NetworkID:      "testnet",
		HTTPListenAddr: "127.0.0.1:0",
		KeyPath:        filepath.Join(dirA, "node.key"),
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
		Mode:           "server",
	}

	nsA, err := app.NewNodeStart(ctx, configA, t.Logf)
	if err != nil {
		t.Fatalf("NewNodeStart A: %v", err)
	}
	if err := nsA.Start(ctx); err != nil {
		t.Fatalf("Start A: %v", err)
	}
	defer nsA.Stop()

	time.Sleep(500 * time.Millisecond)

	configB := app.NodeStartConfig{
		DataDir:          dirB,
		NetworkID:        "testnet",
		HTTPListenAddr:   "127.0.0.1:0",
		KeyPath:          filepath.Join(dirB, "node.key"),
		ListenAddrs:      []string{"/ip4/127.0.0.1/tcp/0"},
		Mode:             "client",
		AnnounceInterval: 5 * time.Second,
	}

	nsB, err := app.NewNodeStart(ctx, configB, t.Logf)
	if err != nil {
		t.Fatalf("NewNodeStart B: %v", err)
	}
	if err := nsB.Start(ctx); err != nil {
		t.Fatalf("Start B: %v", err)
	}
	defer nsB.Stop()

	time.Sleep(500 * time.Millisecond)

	httpURL_A := "http://" + nsA.Addr()
	peerID_A := nsA.Discovery().Identity().PeerID.String()
	peerID_B := nsB.Discovery().Identity().PeerID.String()
	t.Logf("Node A HTTP: %s PeerID: %s", httpURL_A, peerID_A)
	t.Logf("Node B PeerID: %s", peerID_B)

	var addrAStr string
	for _, a := range nsA.Discovery().Host().Addrs() {
		addrAStr = a.Encapsulate(multiaddrFromStr(t, "/p2p/"+peerID_A)).String()
		break
	}
	if err := nsB.ConnectPeer(ctx, addrAStr); err != nil {
		t.Fatalf("connect B to A: %v", err)
	}

	time.Sleep(5 * time.Second)

	resolvedByB := nsB.Discovery().PeerHTTPURL(ctx, nsA.Discovery().Identity().PeerID)
	t.Logf("Node B resolved A's HTTP URL via libp2p advertise stream: %s", resolvedByB)
	if resolvedByB != httpURL_A {
		t.Fatalf("Node B must resolve Node A HTTP URL via discovery. got=%q want=%q", resolvedByB, httpURL_A)
	}
	t.Logf("Node B successfully resolved A's HTTP URL via discovery protocol")

	for i := 0; i < 4; i++ {
		a := gossip.ObjectAnnouncement{
			ObjectID:   env.ObjectID,
			ObjectType: string(env.ObjectType),
			Scope:      string(env.Scope),
			ScopeID:    env.ScopeID,
			CreatedAt:  env.CreatedAt,
		}
		if err := nsA.GossipService().Publish(ctx, a); err != nil {
			t.Logf("publish %d: %v", i+1, err)
		}
		time.Sleep(3 * time.Second)
	}

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		_, err := nsB.Service().LoadObjectEnvelope(context.Background(), env.ObjectID)
		if err == nil {
			t.Logf("Node B ingested object %s via gossip+fetch", env.ObjectID)
			return
		}
		time.Sleep(1 * time.Second)
	}

	t.Fatalf("Node B should have object %s after gossip+fetch", env.ObjectID)
}

func TestTwoNodeGossipIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	dirA := t.TempDir()
	dirB := t.TempDir()

	for _, d := range []string{dirA, dirB} {
		svc, err := app.Open(d, "testnet")
		if err != nil {
			t.Fatalf("Open %s: %v", d, err)
		}
		svc.Close()
	}

	svcA, err := app.Open(dirA, "testnet")
	if err != nil {
		t.Fatalf("Open svcA: %v", err)
	}
	creatorPub, creatorPriv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	electionPayload := generateTestElectionPayload("ts-int", creatorPub)
	env, err := svcA.CreateTrusteeSelectionElection(ctx, electionPayload, creatorPriv, 500)
	if err != nil {
		t.Fatalf("CreateTrusteeSelectionElection: %v", err)
	}
	t.Logf("Node A election object: %s", env.ObjectID)
	svcA.Close()

	configA := app.NodeStartConfig{
		DataDir:        dirA,
		NetworkID:      "testnet",
		HTTPListenAddr: "127.0.0.1:0",
		KeyPath:        filepath.Join(dirA, "node.key"),
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
		Mode:           "server",
	}

	nsA, err := app.NewNodeStart(ctx, configA, t.Logf)
	if err != nil {
		t.Fatalf("NewNodeStart A: %v", err)
	}
	if err := nsA.Start(ctx); err != nil {
		t.Fatalf("Start A: %v", err)
	}
	defer nsA.Stop()

	time.Sleep(500 * time.Millisecond)

	httpURL_A := "http://" + nsA.Addr()
	peerID_A := nsA.Discovery().Identity().PeerID.String()
	t.Logf("Node A HTTP: %s PeerID: %s", httpURL_A, peerID_A)

	var addrAStr string
	for _, a := range nsA.Discovery().Host().Addrs() {
		addrAStr = a.Encapsulate(multiaddrFromStr(t, "/p2p/"+peerID_A)).String()
		break
	}

	// Start B without bootstrap - connect explicitly after GossipSub is created.
	configB := app.NodeStartConfig{
		DataDir:          dirB,
		NetworkID:        "testnet",
		HTTPListenAddr:   "127.0.0.1:0",
		KeyPath:          filepath.Join(dirB, "node.key"),
		ListenAddrs:      []string{"/ip4/127.0.0.1/tcp/0"},
		Mode:             "client",
		AnnounceInterval: 5 * time.Second,
	}

	nsB, err := app.NewNodeStart(ctx, configB, t.Logf)
	if err != nil {
		t.Fatalf("NewNodeStart B: %v", err)
	}
	if err := nsB.Start(ctx); err != nil {
		t.Fatalf("Start B: %v", err)
	}
	defer nsB.Stop()

	nsB.InjectPeerHTTP(peerID_A, httpURL_A)

	// Connect B to A AFTER both GossipSub services exist.
	t.Logf("connecting B to A after GossipSub init...")
	if err := nsB.ConnectPeer(ctx, addrAStr); err != nil {
		t.Fatalf("connect: %v", err)
	}

	// Give GossipSub mesh time to form.
	t.Logf("waiting for GossipSub mesh...")
	time.Sleep(5 * time.Second)

	// Publish repeatedly.
	for i := 0; i < 6; i++ {
		a := gossip.ObjectAnnouncement{
			ObjectID:   env.ObjectID,
			ObjectType: string(env.ObjectType),
			Scope:      string(env.Scope),
			ScopeID:    env.ScopeID,
			CreatedAt:  env.CreatedAt,
		}
		if err := nsA.GossipService().Publish(ctx, a); err != nil {
			t.Logf("publish %d: %v", i+1, err)
		}
		time.Sleep(3 * time.Second)
	}

	// Wait for B to ingest.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		_, err := nsB.Service().LoadObjectEnvelope(context.Background(), env.ObjectID)
		if err == nil {
			t.Logf("Node B ingested object %s via gossip+fetch", env.ObjectID)
			return
		}
		time.Sleep(1 * time.Second)
	}

	refs, _ := nsB.Service().ListServableObjectRefs(context.Background(), "network", "", nil)
	t.Logf("B objects: %d", len(refs))
	for _, r := range refs {
		t.Logf("  B: %s type=%s", r.ObjectID, r.ObjectType)
	}
	t.Fatalf("Node B should have object %s after gossip+fetch", env.ObjectID)
}

func TestCrossScopeGossipFullTally(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	dirA := t.TempDir()
	dirB := t.TempDir()

	for _, d := range []string{dirA, dirB} {
		svc, err := app.Open(d, "testnet")
		if err != nil {
			t.Fatalf("Open %s: %v", d, err)
		}
		svc.Close()
	}

	svcA, err := app.Open(dirA, "testnet")
	if err != nil {
		t.Fatalf("Open svcA: %v", err)
	}
	_, creatorPriv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate creator key: %v", err)
	}
	voterPub, voterPriv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate voter key: %v", err)
	}

	allVoterKeys := []ed25519.PublicKey{voterPub}
	ballotKey2Pub, ballotKey2Priv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate ballot key 2: %v", err)
	}
	ballotKey3Pub, ballotKey3Priv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate ballot key 3: %v", err)
	}
	allVoterKeys = append(allVoterKeys, ballotKey2Pub, ballotKey3Pub)

	voterEntries := make([]domain.VoterEntry, 0, len(allVoterKeys))
	for i, pk := range allVoterKeys {
		encKey := make([]byte, 32)
		encKey[0] = byte(i + 1)
		voterEntries = append(voterEntries, domain.VoterEntry{
			VoterID:                  fmt.Sprintf("v-%x", pk[:4]),
			VoterSigningPublicKey:    pk,
			VoterEncryptionPublicKey: encKey,
		})
	}

	electionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: "ts-csft",
		NetworkID:          "testnet",
		Title:              "Cross-Scope Test",
		Description:        "Full tally via gossip",
		VoterAllowlist:     voterEntries,
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
	_, err = svcA.CreateTrusteeSelectionElection(ctx, electionPayload, creatorPriv, 500)
	if err != nil {
		t.Fatalf("CreateTrusteeSelectionElection: %v", err)
	}

	candidate1Pub, candidate1Priv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate candidate1 key: %v", err)
	}
	candidate2Pub, candidate2Priv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate candidate2 key: %v", err)
	}
	candidate3Pub, candidate3Priv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate candidate3 key: %v", err)
	}
	candidates := []struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	}{
		{candidate1Pub, candidate1Priv},
		{candidate2Pub, candidate2Priv},
		{candidate3Pub, candidate3Priv},
	}
	for _, c := range candidates {
		nom := domain.TrusteeNominationPayload{
			TrusteeSelectionID:           "ts-csft",
			CandidatePublicKey:           c.pub,
			CandidateBlindTokenPublicKey: randomTestBytes(t, 32),
			CandidateNodePeerID:          "peer-1",
			Statement:                    "I will serve as trustee",
		}
		_, err := svcA.CreateTrusteeNomination(ctx, nom, c.priv, 1500)
		if err != nil {
			t.Fatalf("CreateTrusteeNomination: %v", err)
		}
	}

	votePayload := domain.TrusteeVotePayload{
		TrusteeSelectionID:    "ts-csft",
		VoterPublicKey:        voterPub,
		SelectedCandidateKeys: [][]byte{candidate1Pub, candidate2Pub, candidate3Pub},
	}
	_, err = svcA.CreateTrusteeVote(ctx, votePayload, voterPriv, 3500)
	if err != nil {
		t.Fatalf("CreateTrusteeVote: %v", err)
	}

	reporterPub, reporterPriv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate reporter key: %v", err)
	}
	resultEnv, err := svcA.BuildTrusteeSelectionResult(ctx, "ts-csft", reporterPub, reporterPriv)
	if err != nil {
		t.Fatalf("BuildTrusteeSelectionResult: %v", err)
	}
	resultPayload, err := domain.DecodePayload(domain.ObjectTypeTrusteeSelectionResult, resultEnv.Payload)
	if err != nil {
		t.Fatalf("DecodePayload result: %v", err)
	}
	result := resultPayload.(domain.TrusteeSelectionResultPayload)

	anonPayload := domain.AnonymousElectionPayload{
		ElectionID:                 "an-csft",
		NetworkID:                  "testnet",
		Title:                      "Cross-Scope Gossip Test",
		Description:                "Full tally via gossip",
		Options:                    []string{"yes", "no"},
		VoterAllowlist:             voterEntries,
		TrusteeSelectionID:         "ts-csft",
		TrusteeSelectionResultHash: result.ResultHash,
		ThresholdT:                 domain.ThresholdV1,
		TrusteeCountN:              domain.TrusteeCountV1,
		EligibilityScheme:          domain.EligibilitySchemeBlindTokenV1,
		IssuanceStartsAt:           7000, IssuanceEndsAt: 8000,
		VotingStartsAt: 9000, VotingEndsAt: 10000,
		TallyStartsAt: 11000,
	}
	_, err = svcA.CreateAnonymousElection(ctx, anonPayload, creatorPriv, 6000)
	if err != nil {
		t.Fatalf("CreateAnonymousElection: %v", err)
	}

	electionHash := validation.ComputeElectionParametersHash(anonPayload)
	trusteeKeys := []struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	}{{candidate1Pub, candidate1Priv}, {candidate2Pub, candidate2Priv}, {candidate3Pub, candidate3Priv}}
	tallySetupKeys := [][]byte{randomTestBytes(t, 32), randomTestBytes(t, 32), randomTestBytes(t, 32)}

	for i, tk := range trusteeKeys {
		consentPayload := domain.TrusteeConsentPayload{
			TrusteeSelectionID:         "ts-csft",
			TrusteeSelectionResultHash: result.ResultHash,
			ElectionID:                 "an-csft",
			ElectionParametersHash:     electionHash,
			TrusteePublicKey:           tk.pub,
			TrusteeTallySetupPublicKey: tallySetupKeys[i],
			ThresholdT:                 domain.ThresholdV1,
			TrusteeCountN:              domain.TrusteeCountV1,
		}
		_, err := svcA.CreateTrusteeConsent(ctx, consentPayload, tk.priv, 5500)
		if err != nil {
			t.Fatalf("CreateTrusteeConsent(%d): %v", i, err)
		}
	}

	finalTrustees, err := svcA.FinalTrusteeSet(ctx, "an-csft")
	if err != nil {
		t.Fatalf("FinalTrusteeSet: %v", err)
	}

	for i, tk := range trusteeKeys {
		_, err := svcA.CreateTallyKeyContribution(ctx, "an-csft", tk.pub, tallySetupKeys[i], finalTrustees, tk.priv, 8000)
		if err != nil {
			t.Fatalf("CreateTallyKeyContribution(%d): %v", i, err)
		}
	}

	_, err = svcA.BuildTallyKeySet(ctx, "an-csft", reporterPub, reporterPriv)
	if err != nil {
		t.Fatalf("BuildTallyKeySet: %v", err)
	}

	for _, vote := range []struct {
		voterID string
		choice  string
		key     ed25519.PrivateKey
	}{
		{fmt.Sprintf("v-%x", voterPub[:4]), "yes", voterPriv},
		{fmt.Sprintf("v-%x", ballotKey2Pub[:4]), "no", ballotKey2Priv},
		{fmt.Sprintf("v-%x", ballotKey3Pub[:4]), "yes", ballotKey3Priv},
	} {
		_, err := svcA.CastBallot(ctx, "an-csft", vote.voterID, vote.choice, vote.key, 9500)
		if err != nil {
			t.Fatalf("CastBallot(%s:%s): %v", vote.voterID, vote.choice, err)
		}
	}

	tallyEnv, err := svcA.BuildTallyResult(ctx, "an-csft", reporterPub, reporterPriv, 12000)
	if err != nil {
		t.Fatalf("BuildTallyResult: %v", err)
	}
	t.Logf("Node A tally result: %s", tallyEnv.ObjectID)
	svcA.Close()

	configA := app.NodeStartConfig{
		DataDir:          dirA,
		NetworkID:        "testnet",
		HTTPListenAddr:   "127.0.0.1:0",
		KeyPath:          filepath.Join(dirA, "node.key"),
		ListenAddrs:      []string{"/ip4/127.0.0.1/tcp/0"},
		Mode:             "server",
		AnnounceInterval: 3 * time.Second,
	}

	nsA, err := app.NewNodeStart(ctx, configA, t.Logf)
	if err != nil {
		t.Fatalf("NewNodeStart A: %v", err)
	}
	if err := nsA.Start(ctx); err != nil {
		t.Fatalf("Start A: %v", err)
	}
	defer nsA.Stop()

	time.Sleep(500 * time.Millisecond)

	httpURL_A := "http://" + nsA.Addr()
	peerID_A := nsA.Discovery().Identity().PeerID.String()
	t.Logf("Node A HTTP: %s PeerID: %s", httpURL_A, peerID_A)

	var addrAStr string
	for _, a := range nsA.Discovery().Host().Addrs() {
		addrAStr = a.Encapsulate(multiaddrFromStr(t, "/p2p/"+peerID_A)).String()
		break
	}

	configB := app.NodeStartConfig{
		DataDir:          dirB,
		NetworkID:        "testnet",
		HTTPListenAddr:   "127.0.0.1:0",
		KeyPath:          filepath.Join(dirB, "node.key"),
		ListenAddrs:      []string{"/ip4/127.0.0.1/tcp/0"},
		Mode:             "client",
		AdvertisedHTTP:   "http://127.0.0.1:0",
		AnnounceInterval: 10 * time.Second,
	}

	nsB, err := app.NewNodeStart(ctx, configB, t.Logf)
	if err != nil {
		t.Fatalf("NewNodeStart B: %v", err)
	}
	if err := nsB.Start(ctx); err != nil {
		t.Fatalf("Start B: %v", err)
	}
	defer nsB.Stop()

	time.Sleep(300 * time.Millisecond)

	peerID_B := nsB.Discovery().Identity().PeerID.String()
	t.Logf("Node B PeerID: %s", peerID_B)

	// Do NOT use InjectPeerHTTP. Let Node B discover Node A's HTTP URL via libp2p stream.
	if err := nsB.ConnectPeer(ctx, addrAStr); err != nil {
		t.Fatalf("connect B to A: %v", err)
	}

	time.Sleep(2 * time.Second)

	resolvedURL := nsB.Discovery().PeerHTTPURL(ctx, nsA.Discovery().Identity().PeerID)
	t.Logf("Node B resolved Node A HTTP URL via discovery: %s", resolvedURL)
	if resolvedURL != httpURL_A {
		t.Fatalf("Node B must resolve Node A HTTP URL via discovery. got=%q want=%q", resolvedURL, httpURL_A)
	}

	// Wait for B to ingest all objects via GossipSub announcements.
	deadline := time.Now().Add(120 * time.Second)
	var gatheredCount int
	for time.Now().Before(deadline) {
		refs, _ := nsB.Service().ListServableObjectRefs(context.Background(), "network", "", nil)
		refs2, _ := nsB.Service().ListServableObjectRefs(context.Background(), "trustee_selection_id", "ts-csft", nil)
		refs3, _ := nsB.Service().ListServableObjectRefs(context.Background(), "election_id", "an-csft", nil)
		total := len(refs) + len(refs2) + len(refs3)
		if total != gatheredCount {
			gatheredCount = total
			t.Logf("Node B servable objects: network=%d ts=%d el=%d", len(refs), len(refs2), len(refs3))
		}

		_, err := nsB.Service().LoadObjectEnvelope(context.Background(), tallyEnv.ObjectID)
		if err == nil {
			t.Logf("Node B has full tally result via gossip+fetch")
			break
		}
		time.Sleep(2 * time.Second)
	}

	_, err = nsB.Service().LoadObjectEnvelope(context.Background(), tallyEnv.ObjectID)
	if err != nil {
		refs, _ := nsB.Service().ListServableObjectRefs(context.Background(), "election_id", "an-csft", nil)
		t.Logf("Node B election_id objects: %d", len(refs))
		for _, r := range refs {
			t.Logf("  B: %s type=%s scope=%s/%s", r.ObjectID, r.ObjectType, r.Scope, r.ScopeID)
		}
		t.Fatalf("Node B should receive tally result %s via gossip+fetch: %v", tallyEnv.ObjectID, err)
	}

	inputs, err := nsB.Service().GetTallyComputationInputs(context.Background(), "an-csft")
	if err != nil {
		t.Fatalf("GetTallyComputationInputs on B: %v", err)
	}
	computed := validation.ComputeLocalTallyResultForService("an-csft", inputs.TallyKeySetHash, inputs.RetainedBallots, inputs.Election.Options)
	if computed.ValidBallotCount != 3 {
		t.Fatalf("Node B valid_ballot_count = %d, want 3", computed.ValidBallotCount)
	}
	if computed.ConflictedBallotCount != 0 {
		t.Fatalf("Node B conflicted_ballot_count = %d, want 0", computed.ConflictedBallotCount)
	}
	expectedCounts := map[string]int64{"yes": 2, "no": 1}
	for _, r := range computed.OptionResults {
		if expectedCounts[r.Option] != r.Count {
			t.Fatalf("Node B option %s: count = %d, want %d", r.Option, r.Count, expectedCounts[r.Option])
		}
	}
	t.Logf("Node B tally matches Node A: valid=%d conflicted=%d", computed.ValidBallotCount, computed.ConflictedBallotCount)
}

func TestDiscoveryHTTPURLRequired(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	dirA := t.TempDir()
	dirB := t.TempDir()

	for _, d := range []string{dirA, dirB} {
		svc, err := app.Open(d, "testnet")
		if err != nil {
			t.Fatalf("Open %s: %v", d, err)
		}
		svc.Close()
	}

	svcA, err := app.Open(dirA, "testnet")
	if err != nil {
		t.Fatalf("Open svcA: %v", err)
	}
	creatorPub, creatorPriv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	electionPayload := generateTestElectionPayload("ts-dreq", creatorPub)
	env, err := svcA.CreateTrusteeSelectionElection(ctx, electionPayload, creatorPriv, 500)
	if err != nil {
		t.Fatalf("CreateTrusteeSelectionElection: %v", err)
	}
	t.Logf("Node A election object: %s", env.ObjectID)
	svcA.Close()

	configA := app.NodeStartConfig{
		DataDir:        dirA,
		NetworkID:      "testnet",
		HTTPListenAddr: "127.0.0.1:0",
		KeyPath:        filepath.Join(dirA, "node.key"),
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
		Mode:           "server",
	}

	nsA, err := app.NewNodeStart(ctx, configA, t.Logf)
	if err != nil {
		t.Fatalf("NewNodeStart A: %v", err)
	}
	if err := nsA.Start(ctx); err != nil {
		t.Fatalf("Start A: %v", err)
	}
	defer nsA.Stop()

	time.Sleep(500 * time.Millisecond)

	httpURL_A := "http://" + nsA.Addr()
	peerID_A := nsA.Discovery().Identity().PeerID.String()
	t.Logf("Node A HTTP: %s PeerID: %s", httpURL_A, peerID_A)

	var addrAStr string
	for _, a := range nsA.Discovery().Host().Addrs() {
		addrAStr = a.Encapsulate(multiaddrFromStr(t, "/p2p/"+peerID_A)).String()
		break
	}

	configB := app.NodeStartConfig{
		DataDir:          dirB,
		NetworkID:        "testnet",
		HTTPListenAddr:   "127.0.0.1:0",
		KeyPath:          filepath.Join(dirB, "node.key"),
		ListenAddrs:      []string{"/ip4/127.0.0.1/tcp/0"},
		Mode:             "client",
		AnnounceInterval: 10 * time.Second,
	}

	nsB, err := app.NewNodeStart(ctx, configB, t.Logf)
	if err != nil {
		t.Fatalf("NewNodeStart B: %v", err)
	}
	if err := nsB.Start(ctx); err != nil {
		t.Fatalf("Start B: %v", err)
	}
	defer nsB.Stop()

	time.Sleep(300 * time.Millisecond)

	// Do NOT inject HTTP URL fallback.
	if err := nsB.ConnectPeer(ctx, addrAStr); err != nil {
		t.Fatalf("connect B to A: %v", err)
	}

	time.Sleep(2 * time.Second)

	resolvedURL := nsB.Discovery().PeerHTTPURL(ctx, nsA.Discovery().Identity().PeerID)
	t.Logf("Node B resolved A HTTP URL via discovery: %s", resolvedURL)
	if resolvedURL != httpURL_A {
		t.Fatalf("Node B must resolve Node A HTTP URL via discovery. got=%q want=%q", resolvedURL, httpURL_A)
	}

	t.Logf("Node B successfully resolved A's HTTP URL via discovery protocol")
}

func TestDependencyOrderPublishing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	svc, err := app.Open(dir, "testnet")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	creatorPub, creatorPriv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	electionPayload := generateTestElectionPayload("ts-dop", creatorPub)
	_, err = svc.CreateTrusteeSelectionElection(ctx, electionPayload, creatorPriv, 500)
	if err != nil {
		t.Fatalf("CreateTrusteeSelectionElection: %v", err)
	}

	candidatePub, candidatePriv, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate candidate key: %v", err)
	}
	nomPayload := domain.TrusteeNominationPayload{
		TrusteeSelectionID:           "ts-dop",
		CandidatePublicKey:           candidatePub,
		CandidateBlindTokenPublicKey: make([]byte, 32),
		CandidateNodePeerID:          "peer-x",
		Statement:                    "Candidate",
	}
	_, err = svc.CreateTrusteeNomination(ctx, nomPayload, candidatePriv, 1500)
	if err != nil {
		t.Fatalf("CreateTrusteeNomination: %v", err)
	}
	svc.Close()

	config := app.NodeStartConfig{
		DataDir:        dir,
		NetworkID:      "testnet",
		HTTPListenAddr: "127.0.0.1:0",
		KeyPath:        filepath.Join(dir, "node.key"),
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
	}

	ns, err := app.NewNodeStart(ctx, config, t.Logf)
	if err != nil {
		t.Fatalf("NewNodeStart: %v", err)
	}
	if err := ns.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer ns.Stop()

	time.Sleep(500 * time.Millisecond)

	scopes, err := ns.Service().ListServableScopes(ctx)
	if err != nil {
		t.Fatalf("list scopes: %v", err)
	}
	if len(scopes) < 2 {
		t.Fatalf("expected at least 2 scopes (network + trustee_selection_id), got %d", len(scopes))
	}

	var allRefs []sync.ObjectRef
	for _, sp := range scopes {
		refs, _ := ns.Service().ListServableObjectRefs(ctx, sp.Scope, sp.ScopeID, nil)
		allRefs = append(allRefs, refs...)
	}

	sync.SortByDependencyRank(allRefs)

	t.Logf("publishing order (by dependency rank):")
	prevRank := -1
	for _, ref := range allRefs {
		rank := sync.DependencyRank[ref.ObjectType]
		t.Logf("  rank=%d scope=%s/%s type=%s id=%s", rank, ref.Scope, ref.ScopeID, ref.ObjectType, ref.ObjectID)
		if rank < prevRank {
			t.Fatalf("dependency order violation: rank %d appears after rank %d (object %s)", rank, prevRank, ref.ObjectID)
		}
		prevRank = rank
	}

	if len(allRefs) < 2 {
		t.Fatal("expected at least 2 objects in dependency-sorted list")
	}
}

func funcKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func randomTestBytes(t *testing.T, size int) []byte {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random bytes: %v", err)
	}
	return b
}
