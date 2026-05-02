package gossip_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"librevote/internal/app"
	"librevote/internal/domain"
	"librevote/internal/gossip"
	librevotesync "librevote/internal/sync"
	"librevote/internal/validation"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

func newTestHost(t *testing.T, ctx context.Context) host.Host {
	t.Helper()
	h, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
	)
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	return h
}

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

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("waitFor: condition not met within timeout")
}

func TestTopicName(t *testing.T) {
	name := gossip.TopicName("testnet")
	if name != "librevote.testnet.objects.v1" {
		t.Fatalf("topic name = %q, want librevote.testnet.objects.v1", name)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	a := gossip.ObjectAnnouncement{
		ObjectID:   "abc123",
		ObjectType: "AnonymousBallot",
		Scope:      "election_id",
		ScopeID:    "el-1",
		CreatedAt:  9500,
	}

	data, err := gossip.EncodeAnnouncement(a)
	if err != nil {
		t.Fatalf("EncodeAnnouncement: %v", err)
	}

	decoded, err := gossip.DecodeAnnouncement(data)
	if err != nil {
		t.Fatalf("DecodeAnnouncement: %v", err)
	}

	if decoded.ObjectID != a.ObjectID {
		t.Fatalf("object_id = %q, want %q", decoded.ObjectID, a.ObjectID)
	}
	if decoded.ObjectType != a.ObjectType {
		t.Fatalf("object_type = %q, want %q", decoded.ObjectType, a.ObjectType)
	}
	if decoded.Scope != a.Scope {
		t.Fatalf("scope = %q, want %q", decoded.Scope, a.Scope)
	}
	if decoded.ScopeID != a.ScopeID {
		t.Fatalf("scope_id = %q, want %q", decoded.ScopeID, a.ScopeID)
	}
	if decoded.CreatedAt != a.CreatedAt {
		t.Fatalf("created_at = %d, want %d", decoded.CreatedAt, a.CreatedAt)
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatalf("unmarshal into map: %v", err)
	}
	if _, ok := obj["payload"]; ok {
		t.Fatal("announcement must not contain a payload field")
	}
	if _, ok := obj["pow"]; ok {
		t.Fatal("announcement must not contain a pow field")
	}
}

func TestDecodeAnnouncement_SizeLimit(t *testing.T) {
	hugeData := []byte(strings.Repeat("x", gossip.MaxAnnouncementBytes+1))
	_, err := gossip.DecodeAnnouncement(hugeData)
	if err == nil {
		t.Fatal("expected error for oversized announcement")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeAnnouncement_MalformedJSON(t *testing.T) {
	_, err := gossip.DecodeAnnouncement([]byte("not-json"))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestDecodeAnnouncement_RejectsUnknownFields(t *testing.T) {
	tests := []struct {
		name  string
		extra string
	}{
		{"payload field", `"payload":"data"`},
		{"pow field", `"pow":"nonce"`},
		{"source_peer field", `"source_peer":"peer-1"`},
		{"peer_id field", `"peer_id":"peer-1"`},
		{"node_public_key field", `"node_public_key":"key"`},
		{"arbitrary unknown field", `"foo":"bar"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := `{"object_id":"id","object_type":"AnonymousBallot","scope":"election_id","scope_id":"el-1","created_at":9500,` + tt.extra + `}`
			_, err := gossip.DecodeAnnouncement([]byte(base))
			if err == nil {
				t.Fatal("expected error for unknown field")
			}
			if !strings.Contains(err.Error(), "decode announcement") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDecodeAnnouncement_RejectsTrailingJSON(t *testing.T) {
	base := `{"object_id":"id","object_type":"AnonymousBallot","scope":"election_id","scope_id":"el-1","created_at":9500}`

	tests := []struct {
		name    string
		trailer string
	}{
		{"trailing JSON object", `{"payload":"evil"}`},
		{"trailing JSON object with forbidden field", `{"object_id":"id","object_type":"AnonymousBallot","scope":"election_id","scope_id":"el-1","created_at":9500,"payload":"evil"}`},
		{"trailing garbage", `garbage`},
		{"trailing JSON array", `[1,2,3]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := base + " " + tt.trailer
			_, err := gossip.DecodeAnnouncement([]byte(input))
			if err == nil {
				t.Fatal("expected error for trailing data")
			}
			if !strings.Contains(err.Error(), "trailing") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDecodeAnnouncement_RejectsInvalidObjectType(t *testing.T) {
	tests := []struct {
		name       string
		objectType string
		scope      string
		scopeID    string
		wantErr    string
	}{
		{"unknown object type", "UnknownType", "election_id", "el-1", "unknown object type"},
		{"empty object type", "", "election_id", "el-1", "object_type is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(fmt.Sprintf(`{"object_id":"id","object_type":"%s","scope":"%s","scope_id":"%s","created_at":9500}`, tt.objectType, tt.scope, tt.scopeID))
			_, err := gossip.DecodeAnnouncement(data)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestDecodeAnnouncement_RejectsWrongScopeForObjectType(t *testing.T) {
	tests := []struct {
		name       string
		objectType string
		scope      string
		scopeID    string
		wantErr    string
	}{
		{
			name:       "AnonymousBallot with network scope",
			objectType: "AnonymousBallot",
			scope:      "network",
			scopeID:    "",
			wantErr:    "requires scope",
		},
		{
			name:       "AnonymousElection with election_id scope",
			objectType: "AnonymousElection",
			scope:      "election_id",
			scopeID:    "el-1",
			wantErr:    "requires scope",
		},
		{
			name:       "TrusteeVote with network scope",
			objectType: "TrusteeVote",
			scope:      "network",
			scopeID:    "",
			wantErr:    "requires scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(fmt.Sprintf(`{"object_id":"id","object_type":"%s","scope":"%s","scope_id":"%s","created_at":9500}`, tt.objectType, tt.scope, tt.scopeID))
			_, err := gossip.DecodeAnnouncement(data)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestEncodeAnnouncement_Validation(t *testing.T) {
	tests := []struct {
		name string
		a    gossip.ObjectAnnouncement
		want string
	}{
		{
			name: "missing object_id",
			a:    gossip.ObjectAnnouncement{ObjectType: "AnonymousBallot", Scope: "election_id", ScopeID: "el-1", CreatedAt: 1},
			want: "object_id is required",
		},
		{
			name: "missing object_type",
			a:    gossip.ObjectAnnouncement{ObjectID: "id", Scope: "election_id", ScopeID: "el-1", CreatedAt: 1},
			want: "object_type is required",
		},
		{
			name: "missing scope",
			a:    gossip.ObjectAnnouncement{ObjectID: "id", ObjectType: "AnonymousBallot", ScopeID: "el-1", CreatedAt: 1},
			want: "scope is required",
		},
		{
			name: "unknown scope",
			a:    gossip.ObjectAnnouncement{ObjectID: "id", ObjectType: "AnonymousBallot", Scope: "unknown", ScopeID: "el-1", CreatedAt: 1},
			want: "unknown scope",
		},
		{
			name: "unknown object type",
			a:    gossip.ObjectAnnouncement{ObjectID: "id", ObjectType: "UnknownType", Scope: "election_id", ScopeID: "el-1", CreatedAt: 1},
			want: "unknown object type",
		},
		{
			name: "wrong scope for object type",
			a:    gossip.ObjectAnnouncement{ObjectID: "id", ObjectType: "AnonymousBallot", Scope: "network", ScopeID: "", CreatedAt: 1},
			want: "requires scope",
		},
		{
			name: "zero created_at",
			a:    gossip.ObjectAnnouncement{ObjectID: "id", ObjectType: "AnonymousBallot", Scope: "election_id", ScopeID: "el-1", CreatedAt: 0},
			want: "created_at must be greater than zero",
		},
		{
			name: "network scope with non-empty scope_id",
			a:    gossip.ObjectAnnouncement{ObjectID: "id", ObjectType: "AnonymousElection", Scope: "network", ScopeID: "extra", CreatedAt: 1},
			want: "requires empty scope_id",
		},
		{
			name: "election_id scope with empty scope_id",
			a:    gossip.ObjectAnnouncement{ObjectID: "id", ObjectType: "AnonymousBallot", Scope: "election_id", ScopeID: "", CreatedAt: 1},
			want: "requires non-empty scope_id",
		},
		{
			name: "null byte in object_id",
			a:    gossip.ObjectAnnouncement{ObjectID: "id\x00bad", ObjectType: "AnonymousBallot", Scope: "election_id", ScopeID: "el-1", CreatedAt: 1},
			want: "null byte",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := gossip.EncodeAnnouncement(tt.a)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestEncodeAnnouncement_SizeLimit(t *testing.T) {
	a := gossip.ObjectAnnouncement{
		ObjectID:   strings.Repeat("x", gossip.MaxAnnouncementBytes-100),
		ObjectType: "AnonymousBallot",
		Scope:      "election_id",
		ScopeID:    "el-1",
		CreatedAt:  9500,
	}
	_, err := gossip.EncodeAnnouncement(a)
	if err == nil {
		t.Fatal("expected error for oversized encoded announcement")
	}
}

func TestGossipSubPubSub(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h1 := newTestHost(t, ctx)
	defer h1.Close()
	h2 := newTestHost(t, ctx)
	defer h2.Close()

	h2Addr := h2.Addrs()[0].String() + "/p2p/" + h2.ID().String()
	t.Logf("connecting h1 -> h2: %s", h2Addr)

	addrInfo, err := peer.AddrInfoFromString(h2Addr)
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	if err := h1.Connect(ctx, *addrInfo); err != nil {
		t.Fatalf("connect: %v", err)
	}

	var mu sync.Mutex
	var received []gossip.ObjectAnnouncement
	callback := func(a gossip.ObjectAnnouncement, sourcePeerID string) error {
		mu.Lock()
		defer mu.Unlock()
		received = append(received, a)
		t.Logf("received announcement: %s type=%s from=%s", a.ObjectID, a.ObjectType, sourcePeerID)
		return nil
	}

	svc1, err := gossip.NewService(ctx, h1, "testnet", nil)
	if err != nil {
		t.Fatalf("NewService h1: %v", err)
	}
	defer svc1.Close()

	svc2, err := gossip.NewService(ctx, h2, "testnet", callback)
	if err != nil {
		t.Fatalf("NewService h2: %v", err)
	}
	defer svc2.Close()

	time.Sleep(time.Second)

	published := gossip.ObjectAnnouncement{
		ObjectID:   "obj-test-1",
		ObjectType: "AnonymousBallot",
		Scope:      "election_id",
		ScopeID:    "el-1",
		CreatedAt:  9500,
	}

	if err := svc1.Publish(ctx, published); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	waitFor(t, 10*time.Second, func() bool {
		mu.Lock()
		got := len(received)
		mu.Unlock()
		return got > 0
	})

	mu.Lock()
	defer mu.Unlock()
	if len(received) > 0 {
		r := received[0]
		if r.ObjectID != published.ObjectID {
			t.Fatalf("received object_id = %q, want %q", r.ObjectID, published.ObjectID)
		}
	}
}

func TestDuplicateAnnouncementSuppression(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h1 := newTestHost(t, ctx)
	defer h1.Close()
	h2 := newTestHost(t, ctx)
	defer h2.Close()

	h2Addr := h2.Addrs()[0].String() + "/p2p/" + h2.ID().String()
	addrInfo, err := peer.AddrInfoFromString(h2Addr)
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	if err := h1.Connect(ctx, *addrInfo); err != nil {
		t.Fatalf("connect: %v", err)
	}

	var mu sync.Mutex
	var received []gossip.ObjectAnnouncement
	callback := func(a gossip.ObjectAnnouncement, sourcePeerID string) error {
		mu.Lock()
		defer mu.Unlock()
		received = append(received, a)
		return nil
	}

	svc1, err := gossip.NewService(ctx, h1, "testnet", nil)
	if err != nil {
		t.Fatalf("NewService h1: %v", err)
	}
	defer svc1.Close()

	svc2, err := gossip.NewService(ctx, h2, "testnet", callback)
	if err != nil {
		t.Fatalf("NewService h2: %v", err)
	}
	defer svc2.Close()

	time.Sleep(time.Second)

	a := gossip.ObjectAnnouncement{
		ObjectID:   "obj-dup-test",
		ObjectType: "AnonymousBallot",
		Scope:      "election_id",
		ScopeID:    "el-1",
		CreatedAt:  9500,
	}

	for i := 0; i < 3; i++ {
		if err := svc1.Publish(ctx, a); err != nil {
			t.Fatalf("Publish %d: %v", i, err)
		}
		time.Sleep(300 * time.Millisecond)
	}

	waitFor(t, 10*time.Second, func() bool {
		mu.Lock()
		count := len(received)
		mu.Unlock()
		return count >= 1
	})

	mu.Lock()
	count := len(received)
	mu.Unlock()
	if count != 1 {
		t.Fatalf("received %d announcements, want 1 (duplicates suppressed)", count)
	}
}

func TestDuplicateSuppressionDoesNotBlockAfterCallbackError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h1 := newTestHost(t, ctx)
	defer h1.Close()
	h2 := newTestHost(t, ctx)
	defer h2.Close()

	h2Addr := h2.Addrs()[0].String() + "/p2p/" + h2.ID().String()
	addrInfo, err := peer.AddrInfoFromString(h2Addr)
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	if err := h1.Connect(ctx, *addrInfo); err != nil {
		t.Fatalf("connect: %v", err)
	}

	var mu sync.Mutex
	callCount := 0
	errorCount := 0

	callback := func(a gossip.ObjectAnnouncement, sourcePeerID string) error {
		mu.Lock()
		callCount++
		c := callCount
		mu.Unlock()
		if c == 1 {
			mu.Lock()
			errorCount++
			mu.Unlock()
			return errors.New("simulated callback failure")
		}
		return nil
	}

	svc1, err := gossip.NewService(ctx, h1, "testnet", nil)
	if err != nil {
		t.Fatalf("NewService h1: %v", err)
	}
	defer svc1.Close()

	svc2, err := gossip.NewService(ctx, h2, "testnet", callback)
	if err != nil {
		t.Fatalf("NewService h2: %v", err)
	}
	defer svc2.Close()

	time.Sleep(time.Second)

	a := gossip.ObjectAnnouncement{
		ObjectID:   "obj-err-retry",
		ObjectType: "AnonymousBallot",
		Scope:      "election_id",
		ScopeID:    "el-1",
		CreatedAt:  9500,
	}

	for i := 0; i < 3; i++ {
		if err := svc1.Publish(ctx, a); err != nil {
			t.Fatalf("Publish %d: %v", i, err)
		}
		time.Sleep(300 * time.Millisecond)
	}

	waitFor(t, 10*time.Second, func() bool {
		mu.Lock()
		c := callCount
		mu.Unlock()
		return c >= 2
	})

	mu.Lock()
	c := callCount
	e := errorCount
	mu.Unlock()
	if c < 2 {
		t.Fatalf("callback called %d times, want >= 2 (error did not block retry)", c)
	}
	if e < 1 {
		t.Fatalf("expected at least 1 error callback invocation, got %d", e)
	}
}

func TestForgetSeenAllowsRefetchAfterSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h1 := newTestHost(t, ctx)
	defer h1.Close()
	h2 := newTestHost(t, ctx)
	defer h2.Close()

	h2Addr := h2.Addrs()[0].String() + "/p2p/" + h2.ID().String()
	addrInfo, err := peer.AddrInfoFromString(h2Addr)
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	if err := h1.Connect(ctx, *addrInfo); err != nil {
		t.Fatalf("connect: %v", err)
	}

	var mu sync.Mutex
	callCount := 0

	svc1, err := gossip.NewService(ctx, h1, "testnet", nil)
	if err != nil {
		t.Fatalf("NewService h1: %v", err)
	}
	defer svc1.Close()

	var svc2 *gossip.Service
	callback := func(a gossip.ObjectAnnouncement, sourcePeerID string) error {
		mu.Lock()
		callCount++
		mu.Unlock()
		return nil
	}

	svc2, err = gossip.NewService(ctx, h2, "testnet", callback)
	if err != nil {
		t.Fatalf("NewService h2: %v", err)
	}
	defer svc2.Close()

	time.Sleep(time.Second)

	a := gossip.ObjectAnnouncement{
		ObjectID:   "obj-forget-test",
		ObjectType: "AnonymousBallot",
		Scope:      "election_id",
		ScopeID:    "el-1",
		CreatedAt:  9500,
	}

	if err := svc1.Publish(ctx, a); err != nil {
		t.Fatalf("Publish 1: %v", err)
	}
	waitFor(t, 10*time.Second, func() bool {
		mu.Lock()
		c := callCount
		mu.Unlock()
		return c >= 1
	})

	svc2.ForgetSeen("obj-forget-test")

	if err := svc1.Publish(ctx, a); err != nil {
		t.Fatalf("Publish 2: %v", err)
	}
	waitFor(t, 10*time.Second, func() bool {
		mu.Lock()
		c := callCount
		mu.Unlock()
		return c >= 2
	})

	mu.Lock()
	c := callCount
	mu.Unlock()
	if c < 2 {
		t.Fatalf("callback called %d times, want >= 2 (ForgetSeen should allow re-delivery)", c)
	}
}

func TestAnnouncementCallbackTriggersFetch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h1 := newTestHost(t, ctx)
	defer h1.Close()
	h2 := newTestHost(t, ctx)
	defer h2.Close()

	h2Addr := h2.Addrs()[0].String() + "/p2p/" + h2.ID().String()
	addrInfo, err := peer.AddrInfoFromString(h2Addr)
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	if err := h1.Connect(ctx, *addrInfo); err != nil {
		t.Fatalf("connect: %v", err)
	}

	fetchedObjects := make(map[string]bool)
	var mu sync.Mutex

	callback := func(a gossip.ObjectAnnouncement, sourcePeerID string) error {
		mu.Lock()
		defer mu.Unlock()
		fetchedObjects[a.ObjectID] = true
		t.Logf("callback would fetch object %s from peer %s", a.ObjectID, sourcePeerID)
		return nil
	}

	svc1, err := gossip.NewService(ctx, h1, "testnet", nil)
	if err != nil {
		t.Fatalf("NewService h1: %v", err)
	}
	defer svc1.Close()

	svc2, err := gossip.NewService(ctx, h2, "testnet", callback)
	if err != nil {
		t.Fatalf("NewService h2: %v", err)
	}
	defer svc2.Close()

	time.Sleep(time.Second)

	a := gossip.ObjectAnnouncement{
		ObjectID:   "obj-fetch-test",
		ObjectType: "AnonymousBallot",
		Scope:      "election_id",
		ScopeID:    "el-1",
		CreatedAt:  9500,
	}

	if err := svc1.Publish(ctx, a); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	waitFor(t, 10*time.Second, func() bool {
		mu.Lock()
		f := fetchedObjects["obj-fetch-test"]
		mu.Unlock()
		return f
	})

	mu.Lock()
	fetched := fetchedObjects["obj-fetch-test"]
	mu.Unlock()
	if !fetched {
		t.Fatal("callback should have been invoked to trigger fetch")
	}
}

func TestGossipAnnouncementIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	svcA, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node A: %v", err)
	}
	defer svcA.Close()

	svcB, err := app.Open(t.TempDir(), "testnet")
	if err != nil {
		t.Fatalf("Open node B: %v", err)
	}
	defer svcB.Close()

	creator := newTestKey(t)
	voter := newTestKey(t)

	electionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: "ts-integration",
		NetworkID:          "testnet",
		Title:              "Integration Test Election",
		Description:        "For gossip integration test",
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

	h1 := newTestHost(t, ctx)
	defer h1.Close()
	h2 := newTestHost(t, ctx)
	defer h2.Close()

	h2Addr := h2.Addrs()[0].String() + "/p2p/" + h2.ID().String()
	addrInfo, err := peer.AddrInfoFromString(h2Addr)
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	if err := h1.Connect(ctx, *addrInfo); err != nil {
		t.Fatalf("connect: %v", err)
	}

	transport := librevotesync.NewStaticPeerTransport(map[string]librevotesync.StoreQuerier{
		h1.ID().String(): svcA,
		h2.ID().String(): svcB,
	})

	var ingestedID string
	var mu sync.Mutex
	ingested := make(chan struct{}, 1)

	callback := func(a gossip.ObjectAnnouncement, sourcePeerID string) error {
		env, err := transport.GetObject(ctx, sourcePeerID, a.ObjectID)
		if err != nil {
			return fmt.Errorf("fetch: %w", err)
		}
		if err := svcB.IngestSyncEnvelope(ctx, env); err != nil {
			return fmt.Errorf("ingest: %w", err)
		}
		mu.Lock()
		ingestedID = a.ObjectID
		mu.Unlock()
		select {
		case ingested <- struct{}{}:
		default:
		}
		return nil
	}

	svc1, err := gossip.NewService(ctx, h1, "testnet", nil)
	if err != nil {
		t.Fatalf("NewService h1: %v", err)
	}
	defer svc1.Close()

	svc2, err := gossip.NewService(ctx, h2, "testnet", callback)
	if err != nil {
		t.Fatalf("NewService h2: %v", err)
	}
	defer svc2.Close()

	time.Sleep(time.Second)

	a := gossip.ObjectAnnouncement{
		ObjectID:   electionEnv.ObjectID,
		ObjectType: string(electionEnv.ObjectType),
		Scope:      string(electionEnv.Scope),
		ScopeID:    electionEnv.ScopeID,
		CreatedAt:  electionEnv.CreatedAt,
	}

	if err := svc1.Publish(ctx, a); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case <-ingested:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for fetch+ingest via callback")
	}

	mu.Lock()
	id := ingestedID
	mu.Unlock()
	if id != electionEnv.ObjectID {
		t.Fatalf("ingested object_id = %q, want %q", id, electionEnv.ObjectID)
	}

	status, found, err := svcB.ValidationStatus(ctx, id)
	if err != nil {
		t.Fatalf("ValidationStatus: %v", err)
	}
	if !found {
		t.Fatal("object should be stored in svcB after callback fetch+ingest")
	}
	if status != validation.StatusValid {
		t.Fatalf("object status = %s, want valid", status)
	}
}

func TestAnnouncementContainsNoPayload(t *testing.T) {
	a := gossip.ObjectAnnouncement{
		ObjectID:   "obj-1",
		ObjectType: "AnonymousBallot",
		Scope:      "election_id",
		ScopeID:    "el-1",
		CreatedAt:  9500,
	}
	data, err := gossip.EncodeAnnouncement(a)
	if err != nil {
		t.Fatalf("EncodeAnnouncement: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	forbidden := []string{"payload", "pow", "voter_public_key", "peer_id", "node_public_key"}
	for _, key := range forbidden {
		if _, ok := raw[key]; ok {
			t.Fatalf("announcement must not contain field %q", key)
		}
	}
}
