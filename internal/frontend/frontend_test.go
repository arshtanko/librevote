package frontend

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type fakeController struct {
	peerID       string
	listen       []string
	bootstrap    []string
	connected    int
	connectErr   map[string]error
	connectCalls []string
	refreshCalls int
}

func (f *fakeController) PeerID() string             { return f.peerID }
func (f *fakeController) ListenMultiaddrs() []string { return f.listen }
func (f *fakeController) ConnectedPeerCount() int    { return f.connected }
func (f *fakeController) BootstrapPeers() []string   { return f.bootstrap }
func (f *fakeController) ConnectPeer(ctx context.Context, multiaddr string) error {
	f.connectCalls = append(f.connectCalls, multiaddr)
	if err := f.connectErr[multiaddr]; err != nil {
		return err
	}
	f.connected++
	return nil
}
func (f *fakeController) RefreshPeers(ctx context.Context) ([]string, error) {
	f.refreshCalls++
	return []string{"refresh warning"}, nil
}

func TestStatus(t *testing.T) {
	fc := &fakeController{
		peerID:    "peer-1",
		listen:    []string{"/ip4/127.0.0.1/tcp/1/p2p/peer-1"},
		bootstrap: []string{"/ip4/127.0.0.1/tcp/2/p2p/peer-2"},
		connected: 3,
	}
	ts := httptest.NewServer(NewServer(fc).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/network/status")
	if err != nil {
		t.Fatalf("GET status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if body.NodeName != "LibreVote Node" || body.PeerID != "peer-1" || body.ConnectedPeerCount != 3 {
		t.Fatalf("unexpected status: %+v", body)
	}
	if body.BootstrapPeerCount != 1 || body.ConnectedPeerLabel == "" {
		t.Fatalf("missing honest peer fields: %+v", body)
	}
}

func TestIndexContainsNodeTitle(t *testing.T) {
	ts := httptest.NewServer(NewServer(&fakeController{}).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET index: %v", err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if !strings.Contains(buf.String(), "LibreVote Node") {
		t.Fatalf("index missing LibreVote Node")
	}
	if strings.Contains(strings.ToLower(buf.String()), "demo") {
		t.Fatalf("index contains demo string")
	}
}

func TestConnectAcceptsTextareaInputAndRefreshesOnce(t *testing.T) {
	addr1 := testMultiaddr(t, 1001)
	addr2 := testMultiaddr(t, 1002)
	fc := &fakeController{}
	ts := httptest.NewServer(NewServer(fc).Handler())
	defer ts.Close()

	body := strings.NewReader(`{"bootstrap":"` + addr1 + `,\n ` + addr2 + `"}`)
	resp, err := http.Post(ts.URL+"/api/network/connect", "application/json", body)
	if err != nil {
		t.Fatalf("POST connect: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if len(fc.connectCalls) != 2 {
		t.Fatalf("connect calls = %d, want 2", len(fc.connectCalls))
	}
	if fc.refreshCalls != 1 {
		t.Fatalf("refresh calls = %d, want 1", fc.refreshCalls)
	}
}

func TestConnectAcceptsBootstrapMultiaddrsArray(t *testing.T) {
	addr := testMultiaddr(t, 2001)
	fc := &fakeController{}
	ts := httptest.NewServer(NewServer(fc).Handler())
	defer ts.Close()

	body := strings.NewReader(`{"bootstrap_multiaddrs":["` + addr + `"]}`)
	resp, err := http.Post(ts.URL+"/api/network/connect", "application/json", body)
	if err != nil {
		t.Fatalf("POST connect: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if len(fc.connectCalls) != 1 || fc.connectCalls[0] != addr {
		t.Fatalf("connect calls = %+v, want %q", fc.connectCalls, addr)
	}
}

func TestConnectAllValidEntriesFailedReturnsTopLevelError(t *testing.T) {
	addr1 := testMultiaddr(t, 3001)
	addr2 := testMultiaddr(t, 3002)
	fc := &fakeController{connectErr: map[string]error{
		addr1: errors.New("dial refused"),
		addr2: errors.New("context deadline exceeded"),
	}}
	ts := httptest.NewServer(NewServer(fc).Handler())
	defer ts.Close()

	body := strings.NewReader(`{"bootstrap_multiaddrs":["` + addr1 + `","` + addr2 + `"]}`)
	resp, err := http.Post(ts.URL+"/api/network/connect", "application/json", body)
	if err != nil {
		t.Fatalf("POST connect: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}

	var got connectResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Error != "failed to connect to any bootstrap multiaddr" {
		t.Fatalf("error = %q", got.Error)
	}
	if len(got.Connected) != 0 || len(got.Failed) != 2 {
		t.Fatalf("unexpected attempts: connected=%v failed=%v", got.Connected, got.Failed)
	}
	for _, want := range []string{addr1 + ": dial refused", addr2 + ": context deadline exceeded"} {
		found := false
		for _, failed := range got.Failed {
			if failed == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("failed attempts %v missing %q", got.Failed, want)
		}
	}
	if fc.refreshCalls != 0 {
		t.Fatalf("refresh calls = %d, want 0", fc.refreshCalls)
	}
}

func TestConnectRejectsMissingOrInvalidEntries(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
		want string
	}{
		{name: "missing", body: `{}`, want: "at least one bootstrap multiaddr is required"},
		{name: "invalid", body: `{"bootstrap":"not-a-multiaddr"}`, want: "no valid bootstrap multiaddrs"},
		{name: "missing p2p", body: `{"bootstrap":"/ip4/127.0.0.1/tcp/1"}`, want: "no valid bootstrap multiaddrs"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fc := &fakeController{}
			ts := httptest.NewServer(NewServer(fc).Handler())
			defer ts.Close()

			resp, err := http.Post(ts.URL+"/api/network/connect", "application/json", strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("POST connect: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			var body errorResponse
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if body.Error != tt.want {
				t.Fatalf("error = %q, want %q", body.Error, tt.want)
			}
			if len(fc.connectCalls) != 0 || fc.refreshCalls != 0 {
				t.Fatalf("unexpected calls: connect=%d refresh=%d", len(fc.connectCalls), fc.refreshCalls)
			}
		})
	}
}

func testMultiaddr(t *testing.T, port int) string {
	t.Helper()
	priv, _, err := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("peer id: %v", err)
	}
	return "/ip4/127.0.0.1/tcp/" + strconv.Itoa(port) + "/p2p/" + id.String()
}
