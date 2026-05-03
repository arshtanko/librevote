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

	"librevote/internal/app"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type fakeController struct {
	peerID       string
	listen       []string
	bootstrap    []string
	connected    int
	connectedIDs []string
	connectErr   map[string]error
	connectCalls []string
	refreshCalls int
}

func (f *fakeController) PeerID() string             { return f.peerID }
func (f *fakeController) ListenMultiaddrs() []string { return f.listen }
func (f *fakeController) ConnectedPeerCount() int    { return f.connected }
func (f *fakeController) ConnectedPeerIDs() []string { return append([]string(nil), f.connectedIDs...) }
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

func TestElectionStatusBeforeStart(t *testing.T) {
	svc, err := app.Open(t.TempDir(), "frontend-test")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()
	ts := httptest.NewServer(NewServer(&fakeController{peerID: "peer-local"}, svc).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/election/status")
	if err != nil {
		t.Fatalf("GET election status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body app.ElectionStatus
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode election status: %v", err)
	}
	if body.Available || body.TallyKeySetAvailable || body.Message == "" {
		t.Fatalf("unexpected status before start: %+v", body)
	}
	if body.LocalVoterID != "" {
		t.Fatalf("local voter id = %q, want empty before election", body.LocalVoterID)
	}
}

func TestElectionStartAndStatus(t *testing.T) {
	svc, err := app.Open(t.TempDir(), "frontend-test")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()
	fc := &fakeController{peerID: "peer-local", connectedIDs: []string{"peer-2", "peer-1", "peer-2"}}
	ts := httptest.NewServer(NewServer(fc, svc).Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/election/start", "application/json", nil)
	if err != nil {
		t.Fatalf("POST election start: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var started app.ElectionStatus
	if err := json.NewDecoder(resp.Body).Decode(&started); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	if !started.Available || !started.TallyKeySetAvailable || started.ElectionID == "" || len(started.Options) == 0 {
		t.Fatalf("unexpected started status: %+v", started)
	}
	wantVoters := []string{"peer-1", "peer-2", "peer-local"}
	if strings.Join(started.EligibleVoterIDs, ",") != strings.Join(wantVoters, ",") {
		t.Fatalf("eligible voters = %v, want %v", started.EligibleVoterIDs, wantVoters)
	}
	if started.LocalVoterID != "peer-local" || !started.LocalVoterSignable || started.LocalVoterVoted {
		t.Fatalf("started status missing local voter fields: %+v", started)
	}

	resp2, err := http.Get(ts.URL + "/api/election/status")
	if err != nil {
		t.Fatalf("GET election status: %v", err)
	}
	defer resp2.Body.Close()
	var status app.ElectionStatus
	if err := json.NewDecoder(resp2.Body).Decode(&status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.ElectionID != started.ElectionID || !status.TallyKeySetAvailable {
		t.Fatalf("status after start = %+v, started %+v", status, started)
	}
}

func TestVoteCastUnavailableBeforeStart(t *testing.T) {
	svc, err := app.Open(t.TempDir(), "frontend-test")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()
	ts := httptest.NewServer(NewServer(&fakeController{peerID: "peer-local"}, svc).Handler())
	defer ts.Close()

	resp := postVoteCast(t, ts.URL, `{"choice":"yes"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	var body errorResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !strings.Contains(body.Error, "election is not available locally") {
		t.Fatalf("error = %q", body.Error)
	}
}

func TestVoteCastWithoutLocalPeerIDFails(t *testing.T) {
	svc, err := app.Open(t.TempDir(), "frontend-test")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()
	if _, err := svc.StartMVPElectionForVoters(context.Background(), []string{"peer-other"}); err != nil {
		t.Fatalf("StartMVPElectionForVoters() error = %v", err)
	}
	ts := httptest.NewServer(NewServer(&fakeController{}, svc).Handler())
	defer ts.Close()

	resp := postVoteCast(t, ts.URL, `{"choice":"yes"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var body errorResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if body.Error != "local peer ID is not available" {
		t.Fatalf("error = %q", body.Error)
	}
}

func TestVoteCastSuccessfulAfterStart(t *testing.T) {
	svc, err := app.Open(t.TempDir(), "frontend-test")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()
	ts := httptest.NewServer(NewServer(&fakeController{peerID: "peer-local"}, svc).Handler())
	defer ts.Close()
	postElectionStart(t, ts.URL)

	resp := postVoteCast(t, ts.URL, `{"choice":"yes"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body app.FrontendVoteResult
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode vote: %v", err)
	}
	if body.ObjectID == "" || body.Status != "valid_for_tally" || body.Idempotent {
		t.Fatalf("unexpected vote response: %+v", body)
	}

	statusResp, err := http.Get(ts.URL + "/api/election/status")
	if err != nil {
		t.Fatalf("GET election status: %v", err)
	}
	defer statusResp.Body.Close()
	var status app.ElectionStatus
	if err := json.NewDecoder(statusResp.Body).Decode(&status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.BallotsSeen != 1 || status.ValidBallotCount != 1 || !status.LocalVoterVoted {
		t.Fatalf("status counts = seen %d valid %d, want 1/1", status.BallotsSeen, status.ValidBallotCount)
	}
}

func TestVoteCastMismatchedVoterAndInvalidChoice(t *testing.T) {
	svc, err := app.Open(t.TempDir(), "frontend-test")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()
	ts := httptest.NewServer(NewServer(&fakeController{peerID: "peer-local"}, svc).Handler())
	defer ts.Close()
	postElectionStart(t, ts.URL)

	for _, tt := range []struct {
		name string
		body string
		want string
	}{
		{name: "mismatched voter", body: `{"voter_id":"peer-2","choice":"yes"}`, want: "voter_id does not match local voter binding"},
		{name: "invalid choice", body: `{"choice":"maybe"}`, want: "choice is not valid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp := postVoteCast(t, ts.URL, tt.body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			var body errorResponse
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if !strings.Contains(body.Error, tt.want) {
				t.Fatalf("error = %q, want containing %q", body.Error, tt.want)
			}
		})
	}
}

func TestVoteCastDuplicateIsIdempotent(t *testing.T) {
	svc, err := app.Open(t.TempDir(), "frontend-test")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()
	ts := httptest.NewServer(NewServer(&fakeController{peerID: "peer-local"}, svc).Handler())
	defer ts.Close()
	postElectionStart(t, ts.URL)

	firstResp := postVoteCast(t, ts.URL, `{"choice":"yes"}`)
	defer firstResp.Body.Close()
	var first app.FrontendVoteResult
	if err := json.NewDecoder(firstResp.Body).Decode(&first); err != nil {
		t.Fatalf("decode first vote: %v", err)
	}
	secondResp := postVoteCast(t, ts.URL, `{"choice":"no"}`)
	defer secondResp.Body.Close()
	if secondResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", secondResp.StatusCode)
	}
	var second app.FrontendVoteResult
	if err := json.NewDecoder(secondResp.Body).Decode(&second); err != nil {
		t.Fatalf("decode second vote: %v", err)
	}
	if !second.Idempotent || second.ObjectID != first.ObjectID || second.Choice != "yes" {
		t.Fatalf("duplicate response = %+v, first %+v", second, first)
	}

	statusResp, err := http.Get(ts.URL + "/api/election/status")
	if err != nil {
		t.Fatalf("GET election status: %v", err)
	}
	defer statusResp.Body.Close()
	var status app.ElectionStatus
	if err := json.NewDecoder(statusResp.Body).Decode(&status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.BallotsSeen != 1 || status.ValidBallotCount != 1 {
		t.Fatalf("status counts after duplicate = seen %d valid %d, want 1/1", status.BallotsSeen, status.ValidBallotCount)
	}
}

func TestElectionStartIsIdempotent(t *testing.T) {
	svc, err := app.Open(t.TempDir(), "frontend-test")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()
	ts := httptest.NewServer(NewServer(&fakeController{peerID: "peer-local"}, svc).Handler())
	defer ts.Close()

	first := postElectionStart(t, ts.URL)
	second := postElectionStart(t, ts.URL)
	if first.ElectionID != second.ElectionID || first.Title != second.Title || first.BallotsSeen != second.BallotsSeen {
		t.Fatalf("start not idempotent: first=%+v second=%+v", first, second)
	}
}

func TestVoteCastFailsWhenLocalPeerNotInElectionAllowlist(t *testing.T) {
	svc, err := app.Open(t.TempDir(), "frontend-test")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer svc.Close()
	if _, err := svc.StartMVPElectionForVoters(context.Background(), []string{"peer-other"}); err != nil {
		t.Fatalf("StartMVPElectionForVoters() error = %v", err)
	}
	ts := httptest.NewServer(NewServer(&fakeController{peerID: "peer-local"}, svc).Handler())
	defer ts.Close()

	resp := postVoteCast(t, ts.URL, `{"choice":"yes"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var body errorResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !strings.Contains(body.Error, "voter is not eligible") {
		t.Fatalf("error = %q", body.Error)
	}
}

func postElectionStart(t *testing.T, baseURL string) app.ElectionStatus {
	t.Helper()
	resp, err := http.Post(baseURL+"/api/election/start", "application/json", nil)
	if err != nil {
		t.Fatalf("POST election start: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body app.ElectionStatus
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	return body
}

func postVoteCast(t *testing.T, baseURL string, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(baseURL+"/api/vote/cast", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST vote cast: %v", err)
	}
	return resp
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
