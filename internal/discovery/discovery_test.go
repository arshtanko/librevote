package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ma "github.com/multiformats/go-multiaddr"
)

func TestLoadOrCreateIdentity_SameKeyPathReturnsSamePeerID(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "node.key")

	id1, err := LoadOrCreateIdentity(keyPath)
	if err != nil {
		t.Fatalf("first LoadOrCreateIdentity: %v", err)
	}

	id2, err := LoadOrCreateIdentity(keyPath)
	if err != nil {
		t.Fatalf("second LoadOrCreateIdentity: %v", err)
	}

	if id1.PeerID != id2.PeerID {
		t.Fatalf("peer IDs differ across runs: %s != %s", id1.PeerID, id2.PeerID)
	}
}

func TestLoadOrCreateIdentity_EmptyKeyPathGeneratesNewEachTime(t *testing.T) {
	id1, err := LoadOrCreateIdentity("")
	if err != nil {
		t.Fatalf("first generate: %v", err)
	}
	id2, err := LoadOrCreateIdentity("")
	if err != nil {
		t.Fatalf("second generate: %v", err)
	}
	if id1.PeerID == id2.PeerID {
		t.Fatal("ephemeral identities should differ")
	}
}

func TestLoadOrCreateIdentity_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	nestedPath := filepath.Join(dir, "subdir", "nested", "node.key")

	id, err := LoadOrCreateIdentity(nestedPath)
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity with nested path: %v", err)
	}
	if id.PeerID == "" {
		t.Fatal("peer_id is empty")
	}
	if _, err := os.Stat(nestedPath); os.IsNotExist(err) {
		t.Fatal("key file was not created")
	}

	id2, err := LoadOrCreateIdentity(nestedPath)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if id.PeerID != id2.PeerID {
		t.Fatal("peer IDs differ on second load")
	}
}

func TestLoadOrCreateIdentity_RejectsCorruptedFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "node.key")

	if err := os.WriteFile(keyPath, []byte("not-json"), 0600); err != nil {
		t.Fatalf("write corrupted file: %v", err)
	}

	_, err := LoadOrCreateIdentity(keyPath)
	if err == nil {
		t.Fatal("expected error loading corrupted file")
	}
	if !strings.Contains(err.Error(), "parse identity file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadOrCreateIdentity_IdentityIsLibp2pCompatible(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "node.key")

	id, err := LoadOrCreateIdentity(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}

	if id.PeerID == "" {
		t.Fatal("peer ID is empty")
	}
	if id.PrivKey == nil {
		t.Fatal("private key is nil")
	}

	pidStr := id.PeerID.String()
	if pidStr == "" {
		t.Fatal("peer ID string is empty")
	}
}

func TestConfigDefaults(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	config := Config{
		NetworkID: "testnet",
		KeyPath:   filepath.Join(t.TempDir(), "node.key"),
	}

	disc, err := New(ctx, config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer disc.Close()

	if disc.Namespace() != "/librevote/testnet/v1" {
		t.Fatalf("namespace = %q, want /librevote/testnet/v1", disc.Namespace())
	}

	if disc.Config().RendezvousPrefix != "/librevote" {
		t.Fatalf("default rendezvous prefix not set")
	}

	if disc.Config().Mode != "auto" {
		t.Fatalf("default mode = %q, want auto", disc.Config().Mode)
	}
}

func TestConfigCustomRendezvous(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	config := Config{
		NetworkID:        "mainnet",
		RendezvousPrefix: "/custom",
		KeyPath:          filepath.Join(t.TempDir(), "node.key"),
	}

	disc, err := New(ctx, config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer disc.Close()

	if disc.Namespace() != "/custom/mainnet/v1" {
		t.Fatalf("namespace = %q, want /custom/mainnet/v1", disc.Namespace())
	}
}

func TestNew_RequiresNetworkID(t *testing.T) {
	ctx := context.Background()
	_, err := New(ctx, Config{})
	if err == nil {
		t.Fatal("expected error for empty network_id")
	}
	if !strings.Contains(err.Error(), "network_id is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_InvalidListenAddr(t *testing.T) {
	ctx := context.Background()
	config := Config{
		NetworkID:   "testnet",
		ListenAddrs: []string{"not-a-valid-multiaddr"},
		KeyPath:     filepath.Join(t.TempDir(), "node.key"),
	}
	_, err := New(ctx, config)
	if err == nil {
		t.Fatal("expected error for invalid listen address")
	}
}

func TestDiscoveryModeOptions(t *testing.T) {
	for _, mode := range []string{"server", "client", "auto"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			config := Config{
				NetworkID: "testnet",
				Mode:      mode,
				KeyPath:   filepath.Join(t.TempDir(), "node.key"),
			}
			disc, err := New(ctx, config)
			if err != nil {
				t.Fatalf("New with mode=%q: %v", mode, err)
			}
			disc.Close()
		})
	}
}

func TestDiscoveryRejectsInvalidMode(t *testing.T) {
	invalidModes := []string{"invalid", "automatic", "peer", "full"}
	for _, mode := range invalidModes {
		t.Run("mode="+mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			config := Config{
				NetworkID: "testnet",
				Mode:      mode,
				KeyPath:   filepath.Join(t.TempDir(), "node.key"),
			}
			_, err := New(ctx, config)
			if err == nil {
				t.Fatalf("expected error for invalid mode %q", mode)
			}
			if !strings.Contains(err.Error(), "invalid mode") {
				t.Fatalf("unexpected error for mode %q: %v", mode, err)
			}
		})
	}
}

func TestDiscovery_NoBootstrapPeers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	config := Config{
		NetworkID: "testnet",
		KeyPath:   filepath.Join(t.TempDir(), "node.key"),
	}

	disc, err := New(ctx, config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer disc.Close()

	discoverCtx, discoverCancel := context.WithTimeout(ctx, 10*time.Second)
	defer discoverCancel()

	peers, err := disc.DiscoverPeers(discoverCtx)
	if err != nil && err != ErrHTTPURLNotAnnounced {
		t.Fatalf("DiscoverPeers: %v", err)
	}
	if len(peers) != 0 {
		t.Fatalf("expected 0 peers with no bootstraps, got %d", len(peers))
	}
}

func TestTwoNodeKademliaDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()

	// Node A - bootstrap server mode
	configA := Config{
		NetworkID:   "testnet",
		Mode:        "server",
		KeyPath:     filepath.Join(dir, "node-a.key"),
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
	}
	discA, err := New(ctx, configA)
	if err != nil {
		t.Fatalf("New node A: %v", err)
	}
	defer discA.Close()

	peerID_A := discA.Identity().PeerID.String()
	t.Logf("node A peer ID: %s", peerID_A)

	// Node A announces itself so it can be found
	if _, err := discA.DiscoverPeers(ctx); err != nil {
		t.Logf("node A discover (expected empty): %v", err)
	}

	// Get node A's listen addresses for bootstrap
	var bootstrapAddr string
	for _, a := range discA.host.Addrs() {
		maStr := a.Encapsulate(multiaddrFromString(t, "/p2p/"+peerID_A)).String()
		bootstrapAddr = maStr
		break
	}
	if bootstrapAddr == "" {
		t.Fatal("node A has no listen addresses")
	}
	t.Logf("bootstrap addr: %s", bootstrapAddr)

	// Node B - client mode, bootstraps from A
	configB := Config{
		NetworkID:      "testnet",
		Mode:           "client",
		KeyPath:        filepath.Join(dir, "node-b.key"),
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
		BootstrapPeers: []string{bootstrapAddr},
	}
	discB, err := New(ctx, configB)
	if err != nil {
		t.Fatalf("New node B: %v", err)
	}
	defer discB.Close()

	t.Logf("node B peer ID: %s", discB.Identity().PeerID.String())

	discoverCtx, discoverCancel := context.WithTimeout(ctx, 30*time.Second)
	defer discoverCancel()

	var peers []PeerInfo
	var discoverErr error
	for i := 0; i < 5; i++ {
		if i > 0 {
			select {
			case <-time.After(500 * time.Millisecond):
			case <-discoverCtx.Done():
				t.Fatalf("timeout before discovery succeeded: %v", discoverCtx.Err())
			}
		}
		peers, discoverErr = discB.DiscoverPeers(discoverCtx)
		if discoverErr != nil {
			t.Logf("DiscoverPeers attempt %d: %v", i+1, discoverErr)
			continue
		}
		if len(peers) > 0 {
			break
		}
	}

	foundA := false
	for _, p := range peers {
		t.Logf("discovered: peer_id=%s addrs=%v http_url=%q", p.PeerID, p.Addrs, p.HTTPURL)
		if p.PeerID == peerID_A {
			foundA = true
		}
	}
	if !foundA {
		t.Fatalf("node A not discovered by node B. peers=%d err=%v", len(peers), discoverErr)
	}
}

func TestDiscoveryWithHTTPAdvertise(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()

	configA := Config{
		NetworkID:      "testnet",
		Mode:           "server",
		KeyPath:        filepath.Join(dir, "node-a.key"),
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
		AdvertisedHTTP: "http://localhost:9090",
	}
	discA, err := New(ctx, configA)
	if err != nil {
		t.Fatalf("New node A: %v", err)
	}
	defer discA.Close()

	peerID_A := discA.Identity().PeerID.String()

	var bootstrapAddr string
	for _, a := range discA.host.Addrs() {
		maStr := a.Encapsulate(multiaddrFromString(t, "/p2p/"+peerID_A)).String()
		bootstrapAddr = maStr
		break
	}
	if bootstrapAddr == "" {
		t.Fatal("node A has no listen addresses")
	}

	configB := Config{
		NetworkID:      "testnet",
		Mode:           "client",
		KeyPath:        filepath.Join(dir, "node-b.key"),
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
		BootstrapPeers: []string{bootstrapAddr},
	}
	discB, err := New(ctx, configB)
	if err != nil {
		t.Fatalf("New node B: %v", err)
	}
	defer discB.Close()

	discoverCtx1, cancel1 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel1()

	peers, err := discB.DiscoverPeers(discoverCtx1)
	if err != nil {
		t.Logf("B discover (may have announce err): %v", err)
	}
	for _, p := range peers {
		t.Logf("B discovered: peer_id=%s addrs=%v http_url=%q", p.PeerID, p.Addrs, p.HTTPURL)
	}

	discoverCtx2, cancel2 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel2()

	peers2, err := discA.DiscoverPeers(discoverCtx2)
	if err != nil {
		t.Logf("A re-discover: %v", err)
	}
	for _, p := range peers2 {
		t.Logf("A discovered: peer_id=%s addrs=%v http_url=%q", p.PeerID, p.Addrs, p.HTTPURL)
	}

	discoverCtx3, cancel3 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel3()

	var httpFound bool
	for i := 0; i < 5; i++ {
		if i > 0 {
			select {
			case <-time.After(500 * time.Millisecond):
			case <-discoverCtx3.Done():
				break
			}
		}
		peers3, discoverErr := discB.DiscoverPeers(discoverCtx3)
		if discoverErr != nil {
			t.Logf("B re-discover attempt %d: %v", i+1, discoverErr)
			continue
		}
		for _, p := range peers3 {
			t.Logf("B re-discovered: peer_id=%s addrs=%v http_url=%q", p.PeerID, p.Addrs, p.HTTPURL)
			if p.HTTPURL == "http://localhost:9090" {
				httpFound = true
			}
		}
		if httpFound {
			break
		}
	}

	if !httpFound {
		t.Fatalf("HTTP URL http://localhost:9090 not discovered for node A")
	}
}

func TestDiscoveryExcludesSelf(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	config := Config{
		NetworkID: "testnet",
		KeyPath:   filepath.Join(t.TempDir(), "node.key"),
	}
	disc, err := New(ctx, config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer disc.Close()

	discoverCtx, discoverCancel := context.WithTimeout(ctx, 10*time.Second)
	defer discoverCancel()

	peers, err := disc.DiscoverPeers(discoverCtx)
	if err != nil && err != ErrHTTPURLNotAnnounced {
		t.Fatalf("DiscoverPeers: %v", err)
	}
	for _, p := range peers {
		if p.PeerID == disc.Identity().PeerID.String() {
			t.Fatal("discovered peers should not include self")
		}
	}
}

func TestHostReturnsListenAddrs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	config := Config{
		NetworkID:   "testnet",
		KeyPath:     filepath.Join(t.TempDir(), "node.key"),
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
	}
	disc, err := New(ctx, config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer disc.Close()

	addrs := disc.host.Addrs()
	if len(addrs) == 0 {
		t.Fatal("host should have at least one listen address")
	}
	for _, a := range addrs {
		t.Logf("listen addr: %s", a)
	}
}

func TestNewInvalidBootstrapMultiaddr(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	config := Config{
		NetworkID:      "testnet",
		KeyPath:        filepath.Join(t.TempDir(), "node.key"),
		BootstrapPeers: []string{"garbage-not-a-multiaddr"},
	}
	_, err := New(ctx, config)
	if err == nil {
		t.Fatal("expected error for invalid bootstrap multiaddr")
	}
	if !strings.Contains(err.Error(), "bootstrap failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCloseIsSafe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	config := Config{
		NetworkID: "testnet",
		KeyPath:   filepath.Join(t.TempDir(), "node.key"),
	}
	disc, err := New(ctx, config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := disc.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	disc.Close()
	disc.Close()
}

func multiaddrFromString(t *testing.T, s string) ma.Multiaddr {
	t.Helper()
	maddr, err := ma.NewMultiaddr(s)
	if err != nil {
		t.Fatalf("parse multiaddr %q: %v", s, err)
	}
	return maddr
}
