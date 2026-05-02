package app

import (
	"context"
	"fmt"
	"net"
	nethttp "net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"librevote/internal/discovery"
	"librevote/internal/gossip"
	librevotesync "librevote/internal/sync"
	"librevote/internal/transport"
)

const defaultAnnounceInterval = 10 * time.Second

// NodeStartConfig holds configuration for the integrated node.
type NodeStartConfig struct {
	DataDir          string
	NetworkID        string
	HTTPListenAddr   string
	KeyPath          string
	ListenAddrs      []string
	BootstrapPeers   []string
	RendezvousPrefix string
	Mode             string
	AdvertisedHTTP   string
	AnnounceInterval time.Duration
}

// NodeStart runs an integrated node with HTTP object server, libp2p/Kademlia
// discovery, GossipSub object announcements, and direct fetch/ingest.
type NodeStart struct {
	svc       *Service
	config    NodeStartConfig
	discovery *discovery.Discovery
	gossipSvc *gossip.Service
	httpSrv   *nethttp.Server
	httpAddr  string // actual bound address after listener starts
	transport *transport.HTTPTransport
	peerHTTP  map[string]string
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	logf      func(format string, args ...interface{})
}

// NewNodeStart creates an unstarted integrated node. The caller must call
// Start to begin serving and Run to block until shutdown.
func NewNodeStart(ctx context.Context, config NodeStartConfig, logf func(string, ...interface{})) (*NodeStart, error) {
	if config.DataDir == "" {
		return nil, fmt.Errorf("data dir is required")
	}
	if config.NetworkID == "" {
		return nil, fmt.Errorf("network id is required")
	}
	if config.HTTPListenAddr == "" {
		config.HTTPListenAddr = ":8080"
	}
	if config.Mode == "" {
		config.Mode = "auto"
	}
	if config.RendezvousPrefix == "" {
		config.RendezvousPrefix = "/librevote"
	}
	if config.KeyPath == "" {
		config.KeyPath = config.DataDir + "/node_start.key"
	}
	if config.AnnounceInterval <= 0 {
		config.AnnounceInterval = defaultAnnounceInterval
	}
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}

	svc, err := Open(config.DataDir, config.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("open service: %w", err)
	}

	nsCtx, cancel := context.WithCancel(ctx)

	ns := &NodeStart{
		svc:       svc,
		config:    config,
		transport: transport.NewHTTPTransport(),
		peerHTTP:  make(map[string]string),
		ctx:       nsCtx,
		cancel:    cancel,
		logf:      logf,
	}

	return ns, nil
}

// Start begins the HTTP server, libp2p host, discovery, and GossipSub.
func (ns *NodeStart) Start(ctx context.Context) error {
	// 1. Start HTTP server
	ln, err := net.Listen("tcp", ns.config.HTTPListenAddr)
	if err != nil {
		return fmt.Errorf("listen http %s: %w", ns.config.HTTPListenAddr, err)
	}
	ns.httpAddr = ln.Addr().String()

	if ns.config.AdvertisedHTTP == "" {
		if ns.config.HTTPListenAddr == "" {
			ns.config.AdvertisedHTTP = "http://" + ns.httpAddr
		} else {
			host, _, err := net.SplitHostPort(ns.config.HTTPListenAddr)
			if err != nil {
				ns.config.AdvertisedHTTP = "http://" + ns.httpAddr
			} else if host == "" {
				ns.config.AdvertisedHTTP = "http://127.0.0.1:" + ns.httpAddr[strings.LastIndex(ns.httpAddr, ":")+1:]
			} else {
				ns.config.AdvertisedHTTP = "http://" + ns.httpAddr
			}
		}
	}

	server := transport.NewServer(ns.svc, ns.config.NetworkID)
	ns.httpSrv = &nethttp.Server{
		Handler: server.Handler(),
	}

	ns.logf("http server listening on %s", ns.httpAddr)
	ns.logf("http advertise: %s", ns.config.AdvertisedHTTP)

	go func() {
		if err := ns.httpSrv.Serve(ln); err != nil && err != nethttp.ErrServerClosed {
			ns.logf("http server error: %v", err)
		}
	}()

	// 2. Start libp2p/Kademlia discovery
	discConfig := discovery.Config{
		NetworkID:        ns.config.NetworkID,
		BootstrapPeers:   ns.config.BootstrapPeers,
		KeyPath:          ns.config.KeyPath,
		ListenAddrs:      ns.config.ListenAddrs,
		AdvertisedHTTP:   ns.config.AdvertisedHTTP,
		RendezvousPrefix: ns.config.RendezvousPrefix,
		Mode:             ns.config.Mode,
	}

	d, err := discovery.New(ctx, discConfig)
	if err != nil {
		return fmt.Errorf("start discovery: %w", err)
	}
	ns.discovery = d

	ns.logf("libp2p peer_id: %s", d.Identity().PeerID)
	ns.logf("libp2p namespace: %s", d.Namespace())
	for _, a := range d.Host().Addrs() {
		ns.logf("libp2p listen: %s/p2p/%s", a, d.Identity().PeerID)
	}

	// 3. Start GossipSub
	gs, err := gossip.NewService(ctx, d.Host(), ns.config.NetworkID, ns.onAnnouncement)
	if err != nil {
		return fmt.Errorf("start gossipsub: %w", err)
	}
	ns.gossipSvc = gs
	ns.logf("gossipsub topic: %s", gossip.TopicName(ns.config.NetworkID))

	// 4. Start periodic discovery to populate peer HTTP URLs
	ns.wg.Add(1)
	go ns.discoveryLoop()

	// 5. Start periodic announcement publishing
	ns.wg.Add(1)
	go ns.announceLoop()

	return nil
}

// Stop gracefully shuts down all subsystems.
// Order: cancel background loops, wait for them to exit, then close resources.
func (ns *NodeStart) Stop() error {
	ns.cancel()
	ns.wg.Wait()

	if ns.httpSrv != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		ns.httpSrv.Shutdown(shutdownCtx)
	}

	if ns.gossipSvc != nil {
		ns.gossipSvc.Close()
	}

	if ns.discovery != nil {
		ns.discovery.Close()
	}

	if ns.svc != nil {
		ns.svc.Close()
	}

	return nil
}

// Run blocks until an interrupt signal is received, then calls Stop.
func (ns *NodeStart) Run() error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	return ns.Stop()
}

// Service returns the underlying app service for direct use in tests.
func (ns *NodeStart) Service() *Service {
	return ns.svc
}

// GossipService returns the gossip service for direct use in tests.
func (ns *NodeStart) GossipService() *gossip.Service {
	return ns.gossipSvc
}

// Discovery returns the discovery instance for direct use in tests.
func (ns *NodeStart) Discovery() *discovery.Discovery {
	return ns.discovery
}

// Addr returns the actual HTTP listen address (e.g. "127.0.0.1:45678").
// When configured with port 0, the real port is resolved from the listener.
func (ns *NodeStart) Addr() string {
	if ns.httpAddr != "" {
		return ns.httpAddr
	}
	if ns.httpSrv != nil {
		return ns.httpSrv.Addr
	}
	return ""
}

// InjectPeerHTTP sets an explicit HTTP URL for a peer ID, useful for tests.
func (ns *NodeStart) InjectPeerHTTP(peerID, httpURL string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.peerHTTP == nil {
		ns.peerHTTP = make(map[string]string)
	}
	ns.peerHTTP[peerID] = httpURL
}

// ConnectPeer connects the local libp2p host to a peer by multiaddr string.
// Returns an error if the connection fails.
func (ns *NodeStart) ConnectPeer(ctx context.Context, multiaddrStr string) error {
	if ns.discovery == nil {
		return fmt.Errorf("discovery not started")
	}
	info, err := peer.AddrInfoFromString(multiaddrStr)
	if err != nil {
		return fmt.Errorf("parse peer addr: %w", err)
	}
	return ns.discovery.Host().Connect(ctx, *info)
}

// PublishInventory publishes announcements for all local servable objects.
// Exported for use in tests and manual re-triggering.
func (ns *NodeStart) PublishInventory(ctx context.Context) error {
	if ns.gossipSvc == nil {
		return fmt.Errorf("gossip service not started")
	}
	return ns.publishInventory()
}

func (ns *NodeStart) onAnnouncement(a gossip.ObjectAnnouncement, sourcePeerID string) error {
	ns.logf("gossip: received announcement for %s from %s", a.ObjectID, sourcePeerID)

	status, found, err := ns.svc.ValidationStatus(ns.ctx, a.ObjectID)
	if err != nil {
		ns.logf("gossip: error checking status for %s: %v", a.ObjectID, err)
	}
	if found && status.RepublishEligible() {
		ns.logf("gossip: already have servable object %s (%s)", a.ObjectID, status)
		return nil
	}

	httpURL := ns.getPeerHTTPURL(sourcePeerID)
	if httpURL == "" {
		ns.logf("gossip: no HTTP URL for peer %s (object %s), known peers: %d", sourcePeerID, a.ObjectID, len(ns.peerHTTP))
		return fmt.Errorf("no HTTP URL for peer %s (object %s)", sourcePeerID, a.ObjectID)
	}

	ns.logf("gossip: fetching object %s from %s (status=%s found=%v)", a.ObjectID, httpURL, status, found)
	envelope, err := ns.transport.GetObject(ns.ctx, httpURL, a.ObjectID)
	if err != nil {
		return fmt.Errorf("fetch object %s from %s: %w", a.ObjectID, httpURL, err)
	}

	if err := ns.svc.IngestSyncEnvelope(ns.ctx, envelope); err != nil {
		return fmt.Errorf("ingest object %s: %w", a.ObjectID, err)
	}

	statusAfter, foundAfter, _ := ns.svc.ValidationStatus(ns.ctx, a.ObjectID)
	if !foundAfter || !statusAfter.RepublishEligible() {
		ns.logf("gossip: object %s remains %s after ingest, will retry", a.ObjectID, statusAfter)
		return fmt.Errorf("object %s pending after ingest: %s", a.ObjectID, statusAfter)
	}

	ns.logf("gossip: ingested object %s from peer %s (%s)", a.ObjectID, sourcePeerID, statusAfter)

	if err := ns.svc.RevalidateDependents(ns.ctx, a.ObjectID); err != nil {
		ns.logf("gossip: revalidate dependents for %s: %v", a.ObjectID, err)
	}
	return nil
}

func (ns *NodeStart) getPeerHTTPURL(peerID string) string {
	ns.mu.Lock()
	url, ok := ns.peerHTTP[peerID]
	ns.mu.Unlock()
	if ok && url != "" {
		return url
	}

	if ns.discovery != nil {
		pid, err := peer.Decode(peerID)
		if err != nil {
			return ""
		}
		ctx, cancel := context.WithTimeout(ns.ctx, 5*time.Second)
		defer cancel()
		url := ns.discovery.PeerHTTPURL(ctx, pid)
		if url != "" {
			ns.mu.Lock()
			ns.peerHTTP[peerID] = url
			ns.mu.Unlock()
		}
		return url
	}
	return ""
}

func (ns *NodeStart) discoveryLoop() {
	defer ns.wg.Done()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	ns.doDiscovery()

	for {
		select {
		case <-ns.ctx.Done():
			return
		case <-ticker.C:
			ns.doDiscovery()
		}
	}
}

func (ns *NodeStart) doDiscovery() {
	if ns.discovery == nil {
		return
	}

	ctx, cancel := context.WithTimeout(ns.ctx, 20*time.Second)
	defer cancel()

	peers, err := ns.discovery.DiscoverPeers(ctx)
	if err != nil {
		ns.logf("discovery: %v", err)
		return
	}

	ns.mu.Lock()
	for _, p := range peers {
		if p.HTTPURL != "" {
			ns.peerHTTP[p.PeerID] = p.HTTPURL
		}
	}
	count := len(ns.peerHTTP)
	ns.mu.Unlock()

	ns.logf("discovery: found %d peers (%d with HTTP)", len(peers), count)
}

func (ns *NodeStart) announceLoop() {
	defer ns.wg.Done()

	ns.publishInventory()

	ticker := time.NewTicker(ns.config.AnnounceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ns.ctx.Done():
			return
		case <-ticker.C:
			ns.publishInventory()
		}
	}
}

func (ns *NodeStart) publishInventory() error {
	if ns.gossipSvc == nil || ns.svc == nil {
		return fmt.Errorf("not started")
	}

	ctx, cancel := context.WithTimeout(ns.ctx, 30*time.Second)
	defer cancel()

	scopes, err := ns.svc.ListServableScopes(ctx)
	if err != nil {
		ns.logf("inventory scopes query: %v", err)
		return err
	}

	var allRefs []librevotesync.ObjectRef
	for _, sp := range scopes {
		refs, err := ns.svc.ListServableObjectRefs(ctx, sp.Scope, sp.ScopeID, nil)
		if err != nil {
			ns.logf("inventory query scope=%s scope_id=%s: %v", sp.Scope, sp.ScopeID, err)
			continue
		}
		allRefs = append(allRefs, refs...)
	}

	librevotesync.SortByDependencyRank(allRefs)

	cycleTimestamp := time.Now().UnixNano()
	totalPublished := 0
	for _, ref := range allRefs {
		a := gossip.ObjectAnnouncement{
			ObjectID:         ref.ObjectID,
			ObjectType:       ref.ObjectType,
			Scope:            ref.Scope,
			ScopeID:          ref.ScopeID,
			CreatedAt:        ref.CreatedAt,
			PublishTimestamp: cycleTimestamp,
		}
		if err := ns.gossipSvc.Publish(ctx, a); err != nil {
			ns.logf("publish announce %s: %v", ref.ObjectID, err)
			continue
		}
		totalPublished++
	}

	ns.logf("announce: published %d objects across %d scopes (ts=%d)", totalPublished, len(scopes), cycleTimestamp)
	return nil
}
