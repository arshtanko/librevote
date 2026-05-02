package discovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	mh "github.com/multiformats/go-multihash"
)

const (
	DefaultDiscoverTimeout     = 30 * time.Second
	DefaultDHTBootstrapTimeout = 20 * time.Second
)

const httpAdvertiseProtocol = "/librevote/http-advertise/1.0.0"

// Config holds discovery configuration.
type Config struct {
	NetworkID        string
	BootstrapPeers   []string // multiaddr strings
	KeyPath          string
	ListenAddrs      []string // multiaddr strings for host listen
	AdvertisedHTTP   string   // optional HTTP sync URL associated with this peer
	RendezvousPrefix string
	Mode             string // "server", "client", "auto" (validated)
}

var validModes = map[string]bool{"auto": true, "server": true, "client": true}

// PeerInfo represents a discovered peer.
type PeerInfo struct {
	PeerID  string   `json:"peer_id"`
	Addrs   []string `json:"addrs"`
	HTTPURL string   `json:"http_url,omitempty"`
}

// Discovery manages peer discovery via libp2p + Kademlia DHT.
type Discovery struct {
	config   Config
	identity *Identity
	host     host.Host
	dht      *dht.IpfsDHT
}

// New creates a new Discovery instance with a running libp2p host and DHT.
func New(ctx context.Context, config Config) (*Discovery, error) {
	if config.NetworkID == "" {
		return nil, fmt.Errorf("network_id is required")
	}
	if config.RendezvousPrefix == "" {
		config.RendezvousPrefix = "/librevote"
	}
	if config.Mode == "" {
		config.Mode = "auto"
	}
	if !validModes[config.Mode] {
		return nil, fmt.Errorf("invalid mode %q (valid: auto, server, client)", config.Mode)
	}

	id, err := LoadOrCreateIdentity(config.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}

	opts := []libp2p.Option{
		libp2p.Identity(id.PrivKey),
	}

	if len(config.ListenAddrs) > 0 {
		addrs := make([]ma.Multiaddr, 0, len(config.ListenAddrs))
		for _, a := range config.ListenAddrs {
			maddr, err := ma.NewMultiaddr(a)
			if err != nil {
				return nil, fmt.Errorf("parse listen address %q: %w", a, err)
			}
			addrs = append(addrs, maddr)
		}
		opts = append(opts, libp2p.ListenAddrs(addrs...))
	} else {
		defaultAddr, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
		if err != nil {
			return nil, fmt.Errorf("default listen address: %w", err)
		}
		opts = append(opts, libp2p.ListenAddrs(defaultAddr))
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("create libp2p host: %w", err)
	}

	var dhtMode dht.ModeOpt
	switch config.Mode {
	case "server":
		dhtMode = dht.ModeServer
	case "client":
		dhtMode = dht.ModeClient
	default:
		dhtMode = dht.ModeAuto
	}

	kdht, err := dht.New(ctx, h, dht.Mode(dhtMode))
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("create kademlia DHT: %w", err)
	}

	d := &Discovery{
		config:   config,
		identity: id,
		host:     h,
		dht:      kdht,
	}

	h.SetStreamHandler(httpAdvertiseProtocol, d.handleHTTPAdvertise)

	if len(config.BootstrapPeers) > 0 {
		bootstrapCtx, cancel := context.WithTimeout(ctx, DefaultDHTBootstrapTimeout)
		defer cancel()

		if err := d.bootstrap(bootstrapCtx); err != nil {
			return d, fmt.Errorf("bootstrap failed: %w", err)
		}

		if err := kdht.Bootstrap(bootstrapCtx); err != nil {
			return d, fmt.Errorf("DHT bootstrap: %w", err)
		}
	}

	return d, nil
}

// Identity returns the local peer identity.
func (d *Discovery) Identity() *Identity {
	return d.identity
}

// Config returns the discovery configuration.
func (d *Discovery) Config() Config {
	return d.config
}

// Host returns the libp2p host.
func (d *Discovery) Host() host.Host {
	return d.host
}

// Namespace returns the rendezvous namespace string.
func (d *Discovery) Namespace() string {
	return fmt.Sprintf("%s/%s/v1", d.config.RendezvousPrefix, d.config.NetworkID)
}

// rendezvousCID returns a content-addressed CID derived from the namespace
// for use with DHT Provide/FindProviders.
func (d *Discovery) rendezvousCID() cid.Cid {
	h := sha256.Sum256([]byte(d.Namespace()))
	mhash, err := mh.Encode(h[:], mh.SHA2_256)
	if err != nil {
		panic("multihash encode failed: " + err.Error())
	}
	return cid.NewCidV1(cid.Raw, mhash)
}

// ErrHTTPURLNotAnnounced is returned when the HTTP sync URL could not be
// announced because there are no routing peers (e.g. first node in network).
// The node should re-announce once peers join the routing table.
var ErrHTTPURLNotAnnounced = fmt.Errorf("http url not announced: no peers in routing table")

// announceSelf announces this node as a provider for the rendezvous namespace.
// Errors from empty routing tables for Provide are expected when the node is
// the first in the network and are silently ignored.
func (d *Discovery) announceSelf(ctx context.Context) error {
	if err := d.dht.Provide(ctx, d.rendezvousCID(), true); err != nil {
		if strings.Contains(err.Error(), "failed to find any peer in table") {
			return ErrHTTPURLNotAnnounced
		}
		return fmt.Errorf("announce provider: %w", err)
	}
	return nil
}

// DiscoverPeers discovers peers using Kademlia DHT provider records.
func (d *Discovery) DiscoverPeers(ctx context.Context) ([]PeerInfo, error) {
	announceErr := d.announceSelf(ctx)
	if announceErr != nil && !errors.Is(announceErr, ErrHTTPURLNotAnnounced) {
		return nil, fmt.Errorf("announce self: %w", announceErr)
	}

	providers, err := d.dht.FindProviders(ctx, d.rendezvousCID())
	if err != nil {
		if strings.Contains(err.Error(), "failed to find any peer in table") {
			return nil, announceErr
		}
		return nil, fmt.Errorf("find providers: %w", err)
	}

	seen := make(map[peer.ID]peer.AddrInfo)
	for _, p := range providers {
		if p.ID == d.identity.PeerID {
			continue
		}
		if existing, ok := seen[p.ID]; ok {
			existing.Addrs = append(existing.Addrs, p.Addrs...)
			seen[p.ID] = existing
		} else {
			addrs := make([]ma.Multiaddr, len(p.Addrs))
			copy(addrs, p.Addrs)
			seen[p.ID] = peer.AddrInfo{ID: p.ID, Addrs: addrs}
		}
	}

	result := make([]PeerInfo, 0, len(seen))
	for pid, info := range seen {
		pi := PeerInfo{
			PeerID: pid.String(),
		}
		for _, a := range info.Addrs {
			pi.Addrs = append(pi.Addrs, a.String())
		}
		pi.HTTPURL = d.PeerHTTPURL(ctx, pid)
		result = append(result, pi)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].PeerID < result[j].PeerID
	})

	return result, announceErr
}

// PeerHTTPURL queries a peer for its HTTP sync URL via a libp2p stream.
func (d *Discovery) PeerHTTPURL(ctx context.Context, pid peer.ID) string {
	return d.lookupHTTPURL(ctx, pid)
}

// handleHTTPAdvertise responds to HTTP URL queries from peers.
func (d *Discovery) handleHTTPAdvertise(s network.Stream) {
	defer s.Close()
	if d.config.AdvertisedHTTP != "" {
		io.WriteString(s, d.config.AdvertisedHTTP)
	}
}

// lookupHTTPURL queries a peer for its HTTP sync URL via a libp2p stream.
func (d *Discovery) lookupHTTPURL(ctx context.Context, pid peer.ID) string {
	s, err := d.host.NewStream(ctx, pid, httpAdvertiseProtocol)
	if err != nil {
		return ""
	}
	defer s.Close()

	buf := make([]byte, 2048)
	n, err := s.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return string(bytes.TrimSpace(buf[:n]))
}

// Close shuts down the DHT and libp2p host.
func (d *Discovery) Close() error {
	if d.dht != nil {
		if err := d.dht.Close(); err != nil {
			d.host.Close()
			return fmt.Errorf("close DHT: %w", err)
		}
	}
	if d.host != nil {
		if err := d.host.Close(); err != nil {
			return fmt.Errorf("close host: %w", err)
		}
	}
	return nil
}

func (d *Discovery) bootstrap(ctx context.Context) error {
	var bootstrapInfos []peer.AddrInfo
	var errs []string

	for _, bs := range d.config.BootstrapPeers {
		maddr, err := ma.NewMultiaddr(bs)
		if err != nil {
			errs = append(errs, fmt.Sprintf("parse %q: %v", bs, err))
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			errs = append(errs, fmt.Sprintf("addr info from %q: %v", bs, err))
			continue
		}
		bootstrapInfos = append(bootstrapInfos, *info)
	}

	if len(bootstrapInfos) == 0 {
		if len(errs) > 0 {
			return fmt.Errorf("no valid bootstrap peers: %s", strings.Join(errs, "; "))
		}
		return nil
	}

	var connectErrs []string
	for _, info := range bootstrapInfos {
		if err := d.host.Connect(ctx, info); err != nil {
			connectErrs = append(connectErrs, fmt.Sprintf("connect %s: %v", info.ID, err))
		}
	}

	if len(connectErrs) > 0 && len(connectErrs) == len(bootstrapInfos) {
		return fmt.Errorf("failed to connect to any bootstrap peers: %s", strings.Join(connectErrs, "; "))
	}

	return nil
}
