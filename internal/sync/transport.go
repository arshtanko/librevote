package sync

import (
	"context"
	"fmt"

	"librevote/internal/domain"
)

// StaticPeerTransport provides an in-memory transport that routes peer
// requests to registered StoreQuerier instances. It is intended for
// testing and simple static-peer deployments.
type StaticPeerTransport struct {
	peers map[string]StoreQuerier
}

// NewStaticPeerTransport creates a transport backed by an in-memory peer map.
func NewStaticPeerTransport(peers map[string]StoreQuerier) *StaticPeerTransport {
	if peers == nil {
		peers = make(map[string]StoreQuerier)
	}
	return &StaticPeerTransport{peers: peers}
}

// RegisterPeer adds or replaces a peer store.
func (t *StaticPeerTransport) RegisterPeer(peerID string, store StoreQuerier) {
	t.peers[peerID] = store
}

// Inventory returns object refs from a registered peer's store.
func (t *StaticPeerTransport) Inventory(ctx context.Context, peerID string, scope string, scopeID string, objectTypes []string) ([]ObjectRef, error) {
	store, ok := t.peers[peerID]
	if !ok {
		return nil, fmt.Errorf("peer %s not registered", peerID)
	}
	return store.ListServableObjectRefs(ctx, scope, scopeID, objectTypes)
}

// GetObject fetches a full object from a registered peer's store.
func (t *StaticPeerTransport) GetObject(ctx context.Context, peerID string, objectID string) (domain.ObjectEnvelope, error) {
	store, ok := t.peers[peerID]
	if !ok {
		return domain.ObjectEnvelope{}, fmt.Errorf("peer %s not registered", peerID)
	}
	return store.LoadObjectEnvelope(ctx, objectID)
}
