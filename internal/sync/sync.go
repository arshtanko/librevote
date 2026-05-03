package sync

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"librevote/internal/domain"
	"librevote/internal/storage"
)

// ObjectRef is re-exported from the storage package for convenience.
type ObjectRef = storage.ObjectRef

// EnvelopeIngester receives a validated envelope for local storage and
// validation. Implementations must be idempotent: ingesting the same envelope
// multiple times must not create duplicates or alter the object log.
type EnvelopeIngester interface {
	IngestSyncEnvelope(ctx context.Context, envelope domain.ObjectEnvelope) error
}

// StoreQuerier provides the local storage queries needed to serve objects to
// peers and to compare local state during sync.
type StoreQuerier interface {
	ListServableObjectRefs(ctx context.Context, scope string, scopeID string, objectTypes []string) ([]storage.ObjectRef, error)
	LoadObjectEnvelope(ctx context.Context, objectID string) (domain.ObjectEnvelope, error)
}

// Transport abstracts peer communication. Each method targets a specific peer.
type Transport interface {
	Inventory(ctx context.Context, peerID string, scope string, scopeID string, objectTypes []string) ([]ObjectRef, error)
	GetObject(ctx context.Context, peerID string, objectID string) (domain.ObjectEnvelope, error)
}

// Result summarises a sync operation.
type Result struct {
	Fetched  int
	Ingested int
	Errors   []string
}

// Error summarises collected errors as a single aggregated error, or nil.
func (r Result) Error() error {
	if len(r.Errors) == 0 {
		return nil
	}
	return fmt.Errorf("%d sync errors: %s", len(r.Errors), strings.Join(r.Errors, "; "))
}

// DependencyRank returns a low-to-high rank for ingestion order and
// announcement publishing order.
var DependencyRank = map[string]int{
	string(domain.ObjectTypeTrusteeSelectionElection): 0,
	string(domain.ObjectTypeAnonymousElection):        0,
	string(domain.ObjectTypeElectionInvite):           0,
	string(domain.ObjectTypeElectionAcceptance):       1,
	string(domain.ObjectTypeTrusteeNomination):        1,
	string(domain.ObjectTypeTrusteeConsent):           1,
	string(domain.ObjectTypeTrusteeVote):              2,
	string(domain.ObjectTypeTallyKeyContribution):     2,
	string(domain.ObjectTypeTrusteeSelectionResult):   3,
	string(domain.ObjectTypeTallyKeySet):              3,
	string(domain.ObjectTypeBlindTokenRequest):        4,
	string(domain.ObjectTypeBlindTokenIssue):          5,
	string(domain.ObjectTypeAnonymousBallot):          6,
	string(domain.ObjectTypeTallyDecryptionShare):     7,
	string(domain.ObjectTypeTallyResult):              8,
}

// SortByDependencyRank sorts refs in ascending dependency order.
// Within the same rank, refs are ordered by ObjectID.
func SortByDependencyRank(refs []ObjectRef) {
	sort.Slice(refs, func(i, j int) bool {
		ri := DependencyRank[refs[i].ObjectType]
		rj := DependencyRank[refs[j].ObjectType]
		if ri != rj {
			return ri < rj
		}
		return refs[i].ObjectID < refs[j].ObjectID
	})
}

func verifyEnvelopeMatchesRef(envelope domain.ObjectEnvelope, ref ObjectRef, scope string, scopeID string) error {
	if envelope.ObjectID != ref.ObjectID {
		return fmt.Errorf("object_id mismatch: envelope %q != ref %q", envelope.ObjectID, ref.ObjectID)
	}
	if string(envelope.ObjectType) != ref.ObjectType {
		return fmt.Errorf("object_type mismatch: envelope %q != ref %q", envelope.ObjectType, ref.ObjectType)
	}
	if string(envelope.Scope) != ref.Scope {
		return fmt.Errorf("scope mismatch: envelope %q != ref %q", envelope.Scope, ref.Scope)
	}
	if envelope.ScopeID != ref.ScopeID {
		return fmt.Errorf("scope_id mismatch: envelope %q != ref %q", envelope.ScopeID, ref.ScopeID)
	}
	if string(envelope.Scope) != scope {
		return fmt.Errorf("envelope scope %q does not match sync scope %q", envelope.Scope, scope)
	}
	if scopeID != "" && envelope.ScopeID != scopeID {
		return fmt.Errorf("envelope scope_id %q does not match sync scope_id %q", envelope.ScopeID, scopeID)
	}
	if scopeID == "" && envelope.ScopeID != "" {
		return fmt.Errorf("envelope scope_id %q but sync scope_id is empty (scope=%s)", envelope.ScopeID, scope)
	}
	return nil
}

type peerRefInfo struct {
	ref   ObjectRef
	peers []string
}

// Sync pulls inventory from each connected peer, determines which objects are
// missing locally, fetches them (in dependency order, trying alternate peers on
// fetch failure), and ingests each through the ingester.
func Sync(ctx context.Context, transport Transport, store StoreQuerier, ingester EnvelopeIngester, scope string, scopeID string, objectTypes []string, peerIDs []string) (Result, error) {
	var result Result
	if transport == nil {
		return result, errors.New("transport is required")
	}
	if store == nil {
		return result, errors.New("store querier is required")
	}
	if ingester == nil {
		return result, errors.New("envelope ingester is required")
	}
	if scope == "" {
		return result, errors.New("scope is required")
	}
	if len(peerIDs) == 0 {
		return result, nil
	}

	localObjectIDs, err := buildLocalSet(ctx, store, scope, scopeID, objectTypes)
	if err != nil {
		return result, fmt.Errorf("build local object set: %w", err)
	}

	remoteRefs, inventoryErrors := fetchPeerInventories(ctx, transport, scope, scopeID, objectTypes, peerIDs)
	for _, invErr := range inventoryErrors {
		result.Errors = append(result.Errors, "inventory: "+invErr)
	}

	var missingRefs []ObjectRef
	for objectID, info := range remoteRefs {
		if _, ok := localObjectIDs[objectID]; ok {
			continue
		}
		missingRefs = append(missingRefs, info.ref)
	}

	SortByDependencyRank(missingRefs)

	for _, ref := range missingRefs {
		info := remoteRefs[ref.ObjectID]
		peers := info.peers
		if len(peers) == 0 {
			peers = peerIDs
		}
		var envelope domain.ObjectEnvelope
		var fetchErr error
		for _, p := range peers {
			envelope, fetchErr = transport.GetObject(ctx, p, ref.ObjectID)
			if fetchErr == nil {
				break
			}
		}
		if fetchErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("fetch %s: %v", ref.ObjectID, fetchErr))
			continue
		}
		if err := verifyEnvelopeMatchesRef(envelope, ref, scope, scopeID); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("verify %s: %v", ref.ObjectID, err))
			continue
		}
		result.Fetched++
		if err := ingester.IngestSyncEnvelope(ctx, envelope); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("ingest %s: %v", ref.ObjectID, err))
			continue
		}
		result.Ingested++
	}

	return result, result.Error()
}

func buildLocalSet(ctx context.Context, store StoreQuerier, scope string, scopeID string, objectTypes []string) (map[string]struct{}, error) {
	refs, err := store.ListServableObjectRefs(ctx, scope, scopeID, objectTypes)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		set[ref.ObjectID] = struct{}{}
	}
	return set, nil
}

func fetchPeerInventories(ctx context.Context, transport Transport, scope string, scopeID string, objectTypes []string, peerIDs []string) (map[string]*peerRefInfo, []string) {
	refs := make(map[string]*peerRefInfo)
	var errors []string

	for _, peerID := range peerIDs {
		peerRefs, err := transport.Inventory(ctx, peerID, scope, scopeID, objectTypes)
		if err != nil {
			errors = append(errors, fmt.Sprintf("peer %s: %v", peerID, err))
			continue
		}
		for _, ref := range peerRefs {
			info, ok := refs[ref.ObjectID]
			if !ok {
				info = &peerRefInfo{ref: ref}
				refs[ref.ObjectID] = info
			}
			info.peers = append(info.peers, peerID)
		}
	}
	return refs, errors
}
