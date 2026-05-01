package app

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"librevote/internal/crypto"
	"librevote/internal/domain"
	"librevote/internal/storage"
	"librevote/internal/validation"
)

const (
	protocolVersion     = "v1"
	validatorVersion    = "app-service-v1"
	objectPoWDifficulty = 0
)

type Service struct {
	store     *storage.Store
	runner    *validation.Runner
	networkID string
}

func Open(dataDir, networkID string) (*Service, error) {
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Config{
		DataDir:   dataDir,
		NetworkID: networkID,
	})
	if err != nil {
		return nil, fmt.Errorf("app open storage: %w", err)
	}

	contextual, err := validation.NewContextualValidator(store)
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("app contextual validator: %w", err)
	}
	structural, err := validation.NewStructuralValidator(contextual)
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("app structural validator: %w", err)
	}
	now := time.Now
	runner, err := validation.NewRunner(validation.RunnerConfig{
		Envelope: validation.EnvelopeConfig{
			NetworkID:           networkID,
			ProtocolVersion:     protocolVersion,
			ObjectPoWDifficulty: objectPoWDifficulty,
			Now:                 now,
		},
		Store:            store,
		DomainValidator:  structural,
		ValidatorVersion: validatorVersion,
		Now:              now,
	})
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("app validation runner: %w", err)
	}

	return &Service{
		store:     store,
		runner:    runner,
		networkID: networkID,
	}, nil
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	return s.store.Close()
}

// ListServableObjectRefs returns sync inventory items for locally retained
// objects with servable validation statuses. It delegates to the storage layer.
func (s *Service) ListServableObjectRefs(ctx context.Context, scope string, scopeID string, objectTypes []string) ([]storage.ObjectRef, error) {
	return s.store.ListServableObjectRefs(ctx, scope, scopeID, objectTypes)
}

// LoadObjectEnvelope reconstructs a full domain object envelope for a retained
// and servable object. It delegates to the storage layer.
func (s *Service) LoadObjectEnvelope(ctx context.Context, objectID string) (domain.ObjectEnvelope, error) {
	return s.store.LoadObjectEnvelope(ctx, objectID)
}

func (s *Service) ValidationStatus(ctx context.Context, objectID string) (validation.Status, bool, error) {
	return s.store.ValidationStatus(ctx, objectID)
}

func (s *Service) IngestEnvelope(ctx context.Context, envelope domain.ObjectEnvelope) (validation.RunnerResult, error) {
	return s.runner.IngestAndValidate(ctx, envelope)
}

// IngestSyncEnvelope ingests a received envelope and returns only the error.
// It satisfies the sync.EnvelopeIngester interface for P2P sync.
func (s *Service) IngestSyncEnvelope(ctx context.Context, envelope domain.ObjectEnvelope) error {
	_, err := s.runner.IngestAndValidate(ctx, envelope)
	return err
}

// EvictPendingPayload delegates to the storage layer to evict a pending
// object's retained payload. The object must have a pending_dependencies or
// pending_payload_evicted status.
func (s *Service) EvictPendingPayload(ctx context.Context, objectID string, checkedAt int64, validatorVersion string) error {
	return s.store.EvictPendingPayload(ctx, objectID, checkedAt, validatorVersion)
}

func (s *Service) CreateTrusteeSelectionElection(ctx context.Context, payload domain.TrusteeSelectionElectionPayload, creatorPrivKey ed25519.PrivateKey, createdAt int64) (domain.ObjectEnvelope, error) {
	if len(payload.CreatorPublicKey) == 0 {
		payload.CreatorPublicKey = []byte(creatorPrivKey.Public().(ed25519.PublicKey))
	}
	unsignedPayload := payload
	unsignedPayload.Signature = nil
	unsigned := domain.EncodeTrusteeSelectionElectionPayload(unsignedPayload)

	sig, err := s.sign(crypto.DomainTrusteeSelectionElectionSign, domain.ObjectTypeTrusteeSelectionElection, domain.ScopeNetwork, "", createdAt, unsigned, creatorPrivKey)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}
	payload.Signature = sig

	encoded := domain.EncodeTrusteeSelectionElectionPayload(payload)
	envelope, err := s.buildEnvelope(domain.ObjectTypeTrusteeSelectionElection, domain.ScopeNetwork, "", encoded, createdAt)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}

	return s.ingestLocal(ctx, envelope, validation.StatusValid)
}

func (s *Service) CreateTrusteeNomination(ctx context.Context, payload domain.TrusteeNominationPayload, candidatePrivKey ed25519.PrivateKey, createdAt int64) (domain.ObjectEnvelope, error) {
	if len(payload.CandidatePublicKey) == 0 {
		payload.CandidatePublicKey = []byte(candidatePrivKey.Public().(ed25519.PublicKey))
	}
	unsignedPayload := payload
	unsignedPayload.Signature = nil
	unsigned := domain.EncodeTrusteeNominationPayload(unsignedPayload)

	sig, err := s.sign(crypto.DomainTrusteeNominationSign, domain.ObjectTypeTrusteeNomination, domain.ScopeTrusteeSelectionID, payload.TrusteeSelectionID, createdAt, unsigned, candidatePrivKey)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}
	payload.Signature = sig

	encoded := domain.EncodeTrusteeNominationPayload(payload)
	envelope, err := s.buildEnvelope(domain.ObjectTypeTrusteeNomination, domain.ScopeTrusteeSelectionID, payload.TrusteeSelectionID, encoded, createdAt)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}

	return s.ingestLocal(ctx, envelope, validation.StatusValid)
}

func (s *Service) CreateTrusteeVote(ctx context.Context, payload domain.TrusteeVotePayload, voterPrivKey ed25519.PrivateKey, createdAt int64) (domain.ObjectEnvelope, error) {
	if len(payload.VoterPublicKey) == 0 {
		payload.VoterPublicKey = []byte(voterPrivKey.Public().(ed25519.PublicKey))
	}
	unsignedPayload := payload
	unsignedPayload.Signature = nil
	unsigned := domain.EncodeTrusteeVotePayload(unsignedPayload)

	sig, err := s.sign(crypto.DomainTrusteeVoteSign, domain.ObjectTypeTrusteeVote, domain.ScopeTrusteeSelectionID, payload.TrusteeSelectionID, createdAt, unsigned, voterPrivKey)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}
	payload.Signature = sig

	encoded := domain.EncodeTrusteeVotePayload(payload)
	envelope, err := s.buildEnvelope(domain.ObjectTypeTrusteeVote, domain.ScopeTrusteeSelectionID, payload.TrusteeSelectionID, encoded, createdAt)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}

	return s.ingestLocal(ctx, envelope, validation.StatusValidForTally)
}

func (s *Service) BuildTrusteeSelectionResult(ctx context.Context, selectionID string, reporterPublicKey []byte, reporterPrivKey ed25519.PrivateKey) (domain.ObjectEnvelope, error) {
	inputs, err := s.store.TrusteeSelectionInputs(ctx, selectionID)
	if err != nil {
		return domain.ObjectEnvelope{}, fmt.Errorf("app build result: %w", err)
	}
	if !inputs.ElectionFound || !inputs.ElectionStatus.Final() || inputs.ElectionStatus != validation.StatusValid {
		return domain.ObjectEnvelope{}, fmt.Errorf("trustee selection election %s is not valid", selectionID)
	}

	validNominations := make(map[string]domain.TrusteeNominationPayload)
	for _, nomination := range inputs.Nominations {
		if nomination.Status == validation.StatusValid {
			validNominations[string(nomination.Payload.CandidatePublicKey)] = nomination.Payload
		}
	}
	if len(validNominations) == 0 {
		return domain.ObjectEnvelope{}, fmt.Errorf("no valid nominations for trustee selection %s", selectionID)
	}

	computed, err := validation.RecomputeTrusteeSelectionResult(selectionID, validNominations, inputs.Votes)
	if err != nil {
		return domain.ObjectEnvelope{}, fmt.Errorf("app recompute result: %w", err)
	}
	computed.ReporterPublicKey = append([]byte(nil), reporterPublicKey...)
	computed.Signature = ed25519.Sign(reporterPrivKey, crypto.Hash(crypto.DomainTrusteeSelectionResultSign, computed.ResultHash).Bytes())

	encoded := domain.EncodeTrusteeSelectionResultPayload(computed)
	envelope, err := s.buildEnvelope(domain.ObjectTypeTrusteeSelectionResult, domain.ScopeTrusteeSelectionID, selectionID, encoded, time.Now().UnixMilli())
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}

	return s.ingestLocal(ctx, envelope, validation.StatusValid)
}

func (s *Service) sign(signDomain crypto.Domain, objectType domain.ObjectType, scope domain.Scope, scopeID string, createdAt int64, unsignedPayload []byte, privKey ed25519.PrivateKey) ([]byte, error) {
	digest, err := crypto.SigningDigest(crypto.SigningContext{
		Domain:          signDomain,
		ProtocolVersion: protocolVersion,
		NetworkID:       s.networkID,
		ObjectType:      objectType,
		Scope:           scope,
		ScopeID:         scopeID,
		CreatedAt:       createdAt,
	}, unsignedPayload)
	if err != nil {
		return nil, fmt.Errorf("signing digest: %w", err)
	}
	return crypto.SignEd25519(privKey, digest)
}

func (s *Service) ingestLocal(ctx context.Context, envelope domain.ObjectEnvelope, expected validation.Status) (domain.ObjectEnvelope, error) {
	result, err := s.runner.IngestAndValidate(ctx, envelope)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}
	if result.Outcome.Status != expected {
		reason := result.Outcome.ValidationErrorReason
		if reason == "" {
			reason = result.Outcome.ValidationErrorCode
		}
		return domain.ObjectEnvelope{}, fmt.Errorf("locally created %s has status %s, expected %s: %s", envelope.ObjectType, result.Outcome.Status, expected, reason)
	}
	return envelope, nil
}

func (s *Service) buildEnvelope(objectType domain.ObjectType, scope domain.Scope, scopeID string, payload []byte, createdAt int64) (domain.ObjectEnvelope, error) {
	envelope := domain.ObjectEnvelope{
		ObjectType:      objectType,
		ProtocolVersion: protocolVersion,
		NetworkID:       s.networkID,
		Scope:           scope,
		ScopeID:         scopeID,
		Payload:         payload,
		Pow:             []byte("mvp-nonce"),
		CreatedAt:       createdAt,
	}
	canonicalBytes, err := domain.CanonicalObjectBytes(envelope)
	if err != nil {
		return domain.ObjectEnvelope{}, fmt.Errorf("canonical bytes: %w", err)
	}
	objectID, err := crypto.ObjectID(canonicalBytes)
	if err != nil {
		return domain.ObjectEnvelope{}, fmt.Errorf("object id: %w", err)
	}
	envelope.ObjectID = objectID.String()
	return envelope, nil
}

const databaseFileName = "librevote.sqlite"

func ReadNetworkID(dataDir string) (string, error) {
	dbPath := filepath.Join(dataDir, databaseFileName)
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return "", fmt.Errorf("no database at %s: run init first", dataDir)
	}
	dsn := (&url.URL{Scheme: "file", Path: dbPath}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return "", fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	rows, err := db.Query("SELECT key, value FROM schema_metadata")
	if err != nil {
		return "", fmt.Errorf("read schema metadata: %w", err)
	}
	defer rows.Close()

	values := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return "", fmt.Errorf("scan schema metadata: %w", err)
		}
		values[key] = value
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("iterate schema metadata: %w", err)
	}

	networkID, ok := values["network_id"]
	if !ok || networkID == "" {
		return "", errors.New("schema metadata missing network_id")
	}
	return networkID, nil
}
