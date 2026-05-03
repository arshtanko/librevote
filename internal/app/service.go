package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

type CreateElectionInviteInput struct {
	Title          string
	Options        []string
	InvitedPeerIDs []string
	CreatorPeerID  string
	IncludeSelf    bool
}

type ElectionInvitationStatus struct {
	ElectionID      string   `json:"election_id"`
	Title           string   `json:"title"`
	Options         []string `json:"options"`
	CreatorPeerID   string   `json:"creator_peer_id"`
	InvitedPeerIDs  []string `json:"invited_peer_ids"`
	AcceptedPeerIDs []string `json:"accepted_peer_ids"`
	DeclinedPeerIDs []string `json:"declined_peer_ids"`
	LocalInvited    bool     `json:"local_invited"`
	LocalAccepted   bool     `json:"local_accepted"`
	LocalDeclined   bool     `json:"local_declined"`
	Finalized       bool     `json:"finalized"`
}

type ElectionStatus struct {
	Available            bool                       `json:"available"`
	ElectionID           string                     `json:"election_id,omitempty"`
	Title                string                     `json:"title,omitempty"`
	Options              []string                   `json:"options,omitempty"`
	Invitations          []ElectionInvitationStatus `json:"invitations,omitempty"`
	PendingInvitations   []ElectionInvitationStatus `json:"pending_invitations,omitempty"`
	AcceptedVoterIDs     []string                   `json:"accepted_voter_ids,omitempty"`
	Finalized            bool                       `json:"finalized"`
	VoterIDs             []string                   `json:"voter_ids,omitempty"`
	EligibleVoterIDs     []string                   `json:"eligible_voter_ids,omitempty"`
	LocalVoterID         string                     `json:"local_voter_id,omitempty"`
	LocalVoterSignable   bool                       `json:"local_voter_signable"`
	LocalVoterVoted      bool                       `json:"local_voter_voted"`
	TallyKeySetAvailable bool                       `json:"tally_key_set_available"`
	BallotsSeen          int                        `json:"ballots_seen"`
	ValidBallotCount     int                        `json:"valid_ballot_count"`
	Message              string                     `json:"message,omitempty"`
}

type FrontendVoteResult struct {
	ElectionID string `json:"election_id"`
	VoterID    string `json:"voter_id"`
	Choice     string `json:"choice"`
	ObjectID   string `json:"object_id,omitempty"`
	Status     string `json:"status"`
	Idempotent bool   `json:"idempotent"`
	Message    string `json:"message"`
}

var (
	ErrFrontendElectionUnavailable    = errors.New("election is not available locally")
	ErrFrontendTallyKeySetUnavailable = errors.New("tally key set is not available locally")
	ErrFrontendVoterNotEligible       = errors.New("voter is not eligible for this election")
	ErrFrontendInvalidChoice          = errors.New("choice is not valid for this election")
)

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

// ListServableScopes returns distinct (scope, scope_id) pairs for all locally
// retained objects with servable validation statuses.
func (s *Service) ListServableScopes(ctx context.Context) ([]storage.ScopePair, error) {
	return s.store.ListServableScopes(ctx)
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

func (s *Service) electionStatus(ctx context.Context, localPeerID string) (ElectionStatus, error) {
	invitations, err := s.invitationStatuses(ctx, localPeerID)
	if err != nil {
		return ElectionStatus{}, err
	}
	pending := pendingInvitations(invitations)
	refs, err := s.ListServableObjectRefs(ctx, string(domain.ScopeNetwork), "", []string{string(domain.ObjectTypeAnonymousElection)})
	if err != nil {
		return ElectionStatus{}, fmt.Errorf("election status: %w", err)
	}
	if len(refs) == 0 {
		return ElectionStatus{Invitations: invitations, PendingInvitations: pending, Message: "no finalized election locally; create or accept an invitation"}, nil
	}

	envelope, err := s.LoadObjectEnvelope(ctx, refs[0].ObjectID)
	if err != nil {
		return ElectionStatus{}, fmt.Errorf("load election %s: %w", refs[0].ObjectID, err)
	}
	decoded, err := domain.DecodePayload(domain.ObjectTypeAnonymousElection, envelope.Payload)
	if err != nil {
		return ElectionStatus{}, fmt.Errorf("decode election %s: %w", refs[0].ObjectID, err)
	}
	election := decoded.(domain.AnonymousElectionPayload)

	inputs, err := s.GetTallyComputationInputs(ctx, election.ElectionID)
	if err != nil {
		return ElectionStatus{}, fmt.Errorf("load election tally inputs: %w", err)
	}
	message := ""
	if !inputs.TallyKeySetFound {
		message = "waiting for valid TallyKeySet"
	}
	eligibleVoterIDs := make([]string, 0, len(election.VoterAllowlist))
	for _, voter := range election.VoterAllowlist {
		eligibleVoterIDs = append(eligibleVoterIDs, voter.VoterID)
	}
	voterIDs := frontendSignableVoterIDs(election)
	if inputs.TallyKeySetFound && len(voterIDs) == 0 {
		message = "election is available, but this node has no local signing keys for eligible voters"
	} else if len(voterIDs) == 0 {
		message = strings.TrimSpace(message + "; no local signing keys for eligible voters")
	}
	validBallots := 0
	for _, ballot := range inputs.RetainedBallots {
		if ballot.Status == validation.StatusValidForTally {
			validBallots++
		}
	}

	return ElectionStatus{
		Available:            true,
		ElectionID:           election.ElectionID,
		Title:                election.Title,
		Options:              append([]string(nil), election.Options...),
		Invitations:          invitations,
		PendingInvitations:   pending,
		AcceptedVoterIDs:     acceptedVotersForElection(invitations, election.ElectionID),
		Finalized:            true,
		VoterIDs:             voterIDs,
		EligibleVoterIDs:     eligibleVoterIDs,
		TallyKeySetAvailable: inputs.TallyKeySetFound,
		BallotsSeen:          len(inputs.RetainedBallots),
		ValidBallotCount:     validBallots,
		Message:              message,
	}, nil
}

func (s *Service) ElectionStatus(ctx context.Context, localPeerID string) (ElectionStatus, error) {
	return s.electionStatus(ctx, localPeerID)
}

func (s *Service) ElectionStatusForLocalVoter(ctx context.Context, voterID string) (ElectionStatus, error) {
	voterID = strings.TrimSpace(voterID)
	status, err := s.ElectionStatus(ctx, voterID)
	if err != nil {
		return ElectionStatus{}, err
	}
	status.LocalVoterID = voterID
	if voterID == "" || !status.Available {
		return status, nil
	}
	for _, signable := range status.VoterIDs {
		if signable == voterID {
			status.LocalVoterSignable = true
			break
		}
	}
	if !status.TallyKeySetAvailable {
		return status, nil
	}
	inputs, err := s.store.TallyComputationInputs(ctx, status.ElectionID)
	if err != nil {
		return ElectionStatus{}, fmt.Errorf("local voter status inputs: %w", err)
	}
	for _, ballot := range inputs.RetainedBallots {
		if ballot.Status == validation.StatusValidForTally && ballot.Payload.VoterID == voterID {
			status.LocalVoterVoted = true
			break
		}
	}
	return status, nil
}

func (s *Service) StartMVPElectionForVoters(ctx context.Context, voterIDs []string) (ElectionStatus, error) {
	status, err := s.ElectionStatus(ctx, "")
	if err != nil {
		return ElectionStatus{}, err
	}
	if status.Available && status.TallyKeySetAvailable {
		return status, nil
	}
	if status.Available {
		return status, nil
	}

	voterIDs = normalizeVoterIDs(voterIDs)
	if len(voterIDs) == 0 {
		return ElectionStatus{}, fmt.Errorf("start election: at least one voter peer ID is required")
	}
	if err := s.createDeterministicMVPElectionObjects(ctx, voterIDs); err != nil {
		return ElectionStatus{}, err
	}
	return s.ElectionStatus(ctx, "")
}

func (s *Service) CreateElectionInvite(ctx context.Context, input CreateElectionInviteInput) (ElectionStatus, error) {
	creatorPeerID := strings.TrimSpace(input.CreatorPeerID)
	if creatorPeerID == "" {
		return ElectionStatus{}, errors.New("creator peer ID is required")
	}
	title := strings.TrimSpace(input.Title)
	if title == "" {
		return ElectionStatus{}, errors.New("election title is required")
	}
	options := normalizeOptions(input.Options)
	if len(options) < 2 {
		return ElectionStatus{}, errors.New("at least two election options are required")
	}
	invited := normalizeVoterIDs(input.InvitedPeerIDs)
	if input.IncludeSelf {
		invited = normalizeVoterIDs(append(invited, creatorPeerID))
	}
	if len(invited) == 0 {
		return ElectionStatus{}, errors.New("at least one invited peer is required")
	}
	createdAt := time.Now().UnixMilli()
	electionID := frontendElectionID(title, options, invited, creatorPeerID, createdAt)
	payload := domain.ElectionInvitePayload{
		ElectionID:     electionID,
		Title:          title,
		Options:        options,
		CreatorPeerID:  creatorPeerID,
		InvitedPeerIDs: invited,
		CreatedAt:      createdAt,
	}
	envelope, err := s.buildEnvelope(domain.ObjectTypeElectionInvite, domain.ScopeNetwork, "", domain.EncodeElectionInvitePayload(payload), createdAt)
	if err != nil {
		return ElectionStatus{}, err
	}
	if _, err := s.ingestLocal(ctx, envelope, validation.StatusValid); err != nil {
		return ElectionStatus{}, fmt.Errorf("create election invite: %w", err)
	}
	if input.IncludeSelf {
		if _, err := s.createElectionAcceptance(ctx, electionID, creatorPeerID); err != nil {
			return ElectionStatus{}, err
		}
	}
	return s.electionStatus(ctx, creatorPeerID)
}

func (s *Service) AcceptElectionInvite(ctx context.Context, electionID, voterPeerID string) (ElectionStatus, error) {
	voterPeerID = strings.TrimSpace(voterPeerID)
	if voterPeerID == "" {
		return ElectionStatus{}, errors.New("voter peer ID is required")
	}
	if _, err := s.createElectionAcceptance(ctx, strings.TrimSpace(electionID), voterPeerID); err != nil {
		return ElectionStatus{}, err
	}
	return s.electionStatus(ctx, voterPeerID)
}

func (s *Service) FinalizeElectionInvite(ctx context.Context, electionID, requesterPeerID string) (ElectionStatus, error) {
	electionID = strings.TrimSpace(electionID)
	requesterPeerID = strings.TrimSpace(requesterPeerID)
	if electionID == "" {
		return ElectionStatus{}, errors.New("election_id is required")
	}
	if s.anonymousElectionExists(ctx, electionID) {
		return s.electionStatus(ctx, requesterPeerID)
	}
	invite, accepted, err := s.inviteWithAcceptedVoters(ctx, electionID)
	if err != nil {
		return ElectionStatus{}, err
	}
	if requesterPeerID != "" && invite.CreatorPeerID != requesterPeerID {
		return ElectionStatus{}, errors.New("only the election creator can finalize")
	}
	if len(accepted) == 0 && len(invite.InvitedPeerIDs) > 0 {
		return ElectionStatus{}, errors.New("cannot finalize election without accepted voters")
	}
	if !s.allInvitedResponded(ctx, electionID, invite.InvitedPeerIDs) {
		return ElectionStatus{}, errors.New("cannot finalize until all invited peers have responded (accepted or declined)")
	}
	if err := s.createDeterministicMVPElectionObjectsForInvite(ctx, invite, accepted); err != nil {
		return ElectionStatus{}, err
	}
	return s.electionStatus(ctx, invite.CreatorPeerID)
}

func (s *Service) allInvitedResponded(ctx context.Context, electionID string, invitedPeerIDs []string) bool {
	statuses, err := s.invitationStatuses(ctx, "")
	if err != nil {
		return false
	}
	for _, candidate := range statuses {
		if candidate.ElectionID != electionID {
			continue
		}
		responded := make(map[string]bool)
		for _, id := range candidate.AcceptedPeerIDs {
			responded[id] = true
		}
		for _, id := range candidate.DeclinedPeerIDs {
			responded[id] = true
		}
		for _, id := range invitedPeerIDs {
			if !responded[id] {
				return false
			}
		}
		return true
	}
	return false
}

func (s *Service) DeclineElectionInvite(ctx context.Context, electionID, voterPeerID string) (ElectionStatus, error) {
	electionID = strings.TrimSpace(electionID)
	voterPeerID = strings.TrimSpace(voterPeerID)
	if electionID == "" {
		return ElectionStatus{}, errors.New("election_id is required")
	}
	if voterPeerID == "" {
		return ElectionStatus{}, errors.New("voter peer ID is required")
	}
	if s.anonymousElectionExists(ctx, electionID) {
		return s.electionStatus(ctx, voterPeerID)
	}
	if _, err := s.createElectionDecline(ctx, electionID, voterPeerID); err != nil {
		return ElectionStatus{}, err
	}
	return s.electionStatus(ctx, voterPeerID)
}

func (s *Service) createElectionAcceptance(ctx context.Context, electionID, voterPeerID string) (domain.ObjectEnvelope, error) {
	if electionID == "" {
		return domain.ObjectEnvelope{}, errors.New("election_id is required")
	}
	refs, err := s.ListServableObjectRefs(ctx, string(domain.ScopeNetwork), "", []string{string(domain.ObjectTypeElectionAcceptance)})
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}
	for _, ref := range refs {
		envelope, err := s.LoadObjectEnvelope(ctx, ref.ObjectID)
		if err != nil {
			return domain.ObjectEnvelope{}, err
		}
		decoded, err := domain.DecodePayload(domain.ObjectTypeElectionAcceptance, envelope.Payload)
		if err != nil {
			return domain.ObjectEnvelope{}, err
		}
		acceptance := decoded.(domain.ElectionAcceptancePayload)
		if acceptance.ElectionID == electionID && acceptance.VoterPeerID == voterPeerID {
			return envelope, nil
		}
	}
	createdAt := time.Now().UnixMilli()
	payload := domain.ElectionAcceptancePayload{ElectionID: electionID, VoterPeerID: voterPeerID, CreatedAt: createdAt}
	envelope, err := s.buildEnvelope(domain.ObjectTypeElectionAcceptance, domain.ScopeNetwork, "", domain.EncodeElectionAcceptancePayload(payload), createdAt)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}
	return s.ingestLocal(ctx, envelope, validation.StatusValid)
}

func (s *Service) createElectionDecline(ctx context.Context, electionID, voterPeerID string) (domain.ObjectEnvelope, error) {
	if electionID == "" {
		return domain.ObjectEnvelope{}, errors.New("election_id is required")
	}
	refs, err := s.ListServableObjectRefs(ctx, string(domain.ScopeNetwork), "", []string{string(domain.ObjectTypeElectionDecline)})
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}
	for _, ref := range refs {
		envelope, err := s.LoadObjectEnvelope(ctx, ref.ObjectID)
		if err != nil {
			return domain.ObjectEnvelope{}, err
		}
		decoded, err := domain.DecodePayload(domain.ObjectTypeElectionDecline, envelope.Payload)
		if err != nil {
			return domain.ObjectEnvelope{}, err
		}
		decline := decoded.(domain.ElectionDeclinePayload)
		if decline.ElectionID == electionID && decline.VoterPeerID == voterPeerID {
			return envelope, nil
		}
	}
	createdAt := time.Now().UnixMilli()
	payload := domain.ElectionDeclinePayload{ElectionID: electionID, VoterPeerID: voterPeerID, CreatedAt: createdAt}
	envelope, err := s.buildEnvelope(domain.ObjectTypeElectionDecline, domain.ScopeNetwork, "", domain.EncodeElectionDeclinePayload(payload), createdAt)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}
	return s.ingestLocal(ctx, envelope, validation.StatusValid)
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

func (s *Service) CreateAnonymousElection(ctx context.Context, payload domain.AnonymousElectionPayload, creatorPrivKey ed25519.PrivateKey, createdAt int64) (domain.ObjectEnvelope, error) {
	if len(payload.CreatorPublicKey) == 0 {
		payload.CreatorPublicKey = []byte(creatorPrivKey.Public().(ed25519.PublicKey))
	}
	unsignedPayload := payload
	unsignedPayload.Signature = nil
	unsigned := domain.EncodeAnonymousElectionPayload(unsignedPayload)

	sig, err := s.sign(crypto.DomainAnonymousElectionSign, domain.ObjectTypeAnonymousElection, domain.ScopeNetwork, "", createdAt, unsigned, creatorPrivKey)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}
	payload.Signature = sig

	encoded := domain.EncodeAnonymousElectionPayload(payload)
	envelope, err := s.buildEnvelope(domain.ObjectTypeAnonymousElection, domain.ScopeNetwork, "", encoded, createdAt)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}

	return s.ingestLocal(ctx, envelope, validation.StatusValid)
}

func (s *Service) CreateTrusteeConsent(ctx context.Context, payload domain.TrusteeConsentPayload, trusteePrivKey ed25519.PrivateKey, createdAt int64) (domain.ObjectEnvelope, error) {
	if len(payload.TrusteePublicKey) == 0 {
		payload.TrusteePublicKey = []byte(trusteePrivKey.Public().(ed25519.PublicKey))
	}
	unsignedPayload := payload
	unsignedPayload.Signature = nil
	unsigned := domain.EncodeTrusteeConsentPayload(unsignedPayload)

	sig, err := s.sign(crypto.DomainTrusteeConsentSign, domain.ObjectTypeTrusteeConsent, domain.ScopeElectionID, payload.ElectionID, createdAt, unsigned, trusteePrivKey)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}
	payload.Signature = sig

	encoded := domain.EncodeTrusteeConsentPayload(payload)
	envelope, err := s.buildEnvelope(domain.ObjectTypeTrusteeConsent, domain.ScopeElectionID, payload.ElectionID, encoded, createdAt)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}

	return s.ingestLocal(ctx, envelope, validation.StatusValid)
}

func (s *Service) CreateTallyKeyContribution(ctx context.Context, electionID string, trusteePublicKey, trusteeTallySetupPublicKey []byte, finalTrustees []domain.TrusteeCandidate, trusteePrivKey ed25519.PrivateKey, createdAt int64) (domain.ObjectEnvelope, error) {
	if len(trusteePublicKey) == 0 {
		trusteePublicKey = []byte(trusteePrivKey.Public().(ed25519.PublicKey))
	}

	commitment := domain.DKGCommitment{
		SenderTrusteePublicKey: append([]byte(nil), trusteePublicKey...),
		CoefficientIndex:       0,
		Commitment:             placeholderBytes("dkg-commit", trusteePublicKey, 32),
	}

	shares := make([]domain.DKGEncryptedShare, 0, len(finalTrustees))
	for i, trustee := range finalTrustees {
		setupKeyID, err := crypto.KeyID(crypto.KeyTypeTrusteeTallySetup, trustee.TrusteeTallySetupKey)
		if err != nil {
			return domain.ObjectEnvelope{}, fmt.Errorf("tally key contribution key id: %w", err)
		}
		shares = append(shares, domain.DKGEncryptedShare{
			SenderTrusteePublicKey:    append([]byte(nil), trusteePublicKey...),
			RecipientTrusteePublicKey: append([]byte(nil), trustee.TrusteePublicKey...),
			RecipientTallySetupKeyID:  append([]byte(nil), setupKeyID[:]...),
			RecipientIndex:            int64(i + 1),
			EncryptedShare:            placeholderBytes("dkg-share", append(trusteePublicKey, trustee.TrusteePublicKey...), 16),
			ShareEncryptionProof:      placeholderBytes("dkg-proof", append(trusteePublicKey, trustee.TrusteePublicKey...), 16),
		})
	}

	payload := domain.TallyKeyContributionPayload{
		ElectionID:                 electionID,
		TrusteePublicKey:           append([]byte(nil), trusteePublicKey...),
		TrusteeTallySetupPublicKey: append([]byte(nil), trusteeTallySetupPublicKey...),
		DKGCommitments:             []domain.DKGCommitment{commitment},
		DKGEncryptedShares:         shares,
		SetupProof:                 placeholderBytes("dkg-setup-proof", trusteePublicKey, 32),
	}

	unsignedPayload := payload
	unsignedPayload.Signature = nil
	unsigned := domain.EncodeTallyKeyContributionPayload(unsignedPayload)

	sig, err := s.sign(crypto.DomainTallyKeyContributionSign, domain.ObjectTypeTallyKeyContribution, domain.ScopeElectionID, electionID, createdAt, unsigned, trusteePrivKey)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}
	payload.Signature = sig

	encoded := domain.EncodeTallyKeyContributionPayload(payload)
	envelope, err := s.buildEnvelope(domain.ObjectTypeTallyKeyContribution, domain.ScopeElectionID, electionID, encoded, createdAt)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}

	return s.ingestLocal(ctx, envelope, validation.StatusValid)
}

func (s *Service) BuildTallyKeySet(ctx context.Context, electionID string, reporterPublicKey []byte, reporterPrivKey ed25519.PrivateKey) (domain.ObjectEnvelope, error) {
	inputs, err := s.store.ElectionActivationInputs(ctx, electionID)
	if err != nil {
		return domain.ObjectEnvelope{}, fmt.Errorf("app build tally key set: %w", err)
	}
	if !inputs.ElectionFound || !inputs.ElectionStatus.Final() || inputs.ElectionStatus != validation.StatusValid {
		return domain.ObjectEnvelope{}, fmt.Errorf("anonymous election %s is not valid", electionID)
	}
	if !inputs.ResultFound || !inputs.ResultStatus.Final() || inputs.ResultStatus != validation.StatusValid {
		return domain.ObjectEnvelope{}, fmt.Errorf("trustee selection result for election %s is not valid", electionID)
	}

	if validation.HasDuplicateValidTrusteeConsent(inputs.Consents) {
		return domain.ObjectEnvelope{}, fmt.Errorf("duplicate valid trustee consents for election %s", electionID)
	}
	finalSet, consentIDs, ok := validation.DeriveFinalTrusteeSet(inputs.Result, inputs.Consents)
	if !ok {
		return domain.ObjectEnvelope{}, fmt.Errorf("cannot derive final trustee set for election %s", electionID)
	}

	contributionIDs, commitments, setupProofs, contributionIssue, contributionDependencyID := validation.RetainedContributionsForTrustees(electionID, finalSet, inputs.Contributions)
	if contributionIssue != "" {
		return domain.ObjectEnvelope{}, fmt.Errorf("contributions issue for election %s: %s (%s)", electionID, contributionIssue, contributionDependencyID)
	}

	trusteeSetHash := validation.ComputeTrusteeSetHash(finalSet)
	tallyPublicKey := validation.ComputeTallyPublicKey(commitments)

	resultHash := inputs.Election.TrusteeSelectionResultHash
	payload := domain.TallyKeySetPayload{
		ElectionID:                    electionID,
		TrusteeSelectionResultHash:    append([]byte(nil), resultHash...),
		TrusteeSet:                    append([]domain.TrusteeCandidate(nil), finalSet...),
		TrusteeConsentObjectIDs:       append([]string(nil), consentIDs...),
		TallyKeyContributionObjectIDs: append([]string(nil), contributionIDs...),
		TrusteeSetHash:                append([]byte(nil), trusteeSetHash...),
		ThresholdT:                    domain.ThresholdV1,
		TrusteeCountN:                 domain.TrusteeCountV1,
		TallyPublicKey:                append([]byte(nil), tallyPublicKey...),
		TrusteeKeyCommitments:         deepCopyBytesSlice(commitments),
		SetupProofs:                   deepCopyBytesSlice(setupProofs),
	}

	activationHash := validation.ComputeTallyKeySetHash(payload.ElectionID, payload.TrusteeSelectionResultHash, finalSet, consentIDs, contributionIDs, commitments, tallyPublicKey)
	payload.TallyKeySetHash = append([]byte(nil), activationHash...)
	payload.ReporterPublicKey = append([]byte(nil), reporterPublicKey...)

	unsignedPayload := payload
	unsignedPayload.Signature = nil
	unsigned := domain.EncodeTallyKeySetPayload(unsignedPayload)

	createdAt := time.Now().UnixMilli()
	digest, err := crypto.SigningDigest(crypto.SigningContext{
		Domain:          crypto.DomainTallyKeySetSign,
		ProtocolVersion: protocolVersion,
		NetworkID:       s.networkID,
		ObjectType:      domain.ObjectTypeTallyKeySet,
		Scope:           domain.ScopeElectionID,
		ScopeID:         electionID,
		CreatedAt:       createdAt,
	}, unsigned)
	if err != nil {
		return domain.ObjectEnvelope{}, fmt.Errorf("tally key set signing digest: %w", err)
	}
	sig, err := crypto.SignEd25519(reporterPrivKey, digest)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}
	payload.Signature = sig

	encoded := domain.EncodeTallyKeySetPayload(payload)
	envelope, err := s.buildEnvelope(domain.ObjectTypeTallyKeySet, domain.ScopeElectionID, electionID, encoded, createdAt)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}

	return s.ingestLocal(ctx, envelope, validation.StatusValid)
}

func (s *Service) CastBallot(ctx context.Context, electionID, voterID, choice string, voterPrivKey ed25519.PrivateKey, createdAt int64) (domain.ObjectEnvelope, error) {
	payload := domain.AnonymousBallotPayload{
		ElectionID:     electionID,
		Choice:         choice,
		VoterID:        voterID,
		VoterPublicKey: []byte(voterPrivKey.Public().(ed25519.PublicKey)),
	}
	unsignedPayload := payload
	unsignedPayload.Signature = nil
	unsigned := domain.EncodeAnonymousBallotPayload(unsignedPayload)

	sig, err := s.sign(crypto.DomainAnonymousBallotSign, domain.ObjectTypeAnonymousBallot, domain.ScopeElectionID, electionID, createdAt, unsigned, voterPrivKey)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}
	payload.Signature = sig

	encoded := domain.EncodeAnonymousBallotPayload(payload)
	envelope, err := s.buildEnvelope(domain.ObjectTypeAnonymousBallot, domain.ScopeElectionID, electionID, encoded, createdAt)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}

	return s.ingestLocal(ctx, envelope, validation.StatusValidForTally)
}

func (s *Service) CastFrontendVote(ctx context.Context, voterID, choice string) (FrontendVoteResult, error) {
	voterID = strings.TrimSpace(voterID)
	choice = strings.TrimSpace(choice)
	if voterID == "" {
		return FrontendVoteResult{}, fmt.Errorf("%w: voter_id is required", ErrFrontendVoterNotEligible)
	}
	if choice == "" {
		return FrontendVoteResult{}, fmt.Errorf("%w: choice is required", ErrFrontendInvalidChoice)
	}

	election, err := s.currentAnonymousElection(ctx)
	if err != nil {
		return FrontendVoteResult{}, err
	}
	inputs, err := s.store.TallyComputationInputs(ctx, election.ElectionID)
	if err != nil {
		return FrontendVoteResult{}, fmt.Errorf("frontend vote inputs: %w", err)
	}
	if !inputs.ElectionFound || !inputs.ElectionStatus.Final() || inputs.ElectionStatus != validation.StatusValid {
		return FrontendVoteResult{}, ErrFrontendElectionUnavailable
	}
	if !inputs.TallyKeySetFound {
		return FrontendVoteResult{}, ErrFrontendTallyKeySetUnavailable
	}

	voterPriv := deterministicEd25519Priv(voterID)
	voterPub := voterPriv.Public().(ed25519.PublicKey)
	if !frontendVoterEligible(election, voterID, voterPub) {
		return FrontendVoteResult{}, fmt.Errorf("%w: %s", ErrFrontendVoterNotEligible, voterID)
	}
	if !choiceAllowed(election.Options, choice) {
		return FrontendVoteResult{}, fmt.Errorf("%w: %s", ErrFrontendInvalidChoice, choice)
	}

	for _, ballot := range inputs.RetainedBallots {
		if ballot.Status == validation.StatusValidForTally && ballot.Payload.VoterID == voterID {
			return FrontendVoteResult{
				ElectionID: election.ElectionID,
				VoterID:    voterID,
				Choice:     ballot.Payload.Choice,
				ObjectID:   ballot.ObjectID,
				Status:     ballot.Status.String(),
				Idempotent: true,
				Message:    "voter already has a valid ballot locally",
			}, nil
		}
	}

	createdAt := time.Now().UnixMilli()
	if createdAt < election.VotingStartsAt || createdAt > election.VotingEndsAt {
		createdAt = election.VotingStartsAt
	}
	envelope, err := s.CastBallot(ctx, election.ElectionID, voterID, choice, voterPriv, createdAt)
	if err != nil {
		return FrontendVoteResult{}, fmt.Errorf("cast frontend vote: %w", err)
	}
	status, _, err := s.ValidationStatus(ctx, envelope.ObjectID)
	if err != nil {
		return FrontendVoteResult{}, fmt.Errorf("frontend vote status: %w", err)
	}
	return FrontendVoteResult{
		ElectionID: election.ElectionID,
		VoterID:    voterID,
		Choice:     choice,
		ObjectID:   envelope.ObjectID,
		Status:     status.String(),
		Message:    "vote cast",
	}, nil
}

func (s *Service) BuildTallyResult(ctx context.Context, electionID string, reporterPublicKey []byte, reporterPrivKey ed25519.PrivateKey, createdAt int64) (domain.ObjectEnvelope, error) {
	inputs, err := s.store.TallyComputationInputs(ctx, electionID)
	if err != nil {
		return domain.ObjectEnvelope{}, fmt.Errorf("app build tally result: %w", err)
	}
	if !inputs.ElectionFound || !inputs.ElectionStatus.Final() || inputs.ElectionStatus != validation.StatusValid {
		return domain.ObjectEnvelope{}, fmt.Errorf("anonymous election %s is not valid", electionID)
	}
	if !inputs.TallyKeySetFound {
		return domain.ObjectEnvelope{}, fmt.Errorf("no valid TallyKeySet for election %s", electionID)
	}

	computed := validation.ComputeLocalTallyResultForService(electionID, inputs.TallyKeySetHash, inputs.RetainedBallots, inputs.Election.Options)
	computed.ReporterPublicKey = append([]byte(nil), reporterPublicKey...)

	unsignedPayload := computed
	unsignedPayload.Signature = nil
	unsigned := domain.EncodeTallyResultPayload(unsignedPayload)
	digest, err := crypto.SigningDigest(crypto.SigningContext{
		Domain:          crypto.DomainTallyResultSign,
		ProtocolVersion: protocolVersion,
		NetworkID:       s.networkID,
		ObjectType:      domain.ObjectTypeTallyResult,
		Scope:           domain.ScopeElectionID,
		ScopeID:         electionID,
		CreatedAt:       createdAt,
	}, unsigned)
	if err != nil {
		return domain.ObjectEnvelope{}, fmt.Errorf("tally result signing digest: %w", err)
	}
	sig, err := crypto.SignEd25519(reporterPrivKey, digest)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}
	computed.Signature = sig

	encoded := domain.EncodeTallyResultPayload(computed)
	envelope, err := s.buildEnvelope(domain.ObjectTypeTallyResult, domain.ScopeElectionID, electionID, encoded, createdAt)
	if err != nil {
		return domain.ObjectEnvelope{}, err
	}

	return s.ingestLocal(ctx, envelope, validation.StatusValid)
}

func (s *Service) GetTallyComputationInputs(ctx context.Context, electionID string) (validation.TallyComputationInputs, error) {
	return s.store.TallyComputationInputs(ctx, electionID)
}

func (s *Service) TrusteeSelectionResultHash(ctx context.Context, selectionID string) ([]byte, error) {
	resultHash, err := s.store.TrusteeSelectionResultHash(ctx, selectionID)
	if err != nil {
		return nil, fmt.Errorf("trustee selection result hash: %w", err)
	}
	return resultHash, nil
}

func (s *Service) LoadAnonymousElection(ctx context.Context, electionID string) (domain.AnonymousElectionPayload, error) {
	inputs, err := s.store.ElectionActivationInputs(ctx, electionID)
	if err != nil {
		return domain.AnonymousElectionPayload{}, fmt.Errorf("load anonymous election: %w", err)
	}
	if !inputs.ElectionFound {
		return domain.AnonymousElectionPayload{}, fmt.Errorf("anonymous election %s not found", electionID)
	}
	return inputs.Election, nil
}

func (s *Service) currentAnonymousElection(ctx context.Context) (domain.AnonymousElectionPayload, error) {
	refs, err := s.ListServableObjectRefs(ctx, string(domain.ScopeNetwork), "", []string{string(domain.ObjectTypeAnonymousElection)})
	if err != nil {
		return domain.AnonymousElectionPayload{}, fmt.Errorf("load current election: %w", err)
	}
	if len(refs) == 0 {
		return domain.AnonymousElectionPayload{}, ErrFrontendElectionUnavailable
	}
	envelope, err := s.LoadObjectEnvelope(ctx, refs[0].ObjectID)
	if err != nil {
		return domain.AnonymousElectionPayload{}, fmt.Errorf("load election %s: %w", refs[0].ObjectID, err)
	}
	decoded, err := domain.DecodePayload(domain.ObjectTypeAnonymousElection, envelope.Payload)
	if err != nil {
		return domain.AnonymousElectionPayload{}, fmt.Errorf("decode election %s: %w", refs[0].ObjectID, err)
	}
	return decoded.(domain.AnonymousElectionPayload), nil
}

func frontendVoterEligible(election domain.AnonymousElectionPayload, voterID string, voterPublicKey ed25519.PublicKey) bool {
	for _, voter := range election.VoterAllowlist {
		if voter.VoterID == voterID && bytes.Equal(voter.VoterSigningPublicKey, voterPublicKey) {
			return true
		}
	}
	return false
}

func frontendSignableVoterIDs(election domain.AnonymousElectionPayload) []string {
	voterIDs := make([]string, 0, len(election.VoterAllowlist))
	for _, voter := range election.VoterAllowlist {
		if bytes.Equal(voter.VoterSigningPublicKey, deterministicEd25519Pub(voter.VoterID)) {
			voterIDs = append(voterIDs, voter.VoterID)
		}
	}
	return voterIDs
}

func choiceAllowed(options []string, choice string) bool {
	for _, option := range options {
		if option == choice {
			return true
		}
	}
	return false
}

func (s *Service) RevalidateDependents(ctx context.Context, objectID string) error {
	deps, err := s.store.ObjectsWaitingOnDependency(ctx, storage.Dependency{Type: "object_id", ID: objectID})
	if err != nil {
		return fmt.Errorf("find dependents of %s: %w", objectID, err)
	}
	for _, depID := range deps {
		if depID == objectID {
			continue
		}
		if _, err := s.runner.RevalidateObjectID(ctx, depID); err != nil {
			return fmt.Errorf("revalidate dependent %s: %w", depID, err)
		}
	}
	return nil
}

func (s *Service) FinalTrusteeSet(ctx context.Context, electionID string) ([]domain.TrusteeCandidate, error) {
	inputs, err := s.store.ElectionActivationInputs(ctx, electionID)
	if err != nil {
		return nil, fmt.Errorf("final trustee set: %w", err)
	}
	if !inputs.ElectionFound || !inputs.ElectionStatus.Final() || inputs.ElectionStatus != validation.StatusValid {
		return nil, fmt.Errorf("anonymous election %s is not valid", electionID)
	}
	if !inputs.ResultFound || !inputs.ResultStatus.Final() || inputs.ResultStatus != validation.StatusValid {
		return nil, fmt.Errorf("trustee selection result for election %s is not valid", electionID)
	}
	if validation.HasDuplicateValidTrusteeConsent(inputs.Consents) {
		return nil, fmt.Errorf("duplicate valid trustee consents for election %s", electionID)
	}
	finalSet, _, ok := validation.DeriveFinalTrusteeSet(inputs.Result, inputs.Consents)
	if !ok {
		return nil, fmt.Errorf("cannot derive final trustee set for election %s", electionID)
	}
	return finalSet, nil
}

func (s *Service) createDeterministicMVPElectionObjects(ctx context.Context, voterIDs []string) error {
	const (
		selectionID = "mvp-trustee-selection"
		electionID  = "mvp-election"
	)
	candidateNames := []string{"trustee-1", "trustee-2", "trustee-3"}

	voters := make([]domain.VoterEntry, len(voterIDs))
	for i, name := range voterIDs {
		voters[i] = domain.VoterEntry{
			VoterID:                  name,
			VoterSigningPublicKey:    deterministicEd25519Pub(name),
			VoterEncryptionPublicKey: deterministicBytes(name+".enc", 32),
		}
	}

	creatorPriv := deterministicEd25519Priv("creator")
	selectionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: selectionID,
		NetworkID:          s.networkID,
		Title:              "MVP Trustee Selection",
		Description:        "Deterministic local MVP trustee selection",
		VoterAllowlist:     voters,
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
	if _, err := s.CreateTrusteeSelectionElection(ctx, selectionPayload, creatorPriv, 500); err != nil {
		return fmt.Errorf("start election trustee selection: %w", err)
	}

	candidateKeys := make([]ed25519.PrivateKey, len(candidateNames))
	selectedCandidateKeys := make([][]byte, len(candidateNames))
	for i, name := range candidateNames {
		candidateKeys[i] = deterministicEd25519Priv(name)
		candidatePub := deterministicEd25519Pub(name)
		selectedCandidateKeys[i] = candidatePub
		payload := domain.TrusteeNominationPayload{
			TrusteeSelectionID:           selectionID,
			CandidatePublicKey:           candidatePub,
			CandidateBlindTokenPublicKey: deterministicBytes(name+".blind", 32),
			CandidateNodePeerID:          "mvp-local-peer",
			Statement:                    "Deterministic MVP trustee candidate " + name,
		}
		if _, err := s.CreateTrusteeNomination(ctx, payload, candidateKeys[i], 1500); err != nil {
			return fmt.Errorf("start election nomination %s: %w", name, err)
		}
	}

	voterPriv := deterministicEd25519Priv(voterIDs[0])
	votePayload := domain.TrusteeVotePayload{
		TrusteeSelectionID:    selectionID,
		VoterPublicKey:        deterministicEd25519Pub(voterIDs[0]),
		SelectedCandidateKeys: selectedCandidateKeys,
	}
	if _, err := s.CreateTrusteeVote(ctx, votePayload, voterPriv, 3500); err != nil {
		return fmt.Errorf("start election trustee vote: %w", err)
	}

	reporterPriv := deterministicEd25519Priv("reporter")
	reporterPub := deterministicEd25519Pub("reporter")
	resultEnv, err := s.BuildTrusteeSelectionResult(ctx, selectionID, reporterPub, reporterPriv)
	if err != nil {
		return fmt.Errorf("start election trustee result: %w", err)
	}
	decodedResult, err := domain.DecodePayload(domain.ObjectTypeTrusteeSelectionResult, resultEnv.Payload)
	if err != nil {
		return fmt.Errorf("start election decode trustee result: %w", err)
	}
	result := decodedResult.(domain.TrusteeSelectionResultPayload)

	electionPayload := domain.AnonymousElectionPayload{
		ElectionID:                 electionID,
		NetworkID:                  s.networkID,
		Title:                      "LibreVote MVP Election",
		Description:                "Deterministic local MVP election",
		Options:                    []string{"yes", "no"},
		VoterAllowlist:             voters,
		TrusteeSelectionID:         selectionID,
		TrusteeSelectionResultHash: result.ResultHash,
		ThresholdT:                 domain.ThresholdV1,
		TrusteeCountN:              domain.TrusteeCountV1,
		EligibilityScheme:          domain.EligibilitySchemeBlindTokenV1,
		IssuanceStartsAt:           7000,
		IssuanceEndsAt:             8000,
		VotingStartsAt:             9000,
		VotingEndsAt:               10000,
		TallyStartsAt:              11000,
	}
	if _, err := s.CreateAnonymousElection(ctx, electionPayload, creatorPriv, 6000); err != nil {
		return fmt.Errorf("start election anonymous election: %w", err)
	}

	electionHash := validation.ComputeElectionParametersHash(electionPayload)
	for i, name := range candidateNames {
		payload := domain.TrusteeConsentPayload{
			TrusteeSelectionID:         selectionID,
			TrusteeSelectionResultHash: result.ResultHash,
			ElectionID:                 electionID,
			ElectionParametersHash:     electionHash,
			TrusteePublicKey:           deterministicEd25519Pub(name),
			TrusteeTallySetupPublicKey: deterministicBytes(name+".tally-setup", 32),
			ThresholdT:                 domain.ThresholdV1,
			TrusteeCountN:              domain.TrusteeCountV1,
		}
		if _, err := s.CreateTrusteeConsent(ctx, payload, candidateKeys[i], 5500); err != nil {
			return fmt.Errorf("start election trustee consent %s: %w", name, err)
		}
	}

	finalTrustees, err := s.FinalTrusteeSet(ctx, electionID)
	if err != nil {
		return fmt.Errorf("start election final trustees: %w", err)
	}
	for i, name := range candidateNames {
		if _, err := s.CreateTallyKeyContribution(ctx, electionID, deterministicEd25519Pub(name), deterministicBytes(name+".tally-setup", 32), finalTrustees, candidateKeys[i], 8000); err != nil {
			return fmt.Errorf("start election tally key contribution %s: %w", name, err)
		}
	}
	if _, err := s.BuildTallyKeySet(ctx, electionID, reporterPub, reporterPriv); err != nil {
		return fmt.Errorf("start election tally key set: %w", err)
	}
	return nil
}

func (s *Service) createDeterministicMVPElectionObjectsForInvite(ctx context.Context, invite domain.ElectionInvitePayload, voterIDs []string) error {
	const selectionID = "invite-trustee-selection"
	candidateNames := []string{"trustee-1", "trustee-2", "trustee-3"}

	voters := make([]domain.VoterEntry, len(voterIDs))
	for i, name := range voterIDs {
		voters[i] = domain.VoterEntry{
			VoterID:                  name,
			VoterSigningPublicKey:    deterministicEd25519Pub(name),
			VoterEncryptionPublicKey: deterministicBytes(name+".enc", 32),
		}
	}

	creatorPriv := deterministicEd25519Priv("creator")
	selectionPayload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: selectionID,
		NetworkID:          s.networkID,
		Title:              invite.Title,
		Description:        "Invitation-based trustee selection",
		VoterAllowlist:     voters,
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
	if _, err := s.CreateTrusteeSelectionElection(ctx, selectionPayload, creatorPriv, 500); err != nil {
		return fmt.Errorf("invite election trustee selection: %w", err)
	}

	candidateKeys := make([]ed25519.PrivateKey, len(candidateNames))
	selectedCandidateKeys := make([][]byte, len(candidateNames))
	for i, name := range candidateNames {
		candidateKeys[i] = deterministicEd25519Priv(name)
		candidatePub := deterministicEd25519Pub(name)
		selectedCandidateKeys[i] = candidatePub
		payload := domain.TrusteeNominationPayload{
			TrusteeSelectionID:           selectionID,
			CandidatePublicKey:           candidatePub,
			CandidateBlindTokenPublicKey: deterministicBytes(name+".blind", 32),
			CandidateNodePeerID:          "invite-local-peer",
			Statement:                    "Deterministic invite trustee candidate " + name,
		}
		if _, err := s.CreateTrusteeNomination(ctx, payload, candidateKeys[i], 1500); err != nil {
			return fmt.Errorf("invite election nomination %s: %w", name, err)
		}
	}

	voterPriv := deterministicEd25519Priv(voterIDs[0])
	votePayload := domain.TrusteeVotePayload{
		TrusteeSelectionID:    selectionID,
		VoterPublicKey:        deterministicEd25519Pub(voterIDs[0]),
		SelectedCandidateKeys: selectedCandidateKeys,
	}
	if _, err := s.CreateTrusteeVote(ctx, votePayload, voterPriv, 3500); err != nil {
		return fmt.Errorf("invite election trustee vote: %w", err)
	}

	reporterPriv := deterministicEd25519Priv("reporter")
	reporterPub := deterministicEd25519Pub("reporter")
	resultEnv, err := s.BuildTrusteeSelectionResult(ctx, selectionID, reporterPub, reporterPriv)
	if err != nil {
		return fmt.Errorf("invite election trustee result: %w", err)
	}
	decodedResult, err := domain.DecodePayload(domain.ObjectTypeTrusteeSelectionResult, resultEnv.Payload)
	if err != nil {
		return fmt.Errorf("invite election decode trustee result: %w", err)
	}
	result := decodedResult.(domain.TrusteeSelectionResultPayload)

	electionPayload := domain.AnonymousElectionPayload{
		ElectionID:                 invite.ElectionID,
		NetworkID:                  s.networkID,
		Title:                      invite.Title,
		Description:                "Invitation-based election",
		Options:                    invite.Options,
		VoterAllowlist:             voters,
		TrusteeSelectionID:         selectionID,
		TrusteeSelectionResultHash: result.ResultHash,
		ThresholdT:                 domain.ThresholdV1,
		TrusteeCountN:              domain.TrusteeCountV1,
		EligibilityScheme:          domain.EligibilitySchemeBlindTokenV1,
		IssuanceStartsAt:           7000,
		IssuanceEndsAt:             8000,
		VotingStartsAt:             9000,
		VotingEndsAt:               10000,
		TallyStartsAt:              11000,
	}
	if _, err := s.CreateAnonymousElection(ctx, electionPayload, creatorPriv, 6000); err != nil {
		return fmt.Errorf("invite election anonymous election: %w", err)
	}

	electionHash := validation.ComputeElectionParametersHash(electionPayload)
	for i, name := range candidateNames {
		payload := domain.TrusteeConsentPayload{
			TrusteeSelectionID:         selectionID,
			TrusteeSelectionResultHash: result.ResultHash,
			ElectionID:                 invite.ElectionID,
			ElectionParametersHash:     electionHash,
			TrusteePublicKey:           deterministicEd25519Pub(name),
			TrusteeTallySetupPublicKey: deterministicBytes(name+".tally-setup", 32),
			ThresholdT:                 domain.ThresholdV1,
			TrusteeCountN:              domain.TrusteeCountV1,
		}
		if _, err := s.CreateTrusteeConsent(ctx, payload, candidateKeys[i], 5500); err != nil {
			return fmt.Errorf("invite election trustee consent %s: %w", name, err)
		}
	}

	finalTrustees, err := s.FinalTrusteeSet(ctx, invite.ElectionID)
	if err != nil {
		return fmt.Errorf("invite election final trustees: %w", err)
	}
	for i, name := range candidateNames {
		if _, err := s.CreateTallyKeyContribution(ctx, invite.ElectionID, deterministicEd25519Pub(name), deterministicBytes(name+".tally-setup", 32), finalTrustees, candidateKeys[i], 8000); err != nil {
			return fmt.Errorf("invite election tally key contribution %s: %w", name, err)
		}
	}
	if _, err := s.BuildTallyKeySet(ctx, invite.ElectionID, reporterPub, reporterPriv); err != nil {
		return fmt.Errorf("invite election tally key set: %w", err)
	}
	return nil
}

func (s *Service) invitationStatuses(ctx context.Context, localPeerID string) ([]ElectionInvitationStatus, error) {
	inviteRefs, err := s.ListServableObjectRefs(ctx, string(domain.ScopeNetwork), "", []string{string(domain.ObjectTypeElectionInvite)})
	if err != nil {
		return nil, fmt.Errorf("list election invites: %w", err)
	}
	acceptanceRefs, err := s.ListServableObjectRefs(ctx, string(domain.ScopeNetwork), "", []string{string(domain.ObjectTypeElectionAcceptance)})
	if err != nil {
		return nil, fmt.Errorf("list election acceptances: %w", err)
	}
	declineRefs, err := s.ListServableObjectRefs(ctx, string(domain.ScopeNetwork), "", []string{string(domain.ObjectTypeElectionDecline)})
	if err != nil {
		return nil, fmt.Errorf("list election declines: %w", err)
	}
	acceptedByElection := map[string]map[string]struct{}{}
	for _, ref := range acceptanceRefs {
		envelope, err := s.LoadObjectEnvelope(ctx, ref.ObjectID)
		if err != nil {
			return nil, err
		}
		decoded, err := domain.DecodePayload(domain.ObjectTypeElectionAcceptance, envelope.Payload)
		if err != nil {
			return nil, err
		}
		acceptance := decoded.(domain.ElectionAcceptancePayload)
		peers := acceptedByElection[acceptance.ElectionID]
		if peers == nil {
			peers = map[string]struct{}{}
			acceptedByElection[acceptance.ElectionID] = peers
		}
		peers[acceptance.VoterPeerID] = struct{}{}
	}
	declinedByElection := map[string]map[string]struct{}{}
	for _, ref := range declineRefs {
		envelope, err := s.LoadObjectEnvelope(ctx, ref.ObjectID)
		if err != nil {
			return nil, err
		}
		decoded, err := domain.DecodePayload(domain.ObjectTypeElectionDecline, envelope.Payload)
		if err != nil {
			return nil, err
		}
		decline := decoded.(domain.ElectionDeclinePayload)
		peers := declinedByElection[decline.ElectionID]
		if peers == nil {
			peers = map[string]struct{}{}
			declinedByElection[decline.ElectionID] = peers
		}
		peers[decline.VoterPeerID] = struct{}{}
	}
	var statuses []ElectionInvitationStatus
	for _, ref := range inviteRefs {
		envelope, err := s.LoadObjectEnvelope(ctx, ref.ObjectID)
		if err != nil {
			return nil, err
		}
		decoded, err := domain.DecodePayload(domain.ObjectTypeElectionInvite, envelope.Payload)
		if err != nil {
			return nil, err
		}
		invite := decoded.(domain.ElectionInvitePayload)
		accepted := keysSorted(acceptedByElection[invite.ElectionID])
		declined := keysSorted(declinedByElection[invite.ElectionID])
		statuses = append(statuses, ElectionInvitationStatus{
			ElectionID:      invite.ElectionID,
			Title:           invite.Title,
			Options:         append([]string(nil), invite.Options...),
			CreatorPeerID:   invite.CreatorPeerID,
			InvitedPeerIDs:  append([]string(nil), invite.InvitedPeerIDs...),
			AcceptedPeerIDs: accepted,
			DeclinedPeerIDs: declined,
			LocalInvited:    localPeerID != "" && containsString(invite.InvitedPeerIDs, localPeerID),
			LocalAccepted:   localPeerID != "" && containsString(accepted, localPeerID),
			LocalDeclined:   localPeerID != "" && containsString(declined, localPeerID),
			Finalized:       s.anonymousElectionExists(ctx, invite.ElectionID),
		})
	}
	return statuses, nil
}

func (s *Service) inviteWithAcceptedVoters(ctx context.Context, electionID string) (domain.ElectionInvitePayload, []string, error) {
	invite, status, found, err := s.store.ElectionInvitationByID(ctx, electionID)
	if err != nil {
		return domain.ElectionInvitePayload{}, nil, err
	}
	if !found || status != validation.StatusValid {
		return domain.ElectionInvitePayload{}, nil, fmt.Errorf("valid election invite %s not found", electionID)
	}
	statuses, err := s.invitationStatuses(ctx, "")
	if err != nil {
		return domain.ElectionInvitePayload{}, nil, err
	}
	for _, candidate := range statuses {
		if candidate.ElectionID == electionID {
			return invite, candidate.AcceptedPeerIDs, nil
		}
	}
	return invite, nil, nil
}

func (s *Service) anonymousElectionExists(ctx context.Context, electionID string) bool {
	inputs, err := s.store.ElectionActivationInputs(ctx, electionID)
	return err == nil && inputs.ElectionFound && inputs.ElectionStatus == validation.StatusValid
}

func pendingInvitations(invitations []ElectionInvitationStatus) []ElectionInvitationStatus {
	var pending []ElectionInvitationStatus
	for _, invitation := range invitations {
		if invitation.LocalInvited && !invitation.LocalAccepted && !invitation.Finalized {
			pending = append(pending, invitation)
		}
	}
	return pending
}

func acceptedVotersForElection(invitations []ElectionInvitationStatus, electionID string) []string {
	for _, invitation := range invitations {
		if invitation.ElectionID == electionID {
			return append([]string(nil), invitation.AcceptedPeerIDs...)
		}
	}
	return nil
}

func frontendElectionID(title string, options []string, invited []string, creator string, createdAt int64) string {
	digest := crypto.Hash(crypto.DomainObjectID, []byte("frontend-election"), []byte(title), []byte(strings.Join(options, "\x00")), []byte(strings.Join(invited, "\x00")), []byte(creator), []byte(fmt.Sprint(createdAt)))
	return "election-" + digest.String()[:16]
}

func normalizeVoterIDs(voterIDs []string) []string {
	seen := make(map[string]struct{}, len(voterIDs))
	normalized := make([]string, 0, len(voterIDs))
	for _, id := range voterIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		normalized = append(normalized, id)
	}
	sort.Strings(normalized)
	return normalized
}

func deterministicEd25519Priv(name string) ed25519.PrivateKey {
	h := sha256.Sum256([]byte(name))
	return ed25519.NewKeyFromSeed(h[:])
}

func deterministicEd25519Pub(name string) ed25519.PublicKey {
	return deterministicEd25519Priv(name).Public().(ed25519.PublicKey)
}

func deterministicBytes(seed string, size int) []byte {
	h := sha256.Sum256([]byte(seed))
	if size > len(h) {
		size = len(h)
	}
	return h[:size]
}

func normalizeOptions(options []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(options))
	for _, option := range options {
		option = strings.TrimSpace(option)
		if option == "" {
			continue
		}
		if _, ok := seen[option]; ok {
			continue
		}
		seen[option] = struct{}{}
		out = append(out, option)
	}
	sort.Strings(out)
	return out
}

func keysSorted(m map[string]struct{}) []string {
	if m == nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
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

func deepCopyBytesSlice(src [][]byte) [][]byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([][]byte, len(src))
	for i, b := range src {
		dst[i] = append([]byte(nil), b...)
	}
	return dst
}

func placeholderBytes(tag string, seed []byte, size int) []byte {
	h := sha256.New()
	h.Write([]byte(tag))
	h.Write(seed)
	sum := h.Sum(nil)
	if size > len(sum) {
		size = len(sum)
	}
	return sum[:size]
}
