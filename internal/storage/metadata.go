package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// PeerRecord is local network metadata. It is not part of the domain model.
type PeerRecord struct {
	PeerID          string
	Score           float64
	AdmissionStatus string
	FirstSeenAt     int64
	LastSeenAt      int64
}

// PeerAddress stores a locally observed transport address for a peer.
type PeerAddress struct {
	PeerID      string
	Address     string
	FirstSeenAt int64
	LastSeenAt  int64
}

// SyncState stores an opaque direct-sync cursor for one peer and scope.
type SyncState struct {
	PeerID         string
	Scope          string
	ScopeID        string
	Cursor         []byte
	LastSyncAt     int64
	FailedAttempts int
}

// MessageCacheRecord is duplicate-suppression metadata for announcements only.
type MessageCacheRecord struct {
	ObjectID    string
	FirstSeenAt int64
	LastSeenAt  int64
	SeenCount   int
}

// ObjectSource is local source-peer metadata. It must not affect object_id or validation.
type ObjectSource struct {
	ObjectID    string
	PeerID      string
	FirstSeenAt int64
	LastSeenAt  int64
}

// ElectionState is a local derived-state cache row, not protocol authority.
type ElectionState struct {
	ElectionID         string
	Phase              string
	ValidObjectCount   int
	InvalidObjectCount int
	PendingObjectCount int
	ComputedStateHash  []byte
	UpdatedAt          int64
}

// TrusteeSelectionState is a local derived-state cache row, not protocol authority.
type TrusteeSelectionState struct {
	TrusteeSelectionID          string
	CandidateRankingHash        []byte
	InitialSelectedTrusteesHash []byte
	ValidVoteCount              int
	ConflictedVoteCount         int
	UpdatedAt                   int64
}

// TallyState is a local derived-state cache row, not protocol authority.
type TallyState struct {
	ElectionID                   string
	EncryptedTallyHash           []byte
	ValidBallotCount             int
	ConflictedBallotCount        int
	InvalidBallotCountDiagnostic int
	ResultStatus                 string
	ResultHash                   []byte
	UpdatedAt                    int64
}

func (s *Store) UpsertPeer(ctx context.Context, record PeerRecord) error {
	if record.PeerID == "" {
		return errors.New("peer id is required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO peers(peer_id, score, admission_status, first_seen_at, last_seen_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(peer_id) DO UPDATE SET
		 score = excluded.score,
		 admission_status = excluded.admission_status,
		 last_seen_at = excluded.last_seen_at`,
		record.PeerID, record.Score, record.AdmissionStatus, record.FirstSeenAt, record.LastSeenAt)
	if err != nil {
		return fmt.Errorf("upsert peer: %w", err)
	}
	return nil
}

func (s *Store) Peer(ctx context.Context, peerID string) (PeerRecord, error) {
	var record PeerRecord
	err := s.db.QueryRowContext(ctx,
		`SELECT peer_id, score, admission_status, first_seen_at, last_seen_at
		 FROM peers WHERE peer_id = ?`, peerID).Scan(
		&record.PeerID, &record.Score, &record.AdmissionStatus,
		&record.FirstSeenAt, &record.LastSeenAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return record, fmt.Errorf("peer not found: %w", err)
		}
		return record, fmt.Errorf("read peer: %w", err)
	}
	return record, nil
}

func (s *Store) DeletePeer(ctx context.Context, peerID string) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM peers WHERE peer_id = ?", peerID); err != nil {
		return fmt.Errorf("delete peer: %w", err)
	}
	return nil
}

func (s *Store) UpsertPeerAddress(ctx context.Context, address PeerAddress) error {
	if address.PeerID == "" || address.Address == "" {
		return errors.New("peer id and address are required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO peer_addresses(peer_id, address, first_seen_at, last_seen_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(peer_id, address) DO UPDATE SET
		 last_seen_at = excluded.last_seen_at`,
		address.PeerID, address.Address, address.FirstSeenAt, address.LastSeenAt)
	if err != nil {
		return fmt.Errorf("upsert peer address: %w", err)
	}
	return nil
}

func (s *Store) PeerAddresses(ctx context.Context, peerID string) ([]PeerAddress, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT peer_id, address, first_seen_at, last_seen_at
		 FROM peer_addresses WHERE peer_id = ? ORDER BY address`, peerID)
	if err != nil {
		return nil, fmt.Errorf("query peer addresses: %w", err)
	}
	defer rows.Close()

	var addresses []PeerAddress
	for rows.Next() {
		var address PeerAddress
		if err := rows.Scan(&address.PeerID, &address.Address, &address.FirstSeenAt, &address.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan peer address: %w", err)
		}
		addresses = append(addresses, address)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate peer addresses: %w", err)
	}
	return addresses, nil
}

func (s *Store) PutSyncState(ctx context.Context, state SyncState) error {
	if state.PeerID == "" || state.Scope == "" {
		return errors.New("peer id and scope are required")
	}
	cursor := cloneBytes(state.Cursor)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sync_state(peer_id, scope, scope_id, cursor, last_sync_at, failed_attempts)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(peer_id, scope, scope_id) DO UPDATE SET
		 cursor = excluded.cursor,
		 last_sync_at = excluded.last_sync_at,
		 failed_attempts = excluded.failed_attempts`,
		state.PeerID, state.Scope, state.ScopeID, cursor, state.LastSyncAt, state.FailedAttempts)
	if err != nil {
		return fmt.Errorf("put sync state: %w", err)
	}
	return nil
}

func (s *Store) SyncState(ctx context.Context, peerID, scope, scopeID string) (SyncState, error) {
	var state SyncState
	err := s.db.QueryRowContext(ctx,
		`SELECT peer_id, scope, scope_id, cursor, last_sync_at, failed_attempts
		 FROM sync_state WHERE peer_id = ? AND scope = ? AND scope_id = ?`,
		peerID, scope, scopeID).Scan(
		&state.PeerID, &state.Scope, &state.ScopeID, &state.Cursor,
		&state.LastSyncAt, &state.FailedAttempts)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return state, fmt.Errorf("sync state not found: %w", err)
		}
		return state, fmt.Errorf("read sync state: %w", err)
	}
	state.Cursor = cloneBytes(state.Cursor)
	return state, nil
}

func (s *Store) DeleteSyncState(ctx context.Context, peerID, scope, scopeID string) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM sync_state WHERE peer_id = ? AND scope = ? AND scope_id = ?",
		peerID, scope, scopeID)
	if err != nil {
		return fmt.Errorf("delete sync state: %w", err)
	}
	return nil
}

func (s *Store) RecordMessageSeen(ctx context.Context, objectID string, seenAt int64) error {
	if objectID == "" {
		return errors.New("object id is required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO message_cache(object_id, first_seen_at, last_seen_at, seen_count)
		 VALUES (?, ?, ?, 1)
		 ON CONFLICT(object_id) DO UPDATE SET
		 last_seen_at = excluded.last_seen_at,
		 seen_count = seen_count + 1`,
		objectID, seenAt, seenAt)
	if err != nil {
		return fmt.Errorf("record message seen: %w", err)
	}
	return nil
}

func (s *Store) MessageCache(ctx context.Context, objectID string) (MessageCacheRecord, error) {
	var record MessageCacheRecord
	err := s.db.QueryRowContext(ctx,
		`SELECT object_id, first_seen_at, last_seen_at, seen_count
		 FROM message_cache WHERE object_id = ?`, objectID).Scan(
		&record.ObjectID, &record.FirstSeenAt, &record.LastSeenAt, &record.SeenCount)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return record, fmt.Errorf("message cache record not found: %w", err)
		}
		return record, fmt.Errorf("read message cache: %w", err)
	}
	return record, nil
}

func (s *Store) RecordObjectSource(ctx context.Context, objectID, peerID string, seenAt int64) error {
	if objectID == "" || peerID == "" {
		return errors.New("object id and peer id are required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO object_sources(object_id, peer_id, first_seen_at, last_seen_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(object_id, peer_id) DO UPDATE SET
		 last_seen_at = excluded.last_seen_at`,
		objectID, peerID, seenAt, seenAt)
	if err != nil {
		return fmt.Errorf("record object source: %w", err)
	}
	return nil
}

func (s *Store) ObjectSources(ctx context.Context, objectID string) ([]ObjectSource, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT object_id, peer_id, first_seen_at, last_seen_at
		 FROM object_sources WHERE object_id = ? ORDER BY peer_id`, objectID)
	if err != nil {
		return nil, fmt.Errorf("query object sources: %w", err)
	}
	defer rows.Close()

	var sources []ObjectSource
	for rows.Next() {
		var source ObjectSource
		if err := rows.Scan(&source.ObjectID, &source.PeerID, &source.FirstSeenAt, &source.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan object source: %w", err)
		}
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate object sources: %w", err)
	}
	return sources, nil
}

func (s *Store) PutElectionState(ctx context.Context, state ElectionState) error {
	if state.ElectionID == "" {
		return errors.New("election id is required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO election_state(
		 election_id, phase, valid_object_count, invalid_object_count,
		 pending_object_count, computed_state_hash, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(election_id) DO UPDATE SET
		 phase = excluded.phase,
		 valid_object_count = excluded.valid_object_count,
		 invalid_object_count = excluded.invalid_object_count,
		 pending_object_count = excluded.pending_object_count,
		 computed_state_hash = excluded.computed_state_hash,
		 updated_at = excluded.updated_at`,
		state.ElectionID, state.Phase, state.ValidObjectCount, state.InvalidObjectCount,
		state.PendingObjectCount, cloneBytes(state.ComputedStateHash), state.UpdatedAt)
	if err != nil {
		return fmt.Errorf("put election state: %w", err)
	}
	return nil
}

func (s *Store) ElectionState(ctx context.Context, electionID string) (ElectionState, error) {
	var state ElectionState
	err := s.db.QueryRowContext(ctx,
		`SELECT election_id, phase, valid_object_count, invalid_object_count,
		 pending_object_count, computed_state_hash, updated_at
		 FROM election_state WHERE election_id = ?`, electionID).Scan(
		&state.ElectionID, &state.Phase, &state.ValidObjectCount,
		&state.InvalidObjectCount, &state.PendingObjectCount,
		&state.ComputedStateHash, &state.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return state, fmt.Errorf("election state not found: %w", err)
		}
		return state, fmt.Errorf("read election state: %w", err)
	}
	state.ComputedStateHash = cloneBytes(state.ComputedStateHash)
	return state, nil
}

func (s *Store) ClearElectionState(ctx context.Context, electionID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM election_state WHERE election_id = ?", electionID)
	if err != nil {
		return fmt.Errorf("clear election state: %w", err)
	}
	return nil
}

func (s *Store) PutTrusteeSelectionState(ctx context.Context, state TrusteeSelectionState) error {
	if state.TrusteeSelectionID == "" {
		return errors.New("trustee selection id is required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO trustee_selection_state(
		 trustee_selection_id, candidate_ranking_hash, initial_selected_trustees_hash,
		 valid_vote_count, conflicted_vote_count, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(trustee_selection_id) DO UPDATE SET
		 candidate_ranking_hash = excluded.candidate_ranking_hash,
		 initial_selected_trustees_hash = excluded.initial_selected_trustees_hash,
		 valid_vote_count = excluded.valid_vote_count,
		 conflicted_vote_count = excluded.conflicted_vote_count,
		 updated_at = excluded.updated_at`,
		state.TrusteeSelectionID, cloneBytes(state.CandidateRankingHash),
		cloneBytes(state.InitialSelectedTrusteesHash), state.ValidVoteCount,
		state.ConflictedVoteCount, state.UpdatedAt)
	if err != nil {
		return fmt.Errorf("put trustee selection state: %w", err)
	}
	return nil
}

func (s *Store) TrusteeSelectionState(ctx context.Context, trusteeSelectionID string) (TrusteeSelectionState, error) {
	var state TrusteeSelectionState
	err := s.db.QueryRowContext(ctx,
		`SELECT trustee_selection_id, candidate_ranking_hash, initial_selected_trustees_hash,
		 valid_vote_count, conflicted_vote_count, updated_at
		 FROM trustee_selection_state WHERE trustee_selection_id = ?`, trusteeSelectionID).Scan(
		&state.TrusteeSelectionID, &state.CandidateRankingHash,
		&state.InitialSelectedTrusteesHash, &state.ValidVoteCount,
		&state.ConflictedVoteCount, &state.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return state, fmt.Errorf("trustee selection state not found: %w", err)
		}
		return state, fmt.Errorf("read trustee selection state: %w", err)
	}
	state.CandidateRankingHash = cloneBytes(state.CandidateRankingHash)
	state.InitialSelectedTrusteesHash = cloneBytes(state.InitialSelectedTrusteesHash)
	return state, nil
}

func (s *Store) ClearTrusteeSelectionState(ctx context.Context, trusteeSelectionID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM trustee_selection_state WHERE trustee_selection_id = ?", trusteeSelectionID)
	if err != nil {
		return fmt.Errorf("clear trustee selection state: %w", err)
	}
	return nil
}

func (s *Store) PutTallyState(ctx context.Context, state TallyState) error {
	if state.ElectionID == "" {
		return errors.New("election id is required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tally_state(
		 election_id, encrypted_tally_hash, valid_ballot_count,
		 conflicted_ballot_count, invalid_ballot_count_diagnostic,
		 result_status, result_hash, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(election_id) DO UPDATE SET
		 encrypted_tally_hash = excluded.encrypted_tally_hash,
		 valid_ballot_count = excluded.valid_ballot_count,
		 conflicted_ballot_count = excluded.conflicted_ballot_count,
		 invalid_ballot_count_diagnostic = excluded.invalid_ballot_count_diagnostic,
		 result_status = excluded.result_status,
		 result_hash = excluded.result_hash,
		 updated_at = excluded.updated_at`,
		state.ElectionID, cloneBytes(state.EncryptedTallyHash), state.ValidBallotCount,
		state.ConflictedBallotCount, state.InvalidBallotCountDiagnostic,
		state.ResultStatus, cloneBytes(state.ResultHash), state.UpdatedAt)
	if err != nil {
		return fmt.Errorf("put tally state: %w", err)
	}
	return nil
}

func (s *Store) TallyState(ctx context.Context, electionID string) (TallyState, error) {
	var state TallyState
	err := s.db.QueryRowContext(ctx,
		`SELECT election_id, encrypted_tally_hash, valid_ballot_count,
		 conflicted_ballot_count, invalid_ballot_count_diagnostic,
		 result_status, result_hash, updated_at
		 FROM tally_state WHERE election_id = ?`, electionID).Scan(
		&state.ElectionID, &state.EncryptedTallyHash, &state.ValidBallotCount,
		&state.ConflictedBallotCount, &state.InvalidBallotCountDiagnostic,
		&state.ResultStatus, &state.ResultHash, &state.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return state, fmt.Errorf("tally state not found: %w", err)
		}
		return state, fmt.Errorf("read tally state: %w", err)
	}
	state.EncryptedTallyHash = cloneBytes(state.EncryptedTallyHash)
	state.ResultHash = cloneBytes(state.ResultHash)
	return state, nil
}

func (s *Store) ClearTallyState(ctx context.Context, electionID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM tally_state WHERE election_id = ?", electionID)
	if err != nil {
		return fmt.Errorf("clear tally state: %w", err)
	}
	return nil
}

func (s *Store) ClearDerivedState(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin clear derived state: %w", err)
	}
	defer tx.Rollback()

	for _, table := range []string{"election_state", "trustee_selection_state", "tally_state"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return fmt.Errorf("clear %s: %w", table, err)
		}
	}
	return tx.Commit()
}
