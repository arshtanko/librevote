package storage

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"librevote/internal/crypto"
)

var (
	ErrKeyExists        = errors.New("key already exists")
	ErrKeyNotFound      = errors.New("key not found")
	ErrIssuanceNotFound = errors.New("local issuance state not found")
)

// KeyRecord is a local encrypted-at-rest key store row. It never carries
// plaintext private key material or passphrases.
type KeyRecord struct {
	KeyID               crypto.Digest
	KeyType             crypto.KeyType
	PublicKey           []byte
	EncryptedPrivateKey []byte
	EncryptionMetadata  []byte
	CreatedAt           int64
}

// LocalIssuanceState stores encrypted local voter issuance secrets.
type LocalIssuanceState struct {
	ElectionID                        crypto.Digest
	VoterKeyID                        crypto.Digest
	TokenKeyID                        crypto.Digest
	EncryptedBlindingFactor           []byte
	EncryptedUnblindedTokenSignatures []byte
	CompletedAt                       sql.NullInt64
	UpdatedAt                         int64
}

func (s *Store) PutKey(ctx context.Context, record KeyRecord) error {
	if err := validateKeyRecord(record); err != nil {
		return err
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO keys(key_id, key_type, public_key, encrypted_private_key, encryption_metadata, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		record.KeyID.String(), string(record.KeyType), record.PublicKey, record.EncryptedPrivateKey, record.EncryptionMetadata, record.CreatedAt)
	if err != nil {
		if sqliteConstraint(err) {
			return ErrKeyExists
		}
		return fmt.Errorf("insert key: %w", err)
	}
	return nil
}

func (s *Store) Key(ctx context.Context, keyID crypto.Digest) (KeyRecord, error) {
	if zeroDigest(keyID) {
		return KeyRecord{}, errors.New("key id is required")
	}

	row := s.db.QueryRowContext(ctx,
		`SELECT key_id, key_type, public_key, encrypted_private_key, encryption_metadata, created_at
		 FROM keys WHERE key_id = ?`, keyID.String())
	record, err := scanKeyRecord(row)
	if err != nil {
		return KeyRecord{}, err
	}
	return cloneKeyRecord(record), nil
}

func (s *Store) DeleteKey(ctx context.Context, keyID crypto.Digest) error {
	if zeroDigest(keyID) {
		return errors.New("key id is required")
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM keys WHERE key_id = ?", keyID.String())
	if err != nil {
		return fmt.Errorf("delete key: %w", err)
	}
	return nil
}

func (s *Store) KeysByType(ctx context.Context, keyType crypto.KeyType) ([]KeyRecord, error) {
	if !crypto.KnownKeyType(keyType) {
		return nil, crypto.ErrUnknownKeyType
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT key_id, key_type, public_key, encrypted_private_key, encryption_metadata, created_at
		 FROM keys WHERE key_type = ? ORDER BY created_at, key_id`, string(keyType))
	if err != nil {
		return nil, fmt.Errorf("query keys by type: %w", err)
	}
	defer rows.Close()

	var records []KeyRecord
	for rows.Next() {
		record, err := scanKeyRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, cloneKeyRecord(record))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate keys by type: %w", err)
	}
	return records, nil
}

func (s *Store) requireAnonymousTokenKey(ctx context.Context, keyID crypto.Digest) error {
	var keyTypeText string
	if err := s.db.QueryRowContext(ctx, `SELECT key_type FROM keys WHERE key_id = ?`, keyID.String()).Scan(&keyTypeText); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrKeyNotFound
		}
		return fmt.Errorf("read token key: %w", err)
	}
	if crypto.KeyType(keyTypeText) != crypto.KeyTypeAnonymousToken {
		return fmt.Errorf("token key has key_type %q, want %q", keyTypeText, crypto.KeyTypeAnonymousToken)
	}
	return nil
}

func (s *Store) PutLocalIssuanceState(ctx context.Context, state LocalIssuanceState) error {
	if err := validateLocalIssuanceState(state); err != nil {
		return err
	}
	if err := s.requireAnonymousTokenKey(ctx, state.TokenKeyID); err != nil {
		return err
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO local_issuance_state(
			election_id, voter_key_id, token_key_id,
			encrypted_blinding_factor, encrypted_unblinded_token_signatures,
			completed_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(election_id, voter_key_id) DO UPDATE SET
			token_key_id = excluded.token_key_id,
			encrypted_blinding_factor = excluded.encrypted_blinding_factor,
			encrypted_unblinded_token_signatures = excluded.encrypted_unblinded_token_signatures,
			completed_at = excluded.completed_at,
			updated_at = excluded.updated_at`,
		state.ElectionID.String(), state.VoterKeyID.String(), state.TokenKeyID.String(),
		state.EncryptedBlindingFactor, state.EncryptedUnblindedTokenSignatures,
		nullInt64Value(state.CompletedAt), state.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upsert local issuance state: %w", err)
	}
	return nil
}

func (s *Store) LocalIssuanceState(ctx context.Context, electionID, voterKeyID crypto.Digest) (LocalIssuanceState, error) {
	if zeroDigest(electionID) || zeroDigest(voterKeyID) {
		return LocalIssuanceState{}, errors.New("issuance state ids are required")
	}

	row := s.db.QueryRowContext(ctx,
		`SELECT election_id, voter_key_id, token_key_id,
			encrypted_blinding_factor, encrypted_unblinded_token_signatures,
			completed_at, updated_at
		 FROM local_issuance_state
		 WHERE election_id = ? AND voter_key_id = ?`,
		electionID.String(), voterKeyID.String())
	state, err := scanLocalIssuanceState(row)
	if err != nil {
		return LocalIssuanceState{}, err
	}
	return cloneLocalIssuanceState(state), nil
}

func (s *Store) DeleteLocalIssuanceState(ctx context.Context, electionID, voterKeyID crypto.Digest) error {
	if zeroDigest(electionID) || zeroDigest(voterKeyID) {
		return errors.New("issuance state ids are required")
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM local_issuance_state
		 WHERE election_id = ? AND voter_key_id = ?`,
		electionID.String(), voterKeyID.String())
	if err != nil {
		return fmt.Errorf("delete local issuance state: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanKeyRecord(row rowScanner) (KeyRecord, error) {
	var keyIDText, keyTypeText string
	var record KeyRecord
	if err := row.Scan(&keyIDText, &keyTypeText, &record.PublicKey, &record.EncryptedPrivateKey, &record.EncryptionMetadata, &record.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return KeyRecord{}, ErrKeyNotFound
		}
		return KeyRecord{}, fmt.Errorf("scan key: %w", err)
	}

	keyID, err := parseDigest(keyIDText)
	if err != nil {
		return KeyRecord{}, err
	}
	record.KeyID = keyID
	record.KeyType = crypto.KeyType(keyTypeText)
	if err := validateKeyRecord(record); err != nil {
		return KeyRecord{}, err
	}
	return record, nil
}

func scanLocalIssuanceState(row rowScanner) (LocalIssuanceState, error) {
	var electionIDText, voterKeyIDText, tokenKeyIDText string
	var state LocalIssuanceState
	if err := row.Scan(
		&electionIDText, &voterKeyIDText, &tokenKeyIDText,
		&state.EncryptedBlindingFactor, &state.EncryptedUnblindedTokenSignatures,
		&state.CompletedAt, &state.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return LocalIssuanceState{}, ErrIssuanceNotFound
		}
		return LocalIssuanceState{}, fmt.Errorf("scan local issuance state: %w", err)
	}

	var err error
	if state.ElectionID, err = parseDigest(electionIDText); err != nil {
		return LocalIssuanceState{}, err
	}
	if state.VoterKeyID, err = parseDigest(voterKeyIDText); err != nil {
		return LocalIssuanceState{}, err
	}
	if state.TokenKeyID, err = parseDigest(tokenKeyIDText); err != nil {
		return LocalIssuanceState{}, err
	}
	if err := validateLocalIssuanceState(state); err != nil {
		return LocalIssuanceState{}, err
	}
	return state, nil
}

func validateKeyRecord(record KeyRecord) error {
	if zeroDigest(record.KeyID) {
		return errors.New("key id is required")
	}
	if !crypto.KnownKeyType(record.KeyType) {
		return crypto.ErrUnknownKeyType
	}
	if len(record.PublicKey) == 0 {
		return crypto.ErrEmptyPublicKey
	}
	expectedKeyID, err := crypto.KeyID(record.KeyType, record.PublicKey)
	if err != nil {
		return err
	}
	if expectedKeyID != record.KeyID {
		return crypto.ErrKeyIDMismatch
	}
	if len(record.EncryptedPrivateKey) == 0 {
		return errors.New("encrypted private key is required")
	}
	if len(record.EncryptionMetadata) == 0 {
		return errors.New("encryption metadata is required")
	}
	if record.CreatedAt == 0 {
		return errors.New("created_at is required")
	}
	return nil
}

func validateLocalIssuanceState(state LocalIssuanceState) error {
	if zeroDigest(state.ElectionID) || zeroDigest(state.VoterKeyID) || zeroDigest(state.TokenKeyID) {
		return errors.New("issuance state ids are required")
	}
	if len(state.EncryptedBlindingFactor) == 0 {
		return errors.New("encrypted blinding factor is required")
	}
	if len(state.EncryptedUnblindedTokenSignatures) == 0 {
		return errors.New("encrypted unblinded token signatures are required")
	}
	if state.UpdatedAt == 0 {
		return errors.New("updated_at is required")
	}
	return nil
}

func parseDigest(text string) (crypto.Digest, error) {
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return crypto.Digest{}, fmt.Errorf("parse digest: %w", err)
	}
	var digest crypto.Digest
	if len(decoded) != len(digest) {
		return crypto.Digest{}, fmt.Errorf("parse digest: length %d", len(decoded))
	}
	copy(digest[:], decoded)
	return digest, nil
}

func zeroDigest(digest crypto.Digest) bool {
	return digest == crypto.Digest{}
}

func cloneKeyRecord(record KeyRecord) KeyRecord {
	record.PublicKey = cloneBytes(record.PublicKey)
	record.EncryptedPrivateKey = cloneBytes(record.EncryptedPrivateKey)
	record.EncryptionMetadata = cloneBytes(record.EncryptionMetadata)
	return record
}

func cloneLocalIssuanceState(state LocalIssuanceState) LocalIssuanceState {
	state.EncryptedBlindingFactor = cloneBytes(state.EncryptedBlindingFactor)
	state.EncryptedUnblindedTokenSignatures = cloneBytes(state.EncryptedUnblindedTokenSignatures)
	return state
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func nullInt64Value(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return value.Int64
}

func sqliteConstraint(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "constraint")
}
