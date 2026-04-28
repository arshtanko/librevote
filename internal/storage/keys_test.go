package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"

	"librevote/internal/crypto"
)

func TestPutKeyInsertsAndReadsEncryptedRecord(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer store.Close()

	record := testKeyRecord(t, crypto.KeyTypeVoterSigning, 100)
	if err := store.PutKey(ctx, record); err != nil {
		t.Fatalf("PutKey() error = %v", err)
	}

	got, err := store.Key(ctx, record.KeyID)
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if !reflect.DeepEqual(got, record) {
		t.Fatalf("Key() = %+v, want %+v", got, record)
	}

	byType, err := store.KeysByType(ctx, record.KeyType)
	if err != nil {
		t.Fatalf("KeysByType() error = %v", err)
	}
	if len(byType) != 1 || !reflect.DeepEqual(byType[0], record) {
		t.Fatalf("KeysByType() = %+v, want [%+v]", byType, record)
	}
}

func TestPutKeyRejectsInvalidRecords(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer store.Close()

	valid := testKeyRecord(t, crypto.KeyTypeVoterSigning, 100)
	wrongKeyID := valid
	wrongKeyID.KeyID = crypto.Hash(crypto.DomainKeyID, []byte("wrong"))

	tests := []struct {
		name   string
		record KeyRecord
		want   error
	}{
		{name: "unknown key type", record: func() KeyRecord { r := valid; r.KeyType = "unknown"; return r }(), want: crypto.ErrUnknownKeyType},
		{name: "key id mismatch", record: wrongKeyID, want: crypto.ErrKeyIDMismatch},
		{name: "empty encrypted private key", record: func() KeyRecord { r := valid; r.EncryptedPrivateKey = nil; return r }()},
		{name: "empty encryption metadata", record: func() KeyRecord { r := valid; r.EncryptionMetadata = nil; return r }()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.PutKey(ctx, tt.record)
			if err == nil {
				t.Fatal("PutKey() succeeded, want error")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("PutKey() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestPutKeyDuplicateDoesNotOverwriteEncryptedMaterial(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer store.Close()

	record := testKeyRecord(t, crypto.KeyTypeVoterSigning, 100)
	if err := store.PutKey(ctx, record); err != nil {
		t.Fatalf("PutKey() error = %v", err)
	}
	duplicate := record
	duplicate.EncryptedPrivateKey = []byte("different encrypted private key")
	duplicate.EncryptionMetadata = []byte("different metadata")

	err := store.PutKey(ctx, duplicate)
	if !errors.Is(err, ErrKeyExists) {
		t.Fatalf("duplicate PutKey() error = %v, want ErrKeyExists", err)
	}

	got, err := store.Key(ctx, record.KeyID)
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if !bytes.Equal(got.EncryptedPrivateKey, record.EncryptedPrivateKey) || !bytes.Equal(got.EncryptionMetadata, record.EncryptionMetadata) {
		t.Fatalf("duplicate overwrote encrypted material: got %+v want %+v", got, record)
	}
}

func TestDeleteKeyRemovesKey(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer store.Close()

	record := testKeyRecord(t, crypto.KeyTypeVoterSigning, 100)
	if err := store.PutKey(ctx, record); err != nil {
		t.Fatalf("PutKey() error = %v", err)
	}
	if err := store.DeleteKey(ctx, record.KeyID); err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}
	_, err := store.Key(ctx, record.KeyID)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Key() after delete error = %v, want ErrKeyNotFound", err)
	}
}

func TestKeyReturnsDefensiveCopies(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer store.Close()

	record := testKeyRecord(t, crypto.KeyTypeVoterSigning, 100)
	if err := store.PutKey(ctx, record); err != nil {
		t.Fatalf("PutKey() error = %v", err)
	}
	record.PublicKey[0] ^= 0xff
	record.EncryptedPrivateKey[0] ^= 0xff
	record.EncryptionMetadata[0] ^= 0xff

	got, err := store.Key(ctx, testKeyRecord(t, crypto.KeyTypeVoterSigning, 100).KeyID)
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	original := testKeyRecord(t, crypto.KeyTypeVoterSigning, 100)
	if !reflect.DeepEqual(got, original) {
		t.Fatalf("stored key changed through input alias: got %+v want %+v", got, original)
	}

	got.PublicKey[0] ^= 0xff
	got.EncryptedPrivateKey[0] ^= 0xff
	got.EncryptionMetadata[0] ^= 0xff
	again, err := store.Key(ctx, original.KeyID)
	if err != nil {
		t.Fatalf("second Key() error = %v", err)
	}
	if !reflect.DeepEqual(again, original) {
		t.Fatalf("stored key changed through returned alias: got %+v want %+v", again, original)
	}
}

func TestLocalIssuanceStateUpsertReadDelete(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer store.Close()

	tokenKey := putTestKey(t, ctx, store, crypto.KeyTypeAnonymousToken, 201)
	state := testLocalIssuanceStateWithTokenKey(tokenKey.KeyID)
	if err := store.PutLocalIssuanceState(ctx, state); err != nil {
		t.Fatalf("PutLocalIssuanceState() error = %v", err)
	}

	got, err := store.LocalIssuanceState(ctx, state.ElectionID, state.VoterKeyID)
	if err != nil {
		t.Fatalf("LocalIssuanceState() error = %v", err)
	}
	if !reflect.DeepEqual(got, state) {
		t.Fatalf("LocalIssuanceState() = %+v, want %+v", got, state)
	}

	updated := state
	updated.EncryptedBlindingFactor = []byte("updated encrypted blinding factor")
	updated.EncryptedUnblindedTokenSignatures = []byte("updated encrypted signatures")
	updated.CompletedAt = sql.NullInt64{Int64: 300, Valid: true}
	updated.UpdatedAt = 400
	if err := store.PutLocalIssuanceState(ctx, updated); err != nil {
		t.Fatalf("upsert PutLocalIssuanceState() error = %v", err)
	}
	got, err = store.LocalIssuanceState(ctx, state.ElectionID, state.VoterKeyID)
	if err != nil {
		t.Fatalf("LocalIssuanceState() after upsert error = %v", err)
	}
	if !reflect.DeepEqual(got, updated) {
		t.Fatalf("LocalIssuanceState() after upsert = %+v, want %+v", got, updated)
	}

	if err := store.DeleteLocalIssuanceState(ctx, state.ElectionID, state.VoterKeyID); err != nil {
		t.Fatalf("DeleteLocalIssuanceState() error = %v", err)
	}
	_, err = store.LocalIssuanceState(ctx, state.ElectionID, state.VoterKeyID)
	if !errors.Is(err, ErrIssuanceNotFound) {
		t.Fatalf("LocalIssuanceState() after delete error = %v, want ErrIssuanceNotFound", err)
	}
}

func TestLocalIssuanceStateUpsertUpdatesTokenKeyID(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer store.Close()

	tokenKey := putTestKey(t, ctx, store, crypto.KeyTypeAnonymousToken, 202)
	replacementTokenKey := putTestKey(t, ctx, store, crypto.KeyTypeAnonymousToken, 203)
	state := testLocalIssuanceStateWithTokenKey(tokenKey.KeyID)
	if err := store.PutLocalIssuanceState(ctx, state); err != nil {
		t.Fatalf("PutLocalIssuanceState() error = %v", err)
	}

	updated := state
	updated.TokenKeyID = replacementTokenKey.KeyID
	updated.EncryptedBlindingFactor = []byte("updated encrypted blinding factor")
	updated.EncryptedUnblindedTokenSignatures = []byte("updated encrypted signatures")
	updated.UpdatedAt = 500
	if err := store.PutLocalIssuanceState(ctx, updated); err != nil {
		t.Fatalf("upsert PutLocalIssuanceState() error = %v", err)
	}

	got, err := store.LocalIssuanceState(ctx, state.ElectionID, state.VoterKeyID)
	if err != nil {
		t.Fatalf("LocalIssuanceState() error = %v", err)
	}
	if !reflect.DeepEqual(got, updated) {
		t.Fatalf("LocalIssuanceState() = %+v, want %+v", got, updated)
	}

	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_issuance_state WHERE election_id = ? AND voter_key_id = ?`, state.ElectionID.String(), state.VoterKeyID.String()).Scan(&count); err != nil {
		t.Fatalf("count local issuance state rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("local issuance state row count = %d, want 1", count)
	}
}

func TestLocalIssuanceStateRequiresAnonymousTokenKey(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer store.Close()

	state := testLocalIssuanceState()
	if err := store.PutLocalIssuanceState(ctx, state); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("PutLocalIssuanceState() without token key error = %v, want ErrKeyNotFound", err)
	}

	tokenKey := putTestKey(t, ctx, store, crypto.KeyTypeAnonymousToken, 204)
	state = testLocalIssuanceStateWithTokenKey(tokenKey.KeyID)
	if err := store.PutLocalIssuanceState(ctx, state); err != nil {
		t.Fatalf("PutLocalIssuanceState() with anonymous token key error = %v", err)
	}

	wrongTypeKey := putTestKey(t, ctx, store, crypto.KeyTypeVoterSigning, 205)
	state = testLocalIssuanceStateWithTokenKey(wrongTypeKey.KeyID)
	if err := store.PutLocalIssuanceState(ctx, state); err == nil {
		t.Fatal("PutLocalIssuanceState() with non-anonymous token key succeeded, want error")
	}
}

func TestLocalIssuanceStateUpsertRequiresReplacementAnonymousTokenKey(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer store.Close()

	tokenKey := putTestKey(t, ctx, store, crypto.KeyTypeAnonymousToken, 206)
	state := testLocalIssuanceStateWithTokenKey(tokenKey.KeyID)
	if err := store.PutLocalIssuanceState(ctx, state); err != nil {
		t.Fatalf("PutLocalIssuanceState() error = %v", err)
	}

	missingReplacement := state
	missingReplacement.TokenKeyID = crypto.Hash(crypto.DomainKeyID, []byte("missing replacement token"))
	if err := store.PutLocalIssuanceState(ctx, missingReplacement); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("upsert with missing replacement token key error = %v, want ErrKeyNotFound", err)
	}

	wrongTypeKey := putTestKey(t, ctx, store, crypto.KeyTypeVoterSigning, 207)
	wrongTypeReplacement := state
	wrongTypeReplacement.TokenKeyID = wrongTypeKey.KeyID
	if err := store.PutLocalIssuanceState(ctx, wrongTypeReplacement); err == nil {
		t.Fatal("upsert with non-anonymous replacement token key succeeded, want error")
	}

	got, err := store.LocalIssuanceState(ctx, state.ElectionID, state.VoterKeyID)
	if err != nil {
		t.Fatalf("LocalIssuanceState() error = %v", err)
	}
	if !reflect.DeepEqual(got, state) {
		t.Fatalf("LocalIssuanceState() after rejected upserts = %+v, want %+v", got, state)
	}
}

func TestLocalIssuanceStateDoesNotRequireDomainRows(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer store.Close()

	tokenKey := putTestKey(t, ctx, store, crypto.KeyTypeAnonymousToken, 208)
	state := testLocalIssuanceStateWithTokenKey(tokenKey.KeyID)
	if err := store.PutLocalIssuanceState(ctx, state); err != nil {
		t.Fatalf("PutLocalIssuanceState() without domain rows error = %v", err)
	}
}

func TestLocalIssuanceStateRejectsMissingSecretsAndUpdatedAt(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer store.Close()

	valid := testLocalIssuanceState()
	tests := []struct {
		name  string
		state LocalIssuanceState
	}{
		{name: "empty encrypted blinding factor", state: func() LocalIssuanceState { s := valid; s.EncryptedBlindingFactor = nil; return s }()},
		{name: "empty encrypted unblinded signatures", state: func() LocalIssuanceState { s := valid; s.EncryptedUnblindedTokenSignatures = nil; return s }()},
		{name: "empty updated at", state: func() LocalIssuanceState { s := valid; s.UpdatedAt = 0; return s }()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := store.PutLocalIssuanceState(ctx, tt.state); err == nil {
				t.Fatal("PutLocalIssuanceState() succeeded, want error")
			}
		})
	}
}

func TestLocalIssuanceStateReturnsDefensiveCopies(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, ctx)
	defer store.Close()

	tokenKey := putTestKey(t, ctx, store, crypto.KeyTypeAnonymousToken, 209)
	state := testLocalIssuanceStateWithTokenKey(tokenKey.KeyID)
	if err := store.PutLocalIssuanceState(ctx, state); err != nil {
		t.Fatalf("PutLocalIssuanceState() error = %v", err)
	}
	state.EncryptedBlindingFactor[0] ^= 0xff
	state.EncryptedUnblindedTokenSignatures[0] ^= 0xff

	original := testLocalIssuanceStateWithTokenKey(tokenKey.KeyID)
	got, err := store.LocalIssuanceState(ctx, original.ElectionID, original.VoterKeyID)
	if err != nil {
		t.Fatalf("LocalIssuanceState() error = %v", err)
	}
	if !reflect.DeepEqual(got, original) {
		t.Fatalf("stored issuance state changed through input alias: got %+v want %+v", got, original)
	}

	got.EncryptedBlindingFactor[0] ^= 0xff
	got.EncryptedUnblindedTokenSignatures[0] ^= 0xff
	again, err := store.LocalIssuanceState(ctx, original.ElectionID, original.VoterKeyID)
	if err != nil {
		t.Fatalf("second LocalIssuanceState() error = %v", err)
	}
	if !reflect.DeepEqual(again, original) {
		t.Fatalf("stored issuance state changed through returned alias: got %+v want %+v", again, original)
	}
}

func openTestStore(t *testing.T, ctx context.Context) *Store {
	t.Helper()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return store
}

func testKeyRecord(t *testing.T, keyType crypto.KeyType, seed byte) KeyRecord {
	t.Helper()
	publicKey := bytes.Repeat([]byte{seed}, 32)
	keyID, err := crypto.KeyID(keyType, publicKey)
	if err != nil {
		t.Fatalf("KeyID() error = %v", err)
	}
	return KeyRecord{
		KeyID:               keyID,
		KeyType:             keyType,
		PublicKey:           publicKey,
		EncryptedPrivateKey: []byte("encrypted private key"),
		EncryptionMetadata:  []byte("encryption metadata"),
		CreatedAt:           1000,
	}
}

func putTestKey(t *testing.T, ctx context.Context, store *Store, keyType crypto.KeyType, seed byte) KeyRecord {
	t.Helper()
	record := testKeyRecord(t, keyType, seed)
	if err := store.PutKey(ctx, record); err != nil {
		t.Fatalf("PutKey() error = %v", err)
	}
	return record
}

func testLocalIssuanceState() LocalIssuanceState {
	return LocalIssuanceState{
		ElectionID:                        crypto.Hash(crypto.DomainObjectID, []byte("election")),
		VoterKeyID:                        crypto.Hash(crypto.DomainKeyID, []byte("voter")),
		TokenKeyID:                        crypto.Hash(crypto.DomainKeyID, []byte("token")),
		EncryptedBlindingFactor:           []byte("encrypted blinding factor"),
		EncryptedUnblindedTokenSignatures: []byte("encrypted unblinded token signatures"),
		UpdatedAt:                         200,
	}
}

func testLocalIssuanceStateWithTokenKey(tokenKeyID crypto.Digest) LocalIssuanceState {
	state := testLocalIssuanceState()
	state.TokenKeyID = tokenKeyID
	return state
}
