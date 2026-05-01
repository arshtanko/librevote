package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
)

func TestOpenCreatesAllDocumentedTables(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantTables := []string{
		"schema_metadata",
		"objects",
		"object_payloads",
		"validation_records",
		"object_dependencies",
		"invalid_object_records",
		"election_state",
		"trustee_selection_state",
		"tally_state",
		"keys",
		"local_issuance_state",
		"peers",
		"peer_addresses",
		"sync_state",
		"message_cache",
		"object_sources",
	}

	rows, err := store.db.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
	if err != nil {
		t.Fatalf("query tables: %v", err)
	}
	defer rows.Close()

	var gotTables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		gotTables = append(gotTables, name)
	}

	for _, want := range wantTables {
		found := false
		for _, got := range gotTables {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing table %q, got tables: %v", want, gotTables)
		}
	}
}

type columnSpec struct {
	name    string
	notNull bool
	pk      bool
}

func TestObjectsColumns(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantCols := []columnSpec{
		{"object_id", true, true},
		{"object_type", true, false},
		{"protocol_version", true, false},
		{"network_id", true, false},
		{"scope", true, false},
		{"scope_id", true, false},
		{"created_at", true, false},
		{"first_seen_at", true, false},
		{"last_seen_at", true, false},
		{"object_pow", true, false},
		{"payload_hash", true, false},
		{"payload_size", true, false},
		{"payload_retained", true, false},
	}
	assertColumns(t, ctx, store.db, "objects", wantCols)
}

func TestObjectPayloadsColumns(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantCols := []columnSpec{
		{"object_id", true, true},
		{"payload_bytes", true, false},
	}
	assertColumns(t, ctx, store.db, "object_payloads", wantCols)
}

func TestValidationRecordsColumns(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantCols := []columnSpec{
		{"object_id", true, true},
		{"validation_status", true, false},
		{"validation_error_code", false, false},
		{"validation_error_message", false, false},
		{"validator_version", true, false},
		{"last_checked_at", true, false},
	}
	assertColumns(t, ctx, store.db, "validation_records", wantCols)
}

func TestObjectDependenciesColumns(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantCols := []columnSpec{
		{"object_id", true, false},
		{"dependency_type", true, false},
		{"dependency_id", true, false},
	}
	assertColumns(t, ctx, store.db, "object_dependencies", wantCols)
}

func TestInvalidObjectRecordsColumns(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantCols := []columnSpec{
		{"object_id", true, true},
		{"object_type", true, false},
		{"network_id", true, false},
		{"scope", true, false},
		{"scope_id", true, false},
		{"first_seen_at", true, false},
		{"last_seen_at", true, false},
		{"seen_count", true, false},
		{"validation_error_code", false, false},
	}
	assertColumns(t, ctx, store.db, "invalid_object_records", wantCols)
}

func TestElectionStateColumns(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantCols := []columnSpec{
		{"election_id", true, true},
		{"phase", true, false},
		{"valid_object_count", true, false},
		{"invalid_object_count", true, false},
		{"pending_object_count", true, false},
		{"computed_state_hash", true, false},
		{"updated_at", true, false},
	}
	assertColumns(t, ctx, store.db, "election_state", wantCols)
}

func TestTrusteeSelectionStateColumns(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantCols := []columnSpec{
		{"trustee_selection_id", true, true},
		{"candidate_ranking_hash", true, false},
		{"initial_selected_trustees_hash", true, false},
		{"valid_vote_count", true, false},
		{"conflicted_vote_count", true, false},
		{"updated_at", true, false},
	}
	assertColumns(t, ctx, store.db, "trustee_selection_state", wantCols)
}

func TestTallyStateColumns(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantCols := []columnSpec{
		{"election_id", true, true},
		{"encrypted_tally_hash", true, false},
		{"valid_ballot_count", true, false},
		{"conflicted_ballot_count", true, false},
		{"invalid_ballot_count_diagnostic", true, false},
		{"result_status", true, false},
		{"result_hash", true, false},
		{"updated_at", true, false},
	}
	assertColumns(t, ctx, store.db, "tally_state", wantCols)
}

func TestKeysColumns(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantCols := []columnSpec{
		{"key_id", true, true},
		{"key_type", true, false},
		{"public_key", true, false},
		{"encrypted_private_key", true, false},
		{"encryption_metadata", false, false},
		{"created_at", true, false},
	}
	assertColumns(t, ctx, store.db, "keys", wantCols)
}

func TestLocalIssuanceStateColumns(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantCols := []columnSpec{
		{"election_id", true, false},
		{"voter_key_id", true, false},
		{"token_key_id", true, false},
		{"encrypted_blinding_factor", true, false},
		{"encrypted_unblinded_token_signatures", true, false},
		{"completed_at", false, false},
		{"updated_at", true, false},
	}
	assertColumns(t, ctx, store.db, "local_issuance_state", wantCols)
}

func TestPeersColumns(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantCols := []columnSpec{
		{"peer_id", true, true},
		{"score", true, false},
		{"admission_status", true, false},
		{"first_seen_at", true, false},
		{"last_seen_at", true, false},
	}
	assertColumns(t, ctx, store.db, "peers", wantCols)
}

func TestPeerAddressesColumns(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantCols := []columnSpec{
		{"peer_id", true, false},
		{"address", true, false},
		{"first_seen_at", true, false},
		{"last_seen_at", true, false},
	}
	assertColumns(t, ctx, store.db, "peer_addresses", wantCols)
}

func TestSyncStateColumns(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantCols := []columnSpec{
		{"peer_id", true, false},
		{"scope", true, false},
		{"scope_id", true, false},
		{"cursor", false, false},
		{"last_sync_at", true, false},
		{"failed_attempts", true, false},
	}
	assertColumns(t, ctx, store.db, "sync_state", wantCols)
}

func TestMessageCacheColumns(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantCols := []columnSpec{
		{"object_id", true, true},
		{"first_seen_at", true, false},
		{"last_seen_at", true, false},
		{"seen_count", true, false},
	}
	assertColumns(t, ctx, store.db, "message_cache", wantCols)
}

func TestObjectSourcesColumns(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantCols := []columnSpec{
		{"object_id", true, false},
		{"peer_id", true, false},
		{"first_seen_at", true, false},
		{"last_seen_at", true, false},
	}
	assertColumns(t, ctx, store.db, "object_sources", wantCols)
}

func TestDocumentedIndexesExist(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantIndexes := []string{
		"idx_objects_scope_type_created",
		"idx_objects_type_created",
		"idx_objects_network_created",
		"idx_validation_status_checked",
		"idx_validation_version",
		"idx_dependencies_type_id",
		"idx_dependencies_object",
		"idx_local_issuance_state_identity",
	}

	rows, err := store.db.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'")
	if err != nil {
		t.Fatalf("query indexes: %v", err)
	}
	defer rows.Close()

	var gotIndexes []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan index name: %v", err)
		}
		gotIndexes = append(gotIndexes, name)
	}

	for _, want := range wantIndexes {
		found := false
		for _, got := range gotIndexes {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing index %q, got indexes: %v", want, gotIndexes)
		}
	}
}

type indexColumnSpec struct {
	name    string
	columns []string
}

func TestDocumentedIndexColumnOrder(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	wantIndexes := []indexColumnSpec{
		{"idx_objects_scope_type_created", []string{"scope", "scope_id", "object_type", "created_at"}},
		{"idx_objects_type_created", []string{"object_type", "created_at"}},
		{"idx_objects_network_created", []string{"network_id", "created_at"}},
		{"idx_validation_status_checked", []string{"validation_status", "last_checked_at"}},
		{"idx_validation_version", []string{"validator_version"}},
		{"idx_dependencies_type_id", []string{"dependency_type", "dependency_id"}},
		{"idx_dependencies_object", []string{"object_id"}},
		{"idx_local_issuance_state_identity", []string{"election_id", "voter_key_id"}},
	}

	for _, want := range wantIndexes {
		assertIndexColumnOrder(t, ctx, store.db, want.name, want.columns)
	}
}

func assertIndexColumnOrder(t *testing.T, ctx context.Context, db *sql.DB, indexName string, wantColumns []string) {
	t.Helper()
	rows, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA index_info(%s)", indexName))
	if err != nil {
		t.Fatalf("pragma index_info(%s): %v", indexName, err)
	}
	defer rows.Close()

	type indexCol struct {
		seqno int
		cid   int
		name  string
	}
	var gotCols []indexCol
	for rows.Next() {
		var seqno, cid int
		var name string
		if err := rows.Scan(&seqno, &cid, &name); err != nil {
			t.Fatalf("scan index_info(%s): %v", indexName, err)
		}
		gotCols = append(gotCols, indexCol{seqno: seqno, cid: cid, name: name})
	}

	if len(gotCols) != len(wantColumns) {
		t.Errorf("index %s: got %d columns, want %d", indexName, len(gotCols), len(wantColumns))
		return
	}

	for i, want := range wantColumns {
		if i >= len(gotCols) {
			t.Errorf("index %s: missing column at position %d, want %q", indexName, i, want)
			continue
		}
		if gotCols[i].name != want {
			t.Errorf("index %s: column at position %d = %q, want %q", indexName, i, gotCols[i].name, want)
		}
	}
}

func TestForeignKeysPragmaEnabled(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	var val int
	if err := store.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&val); err != nil {
		t.Fatalf("read foreign_keys pragma: %v", err)
	}
	if val != 1 {
		t.Fatalf("foreign_keys = %d, want 1", val)
	}
}

func TestFKOrphanObjectPayloadsRejected(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	_, err = store.db.ExecContext(ctx,
		"INSERT INTO object_payloads(object_id, payload_bytes) VALUES (?, ?)",
		"nonexistent-object-id", []byte{1, 2, 3})
	if err == nil {
		t.Fatal("insert orphan object_payloads succeeded, want FK violation")
	}
}

func TestFKOrphanValidationRecordsRejected(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	_, err = store.db.ExecContext(ctx,
		"INSERT INTO validation_records(object_id, validation_status, validator_version, last_checked_at) VALUES (?, ?, ?, ?)",
		"nonexistent-object-id", "valid", "v1", 1000)
	if err == nil {
		t.Fatal("insert orphan validation_records succeeded, want FK violation")
	}
}

func TestFKOrphanObjectDependenciesRejected(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	_, err = store.db.ExecContext(ctx,
		"INSERT INTO object_dependencies(object_id, dependency_type, dependency_id) VALUES (?, ?, ?)",
		"nonexistent-object-id", "election", "election-1")
	if err == nil {
		t.Fatal("insert orphan object_dependencies succeeded, want FK violation")
	}
}

func TestObjectConflictKeysBaseStatusCheck(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	oid := "test-object-conflict-status-check"
	insertTestObject(t, ctx, store.db, oid)

	validStatuses := []string{"valid", "valid_for_tally"}
	for _, status := range validStatuses {
		_, err := store.db.ExecContext(ctx,
			"INSERT INTO object_conflict_keys(object_id, conflict_group, conflict_key, base_validation_status) VALUES (?, ?, ?, ?)",
			oid, "group", "key-"+status, status)
		if err != nil {
			t.Fatalf("insert object_conflict_keys with base status %q: %v", status, err)
		}
	}

	invalidStatuses := []string{"pending_dependencies", "pending_payload_evicted", "valid_but_conflicted", "invalid"}
	for _, status := range invalidStatuses {
		_, err := store.db.ExecContext(ctx,
			"INSERT INTO object_conflict_keys(object_id, conflict_group, conflict_key, base_validation_status) VALUES (?, ?, ?, ?)",
			oid, "group", "bad-key-"+status, status)
		if err == nil {
			t.Fatalf("insert object_conflict_keys with base status %q succeeded, want CHECK violation", status)
		}
	}
}

func TestFKOrphanObjectSourcesRejected(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	_, err = store.db.ExecContext(ctx,
		"INSERT INTO object_sources(object_id, peer_id, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?)",
		"nonexistent-object-id", "peer-1", 1000, 2000)
	if err == nil {
		t.Fatal("insert orphan object_sources succeeded, want FK violation")
	}
}

func TestInvalidObjectRecordsWithoutObjectsRow(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	_, err = store.db.ExecContext(ctx,
		`INSERT INTO invalid_object_records(object_id, object_type, network_id, scope, scope_id,
			first_seen_at, last_seen_at, seen_count, validation_error_code)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"invalid-obj-1", "AnonymousBallot", "testnet", "election_id", "election-1",
		1000, 2000, 1, "ERR_INVALID")
	if err != nil {
		t.Fatalf("insert invalid_object_records without objects row: %v", err)
	}
}

func TestFKCascadeDeleteObjectPayloads(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	oid := "test-object-cascade-payload"
	insertTestObject(t, ctx, store.db, oid)
	_, err = store.db.ExecContext(ctx,
		"INSERT INTO object_payloads(object_id, payload_bytes) VALUES (?, ?)",
		oid, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("insert object_payloads: %v", err)
	}

	_, err = store.db.ExecContext(ctx, "DELETE FROM objects WHERE object_id = ?", oid)
	if err != nil {
		t.Fatalf("delete object: %v", err)
	}

	var count int
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM object_payloads WHERE object_id = ?", oid).Scan(&count); err != nil {
		t.Fatalf("count object_payloads: %v", err)
	}
	if count != 0 {
		t.Fatalf("object_payloads count = %d after cascade delete, want 0", count)
	}
}

func TestFKCascadeDeleteValidationRecords(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	oid := "test-object-cascade-validation"
	insertTestObject(t, ctx, store.db, oid)
	_, err = store.db.ExecContext(ctx,
		"INSERT INTO validation_records(object_id, validation_status, validator_version, last_checked_at) VALUES (?, ?, ?, ?)",
		oid, "valid", "v1", 1000)
	if err != nil {
		t.Fatalf("insert validation_records: %v", err)
	}

	_, err = store.db.ExecContext(ctx, "DELETE FROM objects WHERE object_id = ?", oid)
	if err != nil {
		t.Fatalf("delete object: %v", err)
	}

	var count int
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM validation_records WHERE object_id = ?", oid).Scan(&count); err != nil {
		t.Fatalf("count validation_records: %v", err)
	}
	if count != 0 {
		t.Fatalf("validation_records count = %d after cascade delete, want 0", count)
	}
}

func TestFKCascadeDeleteObjectDependencies(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	oid := "test-object-cascade-deps"
	insertTestObject(t, ctx, store.db, oid)
	_, err = store.db.ExecContext(ctx,
		"INSERT INTO object_dependencies(object_id, dependency_type, dependency_id) VALUES (?, ?, ?)",
		oid, "election", "election-1")
	if err != nil {
		t.Fatalf("insert object_dependencies: %v", err)
	}

	_, err = store.db.ExecContext(ctx, "DELETE FROM objects WHERE object_id = ?", oid)
	if err != nil {
		t.Fatalf("delete object: %v", err)
	}

	var count int
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM object_dependencies WHERE object_id = ?", oid).Scan(&count); err != nil {
		t.Fatalf("count object_dependencies: %v", err)
	}
	if count != 0 {
		t.Fatalf("object_dependencies count = %d after cascade delete, want 0", count)
	}
}

func TestFKCascadeDeleteObjectSources(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	oid := "test-object-cascade-sources"
	insertTestObject(t, ctx, store.db, oid)
	_, err = store.db.ExecContext(ctx,
		"INSERT INTO object_sources(object_id, peer_id, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?)",
		oid, "peer-1", 1000, 2000)
	if err != nil {
		t.Fatalf("insert object_sources: %v", err)
	}

	_, err = store.db.ExecContext(ctx, "DELETE FROM objects WHERE object_id = ?", oid)
	if err != nil {
		t.Fatalf("delete object: %v", err)
	}

	var count int
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM object_sources WHERE object_id = ?", oid).Scan(&count); err != nil {
		t.Fatalf("count object_sources: %v", err)
	}
	if count != 0 {
		t.Fatalf("object_sources count = %d after cascade delete, want 0", count)
	}
}

func assertColumns(t *testing.T, ctx context.Context, db *sql.DB, tableName string, wantCols []columnSpec) {
	t.Helper()
	rows, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		t.Fatalf("pragma table_info(%s): %v", tableName, err)
	}
	defer rows.Close()

	colMap := make(map[string]struct {
		notNull bool
		pk      bool
	})
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltValue sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan table_info(%s): %v", tableName, err)
		}
		colMap[name] = struct {
			notNull bool
			pk      bool
		}{notNull: notNull == 1, pk: pk == 1}
	}

	for _, wc := range wantCols {
		info, ok := colMap[wc.name]
		if !ok {
			t.Errorf("table %s: missing column %q", tableName, wc.name)
			continue
		}
		if wc.pk && !info.pk {
			t.Errorf("table %s: column %q pk = false, want true", tableName, wc.name)
		}
		if wc.notNull && !info.notNull {
			t.Errorf("table %s: column %q notNull = false, want true", tableName, wc.name)
		}
	}
}

func TestPrimaryKeyColumnsRejectNull(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	nullPkTests := []struct {
		table  string
		column string
	}{
		{"schema_metadata", "key"},
		{"objects", "object_id"},
		{"object_payloads", "object_id"},
		{"validation_records", "object_id"},
		{"invalid_object_records", "object_id"},
		{"election_state", "election_id"},
		{"trustee_selection_state", "trustee_selection_id"},
		{"tally_state", "election_id"},
		{"keys", "key_id"},
		{"peers", "peer_id"},
		{"message_cache", "object_id"},
	}

	for _, tc := range nullPkTests {
		cols := []string{tc.column}
		placeholders := []string{"?"}
		args := []interface{}{nil}

		switch tc.table {
		case "schema_metadata":
			cols = append(cols, "value")
			placeholders = append(placeholders, "?")
			args = append(args, "v")
		case "objects":
			cols = append(cols, "object_type", "protocol_version", "network_id", "scope", "scope_id", "created_at", "first_seen_at", "last_seen_at", "object_pow", "payload_hash", "payload_size", "payload_retained")
			placeholders = append(placeholders, "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?")
			args = append(args, "t", 1, "testnet", "network", "", 1, 1, 1, []byte{0}, []byte{1}, 1, 1)
		case "object_payloads":
			cols = append(cols, "payload_bytes")
			placeholders = append(placeholders, "?")
			args = append(args, []byte{1})
		case "validation_records":
			cols = append(cols, "validation_status", "validator_version", "last_checked_at")
			placeholders = append(placeholders, "?, ?, ?")
			args = append(args, "valid", "v1", 1)
		case "invalid_object_records":
			cols = append(cols, "object_type", "network_id", "scope", "scope_id", "first_seen_at", "last_seen_at", "seen_count")
			placeholders = append(placeholders, "?, ?, ?, ?, ?, ?, ?")
			args = append(args, "t", "testnet", "network", "", 1, 1, 1)
		case "election_state":
			cols = append(cols, "phase", "valid_object_count", "invalid_object_count", "pending_object_count", "computed_state_hash", "updated_at")
			placeholders = append(placeholders, "?, ?, ?, ?, ?, ?")
			args = append(args, "setup", 0, 0, 0, []byte{0}, 1)
		case "trustee_selection_state":
			cols = append(cols, "candidate_ranking_hash", "initial_selected_trustees_hash", "valid_vote_count", "conflicted_vote_count", "updated_at")
			placeholders = append(placeholders, "?, ?, ?, ?, ?")
			args = append(args, []byte{0}, []byte{0}, 0, 0, 1)
		case "tally_state":
			cols = append(cols, "encrypted_tally_hash", "valid_ballot_count", "conflicted_ballot_count", "invalid_ballot_count_diagnostic", "result_status", "result_hash", "updated_at")
			placeholders = append(placeholders, "?, ?, ?, ?, ?, ?, ?")
			args = append(args, []byte{0}, 0, 0, 0, "pending", []byte{0}, 1)
		case "keys":
			cols = append(cols, "key_type", "public_key", "encrypted_private_key", "created_at")
			placeholders = append(placeholders, "?, ?, ?, ?")
			args = append(args, "node", []byte{0}, []byte{0}, 1)
		case "peers":
			cols = append(cols, "score", "admission_status", "first_seen_at", "last_seen_at")
			placeholders = append(placeholders, "?, ?, ?, ?")
			args = append(args, 0.0, "unknown", 1, 1)
		case "message_cache":
			cols = append(cols, "first_seen_at", "last_seen_at", "seen_count")
			placeholders = append(placeholders, "?, ?, ?")
			args = append(args, 1, 1, 1)
		}

		query := fmt.Sprintf("INSERT INTO %s(%s) VALUES (%s)", tc.table, strings.Join(cols, ", "), strings.Join(placeholders, ", "))
		_, err := store.db.ExecContext(ctx, query, args...)
		if err == nil {
			t.Errorf("table %s: inserting NULL into primary key column %q succeeded, want error", tc.table, tc.column)
		}
	}
}

func insertTestObject(t *testing.T, ctx context.Context, db *sql.DB, objectID string) {
	t.Helper()
	_, err := db.ExecContext(ctx,
		`INSERT INTO objects(object_id, object_type, protocol_version, network_id, scope, scope_id,
			created_at, first_seen_at, last_seen_at, object_pow, payload_hash, payload_size, payload_retained)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		objectID, "AnonymousElection", 1, "testnet", "network", "",
		1000, 1000, 1000, []byte{0}, []byte{1}, 100, 1)
	if err != nil {
		t.Fatalf("insert test object %s: %v", objectID, err)
	}
}
