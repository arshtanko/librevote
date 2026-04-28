package storage

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestOpenCreatesDataDirDBSchemaMetadataAndWAL(t *testing.T) {
	ctx := context.Background()
	dataDir := filepath.Join(t.TempDir(), "data")

	store, err := Open(ctx, Config{DataDir: dataDir, NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	if _, err := os.Stat(dataDir); err != nil {
		t.Fatalf("data dir not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, databaseFileName)); err != nil {
		t.Fatalf("database file not created: %v", err)
	}

	metadata, err := store.SchemaMetadata(ctx)
	if err != nil {
		t.Fatalf("SchemaMetadata() error = %v", err)
	}
	if metadata.SchemaVersion != currentSchemaVersion {
		t.Fatalf("schema version = %q, want %q", metadata.SchemaVersion, currentSchemaVersion)
	}
	if metadata.NetworkID != "testnet" {
		t.Fatalf("network id = %q, want testnet", metadata.NetworkID)
	}
	if metadata.CreatedAt.IsZero() || metadata.UpdatedAt.IsZero() {
		t.Fatalf("metadata timestamps must be set: %+v", metadata)
	}
	metadataValues, err := readMetadata(ctx, store.db)
	if err != nil {
		t.Fatalf("read metadata values: %v", err)
	}
	wantMetadataKeys := map[string]bool{
		"schema_version": true,
		"network_id":     true,
		"created_at":     true,
		"updated_at":     true,
	}
	if len(metadataValues) != len(wantMetadataKeys) {
		t.Fatalf("metadata key count = %d, want %d: %#v", len(metadataValues), len(wantMetadataKeys), metadataValues)
	}
	for key := range wantMetadataKeys {
		if _, ok := metadataValues[key]; !ok {
			t.Fatalf("metadata missing key %q: %#v", key, metadataValues)
		}
	}

	var journalMode string
	if err := store.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("read journal mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal mode = %q, want wal", journalMode)
	}

	var foreignKeys int
	if err := store.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatalf("read foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d, want 1", foreignKeys)
	}

	var synchronous int
	if err := store.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		t.Fatalf("read synchronous: %v", err)
	}
	if synchronous != 1 {
		t.Fatalf("synchronous = %d, want 1", synchronous)
	}
}

func TestReopenSameNetworkIDPreservesMetadata(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()

	store, err := Open(ctx, Config{DataDir: dataDir, NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	first, err := store.SchemaMetadata(ctx)
	if err != nil {
		t.Fatalf("first SchemaMetadata() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}

	store, err = Open(ctx, Config{DataDir: dataDir, NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("second Open() error = %v", err)
	}
	defer store.Close()
	second, err := store.SchemaMetadata(ctx)
	if err != nil {
		t.Fatalf("second SchemaMetadata() error = %v", err)
	}

	if !second.CreatedAt.Equal(first.CreatedAt) || !second.UpdatedAt.Equal(first.UpdatedAt) {
		t.Fatalf("metadata timestamps changed: first=%+v second=%+v", first, second)
	}
}

func TestReopenDifferentNetworkIDFails(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()

	store, err := Open(ctx, Config{DataDir: dataDir, NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}

	store, err = Open(ctx, Config{DataDir: dataDir, NetworkID: "othernet"})
	if err == nil {
		store.Close()
		t.Fatal("Open() succeeded with mismatched network id")
	}
}

func TestReopenUnsupportedSchemaVersionFails(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()

	store, err := Open(ctx, Config{DataDir: dataDir, NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}

	db, err := openDB(Config{DataDir: dataDir, NetworkID: "testnet", BusyTimeout: defaultBusyTimeout})
	if err != nil {
		t.Fatalf("open sqlite for metadata mutation: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE schema_metadata SET value = ? WHERE key = 'schema_version'`, "unsupported"); err != nil {
		db.Close()
		t.Fatalf("mutate schema version: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close mutation db: %v", err)
	}

	store, err = Open(ctx, Config{DataDir: dataDir, NetworkID: "testnet"})
	if err == nil {
		store.Close()
		t.Fatal("Open() succeeded with unsupported schema version")
	}
}

func TestProcessLockPreventsSecondMutatingOpen(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()

	store, err := Open(ctx, Config{DataDir: dataDir, NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	defer store.Close()

	second, err := Open(ctx, Config{DataDir: dataDir, NetworkID: "testnet"})
	if err == nil {
		second.Close()
		t.Fatal("second Open() succeeded while first store is active")
	}
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open() error = %v, want ErrLocked", err)
	}
}

func TestCloseReleasesLockAndAllowsReopen(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()

	store, err := Open(ctx, Config{DataDir: dataDir, NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	store, err = Open(ctx, Config{DataDir: dataDir, NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("reopen Open() error = %v", err)
	}
	defer store.Close()
}

func TestInvalidConfigValidation(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "empty data dir", cfg: Config{NetworkID: "testnet"}},
		{name: "empty network id", cfg: Config{DataDir: t.TempDir()}},
		{name: "negative busy timeout", cfg: Config{DataDir: t.TempDir(), NetworkID: "testnet", BusyTimeout: -time.Second}},
		{name: "sub-millisecond busy timeout", cfg: Config{DataDir: t.TempDir(), NetworkID: "testnet", BusyTimeout: time.Nanosecond}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := Open(ctx, test.cfg)
			if err == nil {
				store.Close()
				t.Fatal("Open() succeeded, want error")
			}
		})
	}
}

func TestConfiguredBusyTimeout(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet", BusyTimeout: 1234 * time.Millisecond})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	got, err := sqliteBusyTimeoutMillis(store.db)
	if err != nil {
		t.Fatalf("read busy timeout: %v", err)
	}
	if got != 1234 {
		t.Fatalf("busy timeout = %d, want 1234", got)
	}
}

func sqliteBusyTimeoutMillis(db *sql.DB) (int, error) {
	var value string
	if err := db.QueryRow("PRAGMA busy_timeout").Scan(&value); err != nil {
		return 0, err
	}
	return strconv.Atoi(value)
}
