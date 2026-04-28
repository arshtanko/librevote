package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

const (
	databaseFileName     = "librevote.sqlite"
	lockFileName         = "librevote.lock"
	defaultBusyTimeout   = 5 * time.Second
	currentSchemaVersion = "1"
)

// ErrLocked reports that another live local process holds the storage lock.
var ErrLocked = errors.New("storage lock is held by another process")

// Config controls storage bootstrap.
type Config struct {
	DataDir     string
	NetworkID   string
	BusyTimeout time.Duration
}

// SchemaMetadata is the durable database schema metadata.
type SchemaMetadata struct {
	SchemaVersion string
	NetworkID     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Store is an open SQLite storage handle with an active mutating process lock.
type Store struct {
	db   *sql.DB
	lock *ProcessLock
}

// ProcessLock is an acquired exclusive process lock.
type ProcessLock struct {
	file *os.File
}

// Open acquires the process lock, opens SQLite, applies required PRAGMAs, and bootstraps schema metadata.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	cfg, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	lock, err := AcquireProcessLock(filepath.Join(cfg.DataDir, lockFileName))
	if err != nil {
		return nil, err
	}

	db, err := openDB(cfg)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}

	store := &Store{db: db, lock: lock}
	if err := store.bootstrap(ctx, cfg.NetworkID); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

// AcquireProcessLock acquires an exclusive non-blocking lock for mutating storage access.
func AcquireProcessLock(path string) (*ProcessLock, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open process lock: %w", err)
	}

	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("acquire process lock: %w", err)
	}

	if err := file.Truncate(0); err != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
		return nil, fmt.Errorf("truncate process lock: %w", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
		return nil, fmt.Errorf("seek process lock: %w", err)
	}
	if _, err := fmt.Fprintf(file, "%d\n", os.Getpid()); err != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
		return nil, fmt.Errorf("write process lock: %w", err)
	}

	return &ProcessLock{file: file}, nil
}

// Close releases the acquired process lock.
func (l *ProcessLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	unlockErr := unix.Flock(int(file.Fd()), unix.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil {
		return fmt.Errorf("release process lock: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close process lock: %w", closeErr)
	}
	return nil
}

// Close closes SQLite and releases the process lock.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	var err error
	if s.db != nil {
		err = s.db.Close()
		s.db = nil
	}
	if lockErr := s.lock.Close(); lockErr != nil && err == nil {
		err = lockErr
	}
	return err
}

// SchemaMetadata reads the current schema metadata.
func (s *Store) SchemaMetadata(ctx context.Context) (SchemaMetadata, error) {
	if s == nil || s.db == nil {
		return SchemaMetadata{}, errors.New("storage is closed")
	}
	values, err := readMetadata(ctx, s.db)
	if err != nil {
		return SchemaMetadata{}, err
	}
	return parseMetadata(values)
}

func normalizeConfig(cfg Config) (Config, error) {
	cfg.DataDir = strings.TrimSpace(cfg.DataDir)
	cfg.NetworkID = strings.TrimSpace(cfg.NetworkID)
	if cfg.DataDir == "" {
		return Config{}, errors.New("data dir is required")
	}
	if cfg.NetworkID == "" {
		return Config{}, errors.New("network id is required")
	}
	if cfg.BusyTimeout == 0 {
		cfg.BusyTimeout = defaultBusyTimeout
	}
	if cfg.BusyTimeout < 0 {
		return Config{}, errors.New("busy timeout must not be negative")
	}
	if cfg.BusyTimeout < time.Millisecond {
		return Config{}, errors.New("busy timeout must be at least 1ms")
	}
	return cfg, nil
}

func openDB(cfg Config) (*sql.DB, error) {
	dbPath := filepath.Join(cfg.DataDir, databaseFileName)
	dsn := (&url.URL{Scheme: "file", Path: dbPath}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	if err := applyPragmas(db, cfg.BusyTimeout); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func applyPragmas(db *sql.DB, busyTimeout time.Duration) error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA synchronous=NORMAL",
		fmt.Sprintf("PRAGMA busy_timeout=%d", busyTimeout.Milliseconds()),
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			return fmt.Errorf("apply %s: %w", pragma, err)
		}
	}
	return nil
}

func (s *Store) bootstrap(ctx context.Context, networkID string) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_metadata (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create schema metadata: %w", err)
	}

	values, err := readMetadata(ctx, s.db)
	if err != nil {
		return err
	}
	if len(values) == 0 {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		entries := map[string]string{
			"schema_version": currentSchemaVersion,
			"network_id":     networkID,
			"created_at":     now,
			"updated_at":     now,
		}
		return writeInitialMetadata(ctx, s.db, entries)
	}

	metadata, err := parseMetadata(values)
	if err != nil {
		return err
	}
	if metadata.SchemaVersion != currentSchemaVersion {
		return fmt.Errorf("unsupported schema version: stored %q current %q", metadata.SchemaVersion, currentSchemaVersion)
	}
	if metadata.NetworkID != networkID {
		return fmt.Errorf("network id mismatch: stored %q requested %q", metadata.NetworkID, networkID)
	}
	return nil
}

func readMetadata(ctx context.Context, db *sql.DB) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT key, value FROM schema_metadata`)
	if err != nil {
		return nil, fmt.Errorf("read schema metadata: %w", err)
	}
	defer rows.Close()

	values := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("scan schema metadata: %w", err)
		}
		values[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schema metadata: %w", err)
	}
	return values, nil
}

func writeInitialMetadata(ctx context.Context, db *sql.DB, entries map[string]string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema metadata bootstrap: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO schema_metadata(key, value) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare schema metadata bootstrap: %w", err)
	}
	defer stmt.Close()

	for key, value := range entries {
		if _, err := stmt.ExecContext(ctx, key, value); err != nil {
			return fmt.Errorf("insert schema metadata %q: %w", key, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema metadata bootstrap: %w", err)
	}
	return nil
}

func parseMetadata(values map[string]string) (SchemaMetadata, error) {
	schemaVersion, ok := values["schema_version"]
	if !ok || schemaVersion == "" {
		return SchemaMetadata{}, errors.New("schema metadata missing schema_version")
	}
	networkID, ok := values["network_id"]
	if !ok || networkID == "" {
		return SchemaMetadata{}, errors.New("schema metadata missing network_id")
	}
	createdAt, err := parseMetadataTime(values, "created_at")
	if err != nil {
		return SchemaMetadata{}, err
	}
	updatedAt, err := parseMetadataTime(values, "updated_at")
	if err != nil {
		return SchemaMetadata{}, err
	}
	return SchemaMetadata{
		SchemaVersion: schemaVersion,
		NetworkID:     networkID,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	}, nil
}

func parseMetadataTime(values map[string]string, key string) (time.Time, error) {
	value, ok := values[key]
	if !ok || value == "" {
		return time.Time{}, fmt.Errorf("schema metadata missing %s", key)
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse schema metadata %s %q: %w", key, value, err)
	}
	return t, nil
}
