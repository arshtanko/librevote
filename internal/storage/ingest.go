package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"librevote/internal/domain"
)

var (
	// ErrPayloadMismatch is returned when a known object_id is ingested with a
	// payload whose hash does not match the retained hash.
	ErrPayloadMismatch = errors.New("payload mismatch for known object_id")
	// ErrNotPending is returned when EvictPendingPayload is called on an object
	// whose validation status is not pending_dependencies (or already evicted).
	ErrNotPending = errors.New("object is not pending, cannot evict payload")
	// ErrDirectEvictedStatus is returned when IngestObject is called with
	// ValidationStatusPendingPayloadEvicted, which is only produced by EvictPendingPayload.
	ErrDirectEvictedStatus = errors.New("direct ingest with pending_payload_evicted status is not allowed")
)

// Dependency describes a single object dependency used for pending objects.
type Dependency struct {
	Type string
	ID   string
}

// IngestObjectInput carries all fields needed for atomic object ingestion.
type IngestObjectInput struct {
	ObjectID               string
	ObjectType             string
	ProtocolVersion        int
	NetworkID              string
	Scope                  string
	ScopeID                string
	CreatedAt              int64
	ObjectPoW              []byte
	PayloadBytes           []byte
	ValidationStatus       domain.ValidationStatus
	ValidationErrorCode    string
	ValidationErrorMessage string
	ValidatorVersion       string
	Dependencies           []Dependency
	SeenAt                 int64
	CheckedAt              int64
}

// IngestObjectResult reports the outcome of an ingest operation.
type IngestObjectResult struct {
	Inserted        bool
	Updated         bool
	Duplicate       bool
	Reacquired      bool
	InvalidRecorded bool
}

// ObjectMetadata mirrors the objects table row.
type ObjectMetadata struct {
	ObjectID        string
	ObjectType      string
	ProtocolVersion int
	NetworkID       string
	Scope           string
	ScopeID         string
	CreatedAt       int64
	FirstSeenAt     int64
	LastSeenAt      int64
	ObjectPoW       []byte
	PayloadHash     []byte
	PayloadSize     int
	PayloadRetained bool
}

// ValidationRecord mirrors the validation_records table row.
type ValidationRecord struct {
	ObjectID               string
	ValidationStatus       string
	ValidationErrorCode    string
	ValidationErrorMessage string
	ValidatorVersion       string
	LastCheckedAt          int64
}

// IngestObject performs an atomic object ingestion transaction.
func (s *Store) IngestObject(ctx context.Context, input IngestObjectInput) (IngestObjectResult, error) {
	var result IngestObjectResult

	if err := validateIngestInput(input); err != nil {
		return result, err
	}

	payloadHash := computePayloadHash(input.PayloadBytes)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, fmt.Errorf("begin ingest transaction: %w", err)
	}
	defer tx.Rollback()

	// Check invalid_object_records.
	var invalidExists bool
	var invalidSeenCount int
	row := tx.QueryRowContext(ctx,
		"SELECT 1, seen_count FROM invalid_object_records WHERE object_id = ?",
		input.ObjectID)
	if err := row.Scan(&invalidExists, &invalidSeenCount); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return result, fmt.Errorf("check invalid_object_records: %w", err)
		}
	} else {
		invalidExists = true
	}

	// Check objects table.
	var objExists bool
	var existingPayloadHash []byte
	var payloadRetained int
	var existingStatus string
	row = tx.QueryRowContext(ctx,
		"SELECT payload_hash, payload_retained FROM objects WHERE object_id = ?",
		input.ObjectID)
	if err := row.Scan(&existingPayloadHash, &payloadRetained); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return result, fmt.Errorf("check objects: %w", err)
		}
	} else {
		objExists = true
		if err := tx.QueryRowContext(ctx,
			"SELECT validation_status FROM validation_records WHERE object_id = ?",
			input.ObjectID).Scan(&existingStatus); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return result, fmt.Errorf("check validation_records: %w", err)
		}
	}

	// Fast path: retained existing object with matching payload is a duplicate.
	// Only last_seen_at is updated; validation record and dependencies are untouched.
	// Pending objects may still be rechecked as invalid by the validation layer.
	if objExists && payloadRetained == 1 && !(input.ValidationStatus == domain.ValidationStatusInvalid && existingStatus == string(domain.ValidationStatusPendingDependencies)) {
		if len(input.PayloadBytes) > 0 {
			if !bytes.Equal(payloadHash, existingPayloadHash) {
				return result, ErrPayloadMismatch
			}
		}
		if invalidExists {
			if _, err := tx.ExecContext(ctx,
				"DELETE FROM invalid_object_records WHERE object_id = ?",
				input.ObjectID); err != nil {
				return result, fmt.Errorf("delete invalid_object_records: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx,
			"UPDATE objects SET last_seen_at = ? WHERE object_id = ?",
			input.SeenAt, input.ObjectID); err != nil {
			return result, fmt.Errorf("update object last_seen_at: %w", err)
		}
		result.Duplicate = true
		return result, tx.Commit()
	}

	switch input.ValidationStatus {
	case domain.ValidationStatusInvalid:
		if objExists {
			if _, err := tx.ExecContext(ctx,
				"DELETE FROM objects WHERE object_id = ?", input.ObjectID); err != nil {
				return result, fmt.Errorf("delete object for invalid transition: %w", err)
			}
			result.Updated = true
		}
		if invalidExists {
			if _, err := tx.ExecContext(ctx,
				`UPDATE invalid_object_records
				 SET last_seen_at = ?, seen_count = seen_count + 1,
				     validation_error_code = ?
				 WHERE object_id = ?`,
				input.SeenAt, input.ValidationErrorCode, input.ObjectID); err != nil {
				return result, fmt.Errorf("update invalid_object_records: %w", err)
			}
			result.Duplicate = true
		} else {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO invalid_object_records
				 (object_id, object_type, network_id, scope, scope_id,
				  first_seen_at, last_seen_at, seen_count, validation_error_code)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				input.ObjectID, input.ObjectType, input.NetworkID,
				input.Scope, input.ScopeID,
				input.SeenAt, input.SeenAt, 1,
				input.ValidationErrorCode); err != nil {
				return result, fmt.Errorf("insert invalid_object_records: %w", err)
			}
		}
		result.InvalidRecorded = true
		return result, tx.Commit()

	default:
		if invalidExists {
			if _, err := tx.ExecContext(ctx,
				"DELETE FROM invalid_object_records WHERE object_id = ?",
				input.ObjectID); err != nil {
				return result, fmt.Errorf("delete invalid_object_records: %w", err)
			}
		}

		if objExists {
			// Reacquire path: object exists but payload was evicted.
			if len(input.PayloadBytes) == 0 {
				return result, errors.New("payload bytes required")
			}
			if !bytes.Equal(payloadHash, existingPayloadHash) {
				return result, ErrPayloadMismatch
			}

			if _, err := tx.ExecContext(ctx,
				"UPDATE objects SET last_seen_at = ? WHERE object_id = ?",
				input.SeenAt, input.ObjectID); err != nil {
				return result, fmt.Errorf("update object last_seen_at: %w", err)
			}

			if _, err := tx.ExecContext(ctx,
				"INSERT INTO object_payloads(object_id, payload_bytes) VALUES (?, ?)",
				input.ObjectID, input.PayloadBytes); err != nil {
				return result, fmt.Errorf("restore object_payloads: %w", err)
			}
			if _, err := tx.ExecContext(ctx,
				"UPDATE objects SET payload_retained = 1 WHERE object_id = ?",
				input.ObjectID); err != nil {
				return result, fmt.Errorf("update payload_retained: %w", err)
			}

			if _, err := tx.ExecContext(ctx,
				`UPDATE validation_records
				 SET validation_status = ?, validation_error_code = ?,
				     validation_error_message = ?, validator_version = ?,
				     last_checked_at = ?
				 WHERE object_id = ?`,
				string(input.ValidationStatus), input.ValidationErrorCode,
				input.ValidationErrorMessage, input.ValidatorVersion,
				input.CheckedAt, input.ObjectID); err != nil {
				return result, fmt.Errorf("update validation record: %w", err)
			}

			if err := replaceDependencies(ctx, tx, input.ObjectID, input.ValidationStatus, input.Dependencies); err != nil {
				return result, err
			}

			result.Reacquired = true
			result.Updated = true
			return result, tx.Commit()
		}

		// New object.
		if len(input.PayloadBytes) == 0 {
			return result, errors.New("payload bytes required")
		}

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO objects
			 (object_id, object_type, protocol_version, network_id, scope, scope_id,
			  created_at, first_seen_at, last_seen_at, object_pow,
			  payload_hash, payload_size, payload_retained)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			input.ObjectID, input.ObjectType, input.ProtocolVersion,
			input.NetworkID, input.Scope, input.ScopeID,
			input.CreatedAt, input.SeenAt, input.SeenAt,
			input.ObjectPoW, payloadHash, len(input.PayloadBytes), 1); err != nil {
			return result, fmt.Errorf("insert object: %w", err)
		}

		if _, err := tx.ExecContext(ctx,
			"INSERT INTO object_payloads(object_id, payload_bytes) VALUES (?, ?)",
			input.ObjectID, input.PayloadBytes); err != nil {
			return result, fmt.Errorf("insert object_payloads: %w", err)
		}

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO validation_records
			 (object_id, validation_status, validation_error_code,
			  validation_error_message, validator_version, last_checked_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			input.ObjectID, string(input.ValidationStatus),
			input.ValidationErrorCode, input.ValidationErrorMessage,
			input.ValidatorVersion, input.CheckedAt); err != nil {
			return result, fmt.Errorf("insert validation_records: %w", err)
		}

		if err := replaceDependencies(ctx, tx, input.ObjectID, input.ValidationStatus, input.Dependencies); err != nil {
			return result, err
		}

		result.Inserted = true
		return result, tx.Commit()
	}
}

// EvictPendingPayload removes the retained payload for a pending object,
// transitions its status to pending_payload_evicted, and clears dependencies.
func (s *Store) EvictPendingPayload(ctx context.Context, objectID string, checkedAt int64, validatorVersion string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin evict transaction: %w", err)
	}
	defer tx.Rollback()

	var payloadRetained int
	if err := tx.QueryRowContext(ctx,
		"SELECT payload_retained FROM objects WHERE object_id = ?",
		objectID).Scan(&payloadRetained); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("object not found: %s", objectID)
		}
		return fmt.Errorf("check objects: %w", err)
	}

	var existingStatus string
	if err := tx.QueryRowContext(ctx,
		"SELECT validation_status FROM validation_records WHERE object_id = ?",
		objectID).Scan(&existingStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("validation record not found: %s", objectID)
		}
		return fmt.Errorf("check validation_records: %w", err)
	}

	if existingStatus != string(domain.ValidationStatusPendingDependencies) &&
		existingStatus != string(domain.ValidationStatusPendingPayloadEvicted) {
		return ErrNotPending
	}

	if existingStatus == string(domain.ValidationStatusPendingPayloadEvicted) && payloadRetained == 0 {
		// Already evicted; idempotent no-op.
		return nil
	}

	res, err := tx.ExecContext(ctx,
		"UPDATE objects SET payload_retained = 0 WHERE object_id = ?",
		objectID)
	if err != nil {
		return fmt.Errorf("update payload_retained: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("object not found: %s", objectID)
	}

	if _, err := tx.ExecContext(ctx,
		"DELETE FROM object_payloads WHERE object_id = ?",
		objectID); err != nil {
		return fmt.Errorf("delete object_payloads: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE validation_records
		 SET validation_status = ?, validator_version = ?, last_checked_at = ?
		 WHERE object_id = ?`,
		domain.ValidationStatusPendingPayloadEvicted, validatorVersion,
		checkedAt, objectID); err != nil {
		return fmt.Errorf("update validation_records: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		"DELETE FROM object_dependencies WHERE object_id = ?",
		objectID); err != nil {
		return fmt.Errorf("delete object_dependencies: %w", err)
	}

	return tx.Commit()
}

// ObjectMetadata reads a single object metadata row.
func (s *Store) ObjectMetadata(ctx context.Context, objectID string) (ObjectMetadata, error) {
	var m ObjectMetadata
	var payloadRetained int
	row := s.db.QueryRowContext(ctx,
		`SELECT object_id, object_type, protocol_version, network_id, scope, scope_id,
		 created_at, first_seen_at, last_seen_at, object_pow,
		 payload_hash, payload_size, payload_retained
		 FROM objects WHERE object_id = ?`, objectID)
	err := row.Scan(
		&m.ObjectID, &m.ObjectType, &m.ProtocolVersion,
		&m.NetworkID, &m.Scope, &m.ScopeID,
		&m.CreatedAt, &m.FirstSeenAt, &m.LastSeenAt,
		&m.ObjectPoW, &m.PayloadHash, &m.PayloadSize, &payloadRetained,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return m, fmt.Errorf("object not found: %w", err)
		}
		return m, fmt.Errorf("read object metadata: %w", err)
	}
	m.ObjectPoW = cloneBytes(m.ObjectPoW)
	m.PayloadHash = cloneBytes(m.PayloadHash)
	m.PayloadRetained = payloadRetained == 1
	return m, nil
}

// ValidationRecord reads a single validation record.
func (s *Store) ValidationRecord(ctx context.Context, objectID string) (ValidationRecord, error) {
	var r ValidationRecord
	row := s.db.QueryRowContext(ctx,
		`SELECT object_id, validation_status, validation_error_code,
		 validation_error_message, validator_version, last_checked_at
		 FROM validation_records WHERE object_id = ?`, objectID)
	err := row.Scan(
		&r.ObjectID, &r.ValidationStatus, &r.ValidationErrorCode,
		&r.ValidationErrorMessage, &r.ValidatorVersion, &r.LastCheckedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return r, fmt.Errorf("validation record not found: %w", err)
		}
		return r, fmt.Errorf("read validation record: %w", err)
	}
	return r, nil
}

// Payload reads retained payload bytes for an object.
func (s *Store) Payload(ctx context.Context, objectID string) ([]byte, error) {
	var payload []byte
	row := s.db.QueryRowContext(ctx,
		"SELECT payload_bytes FROM object_payloads WHERE object_id = ?",
		objectID)
	if err := row.Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("payload not found: %w", err)
		}
		return nil, fmt.Errorf("read payload: %w", err)
	}
	return cloneBytes(payload), nil
}

// Dependencies reads all persisted validation dependency rows for an object.
func (s *Store) Dependencies(ctx context.Context, objectID string) ([]Dependency, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT dependency_type, dependency_id
		 FROM object_dependencies
		 WHERE object_id = ?
		 ORDER BY dependency_type, dependency_id`,
		objectID)
	if err != nil {
		return nil, fmt.Errorf("query dependencies: %w", err)
	}
	defer rows.Close()

	var deps []Dependency
	for rows.Next() {
		var d Dependency
		if err := rows.Scan(&d.Type, &d.ID); err != nil {
			return nil, fmt.Errorf("scan dependency: %w", err)
		}
		deps = append(deps, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate dependencies: %w", err)
	}
	return deps, nil
}

// ObjectsWaitingOnDependency lists objects with persisted validation dependency
// rows matching the dependency. Returned object ids are deterministic and unique.
func (s *Store) ObjectsWaitingOnDependency(ctx context.Context, dependency Dependency) ([]string, error) {
	if dependency.Type == "" || dependency.ID == "" {
		return nil, errors.New("dependency type and id are required")
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT object_id
		 FROM object_dependencies
		 WHERE dependency_type = ? AND dependency_id = ?
		 ORDER BY object_id`,
		dependency.Type, dependency.ID)
	if err != nil {
		return nil, fmt.Errorf("query waiting objects: %w", err)
	}
	defer rows.Close()

	var objectIDs []string
	for rows.Next() {
		var objectID string
		if err := rows.Scan(&objectID); err != nil {
			return nil, fmt.Errorf("scan waiting object: %w", err)
		}
		objectIDs = append(objectIDs, objectID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate waiting objects: %w", err)
	}
	return objectIDs, nil
}

func validateIngestInput(input IngestObjectInput) error {
	if input.ObjectID == "" {
		return errors.New("object_id is required")
	}
	if input.ObjectType == "" && input.ValidationStatus != domain.ValidationStatusInvalid {
		return errors.New("object_type is required")
	}
	if input.NetworkID == "" && input.ValidationStatus != domain.ValidationStatusInvalid {
		return errors.New("network_id is required")
	}
	if input.ValidatorVersion == "" {
		return errors.New("validator_version is required")
	}
	if input.SeenAt <= 0 {
		return errors.New("seen_at must be greater than zero")
	}
	if input.CheckedAt <= 0 {
		return errors.New("checked_at must be greater than zero")
	}
	if input.ValidationStatus == domain.ValidationStatusPendingPayloadEvicted {
		return ErrDirectEvictedStatus
	}
	return nil
}

func computePayloadHash(payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	h := sha256.Sum256(payload)
	return h[:]
}

func replaceDependencies(ctx context.Context, tx *sql.Tx, objectID string, status domain.ValidationStatus, deps []Dependency) error {
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM object_dependencies WHERE object_id = ?",
		objectID); err != nil {
		return fmt.Errorf("delete dependencies: %w", err)
	}

	if status != domain.ValidationStatusPendingDependencies {
		return nil
	}

	if len(deps) == 0 {
		return errors.New("pending_dependencies requires at least one dependency")
	}

	stmt, err := tx.PrepareContext(ctx,
		"INSERT INTO object_dependencies(object_id, dependency_type, dependency_id) VALUES (?, ?, ?)")
	if err != nil {
		return fmt.Errorf("prepare dependency insert: %w", err)
	}
	defer stmt.Close()

	for _, dep := range deps {
		if _, err := stmt.ExecContext(ctx, objectID, dep.Type, dep.ID); err != nil {
			return fmt.Errorf("insert dependency: %w", err)
		}
	}
	return nil
}

// InvalidObjectRecord mirrors the invalid_object_records table row.
type InvalidObjectRecord struct {
	ObjectID            string
	ObjectType          string
	NetworkID           string
	Scope               string
	ScopeID             string
	FirstSeenAt         int64
	LastSeenAt          int64
	SeenCount           int
	ValidationErrorCode string
}

// InvalidObjectRecord reads a single invalid object record.
func (s *Store) InvalidObjectRecord(ctx context.Context, objectID string) (InvalidObjectRecord, error) {
	var r InvalidObjectRecord
	row := s.db.QueryRowContext(ctx,
		`SELECT object_id, object_type, network_id, scope, scope_id,
		 first_seen_at, last_seen_at, seen_count, validation_error_code
		 FROM invalid_object_records WHERE object_id = ?`, objectID)
	err := row.Scan(
		&r.ObjectID, &r.ObjectType, &r.NetworkID, &r.Scope, &r.ScopeID,
		&r.FirstSeenAt, &r.LastSeenAt, &r.SeenCount, &r.ValidationErrorCode,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return r, fmt.Errorf("invalid object record not found: %w", err)
		}
		return r, fmt.Errorf("read invalid object record: %w", err)
	}
	return r, nil
}

// IngestObjectWithDeadline wraps IngestObject with a context deadline to prevent
// runaway transactions. This is a thin helper for callers that do not manage
// their own deadline.
func (s *Store) IngestObjectWithDeadline(ctx context.Context, input IngestObjectInput, timeout time.Duration) (IngestObjectResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return s.IngestObject(ctx, input)
}
