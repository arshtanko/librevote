package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"librevote/internal/domain"
)

// ObjectRef is a lightweight sync inventory item.
type ObjectRef struct {
	ObjectID   string
	ObjectType string
	Scope      string
	ScopeID    string
	CreatedAt  int64
}

// ListServableObjectRefs returns object references for all locally retained
// objects with a servable validation status (valid, valid_for_tally,
// valid_but_conflicted) matching the given scope and optional object type
// filters. Results are ordered by created_at ascending.
func (s *Store) ListServableObjectRefs(ctx context.Context, scope string, scopeID string, objectTypes []string) ([]ObjectRef, error) {
	if err := validateListServableParams(scope, scopeID); err != nil {
		return nil, err
	}

	servableStatuses := []string{
		string(domain.ValidationStatusValid),
		string(domain.ValidationStatusValidForTally),
		string(domain.ValidationStatusValidButConflicted),
	}

	query := `SELECT o.object_id, o.object_type, o.scope, o.scope_id, o.created_at
		FROM objects o
		JOIN validation_records vr ON vr.object_id = o.object_id
		WHERE o.payload_retained = 1
		AND o.scope = ?
		AND vr.validation_status IN (?, ?, ?)`

	args := []interface{}{scope, servableStatuses[0], servableStatuses[1], servableStatuses[2]}

	if scopeID != "" {
		query += " AND o.scope_id = ?"
		args = append(args, scopeID)
	}

	if len(objectTypes) > 0 {
		placeholders := make([]string, len(objectTypes))
		for i, t := range objectTypes {
			placeholders[i] = "?"
			args = append(args, t)
		}
		query += " AND o.object_type IN (" + strings.Join(placeholders, ", ") + ")"
	}

	query += " ORDER BY o.created_at ASC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list servable object refs: %w", err)
	}
	defer rows.Close()

	var refs []ObjectRef
	for rows.Next() {
		var ref ObjectRef
		if err := rows.Scan(&ref.ObjectID, &ref.ObjectType, &ref.Scope, &ref.ScopeID, &ref.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan object ref: %w", err)
		}
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate object refs: %w", err)
	}
	return refs, nil
}

// LoadObjectEnvelope reconstructs a full domain.ObjectEnvelope from stored rows.
// The object must have a retained payload and a servable validation status.
func (s *Store) LoadObjectEnvelope(ctx context.Context, objectID string) (domain.ObjectEnvelope, error) {
	if objectID == "" {
		return domain.ObjectEnvelope{}, errors.New("object_id is required")
	}

	servableStatuses := []string{
		string(domain.ValidationStatusValid),
		string(domain.ValidationStatusValidForTally),
		string(domain.ValidationStatusValidButConflicted),
	}

	var objectType, networkID, scope, scopeID string
	var protocolVersion int
	var createdAt int64
	var pow []byte
	var payload []byte

	row := s.db.QueryRowContext(ctx,
		`SELECT o.object_type, o.protocol_version, o.network_id, o.scope, o.scope_id,
		 o.created_at, o.object_pow, op.payload_bytes
		 FROM objects o
		 JOIN validation_records vr ON vr.object_id = o.object_id
		 JOIN object_payloads op ON op.object_id = o.object_id
		 WHERE o.object_id = ?
		 AND o.payload_retained = 1
		 AND vr.validation_status IN (?, ?, ?)`,
		objectID, servableStatuses[0], servableStatuses[1], servableStatuses[2])

	err := row.Scan(&objectType, &protocolVersion, &networkID, &scope, &scopeID,
		&createdAt, &pow, &payload)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ObjectEnvelope{}, fmt.Errorf("object not found or not servable: %s", objectID)
		}
		return domain.ObjectEnvelope{}, fmt.Errorf("load object envelope: %w", err)
	}

	protoVersion, err := protocolVersionString(protocolVersion)
	if err != nil {
		return domain.ObjectEnvelope{}, fmt.Errorf("protocol version: %w", err)
	}

	return domain.ObjectEnvelope{
		ObjectID:        objectID,
		ObjectType:      domain.ObjectType(objectType),
		ProtocolVersion: protoVersion,
		NetworkID:       networkID,
		Scope:           domain.Scope(scope),
		ScopeID:         scopeID,
		Payload:         cloneBytes(payload),
		Pow:             cloneBytes(pow),
		CreatedAt:       createdAt,
	}, nil
}

// ScopePair is a distinct scope + scope_id from servable objects.
type ScopePair struct {
	Scope   string
	ScopeID string
}

// ListServableScopes returns distinct (scope, scope_id) pairs for all locally
// retained objects with servable validation statuses.
func (s *Store) ListServableScopes(ctx context.Context) ([]ScopePair, error) {
	servableStatuses := []string{
		string(domain.ValidationStatusValid),
		string(domain.ValidationStatusValidForTally),
		string(domain.ValidationStatusValidButConflicted),
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT o.scope, o.scope_id
		 FROM objects o
		 JOIN validation_records vr ON vr.object_id = o.object_id
		 WHERE o.payload_retained = 1
		 AND vr.validation_status IN (?, ?, ?)
		 ORDER BY o.scope, o.scope_id`,
		servableStatuses[0], servableStatuses[1], servableStatuses[2])
	if err != nil {
		return nil, fmt.Errorf("list servable scopes: %w", err)
	}
	defer rows.Close()

	var pairs []ScopePair
	for rows.Next() {
		var p ScopePair
		if err := rows.Scan(&p.Scope, &p.ScopeID); err != nil {
			return nil, fmt.Errorf("scan scope pair: %w", err)
		}
		pairs = append(pairs, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scope pairs: %w", err)
	}
	return pairs, nil
}

func validateListServableParams(scope string, scopeID string) error {
	if scope == "" {
		return errors.New("scope is required")
	}
	if domain.ScopeIDRequired(domain.Scope(scope)) {
		if scopeID == "" {
			return fmt.Errorf("scope %q requires non-empty scope_id", scope)
		}
	} else {
		if scopeID != "" {
			return fmt.Errorf("scope %q requires empty scope_id", scope)
		}
	}
	return nil
}

func protocolVersionString(version int) (string, error) {
	if version <= 0 {
		return "", fmt.Errorf("invalid protocol version %d", version)
	}
	return "v" + strconv.Itoa(version), nil
}
