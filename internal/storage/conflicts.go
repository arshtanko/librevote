package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"librevote/internal/validation"
)

// ConflictMetadata describes one local validation conflict-group membership for
// an object. It is storage metadata around the object log, not domain truth.
type ConflictMetadata struct {
	ObjectID string
	Group    string
	Key      string
}

type conflictGroupMember struct {
	objectID   string
	baseStatus validation.Status
}

// ReplaceConflictMetadata atomically replaces persisted conflict metadata for an
// existing object without mutating domain identity, payload, PoW, or source metadata.
func (s *Store) ReplaceConflictMetadata(ctx context.Context, objectID string, conflicts []ConflictMetadata) error {
	if objectID == "" {
		return errors.New("object_id is required")
	}
	if err := validateConflictMetadata(objectID, conflicts); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin conflict metadata transaction: %w", err)
	}
	defer tx.Rollback()

	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT 1 FROM objects WHERE object_id = ?", objectID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("object not found: %s", objectID)
		}
		return fmt.Errorf("read object metadata: %w", err)
	}

	oldConflicts, err := conflictMetadataForObjectTx(ctx, tx, objectID)
	if err != nil {
		return err
	}
	var oldBaseStatus validation.Status
	if len(oldConflicts) > 0 {
		oldBaseStatus, err = conflictStoredBaseStatusForObjectTx(ctx, tx, objectID)
		if err != nil {
			return err
		}
	}
	if err := replaceConflictMetadataTx(ctx, tx, objectID, conflicts); err != nil {
		return err
	}
	if err := classifyPersistedConflictsTx(ctx, tx, append(oldConflicts, conflicts...)); err != nil {
		return err
	}
	if len(oldConflicts) > 0 {
		if err := restoreSingletonConflictMemberTx(ctx, tx, conflictGroupMember{objectID: objectID, baseStatus: oldBaseStatus}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ConflictMetadataForObject returns persisted conflict metadata rows for an
// object in deterministic order.
func (s *Store) ConflictMetadataForObject(ctx context.Context, objectID string) ([]ConflictMetadata, error) {
	if objectID == "" {
		return nil, errors.New("object_id is required")
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT object_id, conflict_group, conflict_key
		 FROM object_conflict_keys
		 WHERE object_id = ?
		 ORDER BY conflict_group, conflict_key`, objectID)
	if err != nil {
		return nil, fmt.Errorf("query conflict metadata: %w", err)
	}
	defer rows.Close()
	return scanConflictMetadata(rows)
}

// ObjectsInConflictGroup returns object ids in a conflict group in deterministic order.
func (s *Store) ObjectsInConflictGroup(ctx context.Context, group, key string) ([]string, error) {
	if group == "" || key == "" {
		return nil, errors.New("conflict group and key are required")
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT object_id
		 FROM object_conflict_keys
		 WHERE conflict_group = ? AND conflict_key = ?
		 ORDER BY object_id`, group, key)
	if err != nil {
		return nil, fmt.Errorf("query conflict group: %w", err)
	}
	defer rows.Close()

	var objectIDs []string
	for rows.Next() {
		var objectID string
		if err := rows.Scan(&objectID); err != nil {
			return nil, fmt.Errorf("scan conflict group: %w", err)
		}
		objectIDs = append(objectIDs, objectID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate conflict group: %w", err)
	}
	return objectIDs, nil
}

func validateConflictMetadata(objectID string, conflicts []ConflictMetadata) error {
	seen := make(map[ConflictMetadata]struct{}, len(conflicts))
	for _, conflict := range conflicts {
		if conflict.Group == "" || conflict.Key == "" {
			return errors.New("conflict group and key are required")
		}
		if conflict.ObjectID != "" && conflict.ObjectID != objectID {
			return errors.New("conflict object_id must match object_id")
		}
		conflict.ObjectID = objectID
		if _, ok := seen[conflict]; ok {
			return errors.New("duplicate conflict metadata")
		}
		seen[conflict] = struct{}{}
	}
	return nil
}

func replaceConflictMetadataTx(ctx context.Context, tx *sql.Tx, objectID string, conflicts []ConflictMetadata) error {
	var baseStatus validation.Status
	if len(conflicts) > 0 {
		var err error
		baseStatus, err = conflictBaseStatusForObjectTx(ctx, tx, objectID)
		if err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM object_conflict_keys WHERE object_id = ?", objectID); err != nil {
		return fmt.Errorf("delete conflict metadata: %w", err)
	}
	if len(conflicts) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx,
		"INSERT INTO object_conflict_keys(object_id, conflict_group, conflict_key, base_validation_status) VALUES (?, ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("prepare conflict metadata insert: %w", err)
	}
	defer stmt.Close()
	for _, conflict := range conflicts {
		if _, err := stmt.ExecContext(ctx, objectID, conflict.Group, conflict.Key, baseStatus.String()); err != nil {
			return fmt.Errorf("insert conflict metadata: %w", err)
		}
	}
	return nil
}

func conflictBaseStatusForObjectTx(ctx context.Context, tx *sql.Tx, objectID string) (validation.Status, error) {
	var statusText string
	if err := tx.QueryRowContext(ctx,
		"SELECT validation_status FROM validation_records WHERE object_id = ?", objectID).Scan(&statusText); err != nil {
		return "", fmt.Errorf("read validation status for conflict metadata: %w", err)
	}
	status, err := validation.ParseStatus(statusText)
	if err != nil {
		return "", err
	}
	switch status {
	case validation.StatusValid, validation.StatusValidForTally:
		return status, nil
	case validation.StatusValidButConflicted:
		var baseStatusText string
		err := tx.QueryRowContext(ctx,
			`SELECT base_validation_status
			 FROM object_conflict_keys
			 WHERE object_id = ?
			 ORDER BY conflict_group, conflict_key
			 LIMIT 1`, objectID).Scan(&baseStatusText)
		if err == nil {
			baseStatus, parseErr := validation.ParseStatus(baseStatusText)
			if parseErr != nil {
				return "", parseErr
			}
			if baseStatus == validation.StatusValid || baseStatus == validation.StatusValidForTally {
				return baseStatus, nil
			}
		}
		if errors.Is(err, sql.ErrNoRows) {
			return validation.StatusValid, nil
		}
		return "", fmt.Errorf("read conflict base validation status: %w", err)
	default:
		return "", fmt.Errorf("conflict metadata requires usable validation status, got %s", status)
	}
}

func conflictMetadataForObjectTx(ctx context.Context, tx *sql.Tx, objectID string) ([]ConflictMetadata, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT object_id, conflict_group, conflict_key
		 FROM object_conflict_keys
		 WHERE object_id = ?
		 ORDER BY conflict_group, conflict_key`, objectID)
	if err != nil {
		return nil, fmt.Errorf("query conflict metadata: %w", err)
	}
	defer rows.Close()
	return scanConflictMetadata(rows)
}

func conflictStoredBaseStatusForObjectTx(ctx context.Context, tx *sql.Tx, objectID string) (validation.Status, error) {
	var baseStatusText string
	if err := tx.QueryRowContext(ctx,
		`SELECT base_validation_status
		 FROM object_conflict_keys
		 WHERE object_id = ?
		 ORDER BY conflict_group, conflict_key
		 LIMIT 1`, objectID).Scan(&baseStatusText); err != nil {
		return "", fmt.Errorf("read conflict base validation status: %w", err)
	}
	return validation.ParseStatus(baseStatusText)
}

func classifyPersistedConflictsTx(ctx context.Context, tx *sql.Tx, touched []ConflictMetadata) error {
	seen := make(map[ConflictMetadata]struct{}, len(touched))
	for _, conflict := range touched {
		if conflict.Group == "" || conflict.Key == "" {
			continue
		}
		key := ConflictMetadata{Group: conflict.Group, Key: conflict.Key}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		rows, err := tx.QueryContext(ctx,
			`SELECT ck.object_id, ck.base_validation_status
			 FROM object_conflict_keys ck
			 JOIN validation_records vr ON vr.object_id = ck.object_id
			 WHERE ck.conflict_group = ? AND ck.conflict_key = ?
			   AND vr.validation_status IN (?, ?, ?)
			 ORDER BY ck.object_id`,
			conflict.Group, conflict.Key,
			validation.StatusValid.String(), validation.StatusValidForTally.String(), validation.StatusValidButConflicted.String())
		if err != nil {
			return fmt.Errorf("query conflict group members: %w", err)
		}
		var members []conflictGroupMember
		for rows.Next() {
			var member conflictGroupMember
			var baseStatusText string
			if err := rows.Scan(&member.objectID, &baseStatusText); err != nil {
				rows.Close()
				return fmt.Errorf("scan conflict group member: %w", err)
			}
			baseStatus, err := validation.ParseStatus(baseStatusText)
			if err != nil {
				rows.Close()
				return fmt.Errorf("parse conflict base validation status: %w", err)
			}
			member.baseStatus = baseStatus
			members = append(members, member)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate conflict group members: %w", err)
		}
		rows.Close()

		if len(members) <= 1 {
			if len(members) == 1 {
				if err := restoreSingletonConflictMemberTx(ctx, tx, members[0]); err != nil {
					return err
				}
			}
			continue
		}
		for _, member := range members {
			if _, err := tx.ExecContext(ctx,
				`UPDATE validation_records
				 SET validation_status = ?
				 WHERE object_id = ? AND validation_status IN (?, ?)`,
				validation.StatusValidButConflicted.String(), member.objectID,
				validation.StatusValid.String(), validation.StatusValidForTally.String()); err != nil {
				return fmt.Errorf("mark conflict group member conflicted: %w", err)
			}
		}
	}
	return nil
}

func restoreSingletonConflictMemberTx(ctx context.Context, tx *sql.Tx, member conflictGroupMember) error {
	if member.baseStatus != validation.StatusValid && member.baseStatus != validation.StatusValidForTally {
		return nil
	}

	var conflictingGroups int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*)
		 FROM object_conflict_keys ck
		 WHERE ck.object_id = ?
		   AND 1 < (
		     SELECT COUNT(*)
		     FROM object_conflict_keys peer_ck
		     JOIN validation_records peer_vr ON peer_vr.object_id = peer_ck.object_id
		     WHERE peer_ck.conflict_group = ck.conflict_group
		       AND peer_ck.conflict_key = ck.conflict_key
		       AND peer_vr.validation_status IN (?, ?, ?)
		   )`,
		member.objectID,
		validation.StatusValid.String(), validation.StatusValidForTally.String(), validation.StatusValidButConflicted.String()).Scan(&conflictingGroups); err != nil {
		return fmt.Errorf("check remaining object conflicts: %w", err)
	}
	if conflictingGroups != 0 {
		return nil
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE validation_records
		 SET validation_status = ?
		 WHERE object_id = ? AND validation_status = ?`,
		member.baseStatus.String(), member.objectID, validation.StatusValidButConflicted.String()); err != nil {
		return fmt.Errorf("restore singleton conflict member status: %w", err)
	}
	return nil
}

func conflictMetadataFromValidation(objectID string, keys []validation.ConflictKey) []ConflictMetadata {
	if len(keys) == 0 {
		return nil
	}
	conflicts := make([]ConflictMetadata, 0, len(keys))
	for _, key := range keys {
		if key.Group == "" || key.Key == "" {
			continue
		}
		conflicts = append(conflicts, ConflictMetadata{ObjectID: objectID, Group: key.Group, Key: key.Key})
	}
	return conflicts
}

func scanConflictMetadata(rows *sql.Rows) ([]ConflictMetadata, error) {
	var conflicts []ConflictMetadata
	for rows.Next() {
		var conflict ConflictMetadata
		if err := rows.Scan(&conflict.ObjectID, &conflict.Group, &conflict.Key); err != nil {
			return nil, fmt.Errorf("scan conflict metadata: %w", err)
		}
		conflicts = append(conflicts, conflict)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate conflict metadata: %w", err)
	}
	return conflicts, nil
}
