package storage

import (
	"context"
	"fmt"

	"librevote/internal/domain"
	"librevote/internal/validation"
)

// WorklistObject is the read-only object metadata a validation worker needs to
// plan announcement republish or payload reacquire work. It intentionally omits
// payload bytes and source peer metadata.
type WorklistObject struct {
	ObjectID             string
	ObjectType           string
	ProtocolVersion      int
	NetworkID            string
	Scope                string
	ScopeID              string
	CreatedAt            int64
	ObjectPoW            []byte
	PayloadHash          []byte
	PayloadSize          int
	PayloadRetained      bool
	ValidationStatus     validation.Status
	LastCheckedAt        int64
	AffectedScope        validation.AffectedScope
	ShouldRepublish      bool
	ShouldRecomputeState bool
}

// RepublishEligibleObjects lists objects whose validation status is documented
// as eligible and whose latest outcome requested announcement republish. This
// method does not publish anything.
func (s *Store) RepublishEligibleObjects(ctx context.Context) ([]WorklistObject, error) {
	return s.listWorklistObjects(ctx, worklistQuery{
		statuses: []validation.Status{
			validation.StatusValid,
			validation.StatusValidForTally,
			validation.StatusValidButConflicted,
		},
		requireShouldRepublish: true,
	})
}

// PayloadReacquireObjects lists evicted pending objects whose payload must be
// fetched again through sync. This method does not perform any sync fetching.
func (s *Store) PayloadReacquireObjects(ctx context.Context) ([]WorklistObject, error) {
	return s.listWorklistObjects(ctx, worklistQuery{
		statuses:                  []validation.Status{validation.StatusPendingPayloadEvicted},
		requirePayloadNotRetained: true,
	})
}

// RecomputeStateObjects lists objects whose latest validation outcome requested
// derived state recomputation. This method does not recompute derived state.
func (s *Store) RecomputeStateObjects(ctx context.Context) ([]WorklistObject, error) {
	return s.listWorklistObjects(ctx, worklistQuery{
		requireRecomputeState: true,
	})
}

type worklistQuery struct {
	statuses                  []validation.Status
	requirePayloadNotRetained bool
	requireShouldRepublish    bool
	requireRecomputeState     bool
}

func (s *Store) listWorklistObjects(ctx context.Context, q worklistQuery) ([]WorklistObject, error) {
	if len(q.statuses) == 0 && !q.requireRecomputeState && !q.requireShouldRepublish {
		return nil, nil
	}
	for _, status := range q.statuses {
		if !status.Valid() {
			return nil, fmt.Errorf("unknown validation status %q", status)
		}
	}

	args := make([]any, 0, len(q.statuses))
	statusPlaceholders := ""
	for i, status := range q.statuses {
		if i > 0 {
			statusPlaceholders += ", "
		}
		statusPlaceholders += "?"
		args = append(args, status.String())
	}

	payloadRetainedClause := ""
	if q.requirePayloadNotRetained {
		payloadRetainedClause = " AND o.payload_retained = 0"
	}
	statusClause := ""
	if len(q.statuses) > 0 {
		statusClause = fmt.Sprintf("vr.validation_status IN (%s)", statusPlaceholders)
	}
	recomputeClause := ""
	if q.requireRecomputeState {
		recomputeClause = "vom.should_recompute_state = 1"
	}
	republishClause := ""
	if q.requireShouldRepublish {
		republishClause = "vom.should_republish = 1"
	}
	whereClause := statusClause
	if whereClause != "" && recomputeClause != "" {
		whereClause += " AND " + recomputeClause
	} else if recomputeClause != "" {
		whereClause = recomputeClause
	}
	if whereClause != "" && republishClause != "" {
		whereClause += " AND " + republishClause
	} else if republishClause != "" {
		whereClause = republishClause
	}

	query := fmt.Sprintf(`SELECT o.object_id, o.object_type, o.protocol_version,
		 o.network_id, o.scope, o.scope_id, o.created_at, o.object_pow,
		 o.payload_hash, o.payload_size, o.payload_retained,
		 vr.validation_status, vr.last_checked_at,
		 vom.affected_scope, vom.affected_scope_id,
		 vom.should_republish, vom.should_recompute_state
		 FROM objects o
		 JOIN validation_records vr ON vr.object_id = o.object_id
		 JOIN validation_outcome_metadata vom ON vom.object_id = o.object_id
		 WHERE %s%s
		 ORDER BY o.created_at, o.object_id`, whereClause, payloadRetainedClause)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query worklist objects: %w", err)
	}
	defer rows.Close()

	var out []WorklistObject
	for rows.Next() {
		var item WorklistObject
		var payloadRetained, shouldRepublish, shouldRecomputeState int
		var rawStatus, affectedScope string
		if err := rows.Scan(
			&item.ObjectID,
			&item.ObjectType,
			&item.ProtocolVersion,
			&item.NetworkID,
			&item.Scope,
			&item.ScopeID,
			&item.CreatedAt,
			&item.ObjectPoW,
			&item.PayloadHash,
			&item.PayloadSize,
			&payloadRetained,
			&rawStatus,
			&item.LastCheckedAt,
			&affectedScope,
			&item.AffectedScope.ScopeID,
			&shouldRepublish,
			&shouldRecomputeState,
		); err != nil {
			return nil, fmt.Errorf("scan worklist object: %w", err)
		}
		status, err := validation.ParseStatus(rawStatus)
		if err != nil {
			return nil, err
		}
		item.ObjectPoW = cloneBytes(item.ObjectPoW)
		item.PayloadHash = cloneBytes(item.PayloadHash)
		item.PayloadRetained = payloadRetained == 1
		item.ValidationStatus = status
		item.AffectedScope.Scope = domain.Scope(affectedScope)
		item.ShouldRepublish = shouldRepublish == 1
		item.ShouldRecomputeState = shouldRecomputeState == 1
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate worklist objects: %w", err)
	}
	return out, nil
}
