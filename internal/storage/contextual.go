package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"librevote/internal/domain"
	"librevote/internal/validation"
)

// ValidationStatus returns the locally recorded validation status for objectID.
// The boolean is false when no validation record exists.
func (s *Store) ValidationStatus(ctx context.Context, objectID string) (validation.Status, bool, error) {
	if objectID == "" {
		return "", false, errors.New("object_id is required")
	}
	var raw string
	err := s.db.QueryRowContext(ctx,
		"SELECT validation_status FROM validation_records WHERE object_id = ?",
		objectID).Scan(&raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			var exists int
			err := s.db.QueryRowContext(ctx,
				"SELECT 1 FROM invalid_object_records WHERE object_id = ?",
				objectID).Scan(&exists)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return "", false, nil
				}
				return "", false, fmt.Errorf("read invalid object record: %w", err)
			}
			return validation.StatusInvalid, true, nil
		}
		return "", false, fmt.Errorf("read validation status: %w", err)
	}
	status, err := validation.ParseStatus(raw)
	if err != nil {
		return "", false, err
	}
	return status, true, nil
}

// DependencyStatus resolves contextual dependencies that are identified by
// decoded domain references rather than by object_id alone.
func (s *Store) DependencyStatus(ctx context.Context, dep validation.Dependency) (validation.Status, bool, error) {
	if dep.Type == "" || dep.ID == "" {
		return "", false, errors.New("dependency type and id are required")
	}
	switch dep.Type {
	case "trustee_selection":
		return s.statusForTrusteeSelectionID(ctx, dep.ID)
	case "election":
		return s.statusForAnonymousElectionID(ctx, dep.ID)
	case "trustee_selection_result":
		selectionID, resultHash, err := validation.ParseTrusteeSelectionResultDependencyID(dep.ID)
		if err != nil {
			return "", false, err
		}
		return s.statusForTrusteeSelectionResult(ctx, selectionID, resultHash)
	case "trustee_nomination":
		selectionID, candidateKey, err := validation.ParseTrusteeNominationDependencyID(dep.ID)
		if err != nil {
			return "", false, err
		}
		return s.statusForDecodedPayload(ctx, domain.ObjectTypeTrusteeNomination, func(payload []byte) (bool, error) {
			decoded, err := domain.DecodePayload(domain.ObjectTypeTrusteeNomination, payload)
			if err != nil {
				return false, err
			}
			nomination := decoded.(domain.TrusteeNominationPayload)
			return nomination.TrusteeSelectionID == selectionID && bytes.Equal(nomination.CandidatePublicKey, candidateKey), nil
		})
	case "trustee_consent":
		return s.statusForTrusteeConsentDependency(ctx, dep.ID)
	case "tally_key_contribution":
		return s.statusForTallyKeyContributionDependency(ctx, dep.ID)
	default:
		return s.ValidationStatus(ctx, dep.ID)
	}
}

// TrusteeSelectionInputs returns retained local inputs needed to verify a
// TrusteeSelectionResult by recomputation. It only exposes validation state and
// decoded payloads; source peer and other network metadata are intentionally not
// used.
func (s *Store) TrusteeSelectionInputs(ctx context.Context, selectionID string) (validation.TrusteeSelectionInputs, error) {
	if selectionID == "" {
		return validation.TrusteeSelectionInputs{}, errors.New("trustee_selection_id is required")
	}
	status, found, err := s.statusForTrusteeSelectionID(ctx, selectionID)
	if err != nil {
		return validation.TrusteeSelectionInputs{}, err
	}
	inputs := validation.TrusteeSelectionInputs{ElectionFound: found, ElectionStatus: status}

	nominations, err := s.trusteeSelectionNominations(ctx, selectionID)
	if err != nil {
		return validation.TrusteeSelectionInputs{}, err
	}
	votes, err := s.trusteeSelectionVotes(ctx, selectionID)
	if err != nil {
		return validation.TrusteeSelectionInputs{}, err
	}
	inputs.Nominations = nominations
	inputs.Votes = votes
	return inputs, nil
}

// TallyKeySetInputs returns retained local inputs needed to verify election
// activation by recomputing the final trustee set and activation hash.
func (s *Store) TallyKeySetInputs(ctx context.Context, electionID string, resultHash []byte) (validation.TallyKeySetInputs, error) {
	if electionID == "" {
		return validation.TallyKeySetInputs{}, errors.New("election_id is required")
	}
	election, electionStatus, electionFound, err := s.anonymousElectionByID(ctx, electionID)
	if err != nil {
		return validation.TallyKeySetInputs{}, err
	}
	inputs := validation.TallyKeySetInputs{ElectionFound: electionFound, ElectionStatus: electionStatus, Election: election}
	if electionFound {
		result, resultStatus, resultFound, err := s.trusteeSelectionResultByHash(ctx, election.TrusteeSelectionID, resultHash)
		if err != nil {
			return validation.TallyKeySetInputs{}, err
		}
		inputs.ResultFound = resultFound
		inputs.ResultStatus = resultStatus
		inputs.Result = result
	}
	consents, err := s.trusteeConsents(ctx, electionID)
	if err != nil {
		return validation.TallyKeySetInputs{}, err
	}
	contributions, err := s.tallyKeyContributions(ctx, electionID)
	if err != nil {
		return validation.TallyKeySetInputs{}, err
	}
	inputs.Consents = consents
	inputs.Contributions = contributions
	return inputs, nil
}

func (s *Store) ElectionActivationInputs(ctx context.Context, electionID string) (validation.TallyKeySetInputs, error) {
	election, _, found, err := s.anonymousElectionByID(ctx, electionID)
	if err != nil {
		return validation.TallyKeySetInputs{}, err
	}
	if !found {
		return validation.TallyKeySetInputs{ElectionFound: false}, nil
	}
	return s.TallyKeySetInputs(ctx, electionID, election.TrusteeSelectionResultHash)
}

func (s *Store) statusForTrusteeSelectionID(ctx context.Context, selectionID string) (validation.Status, bool, error) {
	return s.statusForDecodedPayload(ctx, domain.ObjectTypeTrusteeSelectionElection, func(payload []byte) (bool, error) {
		decoded, err := domain.DecodePayload(domain.ObjectTypeTrusteeSelectionElection, payload)
		if err != nil {
			return false, err
		}
		election := decoded.(domain.TrusteeSelectionElectionPayload)
		return election.TrusteeSelectionID == selectionID, nil
	})
}

func (s *Store) TrusteeSelectionElectionByID(ctx context.Context, selectionID string) (domain.TrusteeSelectionElectionPayload, validation.Status, bool, error) {
	var out domain.TrusteeSelectionElectionPayload
	status, found, err := s.payloadForDecodedPayload(ctx, domain.ObjectTypeTrusteeSelectionElection, func(payload []byte) (bool, error) {
		decoded, err := domain.DecodePayload(domain.ObjectTypeTrusteeSelectionElection, payload)
		if err != nil {
			return false, err
		}
		election := decoded.(domain.TrusteeSelectionElectionPayload)
		if election.TrusteeSelectionID != selectionID {
			return false, nil
		}
		out = election
		return true, nil
	})
	return out, status, found, err
}

func (s *Store) statusForAnonymousElectionID(ctx context.Context, electionID string) (validation.Status, bool, error) {
	return s.statusForDecodedPayload(ctx, domain.ObjectTypeAnonymousElection, func(payload []byte) (bool, error) {
		decoded, err := domain.DecodePayload(domain.ObjectTypeAnonymousElection, payload)
		if err != nil {
			return false, err
		}
		election := decoded.(domain.AnonymousElectionPayload)
		return election.ElectionID == electionID, nil
	})
}

func (s *Store) statusForTrusteeSelectionResult(ctx context.Context, selectionID string, resultHash []byte) (validation.Status, bool, error) {
	return s.statusForDecodedPayload(ctx, domain.ObjectTypeTrusteeSelectionResult, func(payload []byte) (bool, error) {
		decoded, err := domain.DecodePayload(domain.ObjectTypeTrusteeSelectionResult, payload)
		if err != nil {
			return false, err
		}
		result := decoded.(domain.TrusteeSelectionResultPayload)
		return result.TrusteeSelectionID == selectionID && bytes.Equal(result.ResultHash, resultHash), nil
	})
}

func (s *Store) TrusteeSelectionResultHash(ctx context.Context, selectionID string) ([]byte, error) {
	if selectionID == "" {
		return nil, errors.New("selection_id is required")
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT op.payload_bytes
		 FROM objects o
		 JOIN validation_records vr ON vr.object_id = o.object_id
		 JOIN object_payloads op ON op.object_id = o.object_id
		 WHERE o.object_type = ? AND o.scope = ? AND o.scope_id = ? AND vr.validation_status = ?
		 ORDER BY o.object_id
		 LIMIT 1`,
		string(domain.ObjectTypeTrusteeSelectionResult), string(domain.ScopeTrusteeSelectionID), selectionID, string(validation.StatusValid))
	if err != nil {
		return nil, fmt.Errorf("query trustee selection result hash: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("no valid trustee selection result for %s", selectionID)
	}
	var payload []byte
	if err := rows.Scan(&payload); err != nil {
		return nil, fmt.Errorf("scan trustee selection result hash: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read trustee selection result hash: %w", err)
	}
	decoded, err := domain.DecodePayload(domain.ObjectTypeTrusteeSelectionResult, payload)
	if err != nil {
		return nil, fmt.Errorf("decode trustee selection result: %w", err)
	}
	result := decoded.(domain.TrusteeSelectionResultPayload)
	if result.TrusteeSelectionID != selectionID {
		return nil, fmt.Errorf("trustee selection result does not match selection %s", selectionID)
	}
	return result.ResultHash, nil
}

func (s *Store) anonymousElectionByID(ctx context.Context, electionID string) (domain.AnonymousElectionPayload, validation.Status, bool, error) {
	var out domain.AnonymousElectionPayload
	status, found, err := s.payloadForDecodedPayload(ctx, domain.ObjectTypeAnonymousElection, func(payload []byte) (bool, error) {
		decoded, err := domain.DecodePayload(domain.ObjectTypeAnonymousElection, payload)
		if err != nil {
			return false, err
		}
		election := decoded.(domain.AnonymousElectionPayload)
		if election.ElectionID != electionID {
			return false, nil
		}
		out = election
		return true, nil
	})
	return out, status, found, err
}

func (s *Store) trusteeSelectionResultByHash(ctx context.Context, selectionID string, resultHash []byte) (domain.TrusteeSelectionResultPayload, validation.Status, bool, error) {
	var out domain.TrusteeSelectionResultPayload
	status, found, err := s.payloadForDecodedPayload(ctx, domain.ObjectTypeTrusteeSelectionResult, func(payload []byte) (bool, error) {
		decoded, err := domain.DecodePayload(domain.ObjectTypeTrusteeSelectionResult, payload)
		if err != nil {
			return false, err
		}
		result := decoded.(domain.TrusteeSelectionResultPayload)
		if result.TrusteeSelectionID != selectionID || !bytes.Equal(result.ResultHash, resultHash) {
			return false, nil
		}
		out = result
		return true, nil
	})
	return out, status, found, err
}

func (s *Store) statusForTrusteeConsentDependency(ctx context.Context, id string) (validation.Status, bool, error) {
	if !strings.Contains(id, "/") {
		status, found, err := s.ValidationStatus(ctx, id)
		if err != nil || found {
			return status, found, err
		}
	}
	electionID, trusteeKey, hasTrusteeKey, err := parseScopedTrusteeDependencyID(id)
	if err != nil {
		return "", false, err
	}
	if hasTrusteeKey {
		return s.statusForDecodedPayload(ctx, domain.ObjectTypeTrusteeConsent, func(payload []byte) (bool, error) {
			decoded, err := domain.DecodePayload(domain.ObjectTypeTrusteeConsent, payload)
			if err != nil {
				return false, err
			}
			consent := decoded.(domain.TrusteeConsentPayload)
			return consent.ElectionID == electionID && bytes.Equal(consent.TrusteePublicKey, trusteeKey), nil
		})
	}
	return s.statusForElectionScopedCount(ctx, domain.ObjectTypeTrusteeConsent, electionID, domain.TrusteeCountV1)
}

func (s *Store) statusForTallyKeyContributionDependency(ctx context.Context, id string) (validation.Status, bool, error) {
	if !strings.Contains(id, "/") {
		status, found, err := s.ValidationStatus(ctx, id)
		if err != nil || found {
			return status, found, err
		}
	}
	electionID, trusteeKey, hasTrusteeKey, err := parseScopedTrusteeDependencyID(id)
	if err != nil {
		return "", false, err
	}
	if hasTrusteeKey {
		return s.statusForDecodedPayload(ctx, domain.ObjectTypeTallyKeyContribution, func(payload []byte) (bool, error) {
			decoded, err := domain.DecodePayload(domain.ObjectTypeTallyKeyContribution, payload)
			if err != nil {
				return false, err
			}
			contribution := decoded.(domain.TallyKeyContributionPayload)
			return contribution.ElectionID == electionID && bytes.Equal(contribution.TrusteePublicKey, trusteeKey), nil
		})
	}
	return s.statusForElectionScopedCount(ctx, domain.ObjectTypeTallyKeyContribution, electionID, domain.TrusteeCountV1)
}

func (s *Store) statusForElectionScopedCount(ctx context.Context, objectType domain.ObjectType, electionID string, want int) (validation.Status, bool, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT vr.validation_status
		 FROM objects o
		 JOIN validation_records vr ON vr.object_id = o.object_id
		 WHERE o.object_type = ? AND o.scope = ? AND o.scope_id = ?`,
		string(objectType), string(domain.ScopeElectionID), electionID)
	if err != nil {
		return "", false, fmt.Errorf("query %s scoped dependency: %w", objectType, err)
	}
	defer rows.Close()

	found := false
	validCount := 0
	for rows.Next() {
		found = true
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return "", false, fmt.Errorf("scan %s scoped dependency: %w", objectType, err)
		}
		status, err := validation.ParseStatus(raw)
		if err != nil {
			return "", false, err
		}
		if status == validation.StatusValid {
			validCount++
		}
	}
	if err := rows.Err(); err != nil {
		return "", false, fmt.Errorf("read %s scoped dependency: %w", objectType, err)
	}
	if validCount >= want {
		return validation.StatusValid, true, nil
	}
	return validation.StatusPendingDependencies, found, nil
}

func parseScopedTrusteeDependencyID(id string) (string, []byte, bool, error) {
	electionID, encodedKey, hasKey := strings.Cut(id, "/")
	if electionID == "" {
		return "", nil, false, errors.New("election id is required")
	}
	if !hasKey {
		return electionID, nil, false, nil
	}
	key, err := hex.DecodeString(encodedKey)
	if err != nil {
		return "", nil, false, fmt.Errorf("parse trustee dependency key: %w", err)
	}
	return electionID, key, true, nil
}

func (s *Store) payloadForDecodedPayload(ctx context.Context, objectType domain.ObjectType, matches func([]byte) (bool, error)) (validation.Status, bool, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT vr.validation_status, op.payload_bytes
		 FROM objects o
		 JOIN validation_records vr ON vr.object_id = o.object_id
		 JOIN object_payloads op ON op.object_id = o.object_id
		 WHERE o.object_type = ?
		 ORDER BY o.object_id`,
		string(objectType))
	if err != nil {
		return "", false, fmt.Errorf("query %s payload: %w", objectType, err)
	}
	defer rows.Close()

	var pendingStatus validation.Status
	foundPending := false
	for rows.Next() {
		var rawStatus string
		var payload []byte
		if err := rows.Scan(&rawStatus, &payload); err != nil {
			return "", false, fmt.Errorf("scan %s payload: %w", objectType, err)
		}
		ok, err := matches(payload)
		if err != nil {
			return "", false, fmt.Errorf("decode %s payload: %w", objectType, err)
		}
		if !ok {
			continue
		}
		status, err := validation.ParseStatus(rawStatus)
		if err != nil {
			return "", false, err
		}
		if status.Final() {
			return status, true, nil
		}
		if !foundPending {
			pendingStatus = status
			foundPending = true
		}
	}
	if err := rows.Err(); err != nil {
		return "", false, fmt.Errorf("read %s payload: %w", objectType, err)
	}
	if foundPending {
		return pendingStatus, true, nil
	}
	return "", false, nil
}

func (s *Store) statusForDecodedPayload(ctx context.Context, objectType domain.ObjectType, matches func([]byte) (bool, error)) (validation.Status, bool, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT vr.validation_status, op.payload_bytes
		 FROM objects o
		 JOIN validation_records vr ON vr.object_id = o.object_id
		 JOIN object_payloads op ON op.object_id = o.object_id
		 WHERE o.object_type = ?`,
		string(objectType))
	if err != nil {
		return "", false, fmt.Errorf("query %s dependencies: %w", objectType, err)
	}
	defer rows.Close()

	var pendingStatus validation.Status
	foundPending := false
	for rows.Next() {
		var rawStatus string
		var payload []byte
		if err := rows.Scan(&rawStatus, &payload); err != nil {
			return "", false, fmt.Errorf("scan %s dependency: %w", objectType, err)
		}
		ok, err := matches(payload)
		if err != nil {
			return "", false, fmt.Errorf("decode %s dependency: %w", objectType, err)
		}
		if !ok {
			continue
		}
		status, err := validation.ParseStatus(rawStatus)
		if err != nil {
			return "", false, err
		}
		if status.Final() {
			return status, true, nil
		}
		if !foundPending {
			pendingStatus = status
			foundPending = true
		}
	}
	if err := rows.Err(); err != nil {
		return "", false, fmt.Errorf("read %s dependencies: %w", objectType, err)
	}
	if foundPending {
		return pendingStatus, true, nil
	}
	return "", false, nil
}

func (s *Store) trusteeSelectionNominations(ctx context.Context, selectionID string) ([]validation.TrusteeSelectionNominationInput, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT o.object_id, vr.validation_status, op.payload_bytes
		 FROM objects o
		 JOIN validation_records vr ON vr.object_id = o.object_id
		 LEFT JOIN object_payloads op ON op.object_id = o.object_id
		 WHERE o.object_type = ? AND o.scope = ? AND o.scope_id = ?
		 ORDER BY o.object_id`,
		string(domain.ObjectTypeTrusteeNomination), string(domain.ScopeTrusteeSelectionID), selectionID)
	if err != nil {
		return nil, fmt.Errorf("query trustee nominations: %w", err)
	}
	defer rows.Close()

	var out []validation.TrusteeSelectionNominationInput
	for rows.Next() {
		var objectID, rawStatus string
		var payload []byte
		if err := rows.Scan(&objectID, &rawStatus, &payload); err != nil {
			return nil, fmt.Errorf("scan trustee nomination: %w", err)
		}
		status, err := validation.ParseStatus(rawStatus)
		if err != nil {
			return nil, err
		}
		if !status.Final() {
			out = append(out, validation.TrusteeSelectionNominationInput{ObjectID: objectID, Status: status})
			continue
		}
		if len(payload) == 0 {
			out = append(out, validation.TrusteeSelectionNominationInput{ObjectID: objectID, Status: validation.StatusPendingPayloadEvicted})
			continue
		}
		decoded, err := domain.DecodePayload(domain.ObjectTypeTrusteeNomination, payload)
		if err != nil {
			return nil, fmt.Errorf("decode trustee nomination %s: %w", objectID, err)
		}
		nomination := decoded.(domain.TrusteeNominationPayload)
		if nomination.TrusteeSelectionID != selectionID {
			continue
		}
		out = append(out, validation.TrusteeSelectionNominationInput{ObjectID: objectID, Status: status, Payload: nomination})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read trustee nominations: %w", err)
	}
	return out, nil
}

func (s *Store) trusteeSelectionVotes(ctx context.Context, selectionID string) ([]validation.TrusteeSelectionVoteInput, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT o.object_id, vr.validation_status, op.payload_bytes
		 FROM objects o
		 JOIN validation_records vr ON vr.object_id = o.object_id
		 LEFT JOIN object_payloads op ON op.object_id = o.object_id
		 WHERE o.object_type = ? AND o.scope = ? AND o.scope_id = ?
		 ORDER BY o.object_id`,
		string(domain.ObjectTypeTrusteeVote), string(domain.ScopeTrusteeSelectionID), selectionID)
	if err != nil {
		return nil, fmt.Errorf("query trustee votes: %w", err)
	}
	defer rows.Close()

	var out []validation.TrusteeSelectionVoteInput
	for rows.Next() {
		var objectID, rawStatus string
		var payload []byte
		if err := rows.Scan(&objectID, &rawStatus, &payload); err != nil {
			return nil, fmt.Errorf("scan trustee vote: %w", err)
		}
		status, err := validation.ParseStatus(rawStatus)
		if err != nil {
			return nil, err
		}
		if !status.Final() {
			out = append(out, validation.TrusteeSelectionVoteInput{ObjectID: objectID, Status: status})
			continue
		}
		if len(payload) == 0 {
			out = append(out, validation.TrusteeSelectionVoteInput{ObjectID: objectID, Status: validation.StatusPendingPayloadEvicted})
			continue
		}
		decoded, err := domain.DecodePayload(domain.ObjectTypeTrusteeVote, payload)
		if err != nil {
			return nil, fmt.Errorf("decode trustee vote %s: %w", objectID, err)
		}
		vote := decoded.(domain.TrusteeVotePayload)
		if vote.TrusteeSelectionID != selectionID {
			continue
		}
		out = append(out, validation.TrusteeSelectionVoteInput{ObjectID: objectID, Status: status, Payload: vote})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read trustee votes: %w", err)
	}
	return out, nil
}

func (s *Store) trusteeConsents(ctx context.Context, electionID string) ([]validation.TrusteeConsentInput, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT o.object_id, vr.validation_status, op.payload_bytes
		 FROM objects o
		 JOIN validation_records vr ON vr.object_id = o.object_id
		 LEFT JOIN object_payloads op ON op.object_id = o.object_id
		 WHERE o.object_type = ? AND o.scope = ? AND o.scope_id = ?
		 ORDER BY o.object_id`,
		string(domain.ObjectTypeTrusteeConsent), string(domain.ScopeElectionID), electionID)
	if err != nil {
		return nil, fmt.Errorf("query trustee consents: %w", err)
	}
	defer rows.Close()

	var out []validation.TrusteeConsentInput
	for rows.Next() {
		var objectID, rawStatus string
		var payload []byte
		if err := rows.Scan(&objectID, &rawStatus, &payload); err != nil {
			return nil, fmt.Errorf("scan trustee consent: %w", err)
		}
		status, err := validation.ParseStatus(rawStatus)
		if err != nil {
			return nil, err
		}
		input := validation.TrusteeConsentInput{ObjectID: objectID, Status: status}
		if status.Final() && len(payload) > 0 {
			decoded, err := domain.DecodePayload(domain.ObjectTypeTrusteeConsent, payload)
			if err != nil {
				return nil, fmt.Errorf("decode trustee consent %s: %w", objectID, err)
			}
			consent := decoded.(domain.TrusteeConsentPayload)
			if consent.ElectionID != electionID {
				continue
			}
			input.Payload = consent
		}
		out = append(out, input)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read trustee consents: %w", err)
	}
	return out, nil
}

func (s *Store) tallyKeyContributions(ctx context.Context, electionID string) ([]validation.TallyKeyContributionInput, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT o.object_id, vr.validation_status, op.payload_bytes
		 FROM objects o
		 JOIN validation_records vr ON vr.object_id = o.object_id
		 LEFT JOIN object_payloads op ON op.object_id = o.object_id
		 WHERE o.object_type = ? AND o.scope = ? AND o.scope_id = ?
		 ORDER BY o.object_id`,
		string(domain.ObjectTypeTallyKeyContribution), string(domain.ScopeElectionID), electionID)
	if err != nil {
		return nil, fmt.Errorf("query tally key contributions: %w", err)
	}
	defer rows.Close()

	var out []validation.TallyKeyContributionInput
	for rows.Next() {
		var objectID, rawStatus string
		var payload []byte
		if err := rows.Scan(&objectID, &rawStatus, &payload); err != nil {
			return nil, fmt.Errorf("scan tally key contribution: %w", err)
		}
		status, err := validation.ParseStatus(rawStatus)
		if err != nil {
			return nil, err
		}
		input := validation.TallyKeyContributionInput{ObjectID: objectID, Status: status}
		if status.Final() && len(payload) > 0 {
			decoded, err := domain.DecodePayload(domain.ObjectTypeTallyKeyContribution, payload)
			if err != nil {
				return nil, fmt.Errorf("decode tally key contribution %s: %w", objectID, err)
			}
			contribution := decoded.(domain.TallyKeyContributionPayload)
			if contribution.ElectionID != electionID {
				continue
			}
			input.Payload = contribution
		}
		out = append(out, input)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read tally key contributions: %w", err)
	}
	return out, nil
}
