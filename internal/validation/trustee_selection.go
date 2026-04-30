package validation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"

	"librevote/internal/crypto"
	"librevote/internal/domain"
)

const ErrorTrusteeSelectionResultMismatch = "trustee_selection_result_mismatch"

type TrusteeSelectionInputStore interface {
	TrusteeSelectionInputs(context.Context, string) (TrusteeSelectionInputs, error)
}

type TrusteeSelectionInputs struct {
	ElectionFound    bool
	ElectionStatus   Status
	Nominations      []TrusteeSelectionNominationInput
	Votes            []TrusteeSelectionVoteInput
	PendingInputDeps []Dependency
}

type TrusteeSelectionNominationInput struct {
	ObjectID string
	Status   Status
	Payload  domain.TrusteeNominationPayload
}

type TrusteeSelectionVoteInput struct {
	ObjectID string
	Status   Status
	Payload  domain.TrusteeVotePayload
}

func contextualTrusteeSelectionResult(store ContextualStore) ContextualRule {
	return func(ctx context.Context, envelope domain.ObjectEnvelope) (ContextualRuleResult, error) {
		inputStore, ok := store.(TrusteeSelectionInputStore)
		if !ok {
			return ContextualRuleResult{}, fmt.Errorf("%w for %s recomputation", ErrContextualRuleUnsupported, envelope.ObjectType)
		}
		payload, err := decodePayload[domain.TrusteeSelectionResultPayload](envelope)
		if err != nil {
			return ContextualRuleResult{}, err
		}
		if envelope.ScopeID != payload.TrusteeSelectionID {
			return invalidResult("trustee selection result scope_id does not match payload trustee_selection_id"), nil
		}
		inputs, err := inputStore.TrusteeSelectionInputs(ctx, payload.TrusteeSelectionID)
		if err != nil {
			return ContextualRuleResult{}, err
		}
		return verifyTrusteeSelectionResult(payload, inputs), nil
	}
}

func verifyTrusteeSelectionResult(result domain.TrusteeSelectionResultPayload, inputs TrusteeSelectionInputs) ContextualRuleResult {
	if !inputs.ElectionFound || !inputs.ElectionStatus.Final() {
		return pendingResultDependency("trustee_selection", result.TrusteeSelectionID)
	}
	if inputs.ElectionStatus != StatusValid {
		return invalidResult("referenced trustee selection has status " + inputs.ElectionStatus.String())
	}

	pendingInputDeps := append([]Dependency(nil), inputs.PendingInputDeps...)
	for _, nomination := range inputs.Nominations {
		if !nomination.Status.Final() {
			pendingInputDeps = append(pendingInputDeps, Dependency{Type: "trustee_nomination", ID: nomination.ObjectID})
		}
	}
	for _, vote := range inputs.Votes {
		if !vote.Status.Final() {
			pendingInputDeps = append(pendingInputDeps, Dependency{Type: "trustee_vote", ID: vote.ObjectID})
		}
	}
	if len(pendingInputDeps) > 0 {
		return ContextualRuleResult{Status: StatusPendingDependencies, RequiredDependencies: requiredDependencies(uniqueDependencies(pendingInputDeps), StatusValid, StatusValidForTally, StatusValidButConflicted)}
	}

	validNominations := make(map[string]domain.TrusteeNominationPayload)
	nominationStatuses := make(map[string]Status)
	for _, nomination := range inputs.Nominations {
		key := string(nomination.Payload.CandidatePublicKey)
		if nomination.Status == StatusValid {
			validNominations[key] = nomination.Payload
		}
		if _, ok := nominationStatuses[key]; !ok || nomination.Status.Final() {
			nominationStatuses[key] = nomination.Status
		}
	}

	var missing []Dependency
	for _, candidate := range result.CandidateRanking {
		key := string(candidate.TrusteePublicKey)
		nomination, ok := validNominations[key]
		if !ok {
			status, known := nominationStatuses[key]
			if known && status.Final() {
				return invalidResult("ranked candidate nomination has status " + status.String())
			}
			missing = append(missing, Dependency{Type: "trustee_nomination", ID: TrusteeNominationDependencyID(result.TrusteeSelectionID, candidate.TrusteePublicKey)})
			continue
		}
		if !bytes.Equal(candidate.BlindTokenPublicKey, nomination.CandidateBlindTokenPublicKey) {
			return invalidResult("ranked candidate blind-token key does not match nomination")
		}
	}
	if len(missing) > 0 {
		return ContextualRuleResult{Status: StatusPendingDependencies, RequiredDependencies: requiredDependencies(missing, StatusValid)}
	}

	computed, err := recomputeTrusteeSelectionResult(result.TrusteeSelectionID, validNominations, inputs.Votes)
	if err != nil {
		return invalidResult(err.Error())
	}
	if !trusteeSelectionResultsEqual(result, computed) {
		return invalidResult("published trustee selection result does not match local recomputation")
	}
	if !crypto.VerifyEd25519(ed25519.PublicKey(result.ReporterPublicKey), crypto.Hash(crypto.DomainTrusteeSelectionResultSign, result.ResultHash), result.Signature) {
		return invalidResult("trustee selection result signature is invalid")
	}
	return ContextualRuleResult{Status: StatusValid}
}

func recomputeTrusteeSelectionResult(selectionID string, nominations map[string]domain.TrusteeNominationPayload, votes []TrusteeSelectionVoteInput) (domain.TrusteeSelectionResultPayload, error) {
	scores := make(map[string]int64, len(nominations))
	for key := range nominations {
		scores[key] = 0
	}
	var validVoteCount int64
	var conflictedVoteCount int64
	for _, vote := range votes {
		switch vote.Status {
		case StatusValidForTally:
			validVoteCount++
			for _, selected := range vote.Payload.SelectedCandidateKeys {
				key := string(selected)
				if _, ok := nominations[key]; !ok {
					return domain.TrusteeSelectionResultPayload{}, fmt.Errorf("valid vote %s selects candidate without valid nomination", vote.ObjectID)
				}
				scores[key]++
			}
		case StatusValidButConflicted:
			conflictedVoteCount++
		}
	}

	ranking := make([]domain.TrusteeCandidate, 0, len(nominations))
	for _, nomination := range nominations {
		ranking = append(ranking, domain.TrusteeCandidate{
			TrusteePublicKey:    append([]byte(nil), nomination.CandidatePublicKey...),
			BlindTokenPublicKey: append([]byte(nil), nomination.CandidateBlindTokenPublicKey...),
		})
	}
	sort.Slice(ranking, func(i, j int) bool {
		left := ranking[i].TrusteePublicKey
		right := ranking[j].TrusteePublicKey
		if scores[string(left)] != scores[string(right)] {
			return scores[string(left)] > scores[string(right)]
		}
		leftHash := crypto.Hash(crypto.DomainTrusteeRank, left)
		rightHash := crypto.Hash(crypto.DomainTrusteeRank, right)
		return bytes.Compare(leftHash[:], rightHash[:]) < 0
	})

	selectedCount := len(ranking)
	if selectedCount > domain.TrusteeCountV1 {
		selectedCount = domain.TrusteeCountV1
	}
	computed := domain.TrusteeSelectionResultPayload{
		TrusteeSelectionID:      selectionID,
		CandidateRanking:        ranking,
		InitialSelectedTrustees: append([]domain.TrusteeCandidate(nil), ranking[:selectedCount]...),
		ThresholdT:              domain.ThresholdV1,
		TrusteeCountN:           domain.TrusteeCountV1,
		CandidateScores:         make([]domain.CandidateScore, 0, len(ranking)),
		ConflictedVoteCount:     conflictedVoteCount,
		ValidVoteCount:          validVoteCount,
	}
	for _, candidate := range ranking {
		computed.CandidateScores = append(computed.CandidateScores, domain.CandidateScore{
			TrusteePublicKey: append([]byte(nil), candidate.TrusteePublicKey...),
			Score:            scores[string(candidate.TrusteePublicKey)],
		})
	}
	computed.ResultHash = ComputeTrusteeSelectionResultHash(computed)
	return computed, nil
}

func trusteeSelectionResultsEqual(a, b domain.TrusteeSelectionResultPayload) bool {
	return a.TrusteeSelectionID == b.TrusteeSelectionID &&
		a.ThresholdT == b.ThresholdT &&
		a.TrusteeCountN == b.TrusteeCountN &&
		a.ConflictedVoteCount == b.ConflictedVoteCount &&
		a.ValidVoteCount == b.ValidVoteCount &&
		bytes.Equal(a.ResultHash, b.ResultHash) &&
		candidatesEqual(a.CandidateRanking, b.CandidateRanking) &&
		candidatesEqual(a.InitialSelectedTrustees, b.InitialSelectedTrustees) &&
		scoresEqual(a.CandidateScores, b.CandidateScores)
}

func candidatesEqual(a, b []domain.TrusteeCandidate) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].TrusteePublicKey, b[i].TrusteePublicKey) || !bytes.Equal(a[i].BlindTokenPublicKey, b[i].BlindTokenPublicKey) {
			return false
		}
	}
	return true
}

func scoresEqual(a, b []domain.CandidateScore) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Score != b[i].Score || !bytes.Equal(a[i].TrusteePublicKey, b[i].TrusteePublicKey) {
			return false
		}
	}
	return true
}

func ComputeTrusteeSelectionResultHash(result domain.TrusteeSelectionResultPayload) []byte {
	parts := [][]byte{[]byte(result.TrusteeSelectionID), intPart(result.ThresholdT), intPart(result.TrusteeCountN)}
	for _, candidate := range result.CandidateRanking {
		parts = append(parts, candidate.TrusteePublicKey, candidate.BlindTokenPublicKey)
	}
	parts = append(parts, []byte("selected"))
	for _, candidate := range result.InitialSelectedTrustees {
		parts = append(parts, candidate.TrusteePublicKey, candidate.BlindTokenPublicKey)
	}
	parts = append(parts, []byte("scores"))
	for _, score := range result.CandidateScores {
		parts = append(parts, score.TrusteePublicKey, intPart(score.Score))
	}
	parts = append(parts, intPart(result.ConflictedVoteCount), intPart(result.ValidVoteCount))
	digest := crypto.Hash(crypto.DomainTrusteeSelectionResultHash, parts...)
	return digest.Bytes()
}

func intPart(value int64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], uint64(value))
	return out[:]
}

func requiredDependencies(deps []Dependency, acceptable ...Status) []RequiredDependency {
	required := make([]RequiredDependency, len(deps))
	for i, dep := range deps {
		required[i] = RequiredDependency{Dependency: dep, AcceptableStatuses: acceptable}
	}
	return required
}

func uniqueDependencies(deps []Dependency) []Dependency {
	seen := make(map[Dependency]struct{}, len(deps))
	out := make([]Dependency, 0, len(deps))
	for _, dep := range deps {
		if dep.Type == "" || dep.ID == "" {
			continue
		}
		if _, ok := seen[dep]; ok {
			continue
		}
		seen[dep] = struct{}{}
		out = append(out, dep)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func pendingResultDependency(dependencyType, id string) ContextualRuleResult {
	return ContextualRuleResult{Status: StatusPendingDependencies, RequiredDependencies: []RequiredDependency{RequireObject(dependencyType, id, StatusValid)}}
}

func invalidResult(reason string) ContextualRuleResult {
	return ContextualRuleResult{Status: StatusInvalid, ValidationErrorCode: ErrorTrusteeSelectionResultMismatch, ValidationErrorReason: reason}
}

func TrusteeNominationDependencyID(selectionID string, candidatePublicKey []byte) string {
	if selectionID == "" || len(candidatePublicKey) == 0 {
		return ""
	}
	return selectionID + ":" + hex.EncodeToString(candidatePublicKey)
}
