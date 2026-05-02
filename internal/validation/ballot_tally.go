package validation

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sort"

	"librevote/internal/crypto"
	"librevote/internal/domain"
)

const (
	ErrorBallotElectionNotActive = "ballot_election_not_active"
	ErrorBallotInvalidChoice     = "ballot_invalid_choice"
	ErrorBallotSignatureInvalid  = "ballot_signature_invalid"
	ErrorTallyResultMismatch     = "tally_result_mismatch"
	AnonymousBallotConflictGroup = "anonymous_ballot_conflict_key"
)

type BallotInputStore interface {
	BallotValidationInputs(context.Context, string) (BallotValidationInputs, error)
}

type BallotValidationInputs struct {
	ElectionFound    bool
	ElectionStatus   Status
	Election         domain.AnonymousElectionPayload
	TallyKeySetFound bool
	TallyKeySetHash  []byte
	ExistingBallots  []BallotInput
}

type BallotInput struct {
	ObjectID string
	Status   Status
	Payload  domain.AnonymousBallotPayload
}

type TallyComputationStore interface {
	TallyComputationInputs(context.Context, string) (TallyComputationInputs, error)
}

type TallyComputationInputs struct {
	BallotValidationInputs
	RetainedBallots []BallotInput
}

func contextualAnonymousBallot(store ContextualStore) ContextualRule {
	return func(ctx context.Context, envelope domain.ObjectEnvelope) (ContextualRuleResult, error) {
		inputStore, ok := store.(BallotInputStore)
		if !ok {
			return ContextualRuleResult{}, fmt.Errorf("%w for %s contextual validation", ErrContextualRuleUnsupported, envelope.ObjectType)
		}
		payload, err := decodePayload[domain.AnonymousBallotPayload](envelope)
		if err != nil {
			return ContextualRuleResult{}, err
		}
		if envelope.ScopeID != payload.ElectionID {
			return invalidBallot("anonymous ballot scope_id does not match payload election_id"), nil
		}
		inputs, err := inputStore.BallotValidationInputs(ctx, payload.ElectionID)
		if err != nil {
			return ContextualRuleResult{}, err
		}
		return verifyAnonymousBallot(envelope, payload, inputs), nil
	}
}

func verifyAnonymousBallot(envelope domain.ObjectEnvelope, payload domain.AnonymousBallotPayload, inputs BallotValidationInputs) ContextualRuleResult {
	if !inputs.ElectionFound || !inputs.ElectionStatus.Final() {
		return pendingBallotDependency("election", payload.ElectionID)
	}
	if inputs.ElectionStatus != StatusValid {
		return invalidBallot("referenced anonymous election has status " + inputs.ElectionStatus.String())
	}
	if !inputs.TallyKeySetFound {
		return pendingBallotDependency("tally_key_set", TallyKeySetDependencyID(payload.ElectionID))
	}
	if envelope.CreatedAt < inputs.Election.VotingStartsAt || envelope.CreatedAt > inputs.Election.VotingEndsAt {
		return invalidBallot("ballot created_at is not within voting window")
	}
	choiceValid := false
	for _, option := range inputs.Election.Options {
		if option == payload.Choice {
			choiceValid = true
			break
		}
	}
	if !choiceValid {
		return invalidBallot("ballot choice is not one of election options")
	}
	if !verifyPayloadSignature(envelope, crypto.DomainAnonymousBallotSign, domain.AnonymousBallotSignatureField(), payload.VoterPublicKey, payload.Signature) {
		return invalidBallot("anonymous ballot signature is invalid")
	}
	return ContextualRuleResult{
		Status: StatusValidForTally,
		ConflictKeys: []ConflictKey{
			{Group: AnonymousBallotConflictGroup, Key: payload.ElectionID + "|" + payload.VoterID},
		},
	}
}

func contextualTallyResult(store ContextualStore) ContextualRule {
	return func(ctx context.Context, envelope domain.ObjectEnvelope) (ContextualRuleResult, error) {
		inputStore, ok := store.(TallyComputationStore)
		if !ok {
			return ContextualRuleResult{}, fmt.Errorf("%w for %s contextual validation", ErrContextualRuleUnsupported, envelope.ObjectType)
		}
		payload, err := decodePayload[domain.TallyResultPayload](envelope)
		if err != nil {
			return ContextualRuleResult{}, err
		}
		if envelope.ScopeID != payload.ElectionID {
			return invalidTallyResult("tally result scope_id does not match payload election_id"), nil
		}
		inputs, err := inputStore.TallyComputationInputs(ctx, payload.ElectionID)
		if err != nil {
			return ContextualRuleResult{}, err
		}
		return verifyTallyResult(envelope, payload, inputs), nil
	}
}

func verifyTallyResult(envelope domain.ObjectEnvelope, payload domain.TallyResultPayload, inputs TallyComputationInputs) ContextualRuleResult {
	if !inputs.ElectionFound || !inputs.ElectionStatus.Final() {
		return pendingTallyResultDependency("election", payload.ElectionID)
	}
	if inputs.ElectionStatus != StatusValid {
		return invalidTallyResult("referenced anonymous election has status " + inputs.ElectionStatus.String())
	}
	if !inputs.TallyKeySetFound {
		return pendingTallyResultDependency("tally_key_set", TallyKeySetDependencyID(payload.ElectionID))
	}
	if !bytes.Equal(payload.TallyKeySetHash, inputs.TallyKeySetHash) {
		return invalidTallyResult("tally_key_set_hash does not match local valid TallyKeySet")
	}

	computed := computeLocalTallyResult(payload.ElectionID, inputs.TallyKeySetHash, inputs.RetainedBallots, inputs.Election.Options)
	if !bytes.Equal(payload.ResultHash, computed.ResultHash) {
		return invalidTallyResult("tally result hash does not match local recomputation")
	}
	if payload.ValidBallotCount != computed.ValidBallotCount || payload.ConflictedBallotCount != computed.ConflictedBallotCount {
		return invalidTallyResult("tally result counts do not match local recomputation")
	}
	if len(payload.OptionResults) != len(computed.OptionResults) {
		return invalidTallyResult("tally result option count does not match local recomputation")
	}
	for i := range payload.OptionResults {
		if payload.OptionResults[i].Option != computed.OptionResults[i].Option || payload.OptionResults[i].Count != computed.OptionResults[i].Count {
			return invalidTallyResult("tally result option results do not match local recomputation")
		}
	}
	if !verifyPayloadSignature(envelope, crypto.DomainTallyResultSign, domain.TallyResultSignatureField(), payload.ReporterPublicKey, payload.Signature) {
		return invalidTallyResult("tally result signature is invalid")
	}
	return ContextualRuleResult{Status: StatusValid}
}

func computeLocalTallyResult(electionID string, tallyKeySetHash []byte, ballots []BallotInput, options []string) domain.TallyResultPayload {
	optionCounts := make(map[string]int64, len(options))
	for _, option := range options {
		optionCounts[option] = 0
	}
	var validCount int64
	var conflictedCount int64
	sortedBallotIDs := make([]string, 0)
	for _, ballot := range ballots {
		switch ballot.Status {
		case StatusValidForTally:
			validCount++
			optionCounts[ballot.Payload.Choice]++
			sortedBallotIDs = append(sortedBallotIDs, ballot.ObjectID)
		case StatusValidButConflicted:
			conflictedCount++
		}
	}
	sort.Strings(sortedBallotIDs)

	optionResults := make([]domain.OptionResult, 0, len(options))
	for _, option := range options {
		optionResults = append(optionResults, domain.OptionResult{
			Option: option,
			Count:  optionCounts[option],
		})
	}
	result := domain.TallyResultPayload{
		ElectionID:            electionID,
		TallyKeySetHash:       append([]byte(nil), tallyKeySetHash...),
		OptionResults:         optionResults,
		ValidBallotCount:      validCount,
		ConflictedBallotCount: conflictedCount,
	}
	result.ResultHash = ComputeTallyResultHash(result)
	return result
}

func ComputeLocalTallyResultForService(electionID string, tallyKeySetHash []byte, ballots []BallotInput, options []string) domain.TallyResultPayload {
	return computeLocalTallyResult(electionID, tallyKeySetHash, ballots, options)
}

func ComputeTallyResultHash(result domain.TallyResultPayload) []byte {
	parts := [][]byte{
		[]byte(result.ElectionID),
		result.TallyKeySetHash,
	}
	for _, r := range result.OptionResults {
		parts = append(parts, []byte(r.Option), intPart(r.Count))
	}
	parts = append(parts, intPart(result.ValidBallotCount), intPart(result.ConflictedBallotCount))
	digest := crypto.Hash(crypto.DomainTallyResultHash, parts...)
	return digest.Bytes()
}

func TallyKeySetDependencyID(electionID string) string {
	return electionID + "/tally-key-set"
}

func ParseTallyKeySetDependencyID(id string) (string, error) {
	electionID, ok := splitLast(id, "/tally-key-set")
	if !ok {
		return "", fmt.Errorf("invalid tally_key_set dependency id %q", id)
	}
	return electionID, nil
}

func splitLast(s, sep string) (string, bool) {
	for i := len(s) - len(sep); i >= 0; i-- {
		if s[i:i+len(sep)] == sep {
			return s[:i], true
		}
	}
	return "", false
}

func invalidBallot(reason string) ContextualRuleResult {
	return ContextualRuleResult{Status: StatusInvalid, ValidationErrorCode: ErrorBallotElectionNotActive, ValidationErrorReason: reason}
}

func pendingBallotDependency(dependencyType, id string) ContextualRuleResult {
	return ContextualRuleResult{Status: StatusPendingDependencies, RequiredDependencies: []RequiredDependency{RequireObject(dependencyType, id, StatusValid)}}
}

func invalidTallyResult(reason string) ContextualRuleResult {
	return ContextualRuleResult{Status: StatusInvalid, ValidationErrorCode: ErrorTallyResultMismatch, ValidationErrorReason: reason}
}

func pendingTallyResultDependency(dependencyType, id string) ContextualRuleResult {
	return ContextualRuleResult{Status: StatusPendingDependencies, RequiredDependencies: []RequiredDependency{RequireObject(dependencyType, id, StatusValid)}}
}

func intPartFromHash(value int64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], uint64(value))
	return out[:]
}
