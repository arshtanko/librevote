package validation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"

	"librevote/internal/crypto"
	"librevote/internal/domain"
)

const ErrorTallyKeySetActivationMismatch = "tally_key_set_activation_mismatch"

func TrusteeConsentDependencyID(electionID string, trusteePublicKey []byte) string {
	if len(trusteePublicKey) == 0 {
		return electionID
	}
	return electionID + "/" + hex.EncodeToString(trusteePublicKey)
}

func TallyKeyContributionDependencyID(electionID string, trusteePublicKey []byte) string {
	if len(trusteePublicKey) == 0 {
		return electionID
	}
	return electionID + "/" + hex.EncodeToString(trusteePublicKey)
}

type TallyKeySetInputStore interface {
	TallyKeySetInputs(context.Context, string, []byte) (TallyKeySetInputs, error)
}

type ElectionActivationInputStore interface {
	ElectionActivationInputs(context.Context, string) (TallyKeySetInputs, error)
}

type TallyKeySetInputs struct {
	ElectionFound  bool
	ElectionStatus Status
	Election       domain.AnonymousElectionPayload
	ResultFound    bool
	ResultStatus   Status
	Result         domain.TrusteeSelectionResultPayload
	Consents       []TrusteeConsentInput
	Contributions  []TallyKeyContributionInput
}

type TrusteeConsentInput struct {
	ObjectID string
	Status   Status
	Payload  domain.TrusteeConsentPayload
}

type TallyKeyContributionInput struct {
	ObjectID string
	Status   Status
	Payload  domain.TallyKeyContributionPayload
}

func contextualTallyKeySet(store ContextualStore) ContextualRule {
	return func(ctx context.Context, envelope domain.ObjectEnvelope) (ContextualRuleResult, error) {
		inputStore, ok := store.(TallyKeySetInputStore)
		if !ok {
			return ContextualRuleResult{}, fmt.Errorf("%w for %s activation recomputation", ErrContextualRuleUnsupported, envelope.ObjectType)
		}
		payload, err := decodePayload[domain.TallyKeySetPayload](envelope)
		if err != nil {
			return ContextualRuleResult{}, err
		}
		if envelope.ScopeID != payload.ElectionID {
			return invalidTallyKeySet("tally key set scope_id does not match payload election_id"), nil
		}
		inputs, err := inputStore.TallyKeySetInputs(ctx, payload.ElectionID, payload.TrusteeSelectionResultHash)
		if err != nil {
			return ContextualRuleResult{}, err
		}
		return verifyTallyKeySet(envelope, payload, inputs), nil
	}
}

func contextualTrusteeConsent(store ContextualStore) ContextualRule {
	return func(ctx context.Context, envelope domain.ObjectEnvelope) (ContextualRuleResult, error) {
		inputStore, ok := store.(ElectionActivationInputStore)
		if !ok {
			return ContextualRuleResult{}, fmt.Errorf("%w for %s contextual validation", ErrContextualRuleUnsupported, envelope.ObjectType)
		}
		payload, err := decodePayload[domain.TrusteeConsentPayload](envelope)
		if err != nil {
			return ContextualRuleResult{}, err
		}
		if envelope.ScopeID != payload.ElectionID {
			return invalidTallyKeySet("trustee consent scope_id does not match payload election_id"), nil
		}
		inputs, err := inputStore.ElectionActivationInputs(ctx, payload.ElectionID)
		if err != nil {
			return ContextualRuleResult{}, err
		}
		return verifyTrusteeConsent(envelope, payload, inputs), nil
	}
}

func contextualTallyKeyContribution(store ContextualStore) ContextualRule {
	return func(ctx context.Context, envelope domain.ObjectEnvelope) (ContextualRuleResult, error) {
		inputStore, ok := store.(ElectionActivationInputStore)
		if !ok {
			return ContextualRuleResult{}, fmt.Errorf("%w for %s contextual validation", ErrContextualRuleUnsupported, envelope.ObjectType)
		}
		payload, err := decodePayload[domain.TallyKeyContributionPayload](envelope)
		if err != nil {
			return ContextualRuleResult{}, err
		}
		if envelope.ScopeID != payload.ElectionID {
			return invalidTallyKeySet("tally key contribution scope_id does not match payload election_id"), nil
		}
		inputs, err := inputStore.ElectionActivationInputs(ctx, payload.ElectionID)
		if err != nil {
			return ContextualRuleResult{}, err
		}
		return verifyTallyKeyContribution(envelope, payload, inputs), nil
	}
}

func verifyTrusteeConsent(envelope domain.ObjectEnvelope, payload domain.TrusteeConsentPayload, inputs TallyKeySetInputs) ContextualRuleResult {
	if !inputs.ElectionFound || !inputs.ElectionStatus.Final() {
		return pendingTallyKeySetDependency("election", payload.ElectionID)
	}
	if inputs.ElectionStatus != StatusValid {
		return invalidTallyKeySet("referenced anonymous election has status " + inputs.ElectionStatus.String())
	}
	if payload.TrusteeSelectionID != inputs.Election.TrusteeSelectionID || !bytes.Equal(payload.TrusteeSelectionResultHash, inputs.Election.TrusteeSelectionResultHash) {
		return invalidTallyKeySet("trustee consent does not match anonymous election trustee selection result")
	}
	if !bytes.Equal(payload.ElectionParametersHash, ComputeElectionParametersHash(inputs.Election)) {
		return invalidTallyKeySet("trustee consent election_parameters_hash does not match anonymous election")
	}
	if !inputs.ResultFound || !inputs.ResultStatus.Final() {
		return pendingTallyKeySetDependency("trustee_selection_result", TrusteeSelectionResultDependencyID(payload.TrusteeSelectionID, payload.TrusteeSelectionResultHash))
	}
	if inputs.ResultStatus != StatusValid {
		return invalidTallyKeySet("referenced trustee selection result has status " + inputs.ResultStatus.String())
	}
	for _, candidate := range inputs.Result.CandidateRanking {
		if bytes.Equal(candidate.TrusteePublicKey, payload.TrusteePublicKey) {
			if !verifyPayloadSignature(envelope, crypto.DomainTrusteeConsentSign, 9, payload.TrusteePublicKey, payload.Signature) {
				return invalidTallyKeySet("trustee consent signature is invalid")
			}
			return ContextualRuleResult{Status: StatusValid}
		}
	}
	return invalidTallyKeySet("trustee consent trustee is not in candidate ranking")
}

func verifyTallyKeyContribution(envelope domain.ObjectEnvelope, payload domain.TallyKeyContributionPayload, inputs TallyKeySetInputs) ContextualRuleResult {
	if !inputs.ElectionFound || !inputs.ElectionStatus.Final() {
		return pendingTallyKeySetDependency("election", payload.ElectionID)
	}
	if inputs.ElectionStatus != StatusValid {
		return invalidTallyKeySet("referenced anonymous election has status " + inputs.ElectionStatus.String())
	}
	if !inputs.ResultFound || !inputs.ResultStatus.Final() {
		return pendingTallyKeySetDependency("trustee_selection_result", TrusteeSelectionResultDependencyID(inputs.Election.TrusteeSelectionID, inputs.Election.TrusteeSelectionResultHash))
	}
	if inputs.ResultStatus != StatusValid {
		return invalidTallyKeySet("referenced trustee selection result has status " + inputs.ResultStatus.String())
	}
	matchingConsentPending := ""
	matchingConsentFound := false
	for _, consent := range inputs.Consents {
		if !bytes.Equal(consent.Payload.TrusteePublicKey, payload.TrusteePublicKey) {
			continue
		}
		matchingConsentFound = true
		if !consent.Status.Final() {
			matchingConsentPending = consent.ObjectID
			continue
		}
		if consent.Status == StatusValid && !bytes.Equal(consent.Payload.TrusteeTallySetupPublicKey, payload.TrusteeTallySetupPublicKey) {
			return invalidTallyKeySet("tally key contribution setup key does not match trustee consent")
		}
	}
	if !matchingConsentFound {
		return pendingTallyKeySetDependency("trustee_consent", TrusteeConsentDependencyID(payload.ElectionID, payload.TrusteePublicKey))
	}
	if matchingConsentPending != "" {
		return pendingTallyKeySetDependency("trustee_consent", matchingConsentPending)
	}
	if hasDuplicateValidTrusteeConsent(inputs.Consents) {
		return invalidTallyKeySet("duplicate valid trustee consents")
	}
	finalSet, _, ok := deriveFinalTrusteeSet(inputs.Result, inputs.Consents)
	if !ok {
		return pendingTallyKeySetDependency("trustee_consent", TrusteeConsentDependencyID(payload.ElectionID, nil))
	}
	if !trusteeInFinalSet(payload.TrusteePublicKey, payload.TrusteeTallySetupPublicKey, finalSet) {
		return pendingTallyKeySetDependency("trustee_consent", TrusteeConsentDependencyID(payload.ElectionID, payload.TrusteePublicKey))
	}
	if !sharesMatchTrusteeSet(payload, finalSet) {
		return invalidTallyKeySet("tally key contribution shares do not match final trustee set")
	}
	if !verifyPayloadSignature(envelope, crypto.DomainTallyKeyContributionSign, 7, payload.TrusteePublicKey, payload.Signature) {
		return invalidTallyKeySet("tally key contribution signature is invalid")
	}
	return ContextualRuleResult{Status: StatusValid}
}

func verifyTallyKeySet(envelope domain.ObjectEnvelope, payload domain.TallyKeySetPayload, inputs TallyKeySetInputs) ContextualRuleResult {
	if !inputs.ElectionFound || !inputs.ElectionStatus.Final() {
		return pendingTallyKeySetDependency("election", payload.ElectionID)
	}
	if inputs.ElectionStatus != StatusValid {
		return invalidTallyKeySet("referenced anonymous election has status " + inputs.ElectionStatus.String())
	}
	if !bytes.Equal(inputs.Election.TrusteeSelectionResultHash, payload.TrusteeSelectionResultHash) {
		return invalidTallyKeySet("trustee_selection_result_hash does not match anonymous election")
	}
	if !inputs.ResultFound || !inputs.ResultStatus.Final() {
		return pendingTallyKeySetDependency("trustee_selection_result", TrusteeSelectionResultDependencyID(inputs.Election.TrusteeSelectionID, payload.TrusteeSelectionResultHash))
	}
	if inputs.ResultStatus != StatusValid {
		return invalidTallyKeySet("referenced trustee selection result has status " + inputs.ResultStatus.String())
	}
	if inputs.Result.TrusteeSelectionID != inputs.Election.TrusteeSelectionID {
		return invalidTallyKeySet("trustee selection result id does not match anonymous election")
	}
	if hasDuplicateValidTrusteeConsent(inputs.Consents) {
		return invalidTallyKeySet("duplicate valid trustee consents")
	}

	finalSet, consentIDs, ok := deriveFinalTrusteeSet(inputs.Result, inputs.Consents)
	if !ok {
		return pendingTallyKeySetDependency("trustee_consent", TrusteeConsentDependencyID(payload.ElectionID, nil))
	}
	if !candidatesDeepEqual(payload.TrusteeSet, finalSet) {
		return invalidTallyKeySet("trustee_set does not match locally derived final trustee set")
	}
	if !sameStringSet(payload.TrusteeConsentObjectIDs, consentIDs) {
		return invalidTallyKeySet("trustee_consent_object_ids do not match locally retained valid consents")
	}

	contributionIDs, commitments, setupProofs, contributionIssue, contributionDependencyID := retainedContributionsForTrustees(payload.ElectionID, finalSet, inputs.Contributions)
	if contributionIssue == "missing" {
		return pendingTallyKeySetDependency("tally_key_contribution", contributionDependencyID)
	}
	if contributionIssue != "" {
		return invalidTallyKeySet(contributionIssue)
	}
	if !sameStringSet(payload.TallyKeyContributionObjectIDs, contributionIDs) {
		return invalidTallyKeySet("tally_key_contribution_object_ids do not match locally retained valid contributions")
	}
	if !bytesSlicesEqual(payload.TrusteeKeyCommitments, commitments) || !bytesSlicesEqual(payload.SetupProofs, setupProofs) {
		return invalidTallyKeySet("tally key setup data does not match retained contributions")
	}

	trusteeSetHash := ComputeTrusteeSetHash(finalSet)
	if !bytes.Equal(payload.TrusteeSetHash, trusteeSetHash) {
		return invalidTallyKeySet("trustee_set_hash does not match canonical trustee set")
	}
	tallyPublicKey := ComputeTallyPublicKey(commitments)
	if !bytes.Equal(payload.TallyPublicKey, tallyPublicKey) {
		return invalidTallyKeySet("tally_public_key does not match retained commitments")
	}
	activationHash := ComputeTallyKeySetHash(payload.ElectionID, payload.TrusteeSelectionResultHash, finalSet, consentIDs, contributionIDs, commitments, payload.TallyPublicKey)
	if !bytes.Equal(payload.TallyKeySetHash, activationHash) {
		return invalidTallyKeySet("tally_key_set_hash does not match local activation recomputation")
	}
	signedPayload, err := payloadWithoutField(envelope.Payload, 14)
	if err != nil {
		return invalidTallyKeySet("tally key set signed payload is invalid")
	}
	digest, err := crypto.SigningDigest(crypto.SigningContext{
		Domain:          crypto.DomainTallyKeySetSign,
		ProtocolVersion: envelope.ProtocolVersion,
		NetworkID:       envelope.NetworkID,
		ObjectType:      envelope.ObjectType,
		Scope:           envelope.Scope,
		ScopeID:         envelope.ScopeID,
		CreatedAt:       envelope.CreatedAt,
	}, signedPayload)
	if err != nil {
		return invalidTallyKeySet("tally key set signing context is invalid")
	}
	if !crypto.VerifyEd25519(ed25519.PublicKey(payload.ReporterPublicKey), digest, payload.Signature) {
		return invalidTallyKeySet("tally key set signature is invalid")
	}
	return ContextualRuleResult{Status: StatusValid}
}

func deriveFinalTrusteeSet(result domain.TrusteeSelectionResultPayload, consents []TrusteeConsentInput) ([]domain.TrusteeCandidate, []string, bool) {
	validConsents := make(map[string][]TrusteeConsentInput)
	for _, consent := range consents {
		if consent.Status != StatusValid {
			continue
		}
		key := string(consent.Payload.TrusteePublicKey)
		validConsents[key] = append(validConsents[key], consent)
	}
	seenSetup := map[string]struct{}{}
	finalSet := make([]domain.TrusteeCandidate, 0, domain.TrusteeCountV1)
	consentIDs := make([]string, 0, domain.TrusteeCountV1)
	for _, candidate := range result.CandidateRanking {
		matches := validConsents[string(candidate.TrusteePublicKey)]
		if len(matches) != 1 {
			continue
		}
		consent := matches[0]
		if !bytes.Equal(consent.Payload.TrusteeSelectionResultHash, result.ResultHash) {
			continue
		}
		setupKey := string(consent.Payload.TrusteeTallySetupPublicKey)
		if _, duplicate := seenSetup[setupKey]; duplicate {
			continue
		}
		seenSetup[setupKey] = struct{}{}
		finalSet = append(finalSet, domain.TrusteeCandidate{
			TrusteePublicKey:     append([]byte(nil), candidate.TrusteePublicKey...),
			BlindTokenPublicKey:  append([]byte(nil), candidate.BlindTokenPublicKey...),
			TrusteeTallySetupKey: append([]byte(nil), consent.Payload.TrusteeTallySetupPublicKey...),
		})
		consentIDs = append(consentIDs, consent.ObjectID)
		if len(finalSet) == domain.TrusteeCountV1 {
			return finalSet, consentIDs, true
		}
	}
	return finalSet, consentIDs, false
}

func hasDuplicateValidTrusteeConsent(consents []TrusteeConsentInput) bool {
	seenTrustee := map[string]struct{}{}
	seenSetup := map[string]struct{}{}
	for _, consent := range consents {
		if consent.Status != StatusValid {
			continue
		}
		trusteeKey := string(consent.Payload.TrusteePublicKey)
		if _, duplicate := seenTrustee[trusteeKey]; duplicate {
			return true
		}
		seenTrustee[trusteeKey] = struct{}{}
		setupKey := string(consent.Payload.TrusteeTallySetupPublicKey)
		if _, duplicate := seenSetup[setupKey]; duplicate {
			return true
		}
		seenSetup[setupKey] = struct{}{}
	}
	return false
}

func retainedContributionsForTrustees(electionID string, trustees []domain.TrusteeCandidate, contributions []TallyKeyContributionInput) ([]string, [][]byte, [][]byte, string, string) {
	valid := make(map[string]TallyKeyContributionInput)
	for _, contribution := range contributions {
		if contribution.Status == StatusValid {
			key := string(contribution.Payload.TrusteePublicKey)
			if _, duplicate := valid[key]; duplicate {
				return nil, nil, nil, "duplicate valid tally key contributions", ""
			}
			valid[string(contribution.Payload.TrusteePublicKey)] = contribution
		}
	}
	ids := make([]string, 0, len(trustees))
	commitments := make([][]byte, 0, len(trustees))
	proofs := make([][]byte, 0, len(trustees))
	for _, trustee := range trustees {
		contribution, ok := valid[string(trustee.TrusteePublicKey)]
		if !ok {
			return nil, nil, nil, "missing", TallyKeyContributionDependencyID(electionID, trustee.TrusteePublicKey)
		}
		if !bytes.Equal(contribution.Payload.TrusteeTallySetupPublicKey, trustee.TrusteeTallySetupKey) {
			return nil, nil, nil, "tally key contribution setup key does not match trustee consent", ""
		}
		if !sharesMatchTrusteeSet(contribution.Payload, trustees) {
			return nil, nil, nil, "tally key contribution shares do not match final trustee set", ""
		}
		ids = append(ids, contribution.ObjectID)
		commitments = append(commitments, aggregateContributionCommitments(contribution.Payload.DKGCommitments))
		proofs = append(proofs, append([]byte(nil), contribution.Payload.SetupProof...))
	}
	return ids, commitments, proofs, "", ""
}

func sharesMatchTrusteeSet(contribution domain.TallyKeyContributionPayload, trustees []domain.TrusteeCandidate) bool {
	if len(contribution.DKGEncryptedShares) != len(trustees) {
		return false
	}
	byRecipient := map[string]domain.DKGEncryptedShare{}
	for _, share := range contribution.DKGEncryptedShares {
		byRecipient[string(share.RecipientTrusteePublicKey)] = share
	}
	for i, trustee := range trustees {
		share, ok := byRecipient[string(trustee.TrusteePublicKey)]
		setupKeyID, err := crypto.KeyID(crypto.KeyTypeTrusteeTallySetup, trustee.TrusteeTallySetupKey)
		if err != nil {
			return false
		}
		if !ok || share.RecipientIndex != int64(i+1) || !bytes.Equal(share.RecipientTallySetupKeyID, setupKeyID[:]) {
			return false
		}
	}
	return true
}

func trusteeInFinalSet(trusteePublicKey, setupPublicKey []byte, trustees []domain.TrusteeCandidate) bool {
	for _, trustee := range trustees {
		if bytes.Equal(trustee.TrusteePublicKey, trusteePublicKey) && bytes.Equal(trustee.TrusteeTallySetupKey, setupPublicKey) {
			return true
		}
	}
	return false
}

func verifyPayloadSignature(envelope domain.ObjectEnvelope, signDomain crypto.Domain, signatureField uint64, publicKey, signature []byte) bool {
	signedPayload, err := payloadWithoutField(envelope.Payload, signatureField)
	if err != nil {
		return false
	}
	digest, err := crypto.SigningDigest(crypto.SigningContext{
		Domain:          signDomain,
		ProtocolVersion: envelope.ProtocolVersion,
		NetworkID:       envelope.NetworkID,
		ObjectType:      envelope.ObjectType,
		Scope:           envelope.Scope,
		ScopeID:         envelope.ScopeID,
		CreatedAt:       envelope.CreatedAt,
	}, signedPayload)
	if err != nil {
		return false
	}
	return crypto.VerifyEd25519(ed25519.PublicKey(publicKey), digest, signature)
}

func aggregateContributionCommitments(commitments []domain.DKGCommitment) []byte {
	parts := make([][]byte, 0, len(commitments)*3)
	for _, commitment := range commitments {
		parts = append(parts, commitment.SenderTrusteePublicKey, intPart(commitment.CoefficientIndex), commitment.Commitment)
	}
	digest := crypto.Hash(crypto.DomainTallyKeySetHash, append([][]byte{[]byte("contribution_commitments")}, parts...)...)
	return digest.Bytes()
}

func ComputeTrusteeSetHash(trustees []domain.TrusteeCandidate) []byte {
	parts := make([][]byte, 0, 1+len(trustees)*3)
	parts = append(parts, []byte("trustee_set"))
	for _, trustee := range trustees {
		parts = append(parts, trustee.TrusteePublicKey, trustee.BlindTokenPublicKey, trustee.TrusteeTallySetupKey)
	}
	digest := crypto.Hash(crypto.DomainTallyKeySetHash, parts...)
	return digest.Bytes()
}

func ComputeTallyPublicKey(commitments [][]byte) []byte {
	parts := append([][]byte{[]byte("tally_public_key")}, commitments...)
	digest := crypto.Hash(crypto.DomainTallyKeySetHash, parts...)
	return digest.Bytes()
}

func ComputeTallyKeySetHash(electionID string, resultHash []byte, trustees []domain.TrusteeCandidate, consentIDs, contributionIDs []string, commitments [][]byte, tallyPublicKey []byte) []byte {
	sortedConsentIDs := append([]string(nil), consentIDs...)
	sortedContributionIDs := append([]string(nil), contributionIDs...)
	sort.Strings(sortedConsentIDs)
	sort.Strings(sortedContributionIDs)

	parts := [][]byte{[]byte(electionID), resultHash}
	for _, trustee := range trustees {
		parts = append(parts, trustee.TrusteePublicKey, trustee.BlindTokenPublicKey, trustee.TrusteeTallySetupKey)
	}
	parts = append(parts, []byte("consents"))
	for _, id := range sortedConsentIDs {
		parts = append(parts, []byte(id))
	}
	parts = append(parts, []byte("contributions"))
	for _, id := range sortedContributionIDs {
		parts = append(parts, []byte(id))
	}
	parts = append(parts, []byte("commitments"))
	parts = append(parts, commitments...)
	parts = append(parts, tallyPublicKey)
	digest := crypto.Hash(crypto.DomainTallyKeySetHash, parts...)
	return digest.Bytes()
}

func ComputeElectionParametersHash(election domain.AnonymousElectionPayload) []byte {
	parts := [][]byte{
		[]byte(election.ElectionID),
		[]byte(election.NetworkID),
		[]byte(election.TrusteeSelectionID),
		election.TrusteeSelectionResultHash,
		intPart(election.ThresholdT),
		intPart(election.TrusteeCountN),
		[]byte(election.EligibilityScheme),
		intPart(election.IssuanceStartsAt),
		intPart(election.IssuanceEndsAt),
		intPart(election.VotingStartsAt),
		intPart(election.VotingEndsAt),
		intPart(election.TallyStartsAt),
	}
	for _, option := range election.Options {
		parts = append(parts, []byte(option))
	}
	for _, voter := range election.VoterAllowlist {
		parts = append(parts, []byte(voter.VoterID), voter.VoterSigningPublicKey, voter.VoterEncryptionPublicKey)
	}
	digest := crypto.Hash(crypto.DomainElectionParameters, parts...)
	return digest.Bytes()
}

func payloadWithoutField(payload []byte, excludedField uint64) ([]byte, error) {
	out := make([]byte, 0, len(payload))
	for offset := 0; offset < len(payload); {
		fieldStart := offset
		key, n, err := consumeValidationVarint(payload[offset:])
		if err != nil {
			return nil, err
		}
		offset += n
		field := key >> 3
		wire := key & 0x7
		size := 0
		switch wire {
		case 0:
			_, n, err := consumeValidationVarint(payload[offset:])
			if err != nil {
				return nil, err
			}
			size = n
		case 2:
			length, n, err := consumeValidationVarint(payload[offset:])
			if err != nil {
				return nil, err
			}
			if length > uint64(len(payload[offset+n:])) {
				return nil, io.ErrUnexpectedEOF
			}
			size = n + int(length)
		default:
			return nil, fmt.Errorf("wire type %d: %w", wire, errors.ErrUnsupported)
		}
		fieldEnd := offset + size
		if field != excludedField {
			out = append(out, payload[fieldStart:fieldEnd]...)
		}
		offset = fieldEnd
	}
	return out, nil
}

func consumeValidationVarint(b []byte) (uint64, int, error) {
	var value uint64
	for i, c := range b {
		if i == 10 || (i == 9 && c > 1) {
			return 0, 0, errors.ErrUnsupported
		}
		value |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			return value, i + 1, nil
		}
	}
	return 0, 0, io.ErrUnexpectedEOF
}

func invalidTallyKeySet(reason string) ContextualRuleResult {
	return ContextualRuleResult{Status: StatusInvalid, ValidationErrorCode: ErrorTallyKeySetActivationMismatch, ValidationErrorReason: reason}
}

func pendingTallyKeySetDependency(dependencyType, id string) ContextualRuleResult {
	return ContextualRuleResult{Status: StatusPendingDependencies, RequiredDependencies: []RequiredDependency{RequireObject(dependencyType, id, StatusValid)}}
}

func candidatesDeepEqual(a, b []domain.TrusteeCandidate) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].TrusteePublicKey, b[i].TrusteePublicKey) || !bytes.Equal(a[i].BlindTokenPublicKey, b[i].BlindTokenPublicKey) || !bytes.Equal(a[i].TrusteeTallySetupKey, b[i].TrusteeTallySetupKey) {
			return false
		}
	}
	return true
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]string(nil), a...)
	right := append([]string(nil), b...)
	sort.Strings(left)
	sort.Strings(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func bytesSlicesEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
