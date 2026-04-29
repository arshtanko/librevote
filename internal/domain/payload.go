package domain

import (
	"errors"
	"fmt"
	"io"
)

const (
	EligibilitySchemeBlindTokenV1 = "blind_token_v1"

	TrusteeCountV1       = 3
	ThresholdV1          = 2
	MaxChoicesPerVoteV1  = 3
	ed25519PublicKeySize = 32
	ed25519SignatureSize = 64
	hashSize             = 32
)

var ErrUnknownPayloadField = errors.New("unknown payload field")

type VoterEntry struct {
	VoterID                  string
	VoterSigningPublicKey    []byte
	VoterEncryptionPublicKey []byte
}

type TrusteeSelectionElectionPayload struct {
	TrusteeSelectionID string
	NetworkID          string
	Title              string
	Description        string
	VoterAllowlist     []VoterEntry
	NominationStartsAt int64
	NominationEndsAt   int64
	VotingStartsAt     int64
	VotingEndsAt       int64
	ConsentStartsAt    int64
	ConsentEndsAt      int64
	TrusteeCountN      int64
	ThresholdT         int64
	MaxChoicesPerVote  int64
	CreatorPublicKey   []byte
	Signature          []byte
}

type TrusteeCandidate struct {
	TrusteePublicKey     []byte
	BlindTokenPublicKey  []byte
	TrusteeTallySetupKey []byte
}

type CandidateScore struct {
	TrusteePublicKey []byte
	Score            int64
}

type TrusteeSelectionResultPayload struct {
	TrusteeSelectionID      string
	CandidateRanking        []TrusteeCandidate
	InitialSelectedTrustees []TrusteeCandidate
	ThresholdT              int64
	TrusteeCountN           int64
	CandidateScores         []CandidateScore
	ConflictedVoteCount     int64
	ValidVoteCount          int64
	ResultHash              []byte
	ReporterPublicKey       []byte
	Signature               []byte
}

type TrusteeConsentPayload struct {
	TrusteeSelectionID         string
	TrusteeSelectionResultHash []byte
	ElectionID                 string
	ElectionParametersHash     []byte
	TrusteePublicKey           []byte
	TrusteeTallySetupPublicKey []byte
	ThresholdT                 int64
	TrusteeCountN              int64
	Signature                  []byte
}

type AnonymousElectionPayload struct {
	ElectionID                 string
	NetworkID                  string
	Title                      string
	Description                string
	Options                    []string
	VoterAllowlist             []VoterEntry
	TrusteeSelectionID         string
	TrusteeSelectionResultHash []byte
	ThresholdT                 int64
	TrusteeCountN              int64
	EligibilityScheme          string
	IssuanceStartsAt           int64
	IssuanceEndsAt             int64
	VotingStartsAt             int64
	VotingEndsAt               int64
	TallyStartsAt              int64
	CreatorPublicKey           []byte
	Signature                  []byte
}

type TallyKeySetPayload struct {
	ElectionID                    string
	TrusteeSelectionResultHash    []byte
	TrusteeSet                    []TrusteeCandidate
	TrusteeConsentObjectIDs       []string
	TallyKeyContributionObjectIDs []string
	TrusteeSetHash                []byte
	ThresholdT                    int64
	TrusteeCountN                 int64
	TallyPublicKey                []byte
	TrusteeKeyCommitments         [][]byte
	SetupProofs                   [][]byte
	TallyKeySetHash               []byte
	ReporterPublicKey             []byte
	Signature                     []byte
}

// DecodePayload decodes the implemented v1 canonical protobuf payload subset.
func DecodePayload(objectType ObjectType, payload []byte) (any, error) {
	if err := ValidateCanonicalPayloadWire(payload); err != nil {
		return nil, err
	}
	switch objectType {
	case ObjectTypeTrusteeSelectionElection:
		return decodeTrusteeSelectionElection(payload)
	case ObjectTypeTrusteeSelectionResult:
		return decodeTrusteeSelectionResult(payload)
	case ObjectTypeTrusteeConsent:
		return decodeTrusteeConsent(payload)
	case ObjectTypeAnonymousElection:
		return decodeAnonymousElection(payload)
	case ObjectTypeTallyKeySet:
		return decodeTallyKeySet(payload)
	default:
		return nil, fmt.Errorf("payload decoder for %s is not implemented", objectType)
	}
}

// ValidatePayloadShape applies deterministic structural checks for decoded payloads.
func ValidatePayloadShape(objectType ObjectType, payload []byte) error {
	decoded, err := DecodePayload(objectType, payload)
	if err != nil {
		return err
	}
	switch p := decoded.(type) {
	case TrusteeSelectionElectionPayload:
		return validateTrusteeSelectionElection(p)
	case TrusteeSelectionResultPayload:
		return validateTrusteeSelectionResult(p)
	case TrusteeConsentPayload:
		return validateTrusteeConsent(p)
	case AnonymousElectionPayload:
		return validateAnonymousElection(p)
	case TallyKeySetPayload:
		return validateTallyKeySet(p)
	default:
		return fmt.Errorf("unsupported decoded payload %T", decoded)
	}
}

func decodeTrusteeSelectionElection(payload []byte) (TrusteeSelectionElectionPayload, error) {
	var p TrusteeSelectionElectionPayload
	seen := map[uint64]struct{}{}
	err := rangeProtoFields(payload, func(field uint64, wire uint64, value []byte) error {
		switch field {
		case 1:
			return setString(seen, field, wire, value, &p.TrusteeSelectionID)
		case 2:
			return setString(seen, field, wire, value, &p.NetworkID)
		case 3:
			return setString(seen, field, wire, value, &p.Title)
		case 4:
			return setString(seen, field, wire, value, &p.Description)
		case 5:
			entry, err := decodeVoterEntry(value)
			if err != nil {
				return err
			}
			p.VoterAllowlist = append(p.VoterAllowlist, entry)
		case 6:
			return setInt64(seen, field, wire, value, &p.NominationStartsAt)
		case 7:
			return setInt64(seen, field, wire, value, &p.NominationEndsAt)
		case 8:
			return setInt64(seen, field, wire, value, &p.VotingStartsAt)
		case 9:
			return setInt64(seen, field, wire, value, &p.VotingEndsAt)
		case 10:
			return setInt64(seen, field, wire, value, &p.ConsentStartsAt)
		case 11:
			return setInt64(seen, field, wire, value, &p.ConsentEndsAt)
		case 12:
			return setInt64(seen, field, wire, value, &p.TrusteeCountN)
		case 13:
			return setInt64(seen, field, wire, value, &p.ThresholdT)
		case 14:
			return setInt64(seen, field, wire, value, &p.MaxChoicesPerVote)
		case 15:
			return setBytes(seen, field, wire, value, &p.CreatorPublicKey)
		case 16:
			return setBytes(seen, field, wire, value, &p.Signature)
		default:
			return unknownField(field)
		}
		return nil
	})
	return p, err
}

func decodeTrusteeSelectionResult(payload []byte) (TrusteeSelectionResultPayload, error) {
	var p TrusteeSelectionResultPayload
	seen := map[uint64]struct{}{}
	err := rangeProtoFields(payload, func(field uint64, wire uint64, value []byte) error {
		switch field {
		case 1:
			return setString(seen, field, wire, value, &p.TrusteeSelectionID)
		case 2:
			candidate, err := decodeTrusteeCandidate(value, false)
			if err != nil {
				return err
			}
			p.CandidateRanking = append(p.CandidateRanking, candidate)
		case 3:
			candidate, err := decodeTrusteeCandidate(value, false)
			if err != nil {
				return err
			}
			p.InitialSelectedTrustees = append(p.InitialSelectedTrustees, candidate)
		case 4:
			return setInt64(seen, field, wire, value, &p.ThresholdT)
		case 5:
			return setInt64(seen, field, wire, value, &p.TrusteeCountN)
		case 6:
			score, err := decodeCandidateScore(value)
			if err != nil {
				return err
			}
			p.CandidateScores = append(p.CandidateScores, score)
		case 7:
			return setInt64(seen, field, wire, value, &p.ConflictedVoteCount)
		case 8:
			return setInt64(seen, field, wire, value, &p.ValidVoteCount)
		case 9:
			return setBytes(seen, field, wire, value, &p.ResultHash)
		case 10:
			return setBytes(seen, field, wire, value, &p.ReporterPublicKey)
		case 11:
			return setBytes(seen, field, wire, value, &p.Signature)
		default:
			return unknownField(field)
		}
		return nil
	})
	return p, err
}

func decodeTrusteeConsent(payload []byte) (TrusteeConsentPayload, error) {
	var p TrusteeConsentPayload
	seen := map[uint64]struct{}{}
	err := rangeProtoFields(payload, func(field uint64, wire uint64, value []byte) error {
		switch field {
		case 1:
			return setString(seen, field, wire, value, &p.TrusteeSelectionID)
		case 2:
			return setBytes(seen, field, wire, value, &p.TrusteeSelectionResultHash)
		case 3:
			return setString(seen, field, wire, value, &p.ElectionID)
		case 4:
			return setBytes(seen, field, wire, value, &p.ElectionParametersHash)
		case 5:
			return setBytes(seen, field, wire, value, &p.TrusteePublicKey)
		case 6:
			return setBytes(seen, field, wire, value, &p.TrusteeTallySetupPublicKey)
		case 7:
			return setInt64(seen, field, wire, value, &p.ThresholdT)
		case 8:
			return setInt64(seen, field, wire, value, &p.TrusteeCountN)
		case 9:
			return setBytes(seen, field, wire, value, &p.Signature)
		default:
			return unknownField(field)
		}
	})
	return p, err
}

func decodeAnonymousElection(payload []byte) (AnonymousElectionPayload, error) {
	var p AnonymousElectionPayload
	seen := map[uint64]struct{}{}
	err := rangeProtoFields(payload, func(field uint64, wire uint64, value []byte) error {
		switch field {
		case 1:
			return setString(seen, field, wire, value, &p.ElectionID)
		case 2:
			return setString(seen, field, wire, value, &p.NetworkID)
		case 3:
			return setString(seen, field, wire, value, &p.Title)
		case 4:
			return setString(seen, field, wire, value, &p.Description)
		case 5:
			return appendString(wire, value, &p.Options)
		case 6:
			entry, err := decodeVoterEntry(value)
			if err != nil {
				return err
			}
			p.VoterAllowlist = append(p.VoterAllowlist, entry)
		case 7:
			return setString(seen, field, wire, value, &p.TrusteeSelectionID)
		case 8:
			return setBytes(seen, field, wire, value, &p.TrusteeSelectionResultHash)
		case 9:
			return setInt64(seen, field, wire, value, &p.ThresholdT)
		case 10:
			return setInt64(seen, field, wire, value, &p.TrusteeCountN)
		case 11:
			return setString(seen, field, wire, value, &p.EligibilityScheme)
		case 12:
			return setInt64(seen, field, wire, value, &p.IssuanceStartsAt)
		case 13:
			return setInt64(seen, field, wire, value, &p.IssuanceEndsAt)
		case 14:
			return setInt64(seen, field, wire, value, &p.VotingStartsAt)
		case 15:
			return setInt64(seen, field, wire, value, &p.VotingEndsAt)
		case 16:
			return setInt64(seen, field, wire, value, &p.TallyStartsAt)
		case 17:
			return setBytes(seen, field, wire, value, &p.CreatorPublicKey)
		case 18:
			return setBytes(seen, field, wire, value, &p.Signature)
		default:
			return unknownField(field)
		}
		return nil
	})
	return p, err
}

func decodeTallyKeySet(payload []byte) (TallyKeySetPayload, error) {
	var p TallyKeySetPayload
	seen := map[uint64]struct{}{}
	err := rangeProtoFields(payload, func(field uint64, wire uint64, value []byte) error {
		switch field {
		case 1:
			return setString(seen, field, wire, value, &p.ElectionID)
		case 2:
			return setBytes(seen, field, wire, value, &p.TrusteeSelectionResultHash)
		case 3:
			candidate, err := decodeTrusteeCandidate(value, true)
			if err != nil {
				return err
			}
			p.TrusteeSet = append(p.TrusteeSet, candidate)
		case 4:
			return appendString(wire, value, &p.TrusteeConsentObjectIDs)
		case 5:
			return appendString(wire, value, &p.TallyKeyContributionObjectIDs)
		case 6:
			return setBytes(seen, field, wire, value, &p.TrusteeSetHash)
		case 7:
			return setInt64(seen, field, wire, value, &p.ThresholdT)
		case 8:
			return setInt64(seen, field, wire, value, &p.TrusteeCountN)
		case 9:
			return setBytes(seen, field, wire, value, &p.TallyPublicKey)
		case 10:
			return appendBytes(wire, value, &p.TrusteeKeyCommitments)
		case 11:
			return appendBytes(wire, value, &p.SetupProofs)
		case 12:
			return setBytes(seen, field, wire, value, &p.TallyKeySetHash)
		case 13:
			return setBytes(seen, field, wire, value, &p.ReporterPublicKey)
		case 14:
			return setBytes(seen, field, wire, value, &p.Signature)
		default:
			return unknownField(field)
		}
		return nil
	})
	return p, err
}

func validateTrusteeSelectionElection(p TrusteeSelectionElectionPayload) error {
	if p.TrusteeSelectionID == "" || p.NetworkID == "" || p.Title == "" || len(p.VoterAllowlist) == 0 {
		return errors.New("required trustee selection election fields are missing")
	}
	if p.TrusteeCountN != TrusteeCountV1 || p.ThresholdT != ThresholdV1 || p.MaxChoicesPerVote != MaxChoicesPerVoteV1 {
		return errors.New("unsupported trustee selection parameters")
	}
	if !increasing(p.NominationStartsAt, p.NominationEndsAt, p.VotingStartsAt, p.VotingEndsAt, p.ConsentStartsAt, p.ConsentEndsAt) {
		return errors.New("trustee selection windows must be ordered")
	}
	if err := validateVoterAllowlist(p.VoterAllowlist); err != nil {
		return err
	}
	return validatePublicSignature(p.CreatorPublicKey, p.Signature)
}

func validateTrusteeSelectionResult(p TrusteeSelectionResultPayload) error {
	if p.TrusteeSelectionID == "" || len(p.CandidateRanking) == 0 || len(p.CandidateScores) == 0 || len(p.ResultHash) != hashSize {
		return errors.New("required trustee selection result fields are missing")
	}
	if p.ThresholdT != ThresholdV1 || p.TrusteeCountN != TrusteeCountV1 {
		return errors.New("unsupported trustee selection result parameters")
	}
	if len(p.InitialSelectedTrustees) > TrusteeCountV1 {
		return errors.New("too many initially selected trustees")
	}
	if err := validateCandidates(p.CandidateRanking, false); err != nil {
		return err
	}
	if err := validateCandidates(p.InitialSelectedTrustees, false); err != nil {
		return err
	}
	if err := validateCandidateScores(p.CandidateScores); err != nil {
		return err
	}
	return validatePublicSignature(p.ReporterPublicKey, p.Signature)
}

func validateTrusteeConsent(p TrusteeConsentPayload) error {
	if p.TrusteeSelectionID == "" || p.ElectionID == "" || len(p.TrusteeSelectionResultHash) != hashSize || len(p.ElectionParametersHash) != hashSize {
		return errors.New("required trustee consent fields are missing")
	}
	if p.ThresholdT != ThresholdV1 || p.TrusteeCountN != TrusteeCountV1 {
		return errors.New("unsupported trustee consent parameters")
	}
	if len(p.TrusteeTallySetupPublicKey) == 0 {
		return errors.New("trustee tally setup public key is required")
	}
	return validatePublicSignature(p.TrusteePublicKey, p.Signature)
}

func validateAnonymousElection(p AnonymousElectionPayload) error {
	if p.ElectionID == "" || p.NetworkID == "" || p.Title == "" || p.TrusteeSelectionID == "" || len(p.TrusteeSelectionResultHash) != hashSize {
		return errors.New("required anonymous election fields are missing")
	}
	if len(p.Options) < 2 {
		return errors.New("anonymous election requires at least two options")
	}
	if duplicateStrings(p.Options) {
		return errors.New("anonymous election options contain duplicates")
	}
	if err := validateVoterAllowlist(p.VoterAllowlist); err != nil {
		return err
	}
	if p.EligibilityScheme != EligibilitySchemeBlindTokenV1 {
		return errors.New("unknown eligibility scheme")
	}
	if p.ThresholdT != ThresholdV1 || p.TrusteeCountN != TrusteeCountV1 {
		return errors.New("unsupported anonymous election parameters")
	}
	if !increasing(p.IssuanceStartsAt, p.IssuanceEndsAt, p.VotingStartsAt, p.VotingEndsAt, p.TallyStartsAt) {
		return errors.New("anonymous election windows must be ordered")
	}
	return validatePublicSignature(p.CreatorPublicKey, p.Signature)
}

func validateTallyKeySet(p TallyKeySetPayload) error {
	if p.ElectionID == "" || len(p.TrusteeSelectionResultHash) != hashSize || len(p.TrusteeSetHash) != hashSize || len(p.TallyKeySetHash) != hashSize {
		return errors.New("required tally key set fields are missing")
	}
	if p.ThresholdT != ThresholdV1 || p.TrusteeCountN != TrusteeCountV1 {
		return errors.New("unsupported tally key set parameters")
	}
	if len(p.TrusteeSet) != TrusteeCountV1 || len(p.TrusteeConsentObjectIDs) != TrusteeCountV1 || len(p.TallyKeyContributionObjectIDs) != TrusteeCountV1 {
		return errors.New("tally key set requires exactly three trustees, consents, and contributions")
	}
	if err := validateCandidates(p.TrusteeSet, true); err != nil {
		return err
	}
	if duplicateStrings(p.TrusteeConsentObjectIDs) || duplicateStrings(p.TallyKeyContributionObjectIDs) {
		return errors.New("tally key set object ids contain duplicates")
	}
	if len(p.TallyPublicKey) == 0 || len(p.TrusteeKeyCommitments) != TrusteeCountV1 || len(p.SetupProofs) != TrusteeCountV1 {
		return errors.New("tally public key, commitments, and setup proofs are required")
	}
	return validatePublicSignature(p.ReporterPublicKey, p.Signature)
}

func validateCandidateScores(scores []CandidateScore) error {
	seenTrustees := map[string]struct{}{}
	for _, score := range scores {
		if len(score.TrusteePublicKey) != ed25519PublicKeySize {
			return errors.New("invalid candidate score trustee public key")
		}
		if _, ok := seenTrustees[string(score.TrusteePublicKey)]; ok {
			return errors.New("duplicate candidate score trustee public key")
		}
		seenTrustees[string(score.TrusteePublicKey)] = struct{}{}
	}
	return nil
}

func validateVoterAllowlist(entries []VoterEntry) error {
	if len(entries) == 0 {
		return errors.New("voter allowlist is required")
	}
	signing := map[string]struct{}{}
	encryption := map[string]struct{}{}
	for _, entry := range entries {
		if entry.VoterID == "" || len(entry.VoterSigningPublicKey) != ed25519PublicKeySize || len(entry.VoterEncryptionPublicKey) == 0 {
			return errors.New("invalid voter allowlist entry")
		}
		if _, ok := signing[string(entry.VoterSigningPublicKey)]; ok {
			return errors.New("duplicate voter signing public key")
		}
		if _, ok := encryption[string(entry.VoterEncryptionPublicKey)]; ok {
			return errors.New("duplicate voter encryption public key")
		}
		signing[string(entry.VoterSigningPublicKey)] = struct{}{}
		encryption[string(entry.VoterEncryptionPublicKey)] = struct{}{}
	}
	return nil
}

func validateCandidates(candidates []TrusteeCandidate, requireTallySetup bool) error {
	seenTrustees := map[string]struct{}{}
	seenBlind := map[string]struct{}{}
	seenSetup := map[string]struct{}{}
	for _, c := range candidates {
		if len(c.TrusteePublicKey) != ed25519PublicKeySize || len(c.BlindTokenPublicKey) == 0 {
			return errors.New("invalid trustee candidate")
		}
		if requireTallySetup && len(c.TrusteeTallySetupKey) == 0 {
			return errors.New("trustee tally setup key is required")
		}
		if _, ok := seenTrustees[string(c.TrusteePublicKey)]; ok {
			return errors.New("duplicate trustee public key")
		}
		if _, ok := seenBlind[string(c.BlindTokenPublicKey)]; ok {
			return errors.New("duplicate trustee blind-token key")
		}
		seenTrustees[string(c.TrusteePublicKey)] = struct{}{}
		seenBlind[string(c.BlindTokenPublicKey)] = struct{}{}
		if len(c.TrusteeTallySetupKey) > 0 {
			if _, ok := seenSetup[string(c.TrusteeTallySetupKey)]; ok {
				return errors.New("duplicate trustee tally setup key")
			}
			seenSetup[string(c.TrusteeTallySetupKey)] = struct{}{}
		}
	}
	return nil
}

func validatePublicSignature(publicKey, signature []byte) error {
	if len(publicKey) != ed25519PublicKeySize {
		return errors.New("invalid ed25519 public key size")
	}
	if len(signature) != ed25519SignatureSize {
		return errors.New("invalid ed25519 signature size")
	}
	return nil
}

func decodeVoterEntry(payload []byte) (VoterEntry, error) {
	var entry VoterEntry
	seen := map[uint64]struct{}{}
	err := rangeProtoFields(payload, func(field uint64, wire uint64, value []byte) error {
		switch field {
		case 1:
			return setString(seen, field, wire, value, &entry.VoterID)
		case 2:
			return setBytes(seen, field, wire, value, &entry.VoterSigningPublicKey)
		case 3:
			return setBytes(seen, field, wire, value, &entry.VoterEncryptionPublicKey)
		default:
			return unknownField(field)
		}
	})
	return entry, err
}

func decodeTrusteeCandidate(payload []byte, allowTallySetup bool) (TrusteeCandidate, error) {
	var candidate TrusteeCandidate
	seen := map[uint64]struct{}{}
	err := rangeProtoFields(payload, func(field uint64, wire uint64, value []byte) error {
		switch field {
		case 1:
			return setBytes(seen, field, wire, value, &candidate.TrusteePublicKey)
		case 2:
			return setBytes(seen, field, wire, value, &candidate.BlindTokenPublicKey)
		case 3:
			if !allowTallySetup {
				return unknownField(field)
			}
			return setBytes(seen, field, wire, value, &candidate.TrusteeTallySetupKey)
		default:
			return unknownField(field)
		}
	})
	return candidate, err
}

func decodeCandidateScore(payload []byte) (CandidateScore, error) {
	var score CandidateScore
	seen := map[uint64]struct{}{}
	err := rangeProtoFields(payload, func(field uint64, wire uint64, value []byte) error {
		switch field {
		case 1:
			return setBytes(seen, field, wire, value, &score.TrusteePublicKey)
		case 2:
			return setInt64(seen, field, wire, value, &score.Score)
		default:
			return unknownField(field)
		}
	})
	return score, err
}

func rangeProtoFields(payload []byte, fn func(field uint64, wire uint64, value []byte) error) error {
	var lastField uint64
	for len(payload) > 0 {
		key, n, err := consumeProtoVarint(payload)
		if err != nil {
			return err
		}
		payload = payload[n:]
		field := key >> 3
		wire := key & 0x7
		if field < lastField {
			return fmt.Errorf("field order: %w", ErrInvalidCanonicalPayload)
		}
		lastField = field
		var value []byte
		switch wire {
		case 0:
			_, n, err := consumeProtoVarint(payload)
			if err != nil {
				return err
			}
			value, payload = payload[:n], payload[n:]
		case 2:
			length, n, err := consumeProtoVarint(payload)
			if err != nil {
				return err
			}
			payload = payload[n:]
			if length > uint64(len(payload)) {
				return io.ErrUnexpectedEOF
			}
			value, payload = payload[:int(length)], payload[int(length):]
		default:
			return fmt.Errorf("wire type %d: %w", wire, ErrInvalidCanonicalPayload)
		}
		if err := fn(field, wire, value); err != nil {
			return err
		}
	}
	return nil
}

func setString(seen map[uint64]struct{}, field uint64, wire uint64, value []byte, target *string) error {
	if err := markScalar(seen, field, wire, 2); err != nil {
		return err
	}
	if len(value) == 0 {
		return fmt.Errorf("field %d has default string representation: %w", field, ErrInvalidCanonicalPayload)
	}
	*target = string(value)
	return nil
}

func appendString(wire uint64, value []byte, target *[]string) error {
	if wire != 2 {
		return fmt.Errorf("string field has wire type %d", wire)
	}
	if len(value) == 0 {
		return fmt.Errorf("repeated string has default representation: %w", ErrInvalidCanonicalPayload)
	}
	*target = append(*target, string(value))
	return nil
}

func appendBytes(wire uint64, value []byte, target *[][]byte) error {
	if wire != 2 {
		return fmt.Errorf("bytes field has wire type %d", wire)
	}
	if len(value) == 0 {
		return fmt.Errorf("repeated bytes has default representation: %w", ErrInvalidCanonicalPayload)
	}
	*target = append(*target, append([]byte(nil), value...))
	return nil
}

func setBytes(seen map[uint64]struct{}, field uint64, wire uint64, value []byte, target *[]byte) error {
	if err := markScalar(seen, field, wire, 2); err != nil {
		return err
	}
	if len(value) == 0 {
		return fmt.Errorf("field %d has default bytes representation: %w", field, ErrInvalidCanonicalPayload)
	}
	*target = append((*target)[:0], value...)
	return nil
}

func setInt64(seen map[uint64]struct{}, field uint64, wire uint64, value []byte, target *int64) error {
	if err := markScalar(seen, field, wire, 0); err != nil {
		return err
	}
	v, _, err := consumeProtoVarint(value)
	if err != nil {
		return err
	}
	if v == 0 {
		return fmt.Errorf("field %d has default int representation: %w", field, ErrInvalidCanonicalPayload)
	}
	*target = int64(v)
	return nil
}

func markScalar(seen map[uint64]struct{}, field uint64, wire uint64, wantWire uint64) error {
	if wire != wantWire {
		return fmt.Errorf("field %d has wire type %d", field, wire)
	}
	if _, ok := seen[field]; ok {
		return fmt.Errorf("duplicate scalar field %d", field)
	}
	seen[field] = struct{}{}
	return nil
}

func unknownField(field uint64) error {
	return fmt.Errorf("field %d: %w", field, ErrUnknownPayloadField)
}

func duplicateStrings(values []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		if value == "" {
			return true
		}
		if _, ok := seen[value]; ok {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func increasing(values ...int64) bool {
	if len(values) == 0 {
		return true
	}
	previous := values[0]
	if previous <= 0 {
		return false
	}
	for _, value := range values[1:] {
		if value <= previous {
			return false
		}
		previous = value
	}
	return true
}
