package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
)

// Domain identifies a cryptographic domain separator.
type Domain string

const (
	DomainObjectID                     Domain = "librevote-object-id-v1"
	DomainTrusteeNominationSign        Domain = "librevote-trustee-nomination-sign-v1"
	DomainTrusteeVoteSign              Domain = "librevote-trustee-vote-sign-v1"
	DomainTrusteeRank                  Domain = "librevote-trustee-rank-v1"
	DomainTrusteeSelectionResultHash   Domain = "librevote-trustee-selection-result-hash-v1"
	DomainTrusteeSelectionResultSign   Domain = "librevote-trustee-selection-result-sign-v1"
	DomainTrusteeSelectionElectionSign Domain = "librevote-trustee-selection-election-sign-v1"
	DomainTrusteeConsentSign           Domain = "librevote-trustee-consent-sign-v1"
	DomainTallyKeyContributionSign     Domain = "librevote-tally-key-contribution-sign-v1"
	DomainTallyKeySetSign              Domain = "librevote-tally-key-set-sign-v1"
	DomainPeerAdmissionPoW             Domain = "librevote-peer-admission-pow-v1"
	DomainObjectPoW                    Domain = "librevote-object-pow-v1"
	DomainSyncRequestPoW               Domain = "librevote-sync-request-pow-v1"
	DomainBlindTokenMessage            Domain = "librevote-blind-token-message-v1"
	DomainBlindTokenIssueEncryption    Domain = "librevote-blind-token-issue-encryption-v1"
	DomainTokenHolderSign              Domain = "librevote-token-holder-sign-v1"
	DomainTokenNullifier               Domain = "librevote-token-nullifier-v1"
	DomainChoiceEncryption             Domain = "librevote-choice-encryption-v1"
	DomainTallyShareProof              Domain = "librevote-tally-share-proof-v1"
	DomainElectionParameters           Domain = "librevote-election-parameters-v1"
	DomainDKGShareEncryption           Domain = "librevote-dkg-share-encryption-v1"
	DomainTallyKeySetHash              Domain = "librevote-tally-key-set-hash-v1"
	DomainKeyEncryption                Domain = "librevote-key-encryption-v1"
	DomainKeyID                        Domain = "librevote-key-id-v1"
)

// Digest is a SHA-256 digest.
type Digest [sha256.Size]byte

// Bytes returns a copy of the digest bytes.
func (d Digest) Bytes() []byte {
	out := make([]byte, len(d))
	copy(out, d[:])
	return out
}

// String returns the lowercase hexadecimal digest encoding.
func (d Digest) String() string {
	return hex.EncodeToString(d[:])
}

// Hash computes SHA-256 over the domain separator and length-delimited parts.
func Hash(domain Domain, parts ...[]byte) Digest {
	h := sha256.New()
	write(h, []byte(domain))

	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		write(h, length[:])
		write(h, part)
	}

	var digest Digest
	h.Sum(digest[:0])
	return digest
}

func write(h hash.Hash, b []byte) {
	_, _ = h.Write(b)
}
