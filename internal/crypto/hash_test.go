package crypto

import (
	"encoding/hex"
	"testing"
)

func TestHashDeterministic(t *testing.T) {
	got := Hash(DomainObjectID, []byte("payload"), []byte("signature"))
	want := Hash(DomainObjectID, []byte("payload"), []byte("signature"))

	if got != want {
		t.Fatalf("Hash() = %s; want %s", got, want)
	}
}

func TestHashDomainSeparation(t *testing.T) {
	objectID := Hash(DomainObjectID, []byte("same input"))
	objectPoW := Hash(DomainObjectPoW, []byte("same input"))

	if objectID == objectPoW {
		t.Fatalf("Hash() returned same digest for different domains: %s", objectID)
	}
}

func TestHashPartBoundariesMatter(t *testing.T) {
	abc := Hash(DomainObjectID, []byte("ab"), []byte("c"))
	aBC := Hash(DomainObjectID, []byte("a"), []byte("bc"))

	if abc == aBC {
		t.Fatalf("Hash() ignored part boundaries: %s", abc)
	}
}

func TestHashPartOrderMatters(t *testing.T) {
	ab := Hash(DomainObjectID, []byte("a"), []byte("b"))
	ba := Hash(DomainObjectID, []byte("b"), []byte("a"))

	if ab == ba {
		t.Fatalf("Hash() ignored part order: %s", ab)
	}
}

func TestDigestBytesReturnsCopy(t *testing.T) {
	digest := Hash(DomainObjectID, []byte("payload"))
	bytes := digest.Bytes()
	bytes[0] ^= 0xff

	if bytes[0] == digest.Bytes()[0] {
		t.Fatalf("Bytes() returned mutable digest storage")
	}
}

func TestDigestStringLowercaseHex(t *testing.T) {
	digest := Hash(DomainObjectID, []byte("payload"))
	got := digest.String()

	if len(got) != 64 {
		t.Fatalf("String() length = %d; want 64", len(got))
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("String() is not valid hex: %v", err)
	}
	for _, r := range got {
		if r >= 'A' && r <= 'F' {
			t.Fatalf("String() contains uppercase hex: %q", got)
		}
	}
}

func TestDomainSeparatorValues(t *testing.T) {
	tests := []struct {
		name   string
		domain Domain
		want   string
	}{
		{name: "object id", domain: DomainObjectID, want: "librevote-object-id-v1"},
		{name: "trustee nomination sign", domain: DomainTrusteeNominationSign, want: "librevote-trustee-nomination-sign-v1"},
		{name: "trustee vote sign", domain: DomainTrusteeVoteSign, want: "librevote-trustee-vote-sign-v1"},
		{name: "trustee consent sign", domain: DomainTrusteeConsentSign, want: "librevote-trustee-consent-sign-v1"},
		{name: "tally key contribution sign", domain: DomainTallyKeyContributionSign, want: "librevote-tally-key-contribution-sign-v1"},
		{name: "tally key set sign", domain: DomainTallyKeySetSign, want: "librevote-tally-key-set-sign-v1"},
		{name: "peer admission pow", domain: DomainPeerAdmissionPoW, want: "librevote-peer-admission-pow-v1"},
		{name: "object pow", domain: DomainObjectPoW, want: "librevote-object-pow-v1"},
		{name: "sync request pow", domain: DomainSyncRequestPoW, want: "librevote-sync-request-pow-v1"},
		{name: "blind token message", domain: DomainBlindTokenMessage, want: "librevote-blind-token-message-v1"},
		{name: "blind token issue encryption", domain: DomainBlindTokenIssueEncryption, want: "librevote-blind-token-issue-encryption-v1"},
		{name: "token holder sign", domain: DomainTokenHolderSign, want: "librevote-token-holder-sign-v1"},
		{name: "token nullifier", domain: DomainTokenNullifier, want: "librevote-token-nullifier-v1"},
		{name: "choice encryption", domain: DomainChoiceEncryption, want: "librevote-choice-encryption-v1"},
		{name: "tally share proof", domain: DomainTallyShareProof, want: "librevote-tally-share-proof-v1"},
		{name: "election parameters", domain: DomainElectionParameters, want: "librevote-election-parameters-v1"},
		{name: "dkg share encryption", domain: DomainDKGShareEncryption, want: "librevote-dkg-share-encryption-v1"},
		{name: "tally key set hash", domain: DomainTallyKeySetHash, want: "librevote-tally-key-set-hash-v1"},
		{name: "key encryption", domain: DomainKeyEncryption, want: "librevote-key-encryption-v1"},
		{name: "key id", domain: DomainKeyID, want: "librevote-key-id-v1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.domain); got != tt.want {
				t.Fatalf("domain = %q; want %q", got, tt.want)
			}
		})
	}
}
