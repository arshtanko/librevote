package crypto

import (
	"crypto/sha256"
	"errors"
)

// KeyType identifies the role and cryptographic scheme of a key.
type KeyType string

const (
	KeyTypeNode              KeyType = "node"
	KeyTypeVoterSigning      KeyType = "voter_signing"
	KeyTypeVoterEncryption   KeyType = "voter_encryption"
	KeyTypeTrusteeSigning    KeyType = "trustee_signing"
	KeyTypeTrusteeBlindToken KeyType = "trustee_blind_token"
	KeyTypeTrusteeTallySetup KeyType = "trustee_tally_setup"
	KeyTypeTrusteeTallyShare KeyType = "trustee_tally_share"
	KeyTypeAnonymousToken    KeyType = "anonymous_token"
)

var (
	ErrUnknownKeyType = errors.New("unknown key type")
	ErrEmptyPublicKey = errors.New("empty public key")
)

// KnownKeyType reports whether keyType is a documented LibreVote v1 key type.
func KnownKeyType(keyType KeyType) bool {
	switch keyType {
	case KeyTypeNode,
		KeyTypeVoterSigning,
		KeyTypeVoterEncryption,
		KeyTypeTrusteeSigning,
		KeyTypeTrusteeBlindToken,
		KeyTypeTrusteeTallySetup,
		KeyTypeTrusteeTallyShare,
		KeyTypeAnonymousToken:
		return true
	default:
		return false
	}
}

// KeyID derives the stable key id for a canonical public key.
func KeyID(keyType KeyType, canonicalPublicKey []byte) (Digest, error) {
	if !KnownKeyType(keyType) {
		return Digest{}, ErrUnknownKeyType
	}
	if len(canonicalPublicKey) == 0 {
		return Digest{}, ErrEmptyPublicKey
	}

	h := sha256.New()
	write(h, []byte(DomainKeyID))
	write(h, []byte(keyType))
	write(h, canonicalPublicKey)

	var digest Digest
	h.Sum(digest[:0])
	return digest, nil
}
