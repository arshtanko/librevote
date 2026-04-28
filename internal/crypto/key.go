package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
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
	ErrUnknownKeyType           = errors.New("unknown key type")
	ErrEmptyPublicKey           = errors.New("empty public key")
	ErrUnsupportedKeyType       = errors.New("key generation unsupported for key type")
	ErrInvalidKeyMaterial       = errors.New("invalid key material")
	ErrKeyIDMismatch            = errors.New("key id mismatch")
	ErrPublicPrivateKeyMismatch = errors.New("public key does not match private key")
)

// KeyScheme identifies the cryptographic scheme associated with a key role.
type KeyScheme string

const (
	KeySchemeLibP2PNode                     KeyScheme = "libp2p_node"
	KeySchemeEd25519                        KeyScheme = "ed25519"
	KeySchemeX25519                         KeyScheme = "x25519"
	KeySchemeRistretto255BlindSchnorr       KeyScheme = "ristretto255_blind_schnorr"
	KeySchemeRistretto255DKGEncryption      KeyScheme = "ristretto255_dkg_encryption"
	KeySchemeRistretto255ThresholdShare     KeyScheme = "ristretto255_threshold_elgamal_share"
	KeySchemeRistretto255TokenHolderSchnorr KeyScheme = "ristretto255_token_holder_schnorr"
)

// KeyMetadata describes the documented role, scheme and currently supported operations for a key type.
type KeyMetadata struct {
	Type                  KeyType
	Role                  string
	Scheme                KeyScheme
	Purpose               string
	PublicKeySize         int
	PrivateKeySize        int
	CanGenerate           bool
	CanDomainSign         bool
	CanVoterDecrypt       bool
	TransportOnly         bool
	PendingImplementation bool
}

// LocalKeyMaterial contains plaintext key bytes inside the crypto package boundary.
// Callers must persist private bytes only through encrypted-at-rest key store APIs.
type LocalKeyMaterial struct {
	keyID      Digest
	keyType    KeyType
	publicKey  []byte
	privateKey []byte
}

// NewLocalKeyMaterial builds local key material from byte slices and defensively copies them.
func NewLocalKeyMaterial(keyID Digest, keyType KeyType, publicKey, privateKey []byte) LocalKeyMaterial {
	return LocalKeyMaterial{
		keyID:      keyID,
		keyType:    keyType,
		publicKey:  cloneBytes(publicKey),
		privateKey: cloneBytes(privateKey),
	}
}

// KeyID returns the derived key id.
func (m LocalKeyMaterial) KeyID() Digest { return m.keyID }

// KeyType returns the documented key role.
func (m LocalKeyMaterial) KeyType() KeyType { return m.keyType }

// PublicKey returns a defensive copy of the public key bytes.
func (m LocalKeyMaterial) PublicKey() []byte { return cloneBytes(m.publicKey) }

// PrivateKey returns a defensive copy of the private key bytes.
func (m LocalKeyMaterial) PrivateKey() []byte { return cloneBytes(m.privateKey) }

// DocumentedKeyTypes returns all LibreVote v1 key types in documentation order.
func DocumentedKeyTypes() []KeyType {
	return []KeyType{
		KeyTypeNode,
		KeyTypeVoterSigning,
		KeyTypeVoterEncryption,
		KeyTypeTrusteeSigning,
		KeyTypeTrusteeBlindToken,
		KeyTypeTrusteeTallySetup,
		KeyTypeTrusteeTallyShare,
		KeyTypeAnonymousToken,
	}
}

// KeyTypeMetadata returns the documented metadata for keyType.
func KeyTypeMetadata(keyType KeyType) (KeyMetadata, error) {
	switch keyType {
	case KeyTypeNode:
		return KeyMetadata{Type: keyType, Role: "node key", Scheme: KeySchemeLibP2PNode, Purpose: "libp2p transport identity", TransportOnly: true, PendingImplementation: true}, nil
	case KeyTypeVoterSigning:
		return KeyMetadata{Type: keyType, Role: "voter signing key", Scheme: KeySchemeEd25519, Purpose: "TrusteeVote and BlindTokenRequest signatures", PublicKeySize: ed25519.PublicKeySize, PrivateKeySize: ed25519.PrivateKeySize, CanGenerate: true, CanDomainSign: true}, nil
	case KeyTypeVoterEncryption:
		return KeyMetadata{Type: keyType, Role: "voter encryption key", Scheme: KeySchemeX25519, Purpose: "BlindTokenIssue payload decryption", PublicKeySize: curve25519.PointSize, PrivateKeySize: curve25519.ScalarSize, CanGenerate: true, CanVoterDecrypt: true}, nil
	case KeyTypeTrusteeSigning:
		return KeyMetadata{Type: keyType, Role: "trustee signing key", Scheme: KeySchemeEd25519, Purpose: "trustee domain object signatures", PublicKeySize: ed25519.PublicKeySize, PrivateKeySize: ed25519.PrivateKeySize, CanGenerate: true, CanDomainSign: true}, nil
	case KeyTypeTrusteeBlindToken:
		return KeyMetadata{Type: keyType, Role: "trustee blind-token key", Scheme: KeySchemeRistretto255BlindSchnorr, Purpose: "blind_token_v1 issuance", PendingImplementation: true}, nil
	case KeyTypeTrusteeTallySetup:
		return KeyMetadata{Type: keyType, Role: "trustee tally setup key", Scheme: KeySchemeRistretto255DKGEncryption, Purpose: "verifiable encrypted DKG shares", PendingImplementation: true}, nil
	case KeyTypeTrusteeTallyShare:
		return KeyMetadata{Type: keyType, Role: "trustee tally share key", Scheme: KeySchemeRistretto255ThresholdShare, Purpose: "threshold tally decryption shares", PendingImplementation: true}, nil
	case KeyTypeAnonymousToken:
		return KeyMetadata{Type: keyType, Role: "anonymous token key", Scheme: KeySchemeRistretto255TokenHolderSchnorr, Purpose: "anonymous ballot token holder signatures", PendingImplementation: true}, nil
	default:
		return KeyMetadata{}, ErrUnknownKeyType
	}
}

// KnownKeyType reports whether keyType is a documented LibreVote v1 key type.
func KnownKeyType(keyType KeyType) bool {
	_, err := KeyTypeMetadata(keyType)
	return err == nil
}

// CanGenerateLocalKey reports whether keyType has implemented local generation.
func CanGenerateLocalKey(keyType KeyType) bool {
	metadata, err := KeyTypeMetadata(keyType)
	return err == nil && metadata.CanGenerate
}

// CanPublicDomainSignEd25519 reports whether keyType may sign public domain objects with Ed25519.
func CanPublicDomainSignEd25519(keyType KeyType) bool {
	metadata, err := KeyTypeMetadata(keyType)
	return err == nil && metadata.CanDomainSign && metadata.Scheme == KeySchemeEd25519
}

// CanVoterEncryptionDecrypt reports whether keyType is the voter X25519 decryption role.
func CanVoterEncryptionDecrypt(keyType KeyType) bool {
	metadata, err := KeyTypeMetadata(keyType)
	return err == nil && metadata.CanVoterDecrypt && metadata.Scheme == KeySchemeX25519
}

// PendingKeyImplementation reports whether keyType is documented but its scheme is not implemented yet.
func PendingKeyImplementation(keyType KeyType) bool {
	metadata, err := KeyTypeMetadata(keyType)
	return err == nil && metadata.PendingImplementation
}

// GenerateLocalKey generates plaintext local key material for implemented schemes only.
func GenerateLocalKey(keyType KeyType) (LocalKeyMaterial, error) {
	metadata, err := KeyTypeMetadata(keyType)
	if err != nil {
		return LocalKeyMaterial{}, err
	}
	if !metadata.CanGenerate {
		return LocalKeyMaterial{}, fmt.Errorf("%s: %w", keyType, ErrUnsupportedKeyType)
	}

	switch metadata.Scheme {
	case KeySchemeEd25519:
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return LocalKeyMaterial{}, err
		}
		return newValidatedLocalKeyMaterial(keyType, publicKey, privateKey)
	case KeySchemeX25519:
		privateKey := make([]byte, curve25519.ScalarSize)
		if _, err := rand.Read(privateKey); err != nil {
			return LocalKeyMaterial{}, err
		}
		publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return LocalKeyMaterial{}, err
		}
		return newValidatedLocalKeyMaterial(keyType, publicKey, privateKey)
	default:
		return LocalKeyMaterial{}, fmt.Errorf("%s: %w", keyType, ErrUnsupportedKeyType)
	}
}

// ValidateLocalKeyMaterial checks key type, key id, sizes and public/private consistency.
func ValidateLocalKeyMaterial(material LocalKeyMaterial) error {
	metadata, err := KeyTypeMetadata(material.keyType)
	if err != nil {
		return err
	}
	if !metadata.CanGenerate {
		return fmt.Errorf("%s: %w", material.keyType, ErrUnsupportedKeyType)
	}
	if len(material.publicKey) != metadata.PublicKeySize {
		return fmt.Errorf("public key size %d for %s: %w", len(material.publicKey), material.keyType, ErrInvalidKeyMaterial)
	}
	if len(material.privateKey) != metadata.PrivateKeySize {
		return fmt.Errorf("private key size %d for %s: %w", len(material.privateKey), material.keyType, ErrInvalidKeyMaterial)
	}

	keyID, err := KeyID(material.keyType, material.publicKey)
	if err != nil {
		return err
	}
	if keyID != material.keyID {
		return ErrKeyIDMismatch
	}

	switch metadata.Scheme {
	case KeySchemeEd25519:
		privateKey := ed25519.PrivateKey(material.privateKey)
		publicKey := ed25519.NewKeyFromSeed(privateKey.Seed()).Public().(ed25519.PublicKey)
		if !bytes.Equal(privateKey[ed25519.SeedSize:], publicKey) || !bytes.Equal(material.publicKey, publicKey) {
			return ErrPublicPrivateKeyMismatch
		}
	case KeySchemeX25519:
		publicKey, err := curve25519.X25519(material.privateKey, curve25519.Basepoint)
		if err != nil {
			return err
		}
		if !bytes.Equal(material.publicKey, publicKey) {
			return ErrPublicPrivateKeyMismatch
		}
	default:
		return fmt.Errorf("%s: %w", material.keyType, ErrUnsupportedKeyType)
	}

	return nil
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

func newValidatedLocalKeyMaterial(keyType KeyType, publicKey, privateKey []byte) (LocalKeyMaterial, error) {
	keyID, err := KeyID(keyType, publicKey)
	if err != nil {
		return LocalKeyMaterial{}, err
	}
	material := NewLocalKeyMaterial(keyID, keyType, publicKey, privateKey)
	if err := ValidateLocalKeyMaterial(material); err != nil {
		return LocalKeyMaterial{}, err
	}
	return material, nil
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
