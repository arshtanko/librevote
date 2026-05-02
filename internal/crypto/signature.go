package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"librevote/internal/domain"
)

var (
	ErrUnknownSigningDomain = errors.New("unknown Ed25519 signing domain")
	ErrEmptySigningField    = errors.New("empty signing context field")
	ErrInvalidCreatedAt     = errors.New("created_at must be greater than zero")
	ErrEmptySigningPayload  = errors.New("empty canonical signing payload")
	ErrInvalidPrivateKey    = errors.New("invalid Ed25519 private key")
)

// SigningContext identifies the canonical object fields bound into an Ed25519 signature.
type SigningContext struct {
	Domain          Domain
	ProtocolVersion string
	NetworkID       string
	ObjectType      domain.ObjectType
	Scope           domain.Scope
	ScopeID         string
	CreatedAt       int64
}

// SigningDigest hashes the implementation signing context format for public domain objects.
// Context fields and the canonical payload without signature are length-delimited by Hash.
func SigningDigest(ctx SigningContext, canonicalPayloadWithoutSignature []byte) (Digest, error) {
	if !KnownEd25519SigningDomain(ctx.Domain) {
		return Digest{}, ErrUnknownSigningDomain
	}
	if ctx.ProtocolVersion == "" {
		return Digest{}, fmt.Errorf("protocol_version: %w", ErrEmptySigningField)
	}
	if ctx.NetworkID == "" {
		return Digest{}, fmt.Errorf("network_id: %w", ErrEmptySigningField)
	}
	if ctx.ObjectType == "" {
		return Digest{}, fmt.Errorf("object_type: %w", ErrEmptySigningField)
	}
	if ctx.Scope == "" {
		return Digest{}, fmt.Errorf("scope: %w", ErrEmptySigningField)
	}
	switch ctx.Scope {
	case domain.ScopeNetwork:
		if ctx.ScopeID != "" {
			return Digest{}, fmt.Errorf("scope_id: scope %q requires empty scope_id", ctx.Scope)
		}
	case domain.ScopeElectionID, domain.ScopeTrusteeSelectionID:
		if domain.ScopeIDRequired(ctx.Scope) && ctx.ScopeID == "" {
			return Digest{}, fmt.Errorf("scope_id: %w", ErrEmptySigningField)
		}
	default:
		return Digest{}, fmt.Errorf("scope: unknown scope %q", ctx.Scope)
	}
	if ctx.CreatedAt <= 0 {
		return Digest{}, ErrInvalidCreatedAt
	}
	if len(canonicalPayloadWithoutSignature) == 0 {
		return Digest{}, ErrEmptySigningPayload
	}

	var createdAt [8]byte
	binary.BigEndian.PutUint64(createdAt[:], uint64(ctx.CreatedAt))

	return Hash(
		ctx.Domain,
		[]byte(ctx.ProtocolVersion),
		[]byte(ctx.NetworkID),
		[]byte(ctx.ObjectType),
		[]byte(ctx.Scope),
		[]byte(ctx.ScopeID),
		createdAt[:],
		canonicalPayloadWithoutSignature,
	), nil
}

// KnownEd25519SigningDomain reports whether domain is a documented Ed25519 signing domain.
func KnownEd25519SigningDomain(domain Domain) bool {
	switch domain {
	case DomainTrusteeNominationSign,
		DomainTrusteeVoteSign,
		DomainTrusteeSelectionElectionSign,
		DomainAnonymousElectionSign,
		DomainTrusteeConsentSign,
		DomainTallyKeyContributionSign,
		DomainTallyKeySetSign,
		DomainAnonymousBallotSign,
		DomainTallyResultSign,
		DomainElectionParameters:
		return true
	default:
		return false
	}
}

// SignEd25519 signs an already framed and hashed signing digest.
func SignEd25519(privateKey ed25519.PrivateKey, digest Digest) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	publicKey := ed25519.NewKeyFromSeed(privateKey.Seed()).Public().(ed25519.PublicKey)
	if !bytes.Equal(privateKey[ed25519.SeedSize:], publicKey) {
		return nil, ErrInvalidPrivateKey
	}

	return ed25519.Sign(privateKey, digest[:]), nil
}

// VerifyEd25519 verifies a signature over an already framed and hashed signing digest.
func VerifyEd25519(publicKey ed25519.PublicKey, digest Digest, sig []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}

	return ed25519.Verify(publicKey, digest[:], sig)
}
