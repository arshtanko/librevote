package crypto

import (
	"crypto/sha256"
	"errors"
)

var (
	ErrUnknownPoWDomain = errors.New("unknown pow domain")
	ErrEmptyPoWNonce    = errors.New("empty pow nonce")
)

// PoWProof carries a proof-of-work difficulty and nonce.
type PoWProof struct {
	Difficulty uint8
	Nonce      []byte
}

// ValidatePoW verifies the documented LibreVote v1 proof-of-work construction.
func ValidatePoW(domain Domain, targetHash Digest, difficulty uint8, nonce []byte) (bool, error) {
	if !KnownPoWDomain(domain) {
		return false, ErrUnknownPoWDomain
	}
	if len(nonce) == 0 {
		return false, ErrEmptyPoWNonce
	}
	if difficulty == 0 {
		return true, nil
	}

	digest := PoWHash(domain, targetHash, difficulty, nonce)
	return leadingZeroBits(digest[:]) >= int(difficulty), nil
}

// PoWHash computes SHA256(domain_separator || target_hash || difficulty || nonce).
func PoWHash(domain Domain, targetHash Digest, difficulty uint8, nonce []byte) Digest {
	h := sha256.New()
	write(h, []byte(domain))
	write(h, targetHash[:])
	write(h, []byte{difficulty})
	write(h, nonce)

	var digest Digest
	h.Sum(digest[:0])
	return digest
}

// KnownPoWDomain reports whether domain is one of the documented PoW domains.
func KnownPoWDomain(domain Domain) bool {
	switch domain {
	case DomainPeerAdmissionPoW, DomainObjectPoW, DomainSyncRequestPoW:
		return true
	default:
		return false
	}
}

func leadingZeroBits(b []byte) int {
	bits := 0
	for _, v := range b {
		if v == 0 {
			bits += 8
			continue
		}
		for mask := byte(0x80); mask != 0; mask >>= 1 {
			if v&mask != 0 {
				return bits
			}
			bits++
		}
	}
	return bits
}
