package crypto

import (
	"crypto/sha256"
	"errors"
)

var ErrEmptyCanonicalObject = errors.New("empty canonical object bytes")

// ObjectID derives the content-addressed id for canonical object bytes.
func ObjectID(canonicalObjectBytes []byte) (Digest, error) {
	if len(canonicalObjectBytes) == 0 {
		return Digest{}, ErrEmptyCanonicalObject
	}

	h := sha256.New()
	write(h, []byte(DomainObjectID))
	write(h, canonicalObjectBytes)

	var digest Digest
	h.Sum(digest[:0])
	return digest, nil
}
