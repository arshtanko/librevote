package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	secretSaltSize = 16
	secretKeySize  = chacha20poly1305.KeySize

	minSecretMemory      uint32 = 16 * 1024
	maxSecretMemory      uint32 = 256 * 1024
	minSecretIterations  uint32 = 2
	maxSecretIterations  uint32 = 10
	minSecretParallelism uint8  = 1
	maxSecretParallelism uint8  = 8
)

var (
	ErrEmptyPassphrase       = errors.New("empty passphrase")
	ErrEmptyPlaintext        = errors.New("empty plaintext")
	ErrMalformedKeyID        = errors.New("malformed key id")
	ErrMalformedSecretParams = errors.New("malformed secret encryption params")
	ErrMalformedSecret       = errors.New("malformed encrypted secret")
)

// SecretEncryptionParams are Argon2id key-encryption-key parameters.
type SecretEncryptionParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
}

// SecretEncryptionMetadata is stored with an encrypted local secret.
type SecretEncryptionMetadata struct {
	Salt        []byte
	Nonce       []byte
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
}

// EncryptedSecret contains ciphertext and the metadata required to decrypt it.
type EncryptedSecret struct {
	Ciphertext []byte
	Metadata   SecretEncryptionMetadata
}

// DefaultSecretEncryptionParams returns the v1 local key encryption defaults.
func DefaultSecretEncryptionParams() SecretEncryptionParams {
	return SecretEncryptionParams{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 4,
	}
}

// EncryptSecret encrypts a local secret for encrypted-at-rest storage.
func EncryptSecret(passphrase string, keyID Digest, keyType KeyType, publicKey, plaintext []byte, params SecretEncryptionParams) (EncryptedSecret, error) {
	if err := validateSecretInputs(passphrase, keyID, keyType, publicKey); err != nil {
		return EncryptedSecret{}, err
	}
	if len(plaintext) == 0 {
		return EncryptedSecret{}, ErrEmptyPlaintext
	}
	if err := validateSecretParams(params); err != nil {
		return EncryptedSecret{}, err
	}

	salt := make([]byte, secretSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return EncryptedSecret{}, fmt.Errorf("generate secret encryption salt: %w", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedSecret{}, fmt.Errorf("generate secret encryption nonce: %w", err)
	}

	key := deriveSecretKey(passphrase, salt, params)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return EncryptedSecret{}, fmt.Errorf("create secret encryption cipher: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, secretAAD(keyID, keyType, publicKey))
	return EncryptedSecret{
		Ciphertext: ciphertext,
		Metadata: SecretEncryptionMetadata{
			Salt:        append([]byte(nil), salt...),
			Nonce:       append([]byte(nil), nonce...),
			Memory:      params.Memory,
			Iterations:  params.Iterations,
			Parallelism: params.Parallelism,
		},
	}, nil
}

// DecryptSecret decrypts a local encrypted-at-rest secret.
func DecryptSecret(passphrase string, keyID Digest, keyType KeyType, publicKey []byte, secret EncryptedSecret) ([]byte, error) {
	if err := validateSecretInputs(passphrase, keyID, keyType, publicKey); err != nil {
		return nil, err
	}
	if len(secret.Ciphertext) == 0 {
		return nil, ErrMalformedSecret
	}
	params := SecretEncryptionParams{
		Memory:      secret.Metadata.Memory,
		Iterations:  secret.Metadata.Iterations,
		Parallelism: secret.Metadata.Parallelism,
	}
	if err := validateSecretParams(params); err != nil {
		return nil, err
	}
	if len(secret.Metadata.Salt) != secretSaltSize || len(secret.Metadata.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, ErrMalformedSecret
	}

	salt := append([]byte(nil), secret.Metadata.Salt...)
	nonce := append([]byte(nil), secret.Metadata.Nonce...)
	ciphertext := append([]byte(nil), secret.Ciphertext...)

	key := deriveSecretKey(passphrase, salt, params)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create secret encryption cipher: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, secretAAD(keyID, keyType, publicKey))
	if err != nil {
		return nil, ErrMalformedSecret
	}
	return plaintext, nil
}

func validateSecretInputs(passphrase string, keyID Digest, keyType KeyType, publicKey []byte) error {
	if passphrase == "" {
		return ErrEmptyPassphrase
	}
	if zeroDigest(keyID) {
		return ErrMalformedKeyID
	}
	if !KnownKeyType(keyType) {
		return ErrUnknownKeyType
	}
	if len(publicKey) == 0 {
		return ErrEmptyPublicKey
	}
	expectedKeyID, err := KeyID(keyType, publicKey)
	if err != nil {
		return err
	}
	if keyID != expectedKeyID {
		return ErrMalformedKeyID
	}
	return nil
}

func validateSecretParams(params SecretEncryptionParams) error {
	if params.Memory < minSecretMemory || params.Memory > maxSecretMemory ||
		params.Iterations < minSecretIterations || params.Iterations > maxSecretIterations ||
		params.Parallelism < minSecretParallelism || params.Parallelism > maxSecretParallelism {
		return ErrMalformedSecretParams
	}
	return nil
}

func deriveSecretKey(passphrase string, salt []byte, params SecretEncryptionParams) []byte {
	return argon2.IDKey([]byte(passphrase), salt, params.Iterations, params.Memory, params.Parallelism, secretKeySize)
}

func secretAAD(keyID Digest, keyType KeyType, publicKey []byte) []byte {
	aad := make([]byte, 0, len(DomainKeyEncryption)+len(keyID)+len(keyType)+len(publicKey))
	aad = append(aad, []byte(DomainKeyEncryption)...)
	aad = append(aad, keyID[:]...)
	aad = append(aad, []byte(keyType)...)
	aad = append(aad, publicKey...)
	return aad
}

func zeroDigest(digest Digest) bool {
	return digest == Digest{}
}
