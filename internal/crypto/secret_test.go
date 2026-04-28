package crypto

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestEncryptDecryptSecretRoundTrip(t *testing.T) {
	publicKey := []byte("canonical-public-key")
	keyID := testKeyID(t, KeyTypeVoterSigning, publicKey)
	plaintext := []byte("private-key-bytes")

	secret, err := EncryptSecret("passphrase", keyID, KeyTypeVoterSigning, publicKey, plaintext, testSecretParams())
	if err != nil {
		t.Fatalf("EncryptSecret() error = %v", err)
	}

	got, err := DecryptSecret("passphrase", keyID, KeyTypeVoterSigning, publicKey, secret)
	if err != nil {
		t.Fatalf("DecryptSecret() error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("DecryptSecret() = %q; want %q", got, plaintext)
	}
}

func TestEncryptSecretUsesRandomSaltAndNonce(t *testing.T) {
	publicKey := []byte("canonical-public-key")
	keyID := testKeyID(t, KeyTypeVoterSigning, publicKey)
	plaintext := []byte("private-key-bytes")
	params := testSecretParams()

	first, err := EncryptSecret("passphrase", keyID, KeyTypeVoterSigning, publicKey, plaintext, params)
	if err != nil {
		t.Fatalf("EncryptSecret() first error = %v", err)
	}
	second, err := EncryptSecret("passphrase", keyID, KeyTypeVoterSigning, publicKey, plaintext, params)
	if err != nil {
		t.Fatalf("EncryptSecret() second error = %v", err)
	}

	if bytes.Equal(first.Metadata.Salt, second.Metadata.Salt) {
		t.Fatalf("salt was reused: %x", first.Metadata.Salt)
	}
	if bytes.Equal(first.Metadata.Nonce, second.Metadata.Nonce) {
		t.Fatalf("nonce was reused: %x", first.Metadata.Nonce)
	}
	if bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Fatalf("ciphertext matched despite random salt and nonce")
	}
}

func TestEncryptSecretStoresMetadata(t *testing.T) {
	publicKey := []byte("canonical-public-key")
	keyID := testKeyID(t, KeyTypeVoterSigning, publicKey)
	params := testSecretParams()

	secret, err := EncryptSecret("passphrase", keyID, KeyTypeVoterSigning, publicKey, []byte("private-key-bytes"), params)
	if err != nil {
		t.Fatalf("EncryptSecret() error = %v", err)
	}

	if len(secret.Metadata.Salt) != secretSaltSize {
		t.Fatalf("salt length = %d; want %d", len(secret.Metadata.Salt), secretSaltSize)
	}
	if len(secret.Metadata.Nonce) != chacha20poly1305.NonceSizeX {
		t.Fatalf("nonce length = %d; want %d", len(secret.Metadata.Nonce), chacha20poly1305.NonceSizeX)
	}
	if secret.Metadata.Memory != params.Memory || secret.Metadata.Iterations != params.Iterations || secret.Metadata.Parallelism != params.Parallelism {
		t.Fatalf("metadata params = %+v; want %+v", secret.Metadata, params)
	}
}

func TestDecryptSecretRejectsWrongPassphraseAADAndTampering(t *testing.T) {
	publicKey := []byte("canonical-public-key")
	keyID := testKeyID(t, KeyTypeVoterSigning, publicKey)
	secret, err := EncryptSecret("passphrase", keyID, KeyTypeVoterSigning, publicKey, []byte("private-key-bytes"), testSecretParams())
	if err != nil {
		t.Fatalf("EncryptSecret() error = %v", err)
	}

	wrongKeyID := testKeyID(t, KeyTypeVoterSigning, []byte("other-public-key"))
	tests := []struct {
		name       string
		passphrase string
		keyID      Digest
		keyType    KeyType
		publicKey  []byte
		secret     EncryptedSecret
	}{
		{name: "wrong passphrase", passphrase: "wrong", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, secret: secret},
		{name: "wrong key id", passphrase: "passphrase", keyID: wrongKeyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, secret: secret},
		{name: "wrong key type", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterEncryption, publicKey: publicKey, secret: secret},
		{name: "wrong public key", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: []byte("other-public-key"), secret: secret},
		{name: "tampered ciphertext", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, secret: tamperCiphertext(secret)},
		{name: "tampered salt", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, secret: tamperSalt(secret)},
		{name: "tampered nonce", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, secret: tamperNonce(secret)},
		{name: "tampered params", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, secret: tamperParams(secret)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptSecret(tt.passphrase, tt.keyID, tt.keyType, tt.publicKey, tt.secret)
			if err == nil {
				t.Fatalf("DecryptSecret() error = nil; want failure")
			}
		})
	}
}

func TestEncryptSecretValidationFailures(t *testing.T) {
	publicKey := []byte("canonical-public-key")
	keyID := testKeyID(t, KeyTypeVoterSigning, publicKey)
	params := testSecretParams()

	tests := []struct {
		name       string
		passphrase string
		keyID      Digest
		keyType    KeyType
		publicKey  []byte
		plaintext  []byte
		params     SecretEncryptionParams
		wantErr    error
	}{
		{name: "empty passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, plaintext: []byte("secret"), params: params, wantErr: ErrEmptyPassphrase},
		{name: "malformed key id", passphrase: "passphrase", keyType: KeyTypeVoterSigning, publicKey: publicKey, plaintext: []byte("secret"), params: params, wantErr: ErrMalformedKeyID},
		{name: "mismatched key id", passphrase: "passphrase", keyID: testKeyID(t, KeyTypeVoterSigning, []byte("other-public-key")), keyType: KeyTypeVoterSigning, publicKey: publicKey, plaintext: []byte("secret"), params: params, wantErr: ErrMalformedKeyID},
		{name: "unknown key type", passphrase: "passphrase", keyID: keyID, keyType: KeyType("unknown"), publicKey: publicKey, plaintext: []byte("secret"), params: params, wantErr: ErrUnknownKeyType},
		{name: "empty public key", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, plaintext: []byte("secret"), params: params, wantErr: ErrEmptyPublicKey},
		{name: "empty plaintext", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, params: params, wantErr: ErrEmptyPlaintext},
		{name: "weak memory", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, plaintext: []byte("secret"), params: SecretEncryptionParams{Memory: minSecretMemory - 1, Iterations: minSecretIterations, Parallelism: minSecretParallelism}, wantErr: ErrMalformedSecretParams},
		{name: "excessive memory", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, plaintext: []byte("secret"), params: SecretEncryptionParams{Memory: maxSecretMemory + 1, Iterations: minSecretIterations, Parallelism: minSecretParallelism}, wantErr: ErrMalformedSecretParams},
		{name: "weak iterations", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, plaintext: []byte("secret"), params: SecretEncryptionParams{Memory: minSecretMemory, Iterations: minSecretIterations - 1, Parallelism: minSecretParallelism}, wantErr: ErrMalformedSecretParams},
		{name: "excessive iterations", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, plaintext: []byte("secret"), params: SecretEncryptionParams{Memory: minSecretMemory, Iterations: maxSecretIterations + 1, Parallelism: minSecretParallelism}, wantErr: ErrMalformedSecretParams},
		{name: "zero parallelism", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, plaintext: []byte("secret"), params: SecretEncryptionParams{Memory: minSecretMemory, Iterations: minSecretIterations}, wantErr: ErrMalformedSecretParams},
		{name: "excessive parallelism", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, plaintext: []byte("secret"), params: SecretEncryptionParams{Memory: minSecretMemory, Iterations: minSecretIterations, Parallelism: maxSecretParallelism + 1}, wantErr: ErrMalformedSecretParams},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptSecret(tt.passphrase, tt.keyID, tt.keyType, tt.publicKey, tt.plaintext, tt.params)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("EncryptSecret() error = %v; want %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecryptSecretValidationFailures(t *testing.T) {
	publicKey := []byte("canonical-public-key")
	keyID := testKeyID(t, KeyTypeVoterSigning, publicKey)
	secret, err := EncryptSecret("passphrase", keyID, KeyTypeVoterSigning, publicKey, []byte("private-key-bytes"), testSecretParams())
	if err != nil {
		t.Fatalf("EncryptSecret() error = %v", err)
	}

	tests := []struct {
		name       string
		passphrase string
		keyID      Digest
		keyType    KeyType
		publicKey  []byte
		secret     EncryptedSecret
		wantErr    error
	}{
		{name: "empty passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, secret: secret, wantErr: ErrEmptyPassphrase},
		{name: "malformed key id", passphrase: "passphrase", keyType: KeyTypeVoterSigning, publicKey: publicKey, secret: secret, wantErr: ErrMalformedKeyID},
		{name: "mismatched key id", passphrase: "passphrase", keyID: testKeyID(t, KeyTypeVoterSigning, []byte("other-public-key")), keyType: KeyTypeVoterSigning, publicKey: publicKey, secret: secret, wantErr: ErrMalformedKeyID},
		{name: "unknown key type", passphrase: "passphrase", keyID: keyID, keyType: KeyType("unknown"), publicKey: publicKey, secret: secret, wantErr: ErrUnknownKeyType},
		{name: "empty public key", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, secret: secret, wantErr: ErrEmptyPublicKey},
		{name: "empty ciphertext", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, secret: EncryptedSecret{Metadata: secret.Metadata}, wantErr: ErrMalformedSecret},
		{name: "empty salt", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, secret: withSalt(secret, nil), wantErr: ErrMalformedSecret},
		{name: "empty nonce", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, secret: withNonce(secret, nil), wantErr: ErrMalformedSecret},
		{name: "weak params", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, secret: EncryptedSecret{Ciphertext: secret.Ciphertext, Metadata: SecretEncryptionMetadata{Salt: secret.Metadata.Salt, Nonce: secret.Metadata.Nonce}}, wantErr: ErrMalformedSecretParams},
		{name: "excessive params", passphrase: "passphrase", keyID: keyID, keyType: KeyTypeVoterSigning, publicKey: publicKey, secret: withParams(secret, SecretEncryptionParams{Memory: maxSecretMemory + 1, Iterations: minSecretIterations, Parallelism: minSecretParallelism}), wantErr: ErrMalformedSecretParams},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptSecret(tt.passphrase, tt.keyID, tt.keyType, tt.publicKey, tt.secret)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("DecryptSecret() error = %v; want %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncryptSecretDoesNotAliasInputs(t *testing.T) {
	publicKey := []byte("canonical-public-key")
	keyID := testKeyID(t, KeyTypeVoterSigning, publicKey)
	plaintext := []byte("private-key-bytes")
	publicKeyForEncrypt := append([]byte(nil), publicKey...)
	plaintextForEncrypt := append([]byte(nil), plaintext...)

	secret, err := EncryptSecret("passphrase", keyID, KeyTypeVoterSigning, publicKeyForEncrypt, plaintextForEncrypt, testSecretParams())
	if err != nil {
		t.Fatalf("EncryptSecret() error = %v", err)
	}
	publicKeyForEncrypt[0] ^= 0xff
	plaintextForEncrypt[0] ^= 0xff

	got, err := DecryptSecret("passphrase", keyID, KeyTypeVoterSigning, publicKey, secret)
	if err != nil {
		t.Fatalf("DecryptSecret() error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("DecryptSecret() = %q; want %q", got, plaintext)
	}
}

func TestDecryptSecretReturnsIndependentPlaintext(t *testing.T) {
	publicKey := []byte("canonical-public-key")
	keyID := testKeyID(t, KeyTypeVoterSigning, publicKey)
	plaintext := []byte("private-key-bytes")
	secret, err := EncryptSecret("passphrase", keyID, KeyTypeVoterSigning, publicKey, plaintext, testSecretParams())
	if err != nil {
		t.Fatalf("EncryptSecret() error = %v", err)
	}

	first, err := DecryptSecret("passphrase", keyID, KeyTypeVoterSigning, publicKey, secret)
	if err != nil {
		t.Fatalf("DecryptSecret() first error = %v", err)
	}
	first[0] ^= 0xff
	second, err := DecryptSecret("passphrase", keyID, KeyTypeVoterSigning, publicKey, secret)
	if err != nil {
		t.Fatalf("DecryptSecret() second error = %v", err)
	}
	if !bytes.Equal(second, plaintext) {
		t.Fatalf("DecryptSecret() after mutating previous plaintext = %q; want %q", second, plaintext)
	}
}

func TestSecretAADUsesDocumentedConcatenationWithoutLengthPrefixes(t *testing.T) {
	publicKey := []byte("canonical-public-key")
	keyID := testKeyID(t, KeyTypeVoterSigning, publicKey)

	got := secretAAD(keyID, KeyTypeVoterSigning, publicKey)
	want := append([]byte(nil), []byte(DomainKeyEncryption)...)
	want = append(want, keyID[:]...)
	want = append(want, []byte(KeyTypeVoterSigning)...)
	want = append(want, publicKey...)

	if !bytes.Equal(got, want) {
		t.Fatalf("secretAAD() = %x; want documented concatenation %x", got, want)
	}
}

func testSecretParams() SecretEncryptionParams {
	return SecretEncryptionParams{Memory: minSecretMemory, Iterations: minSecretIterations, Parallelism: minSecretParallelism}
}

func testKeyID(t *testing.T, keyType KeyType, publicKey []byte) Digest {
	t.Helper()
	keyID, err := KeyID(keyType, publicKey)
	if err != nil {
		t.Fatalf("KeyID() error = %v", err)
	}
	return keyID
}

func tamperCiphertext(secret EncryptedSecret) EncryptedSecret {
	secret.Ciphertext = append([]byte(nil), secret.Ciphertext...)
	secret.Ciphertext[0] ^= 0xff
	return secret
}

func tamperSalt(secret EncryptedSecret) EncryptedSecret {
	secret.Metadata.Salt = append([]byte(nil), secret.Metadata.Salt...)
	secret.Metadata.Salt[0] ^= 0xff
	return secret
}

func tamperNonce(secret EncryptedSecret) EncryptedSecret {
	secret.Metadata.Nonce = append([]byte(nil), secret.Metadata.Nonce...)
	secret.Metadata.Nonce[0] ^= 0xff
	return secret
}

func tamperParams(secret EncryptedSecret) EncryptedSecret {
	secret.Metadata.Memory++
	return secret
}

func withParams(secret EncryptedSecret, params SecretEncryptionParams) EncryptedSecret {
	secret.Metadata.Memory = params.Memory
	secret.Metadata.Iterations = params.Iterations
	secret.Metadata.Parallelism = params.Parallelism
	return secret
}

func withSalt(secret EncryptedSecret, salt []byte) EncryptedSecret {
	secret.Metadata.Salt = salt
	return secret
}

func withNonce(secret EncryptedSecret, nonce []byte) EncryptedSecret {
	secret.Metadata.Nonce = nonce
	return secret
}
