package crypto

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestKeyTypeValues(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
		want    string
	}{
		{name: "node", keyType: KeyTypeNode, want: "node"},
		{name: "voter signing", keyType: KeyTypeVoterSigning, want: "voter_signing"},
		{name: "voter encryption", keyType: KeyTypeVoterEncryption, want: "voter_encryption"},
		{name: "trustee signing", keyType: KeyTypeTrusteeSigning, want: "trustee_signing"},
		{name: "trustee blind token", keyType: KeyTypeTrusteeBlindToken, want: "trustee_blind_token"},
		{name: "trustee tally setup", keyType: KeyTypeTrusteeTallySetup, want: "trustee_tally_setup"},
		{name: "trustee tally share", keyType: KeyTypeTrusteeTallyShare, want: "trustee_tally_share"},
		{name: "anonymous token", keyType: KeyTypeAnonymousToken, want: "anonymous_token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.keyType); got != tt.want {
				t.Fatalf("key type = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestKnownKeyType(t *testing.T) {
	known := []KeyType{
		KeyTypeNode,
		KeyTypeVoterSigning,
		KeyTypeVoterEncryption,
		KeyTypeTrusteeSigning,
		KeyTypeTrusteeBlindToken,
		KeyTypeTrusteeTallySetup,
		KeyTypeTrusteeTallyShare,
		KeyTypeAnonymousToken,
	}

	for _, keyType := range known {
		if !KnownKeyType(keyType) {
			t.Fatalf("KnownKeyType(%q) = false; want true", keyType)
		}
	}

	for _, keyType := range []KeyType{"", "unknown"} {
		if KnownKeyType(keyType) {
			t.Fatalf("KnownKeyType(%q) = true; want false", keyType)
		}
	}
}

func TestKeyTypeMetadataDocumentsEveryKeyType(t *testing.T) {
	tests := []struct {
		name                string
		keyType             KeyType
		wantScheme          KeyScheme
		wantPublicKeySize   int
		wantPrivateKeySize  int
		wantCanGenerate     bool
		wantCanDomainSign   bool
		wantCanVoterDecrypt bool
		wantTransportOnly   bool
		wantPending         bool
	}{
		{name: "node", keyType: KeyTypeNode, wantScheme: KeySchemeLibP2PNode, wantTransportOnly: true, wantPending: true},
		{name: "voter signing", keyType: KeyTypeVoterSigning, wantScheme: KeySchemeEd25519, wantPublicKeySize: ed25519.PublicKeySize, wantPrivateKeySize: ed25519.PrivateKeySize, wantCanGenerate: true, wantCanDomainSign: true},
		{name: "voter encryption", keyType: KeyTypeVoterEncryption, wantScheme: KeySchemeX25519, wantPublicKeySize: curve25519.PointSize, wantPrivateKeySize: curve25519.ScalarSize, wantCanGenerate: true, wantCanVoterDecrypt: true},
		{name: "trustee signing", keyType: KeyTypeTrusteeSigning, wantScheme: KeySchemeEd25519, wantPublicKeySize: ed25519.PublicKeySize, wantPrivateKeySize: ed25519.PrivateKeySize, wantCanGenerate: true, wantCanDomainSign: true},
		{name: "trustee blind token", keyType: KeyTypeTrusteeBlindToken, wantScheme: KeySchemeRistretto255BlindSchnorr, wantPending: true},
		{name: "trustee tally setup", keyType: KeyTypeTrusteeTallySetup, wantScheme: KeySchemeRistretto255DKGEncryption, wantPending: true},
		{name: "trustee tally share", keyType: KeyTypeTrusteeTallyShare, wantScheme: KeySchemeRistretto255ThresholdShare, wantPending: true},
		{name: "anonymous token", keyType: KeyTypeAnonymousToken, wantScheme: KeySchemeRistretto255TokenHolderSchnorr, wantPending: true},
	}

	gotTypes := DocumentedKeyTypes()
	if len(gotTypes) != len(tests) {
		t.Fatalf("DocumentedKeyTypes() length = %d; want %d", len(gotTypes), len(tests))
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotTypes[i] != tt.keyType {
				t.Fatalf("DocumentedKeyTypes()[%d] = %q; want %q", i, gotTypes[i], tt.keyType)
			}

			metadata, err := KeyTypeMetadata(tt.keyType)
			if err != nil {
				t.Fatalf("KeyTypeMetadata() error = %v", err)
			}
			if metadata.Type != tt.keyType {
				t.Fatalf("metadata.Type = %q; want %q", metadata.Type, tt.keyType)
			}
			if metadata.Role == "" {
				t.Fatalf("metadata.Role is empty")
			}
			if metadata.Purpose == "" {
				t.Fatalf("metadata.Purpose is empty")
			}
			if metadata.Scheme != tt.wantScheme {
				t.Fatalf("metadata.Scheme = %q; want %q", metadata.Scheme, tt.wantScheme)
			}
			if metadata.PublicKeySize != tt.wantPublicKeySize {
				t.Fatalf("metadata.PublicKeySize = %d; want %d", metadata.PublicKeySize, tt.wantPublicKeySize)
			}
			if metadata.PrivateKeySize != tt.wantPrivateKeySize {
				t.Fatalf("metadata.PrivateKeySize = %d; want %d", metadata.PrivateKeySize, tt.wantPrivateKeySize)
			}
			if metadata.CanGenerate != tt.wantCanGenerate {
				t.Fatalf("metadata.CanGenerate = %t; want %t", metadata.CanGenerate, tt.wantCanGenerate)
			}
			if metadata.CanDomainSign != tt.wantCanDomainSign {
				t.Fatalf("metadata.CanDomainSign = %t; want %t", metadata.CanDomainSign, tt.wantCanDomainSign)
			}
			if metadata.CanVoterDecrypt != tt.wantCanVoterDecrypt {
				t.Fatalf("metadata.CanVoterDecrypt = %t; want %t", metadata.CanVoterDecrypt, tt.wantCanVoterDecrypt)
			}
			if metadata.TransportOnly != tt.wantTransportOnly {
				t.Fatalf("metadata.TransportOnly = %t; want %t", metadata.TransportOnly, tt.wantTransportOnly)
			}
			if metadata.PendingImplementation != tt.wantPending {
				t.Fatalf("metadata.PendingImplementation = %t; want %t", metadata.PendingImplementation, tt.wantPending)
			}
			if CanGenerateLocalKey(tt.keyType) != tt.wantCanGenerate {
				t.Fatalf("CanGenerateLocalKey() = %t; want %t", CanGenerateLocalKey(tt.keyType), tt.wantCanGenerate)
			}
			if CanPublicDomainSignEd25519(tt.keyType) != tt.wantCanDomainSign {
				t.Fatalf("CanPublicDomainSignEd25519() = %t; want %t", CanPublicDomainSignEd25519(tt.keyType), tt.wantCanDomainSign)
			}
			if CanVoterEncryptionDecrypt(tt.keyType) != tt.wantCanVoterDecrypt {
				t.Fatalf("CanVoterEncryptionDecrypt() = %t; want %t", CanVoterEncryptionDecrypt(tt.keyType), tt.wantCanVoterDecrypt)
			}
			if PendingKeyImplementation(tt.keyType) != tt.wantPending {
				t.Fatalf("PendingKeyImplementation() = %t; want %t", PendingKeyImplementation(tt.keyType), tt.wantPending)
			}
		})
	}
}

func TestGenerateAndValidateEd25519LocalKeys(t *testing.T) {
	for _, keyType := range []KeyType{KeyTypeVoterSigning, KeyTypeTrusteeSigning} {
		t.Run(string(keyType), func(t *testing.T) {
			material := mustGenerateLocalKey(t, keyType)
			if err := ValidateLocalKeyMaterial(material); err != nil {
				t.Fatalf("ValidateLocalKeyMaterial() error = %v", err)
			}
			if material.KeyType() != keyType {
				t.Fatalf("KeyType() = %q; want %q", material.KeyType(), keyType)
			}
			if len(material.PublicKey()) != ed25519.PublicKeySize {
				t.Fatalf("public key size = %d; want %d", len(material.PublicKey()), ed25519.PublicKeySize)
			}
			if len(material.PrivateKey()) != ed25519.PrivateKeySize {
				t.Fatalf("private key size = %d; want %d", len(material.PrivateKey()), ed25519.PrivateKeySize)
			}
		})
	}
}

func TestGeneratedEd25519LocalKeysSignAndVerify(t *testing.T) {
	digest := Hash(DomainTrusteeVoteSign, []byte("payload"))

	for _, keyType := range []KeyType{KeyTypeVoterSigning, KeyTypeTrusteeSigning} {
		t.Run(string(keyType), func(t *testing.T) {
			material := mustGenerateLocalKey(t, keyType)
			sig, err := SignEd25519(ed25519.PrivateKey(material.PrivateKey()), digest)
			if err != nil {
				t.Fatalf("SignEd25519() error = %v", err)
			}
			if !VerifyEd25519(ed25519.PublicKey(material.PublicKey()), digest, sig) {
				t.Fatalf("VerifyEd25519() = false; want true")
			}
		})
	}
}

func TestGenerateAndValidateX25519LocalKey(t *testing.T) {
	material := mustGenerateLocalKey(t, KeyTypeVoterEncryption)
	if err := ValidateLocalKeyMaterial(material); err != nil {
		t.Fatalf("ValidateLocalKeyMaterial() error = %v", err)
	}
	if material.KeyType() != KeyTypeVoterEncryption {
		t.Fatalf("KeyType() = %q; want %q", material.KeyType(), KeyTypeVoterEncryption)
	}
	if len(material.PublicKey()) != curve25519.PointSize {
		t.Fatalf("public key size = %d; want %d", len(material.PublicKey()), curve25519.PointSize)
	}
	if len(material.PrivateKey()) != curve25519.ScalarSize {
		t.Fatalf("private key size = %d; want %d", len(material.PrivateKey()), curve25519.ScalarSize)
	}
}

func TestValidateLocalKeyMaterialRejectsMismatches(t *testing.T) {
	edPublicKey, edPrivateKey := deterministicEd25519Key(byte(1))
	edKeyID := mustKeyID(t, KeyTypeVoterSigning, edPublicKey)
	edMaterial := NewLocalKeyMaterial(edKeyID, KeyTypeVoterSigning, edPublicKey, edPrivateKey)
	xMaterial := deterministicX25519Material(t)

	wrongEdPublicKey, _ := deterministicEd25519Key(byte(2))
	wrongEdPublicKeyID := mustKeyID(t, KeyTypeVoterSigning, wrongEdPublicKey)
	wrongXPublicKey := append([]byte(nil), xMaterial.publicKey...)
	wrongXPublicKey[0] ^= 0xff
	wrongXPublicKeyID := mustKeyID(t, KeyTypeVoterEncryption, wrongXPublicKey)
	wrongKeyID := edMaterial.keyID
	wrongKeyID[0] ^= 0xff

	tests := []struct {
		name     string
		material LocalKeyMaterial
		wantErr  error
	}{
		{name: "ed25519 key id mismatch", material: NewLocalKeyMaterial(wrongKeyID, KeyTypeVoterSigning, edPublicKey, edPrivateKey), wantErr: ErrKeyIDMismatch},
		{name: "ed25519 key type mismatch", material: NewLocalKeyMaterial(edKeyID, KeyTypeTrusteeSigning, edPublicKey, edPrivateKey), wantErr: ErrKeyIDMismatch},
		{name: "ed25519 public private mismatch", material: NewLocalKeyMaterial(wrongEdPublicKeyID, KeyTypeVoterSigning, wrongEdPublicKey, edPrivateKey), wantErr: ErrPublicPrivateKeyMismatch},
		{name: "ed25519 invalid public size", material: NewLocalKeyMaterial(edKeyID, KeyTypeVoterSigning, edPublicKey[:ed25519.PublicKeySize-1], edPrivateKey), wantErr: ErrInvalidKeyMaterial},
		{name: "ed25519 invalid private size", material: NewLocalKeyMaterial(edKeyID, KeyTypeVoterSigning, edPublicKey, edPrivateKey[:ed25519.PrivateKeySize-1]), wantErr: ErrInvalidKeyMaterial},
		{name: "x25519 key id mismatch", material: NewLocalKeyMaterial(wrongKeyID, KeyTypeVoterEncryption, xMaterial.publicKey, xMaterial.privateKey), wantErr: ErrKeyIDMismatch},
		{name: "x25519 key type mismatch", material: NewLocalKeyMaterial(xMaterial.keyID, KeyTypeVoterSigning, xMaterial.publicKey, xMaterial.privateKey), wantErr: ErrInvalidKeyMaterial},
		{name: "x25519 public private mismatch", material: NewLocalKeyMaterial(wrongXPublicKeyID, KeyTypeVoterEncryption, wrongXPublicKey, xMaterial.privateKey), wantErr: ErrPublicPrivateKeyMismatch},
		{name: "x25519 invalid public size", material: NewLocalKeyMaterial(xMaterial.keyID, KeyTypeVoterEncryption, xMaterial.publicKey[:curve25519.PointSize-1], xMaterial.privateKey), wantErr: ErrInvalidKeyMaterial},
		{name: "x25519 invalid private size", material: NewLocalKeyMaterial(xMaterial.keyID, KeyTypeVoterEncryption, xMaterial.publicKey, xMaterial.privateKey[:curve25519.ScalarSize-1]), wantErr: ErrInvalidKeyMaterial},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLocalKeyMaterial(tt.material)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateLocalKeyMaterial() error = %v; want %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateLocalKeyRejectsUnsupportedKeyTypes(t *testing.T) {
	for _, keyType := range []KeyType{
		KeyTypeNode,
		KeyTypeTrusteeBlindToken,
		KeyTypeTrusteeTallySetup,
		KeyTypeTrusteeTallyShare,
		KeyTypeAnonymousToken,
	} {
		t.Run(string(keyType), func(t *testing.T) {
			_, err := GenerateLocalKey(keyType)
			if !errors.Is(err, ErrUnsupportedKeyType) {
				t.Fatalf("GenerateLocalKey() error = %v; want %v", err, ErrUnsupportedKeyType)
			}
		})
	}
}

func TestLocalKeyMaterialDefensiveCopies(t *testing.T) {
	publicKey := []byte("public-key")
	privateKey := []byte("private-key")
	keyID := Digest{1, 2, 3}

	material := NewLocalKeyMaterial(keyID, KeyTypeVoterSigning, publicKey, privateKey)
	publicKey[0] = 'P'
	privateKey[0] = 'P'

	if got := material.PublicKey(); !bytes.Equal(got, []byte("public-key")) {
		t.Fatalf("PublicKey() after source mutation = %q; want %q", got, "public-key")
	}
	if got := material.PrivateKey(); !bytes.Equal(got, []byte("private-key")) {
		t.Fatalf("PrivateKey() after source mutation = %q; want %q", got, "private-key")
	}

	returnedPublicKey := material.PublicKey()
	returnedPrivateKey := material.PrivateKey()
	returnedPublicKey[0] = 'P'
	returnedPrivateKey[0] = 'P'

	if got := material.PublicKey(); !bytes.Equal(got, []byte("public-key")) {
		t.Fatalf("PublicKey() after returned slice mutation = %q; want %q", got, "public-key")
	}
	if got := material.PrivateKey(); !bytes.Equal(got, []byte("private-key")) {
		t.Fatalf("PrivateKey() after returned slice mutation = %q; want %q", got, "private-key")
	}
}

func TestKeyIDDeterministic(t *testing.T) {
	publicKey := []byte("canonical-public-key")

	got, err := KeyID(KeyTypeVoterSigning, publicKey)
	if err != nil {
		t.Fatalf("KeyID() error = %v", err)
	}
	want, err := KeyID(KeyTypeVoterSigning, publicKey)
	if err != nil {
		t.Fatalf("KeyID() error = %v", err)
	}

	if got != want {
		t.Fatalf("KeyID() = %s; want %s", got, want)
	}
}

func TestKeyIDUsesDocumentedConcatenation(t *testing.T) {
	publicKey := []byte("canonical-public-key")
	want := "d2cece07af892ef741e0b5f53a17c3ab19d7ba107d0cff944e594f1e815975f1"

	got, err := KeyID(KeyTypeVoterSigning, publicKey)
	if err != nil {
		t.Fatalf("KeyID() error = %v", err)
	}

	if got.String() != want {
		t.Fatalf("KeyID() = %s; want %s", got, want)
	}
}

func TestKeyIDDifferentKeyTypesDiffer(t *testing.T) {
	publicKey := []byte("canonical-public-key")

	voterSigning, err := KeyID(KeyTypeVoterSigning, publicKey)
	if err != nil {
		t.Fatalf("KeyID() error = %v", err)
	}
	voterEncryption, err := KeyID(KeyTypeVoterEncryption, publicKey)
	if err != nil {
		t.Fatalf("KeyID() error = %v", err)
	}

	if voterSigning == voterEncryption {
		t.Fatalf("KeyID() returned same digest for different key types: %s", voterSigning)
	}
}

func TestKeyIDDifferentPublicKeysDiffer(t *testing.T) {
	one, err := KeyID(KeyTypeVoterSigning, []byte("canonical-public-key-1"))
	if err != nil {
		t.Fatalf("KeyID() error = %v", err)
	}
	two, err := KeyID(KeyTypeVoterSigning, []byte("canonical-public-key-2"))
	if err != nil {
		t.Fatalf("KeyID() error = %v", err)
	}

	if one == two {
		t.Fatalf("KeyID() returned same digest for different public keys: %s", one)
	}
}

func TestKeyIDRejectsEmptyPublicKey(t *testing.T) {
	_, err := KeyID(KeyTypeVoterSigning, nil)
	if !errors.Is(err, ErrEmptyPublicKey) {
		t.Fatalf("KeyID() error = %v; want %v", err, ErrEmptyPublicKey)
	}
}

func TestKeyIDRejectsUnknownKeyType(t *testing.T) {
	_, err := KeyID(KeyType("unknown"), []byte("canonical-public-key"))
	if !errors.Is(err, ErrUnknownKeyType) {
		t.Fatalf("KeyID() error = %v; want %v", err, ErrUnknownKeyType)
	}
}

func mustGenerateLocalKey(t *testing.T, keyType KeyType) LocalKeyMaterial {
	t.Helper()

	material, err := GenerateLocalKey(keyType)
	if err != nil {
		t.Fatalf("GenerateLocalKey(%q) error = %v", keyType, err)
	}
	return material
}

func mustKeyID(t *testing.T, keyType KeyType, publicKey []byte) Digest {
	t.Helper()

	keyID, err := KeyID(keyType, publicKey)
	if err != nil {
		t.Fatalf("KeyID(%q) error = %v", keyType, err)
	}
	return keyID
}

func deterministicX25519Material(t *testing.T) LocalKeyMaterial {
	t.Helper()

	privateKey := make([]byte, curve25519.ScalarSize)
	for i := range privateKey {
		privateKey[i] = byte(i + 1)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519.X25519() error = %v", err)
	}
	keyID := mustKeyID(t, KeyTypeVoterEncryption, publicKey)
	return NewLocalKeyMaterial(keyID, KeyTypeVoterEncryption, publicKey, privateKey)
}
