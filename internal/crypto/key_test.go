package crypto

import (
	"errors"
	"testing"
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
