package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"

	"librevote/internal/domain"
)

func TestFrontendSignableVoterIDsUsesDeterministicLocalKeysOnly(t *testing.T) {
	customPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	election := domain.AnonymousElectionPayload{
		VoterAllowlist: []domain.VoterEntry{
			{VoterID: "voter-1", VoterSigningPublicKey: deterministicEd25519Pub("voter-1")},
			{VoterID: "custom-voter", VoterSigningPublicKey: customPub},
		},
	}

	got := frontendSignableVoterIDs(election)
	want := []string{"voter-1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("frontendSignableVoterIDs() = %v, want %v", got, want)
	}
}
