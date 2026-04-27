package crypto

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"librevote/internal/domain"
)

func TestSigningDigestDeterministic(t *testing.T) {
	ctx := validSigningContext()
	payload := []byte("canonical-payload-without-signature")

	got, err := SigningDigest(ctx, payload)
	if err != nil {
		t.Fatalf("SigningDigest() error = %v", err)
	}
	want, err := SigningDigest(ctx, payload)
	if err != nil {
		t.Fatalf("SigningDigest() error = %v", err)
	}

	if got != want {
		t.Fatalf("SigningDigest() = %s; want %s", got, want)
	}
}

func TestSigningDigestContextAndPayloadSeparation(t *testing.T) {
	base := validSigningContext()
	baseDigest, err := SigningDigest(base, []byte("canonical-payload-without-signature"))
	if err != nil {
		t.Fatalf("SigningDigest() error = %v", err)
	}

	tests := []struct {
		name    string
		ctx     SigningContext
		payload []byte
	}{
		{name: "domain", ctx: withContext(base, func(ctx *SigningContext) { ctx.Domain = DomainTrusteeVoteSign }), payload: []byte("canonical-payload-without-signature")},
		{name: "protocol version", ctx: withContext(base, func(ctx *SigningContext) { ctx.ProtocolVersion = "v2" }), payload: []byte("canonical-payload-without-signature")},
		{name: "network id", ctx: withContext(base, func(ctx *SigningContext) { ctx.NetworkID = "other-network" }), payload: []byte("canonical-payload-without-signature")},
		{name: "object type", ctx: withContext(base, func(ctx *SigningContext) { ctx.ObjectType = domain.ObjectTypeTrusteeConsent }), payload: []byte("canonical-payload-without-signature")},
		{name: "scope", ctx: withContext(base, func(ctx *SigningContext) { ctx.Scope = domain.ScopeElectionID }), payload: []byte("canonical-payload-without-signature")},
		{name: "scope id", ctx: withContext(base, func(ctx *SigningContext) { ctx.ScopeID = "other-scope" }), payload: []byte("canonical-payload-without-signature")},
		{name: "created at", ctx: withContext(base, func(ctx *SigningContext) { ctx.CreatedAt++ }), payload: []byte("canonical-payload-without-signature")},
		{name: "payload", ctx: base, payload: []byte("other-canonical-payload")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SigningDigest(tt.ctx, tt.payload)
			if err != nil {
				t.Fatalf("SigningDigest() error = %v", err)
			}
			if got == baseDigest {
				t.Fatalf("SigningDigest() did not bind changed %s: %s", tt.name, got)
			}
		})
	}
}

func TestSigningDigestUsesLengthDelimitedFieldFraming(t *testing.T) {
	one := validSigningContext()
	one.NetworkID = "ab"
	one.ObjectType = domain.ObjectType("c")

	two := validSigningContext()
	two.NetworkID = "a"
	two.ObjectType = domain.ObjectType("bc")

	oneDigest, err := SigningDigest(one, []byte("payload"))
	if err != nil {
		t.Fatalf("SigningDigest() error = %v", err)
	}
	twoDigest, err := SigningDigest(two, []byte("payload"))
	if err != nil {
		t.Fatalf("SigningDigest() error = %v", err)
	}

	if oneDigest == twoDigest {
		t.Fatalf("SigningDigest() ignored field boundaries: %s", oneDigest)
	}
}

func TestSigningDigestRejectsMissingRequiredFields(t *testing.T) {
	base := validSigningContext()
	tests := []struct {
		name    string
		ctx     SigningContext
		payload []byte
		wantErr error
	}{
		{name: "domain", ctx: withContext(base, func(ctx *SigningContext) { ctx.Domain = "" }), payload: []byte("payload"), wantErr: ErrUnknownSigningDomain},
		{name: "protocol version", ctx: withContext(base, func(ctx *SigningContext) { ctx.ProtocolVersion = "" }), payload: []byte("payload"), wantErr: ErrEmptySigningField},
		{name: "network id", ctx: withContext(base, func(ctx *SigningContext) { ctx.NetworkID = "" }), payload: []byte("payload"), wantErr: ErrEmptySigningField},
		{name: "object type", ctx: withContext(base, func(ctx *SigningContext) { ctx.ObjectType = "" }), payload: []byte("payload"), wantErr: ErrEmptySigningField},
		{name: "scope", ctx: withContext(base, func(ctx *SigningContext) { ctx.Scope = "" }), payload: []byte("payload"), wantErr: ErrEmptySigningField},
		{name: "scope id", ctx: withContext(base, func(ctx *SigningContext) { ctx.ScopeID = "" }), payload: []byte("payload"), wantErr: ErrEmptySigningField},
		{name: "created at zero", ctx: withContext(base, func(ctx *SigningContext) { ctx.CreatedAt = 0 }), payload: []byte("payload"), wantErr: ErrInvalidCreatedAt},
		{name: "created at negative", ctx: withContext(base, func(ctx *SigningContext) { ctx.CreatedAt = -1 }), payload: []byte("payload"), wantErr: ErrInvalidCreatedAt},
		{name: "payload", ctx: base, payload: nil, wantErr: ErrEmptySigningPayload},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SigningDigest(tt.ctx, tt.payload)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("SigningDigest() error = %v; want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSigningDigestValidatesScopeIDByScope(t *testing.T) {
	base := validSigningContext()
	tests := []struct {
		name        string
		ctx         SigningContext
		wantErr     error
		wantErrText string
	}{
		{
			name: "network accepts empty scope id",
			ctx: withContext(base, func(ctx *SigningContext) {
				ctx.ObjectType = domain.ObjectTypeAnonymousElection
				ctx.Scope = domain.ScopeNetwork
				ctx.ScopeID = ""
			}),
		},
		{
			name: "network rejects non-empty scope id",
			ctx: withContext(base, func(ctx *SigningContext) {
				ctx.ObjectType = domain.ObjectTypeAnonymousElection
				ctx.Scope = domain.ScopeNetwork
				ctx.ScopeID = "network-root"
			}),
			wantErrText: "requires empty scope_id",
		},
		{
			name: "election id rejects empty scope id",
			ctx: withContext(base, func(ctx *SigningContext) {
				ctx.ObjectType = domain.ObjectTypeTrusteeConsent
				ctx.Scope = domain.ScopeElectionID
				ctx.ScopeID = ""
			}),
			wantErr: ErrEmptySigningField,
		},
		{
			name: "trustee selection id rejects empty scope id",
			ctx: withContext(base, func(ctx *SigningContext) {
				ctx.Scope = domain.ScopeTrusteeSelectionID
				ctx.ScopeID = ""
			}),
			wantErr: ErrEmptySigningField,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SigningDigest(tt.ctx, []byte("payload"))
			if tt.wantErr == nil && tt.wantErrText == "" {
				if err != nil {
					t.Fatalf("SigningDigest() error = %v; want nil", err)
				}
				return
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("SigningDigest() error = %v; want %v", err, tt.wantErr)
			}
			if tt.wantErrText != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrText)) {
				t.Fatalf("SigningDigest() error = %v; want containing %q", err, tt.wantErrText)
			}
		})
	}
}

func TestSigningDigestRejectsUnknownNonSigningDomain(t *testing.T) {
	ctx := validSigningContext()
	ctx.Domain = DomainObjectID

	_, err := SigningDigest(ctx, []byte("payload"))
	if !errors.Is(err, ErrUnknownSigningDomain) {
		t.Fatalf("SigningDigest() error = %v; want %v", err, ErrUnknownSigningDomain)
	}
}

func TestKnownEd25519SigningDomain(t *testing.T) {
	known := []Domain{
		DomainTrusteeNominationSign,
		DomainTrusteeVoteSign,
		DomainTrusteeConsentSign,
		DomainTallyKeyContributionSign,
		DomainTallyKeySetSign,
		DomainElectionParameters,
	}

	for _, domain := range known {
		if !KnownEd25519SigningDomain(domain) {
			t.Fatalf("KnownEd25519SigningDomain(%q) = false; want true", domain)
		}
	}

	for _, domain := range []Domain{"", DomainObjectID, DomainObjectPoW} {
		if KnownEd25519SigningDomain(domain) {
			t.Fatalf("KnownEd25519SigningDomain(%q) = true; want false", domain)
		}
	}
}

func TestSignAndVerifyEd25519(t *testing.T) {
	publicKey, privateKey := deterministicEd25519Key(byte(1))
	digest := mustSigningDigest(t, validSigningContext(), []byte("payload"))

	sig, err := SignEd25519(privateKey, digest)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}

	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature length = %d; want %d", len(sig), ed25519.SignatureSize)
	}
	if !VerifyEd25519(publicKey, digest, sig) {
		t.Fatalf("VerifyEd25519() = false; want true")
	}
}

func TestVerifyEd25519RejectsChangedInputs(t *testing.T) {
	publicKey, privateKey := deterministicEd25519Key(byte(1))
	wrongPublicKey, _ := deterministicEd25519Key(byte(2))
	digest := mustSigningDigest(t, validSigningContext(), []byte("payload"))
	sig, err := SignEd25519(privateKey, digest)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}

	changedDigest := digest
	changedDigest[0] ^= 0xff
	if VerifyEd25519(publicKey, changedDigest, sig) {
		t.Fatalf("VerifyEd25519() accepted changed digest")
	}

	changedSig := append([]byte(nil), sig...)
	changedSig[0] ^= 0xff
	if VerifyEd25519(publicKey, digest, changedSig) {
		t.Fatalf("VerifyEd25519() accepted changed signature")
	}

	if VerifyEd25519(wrongPublicKey, digest, sig) {
		t.Fatalf("VerifyEd25519() accepted wrong public key")
	}
}

func TestSignEd25519RejectsInvalidPrivateKey(t *testing.T) {
	_, err := SignEd25519(ed25519.PrivateKey("short"), Digest{})
	if !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("SignEd25519() error = %v; want %v", err, ErrInvalidPrivateKey)
	}
}

func TestSignEd25519RejectsMismatchedPrivateKeyPublicHalf(t *testing.T) {
	_, privateKey := deterministicEd25519Key(byte(1))
	malformedPrivateKey := append(ed25519.PrivateKey(nil), privateKey...)
	malformedPrivateKey[ed25519.SeedSize] ^= 0xff

	_, err := SignEd25519(malformedPrivateKey, Digest{})
	if !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("SignEd25519() error = %v; want %v", err, ErrInvalidPrivateKey)
	}
}

func TestVerifyEd25519RejectsInvalidLengths(t *testing.T) {
	publicKey, privateKey := deterministicEd25519Key(byte(1))
	digest := mustSigningDigest(t, validSigningContext(), []byte("payload"))
	sig, err := SignEd25519(privateKey, digest)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}

	if VerifyEd25519(ed25519.PublicKey("short"), digest, sig) {
		t.Fatalf("VerifyEd25519() accepted invalid public key length")
	}
	if VerifyEd25519(publicKey, digest, sig[:ed25519.SignatureSize-1]) {
		t.Fatalf("VerifyEd25519() accepted invalid signature length")
	}
}

func validSigningContext() SigningContext {
	return SigningContext{
		Domain:          DomainTrusteeNominationSign,
		ProtocolVersion: "v1",
		NetworkID:       "testnet",
		ObjectType:      domain.ObjectTypeTrusteeNomination,
		Scope:           domain.ScopeTrusteeSelectionID,
		ScopeID:         "trustee-selection-1",
		CreatedAt:       1710000000000,
	}
}

func withContext(ctx SigningContext, mutate func(*SigningContext)) SigningContext {
	mutate(&ctx)
	return ctx
}

func deterministicEd25519Key(seedByte byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func mustSigningDigest(t *testing.T, ctx SigningContext, payload []byte) Digest {
	t.Helper()

	digest, err := SigningDigest(ctx, payload)
	if err != nil {
		t.Fatalf("SigningDigest() error = %v", err)
	}
	return digest
}
