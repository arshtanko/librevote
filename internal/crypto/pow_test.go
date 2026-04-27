package crypto

import (
	"errors"
	"testing"
)

func TestLeadingZeroBits(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int
	}{
		{name: "empty", in: nil, want: 0},
		{name: "all zero byte", in: []byte{0x00}, want: 8},
		{name: "zero then high bit", in: []byte{0x00, 0x80}, want: 8},
		{name: "single leading bit", in: []byte{0x40}, want: 1},
		{name: "nibble", in: []byte{0x0f}, want: 4},
		{name: "multiple bytes", in: []byte{0x00, 0x01}, want: 15},
		{name: "all one", in: []byte{0xff}, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := leadingZeroBits(tt.in); got != tt.want {
				t.Fatalf("leadingZeroBits(%x) = %d; want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidatePoWDifficultyZeroValidForAnyNonce(t *testing.T) {
	valid, err := ValidatePoW(DomainObjectPoW, Digest{}, 0, []byte("nonce"))
	if err != nil {
		t.Fatalf("ValidatePoW() error = %v", err)
	}
	if !valid {
		t.Fatalf("ValidatePoW() = false; want true")
	}
}

func TestPoWHashKnownVector(t *testing.T) {
	target := targetDigest()
	got := PoWHash(DomainObjectPoW, target, 8, []byte("nonce-#"))
	want := "00dad83e6dbee7df66dd9241920cce90a7b823e88602121da2b60d0036c05078"

	if got.String() != want {
		t.Fatalf("PoWHash() = %s; want %s", got, want)
	}
}

func TestValidatePoWKnownThresholds(t *testing.T) {
	target := targetDigest()
	nonce := []byte("nonce-#")

	valid, err := ValidatePoW(DomainObjectPoW, target, 8, nonce)
	if err != nil {
		t.Fatalf("ValidatePoW() error = %v", err)
	}
	if !valid {
		t.Fatalf("ValidatePoW() difficulty 8 = false; want true")
	}

	valid, err = ValidatePoW(DomainObjectPoW, target, 9, nonce)
	if err != nil {
		t.Fatalf("ValidatePoW() error = %v", err)
	}
	if valid {
		t.Fatalf("ValidatePoW() difficulty 9 = true; want false")
	}
}

func TestPoWHashDomainSeparation(t *testing.T) {
	target := targetDigest()
	nonce := []byte("same nonce")

	peer := PoWHash(DomainPeerAdmissionPoW, target, 8, nonce)
	object := PoWHash(DomainObjectPoW, target, 8, nonce)
	sync := PoWHash(DomainSyncRequestPoW, target, 8, nonce)

	if peer == object || peer == sync || object == sync {
		t.Fatalf("PoWHash() returned equal digest for different PoW domains")
	}
}

func TestValidatePoWRejectsUnknownDomain(t *testing.T) {
	valid, err := ValidatePoW(DomainObjectID, Digest{}, 0, []byte("nonce"))
	if !errors.Is(err, ErrUnknownPoWDomain) {
		t.Fatalf("ValidatePoW() error = %v; want %v", err, ErrUnknownPoWDomain)
	}
	if valid {
		t.Fatalf("ValidatePoW() valid = true; want false")
	}
}

func TestValidatePoWRejectsEmptyNonce(t *testing.T) {
	valid, err := ValidatePoW(DomainObjectPoW, Digest{}, 0, nil)
	if !errors.Is(err, ErrEmptyPoWNonce) {
		t.Fatalf("ValidatePoW() error = %v; want %v", err, ErrEmptyPoWNonce)
	}
	if valid {
		t.Fatalf("ValidatePoW() valid = true; want false")
	}
}

func TestValidatePoWMaxUint8Difficulty(t *testing.T) {
	valid, err := ValidatePoW(DomainObjectPoW, targetDigest(), 255, []byte("nonce-#"))
	if err != nil {
		t.Fatalf("ValidatePoW() error = %v", err)
	}
	if valid {
		t.Fatalf("ValidatePoW() difficulty 255 = true; want false for fixed vector")
	}
}

func targetDigest() Digest {
	return Hash(DomainObjectID, []byte("pow-target"))
}
