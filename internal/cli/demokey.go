package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
)

func demoEd25519PrivFromName(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func demoEd25519PubFromName(name string) ed25519.PublicKey {
	priv := demoEd25519PrivFromName(name)
	return priv.Public().(ed25519.PublicKey)
}

func demoBlindKeyFromName(name string) []byte {
	h := sha256.Sum256([]byte(name + ".blind"))
	return h[:]
}

func demoEncryptionKeyFromName(name string) []byte {
	h := sha256.Sum256([]byte(name + ".enc"))
	return h[:]
}

func demoTallySetupKeyFromName(name string) []byte {
	h := sha256.Sum256([]byte(name + ".tally-setup"))
	return h[:]
}
