package discovery

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type identityFile struct {
	KeyData []byte `json:"key_data"`
	PeerID  string `json:"peer_id"`
}

type Identity struct {
	PrivKey crypto.PrivKey
	PeerID  peer.ID
}

func LoadOrCreateIdentity(keyPath string) (*Identity, error) {
	if keyPath == "" {
		return generateIdentity()
	}

	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create key directory %s: %w", dir, err)
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			id, genErr := generateIdentity()
			if genErr != nil {
				return nil, genErr
			}
			if saveErr := saveIdentity(keyPath, id); saveErr != nil {
				return nil, saveErr
			}
			return id, nil
		}
		return nil, fmt.Errorf("read identity file: %w", err)
	}

	return loadIdentity(data)
}

func loadIdentity(data []byte) (*Identity, error) {
	var f identityFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse identity file: %w", err)
	}

	priv, err := crypto.UnmarshalPrivateKey(f.KeyData)
	if err != nil {
		return nil, fmt.Errorf("unmarshal private key: %w", err)
	}

	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("derive peer ID: %w", err)
	}

	if f.PeerID != pid.String() {
		return nil, fmt.Errorf("identity file peer_id mismatch: %s != %s", f.PeerID, pid.String())
	}

	return &Identity{
		PrivKey: priv,
		PeerID:  pid,
	}, nil
}

func generateIdentity() (*Identity, error) {
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("derive peer ID: %w", err)
	}

	return &Identity{
		PrivKey: priv,
		PeerID:  pid,
	}, nil
}

func saveIdentity(keyPath string, id *Identity) error {
	keyData, err := crypto.MarshalPrivateKey(id.PrivKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}

	f := identityFile{
		KeyData: keyData,
		PeerID:  id.PeerID.String(),
	}
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}

	tmpPath := keyPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write identity tmp: %w", err)
	}
	if err := os.Rename(tmpPath, keyPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename identity file: %w", err)
	}
	return nil
}
