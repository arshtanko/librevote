package gossip

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"librevote/internal/domain"
)

const MaxAnnouncementBytes = 4096

// ObjectAnnouncement is a compact GossipSub object advertisement.
type ObjectAnnouncement struct {
	ObjectID   string `json:"object_id"`
	ObjectType string `json:"object_type"`
	Scope      string `json:"scope"`
	ScopeID    string `json:"scope_id"`
	CreatedAt  int64  `json:"created_at"`
}

// EncodeAnnouncement marshals an ObjectAnnouncement to JSON with a size limit.
func EncodeAnnouncement(a ObjectAnnouncement) ([]byte, error) {
	if err := validateAnnouncement(a); err != nil {
		return nil, err
	}
	data, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("encode announcement: %w", err)
	}
	if len(data) > MaxAnnouncementBytes {
		return nil, fmt.Errorf("announcement exceeds %d bytes", MaxAnnouncementBytes)
	}
	return data, nil
}

// DecodeAnnouncement parses JSON bytes into an ObjectAnnouncement with strict
// field checking and domain-level validation.
func DecodeAnnouncement(data []byte) (ObjectAnnouncement, error) {
	if len(data) > MaxAnnouncementBytes {
		return ObjectAnnouncement{}, fmt.Errorf("announcement exceeds %d bytes", MaxAnnouncementBytes)
	}
	var a ObjectAnnouncement
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return ObjectAnnouncement{}, fmt.Errorf("decode announcement: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return ObjectAnnouncement{}, fmt.Errorf("decode announcement: trailing data after JSON object")
	}
	if err := validateAnnouncement(a); err != nil {
		return ObjectAnnouncement{}, err
	}
	return a, nil
}

func validateAnnouncement(a ObjectAnnouncement) error {
	if a.ObjectID == "" {
		return fmt.Errorf("object_id is required")
	}
	if a.ObjectType == "" {
		return fmt.Errorf("object_type is required")
	}
	if a.Scope == "" {
		return fmt.Errorf("scope is required")
	}
	if a.CreatedAt <= 0 {
		return fmt.Errorf("created_at must be greater than zero")
	}
	if err := domain.ValidateScopeForObjectType(domain.ObjectType(a.ObjectType), domain.Scope(a.Scope), a.ScopeID); err != nil {
		return fmt.Errorf("invalid scope: %w", err)
	}
	for _, field := range []string{a.ObjectID, a.ObjectType, a.Scope, a.ScopeID} {
		if strings.ContainsRune(field, 0) {
			return fmt.Errorf("field contains null byte")
		}
	}
	return nil
}
