package domain

import (
	"strings"
	"testing"
)

func TestValidateEnvelopeShapeValidScopes(t *testing.T) {
	tests := []struct {
		name       string
		objectType ObjectType
		scope      Scope
		scopeID    string
	}{
		{
			name:       "network scope",
			objectType: ObjectTypeAnonymousElection,
			scope:      ScopeNetwork,
		},
		{
			name:       "election scope",
			objectType: ObjectTypeBlindTokenRequest,
			scope:      ScopeElectionID,
			scopeID:    "election-1",
		},
		{
			name:       "trustee selection scope",
			objectType: ObjectTypeTrusteeVote,
			scope:      ScopeTrusteeSelectionID,
			scopeID:    "selection-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope := validEnvelope()
			envelope.ObjectType = tt.objectType
			envelope.Scope = tt.scope
			envelope.ScopeID = tt.scopeID

			if err := ValidateEnvelopeShape(envelope); err != nil {
				t.Fatalf("ValidateEnvelopeShape() error = %v; want nil", err)
			}
		})
	}
}

func TestValidateEnvelopeShapeInvalidFields(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*ObjectEnvelope)
		wantErr string
	}{
		{
			name: "empty object_id",
			mutate: func(envelope *ObjectEnvelope) {
				envelope.ObjectID = ""
			},
			wantErr: "object_id is required",
		},
		{
			name: "unknown object_type",
			mutate: func(envelope *ObjectEnvelope) {
				envelope.ObjectType = ObjectType("UnknownObject")
			},
			wantErr: "unknown object_type",
		},
		{
			name: "empty protocol_version",
			mutate: func(envelope *ObjectEnvelope) {
				envelope.ProtocolVersion = ""
			},
			wantErr: "protocol_version is required",
		},
		{
			name: "empty network_id",
			mutate: func(envelope *ObjectEnvelope) {
				envelope.NetworkID = ""
			},
			wantErr: "network_id is required",
		},
		{
			name: "wrong scope for object type",
			mutate: func(envelope *ObjectEnvelope) {
				envelope.Scope = ScopeElectionID
				envelope.ScopeID = "election-1"
			},
			wantErr: "invalid scope",
		},
		{
			name: "empty required scope_id",
			mutate: func(envelope *ObjectEnvelope) {
				envelope.ObjectType = ObjectTypeTrusteeVote
				envelope.Scope = ScopeTrusteeSelectionID
				envelope.ScopeID = ""
			},
			wantErr: "requires non-empty scope_id",
		},
		{
			name: "non-empty network scope_id",
			mutate: func(envelope *ObjectEnvelope) {
				envelope.ScopeID = "network-root"
			},
			wantErr: "requires empty scope_id",
		},
		{
			name: "empty payload",
			mutate: func(envelope *ObjectEnvelope) {
				envelope.Payload = nil
			},
			wantErr: "payload is required",
		},
		{
			name: "empty pow",
			mutate: func(envelope *ObjectEnvelope) {
				envelope.Pow = nil
			},
			wantErr: "pow is required",
		},
		{
			name: "zero created_at",
			mutate: func(envelope *ObjectEnvelope) {
				envelope.CreatedAt = 0
			},
			wantErr: "created_at must be greater than zero",
		},
		{
			name: "negative created_at",
			mutate: func(envelope *ObjectEnvelope) {
				envelope.CreatedAt = -1
			},
			wantErr: "created_at must be greater than zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope := validEnvelope()
			tt.mutate(&envelope)

			err := ValidateEnvelopeShape(envelope)
			if err == nil {
				t.Fatalf("ValidateEnvelopeShape() error = nil; want containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateEnvelopeShape() error = %q; want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func validEnvelope() ObjectEnvelope {
	return ObjectEnvelope{
		ObjectID:        "object-1",
		ObjectType:      ObjectTypeAnonymousElection,
		ProtocolVersion: "v1",
		NetworkID:       "testnet",
		Scope:           ScopeNetwork,
		Payload:         []byte("payload"),
		Pow:             []byte("pow"),
		CreatedAt:       1700000000000,
	}
}
