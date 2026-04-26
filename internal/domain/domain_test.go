package domain

import (
	"strings"
	"testing"
)

func TestObjectTypeLiteralValues(t *testing.T) {
	tests := []struct {
		name       string
		objectType ObjectType
		want       string
	}{
		{"trustee selection election", ObjectTypeTrusteeSelectionElection, "TrusteeSelectionElection"},
		{"trustee nomination", ObjectTypeTrusteeNomination, "TrusteeNomination"},
		{"trustee vote", ObjectTypeTrusteeVote, "TrusteeVote"},
		{"trustee selection result", ObjectTypeTrusteeSelectionResult, "TrusteeSelectionResult"},
		{"trustee consent", ObjectTypeTrusteeConsent, "TrusteeConsent"},
		{"anonymous election", ObjectTypeAnonymousElection, "AnonymousElection"},
		{"tally key contribution", ObjectTypeTallyKeyContribution, "TallyKeyContribution"},
		{"tally key set", ObjectTypeTallyKeySet, "TallyKeySet"},
		{"blind token request", ObjectTypeBlindTokenRequest, "BlindTokenRequest"},
		{"blind token issue", ObjectTypeBlindTokenIssue, "BlindTokenIssue"},
		{"anonymous ballot", ObjectTypeAnonymousBallot, "AnonymousBallot"},
		{"tally decryption share", ObjectTypeTallyDecryptionShare, "TallyDecryptionShare"},
		{"tally result", ObjectTypeTallyResult, "TallyResult"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.objectType); got != tt.want {
				t.Fatalf("ObjectType literal = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestScopeLiteralValues(t *testing.T) {
	tests := []struct {
		name  string
		scope Scope
		want  string
	}{
		{"network", ScopeNetwork, "network"},
		{"election id", ScopeElectionID, "election_id"},
		{"trustee selection id", ScopeTrusteeSelectionID, "trustee_selection_id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.scope); got != tt.want {
				t.Fatalf("Scope literal = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestValidationStatusLiteralValues(t *testing.T) {
	tests := []struct {
		name   string
		status ValidationStatus
		want   string
	}{
		{"pending dependencies", ValidationStatusPendingDependencies, "pending_dependencies"},
		{"pending payload evicted", ValidationStatusPendingPayloadEvicted, "pending_payload_evicted"},
		{"valid", ValidationStatusValid, "valid"},
		{"valid for tally", ValidationStatusValidForTally, "valid_for_tally"},
		{"valid but conflicted", ValidationStatusValidButConflicted, "valid_but_conflicted"},
		{"invalid", ValidationStatusInvalid, "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.status); got != tt.want {
				t.Fatalf("ValidationStatus literal = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestObjectTypeScopeMapping(t *testing.T) {
	tests := []struct {
		objectType ObjectType
		wantScope  Scope
	}{
		{ObjectTypeTrusteeSelectionElection, ScopeNetwork},
		{ObjectTypeTrusteeNomination, ScopeTrusteeSelectionID},
		{ObjectTypeTrusteeVote, ScopeTrusteeSelectionID},
		{ObjectTypeTrusteeSelectionResult, ScopeTrusteeSelectionID},
		{ObjectTypeTrusteeConsent, ScopeElectionID},
		{ObjectTypeAnonymousElection, ScopeNetwork},
		{ObjectTypeTallyKeyContribution, ScopeElectionID},
		{ObjectTypeTallyKeySet, ScopeElectionID},
		{ObjectTypeBlindTokenRequest, ScopeElectionID},
		{ObjectTypeBlindTokenIssue, ScopeElectionID},
		{ObjectTypeAnonymousBallot, ScopeElectionID},
		{ObjectTypeTallyDecryptionShare, ScopeElectionID},
		{ObjectTypeTallyResult, ScopeElectionID},
	}

	for _, tt := range tests {
		t.Run(string(tt.objectType), func(t *testing.T) {
			if !KnownObjectType(tt.objectType) {
				t.Fatalf("KnownObjectType(%q) = false; want true", tt.objectType)
			}

			gotScope, ok := ScopeForObjectType(tt.objectType)
			if !ok {
				t.Fatalf("ScopeForObjectType(%q) ok = false; want true", tt.objectType)
			}
			if gotScope != tt.wantScope {
				t.Fatalf("ScopeForObjectType(%q) scope = %q; want %q", tt.objectType, gotScope, tt.wantScope)
			}

			scopeID := "id"
			if tt.wantScope == ScopeNetwork {
				scopeID = ""
			}
			if err := ValidateScopeForObjectType(tt.objectType, tt.wantScope, scopeID); err != nil {
				t.Fatalf("ValidateScopeForObjectType(%q, %q, %q) error = %v; want nil", tt.objectType, tt.wantScope, scopeID, err)
			}
		})
	}
}

func TestUnknownObjectType(t *testing.T) {
	unknown := ObjectType("UnknownObject")

	if KnownObjectType(unknown) {
		t.Fatalf("KnownObjectType(%q) = true; want false", unknown)
	}
	if scope, ok := ScopeForObjectType(unknown); ok {
		t.Fatalf("ScopeForObjectType(%q) = %q, true; want false", unknown, scope)
	}

	err := ValidateScopeForObjectType(unknown, ScopeNetwork, "")
	assertErrorContains(t, err, "unknown object type")
}

func TestScopeIDRequired(t *testing.T) {
	tests := []struct {
		scope Scope
		want  bool
	}{
		{ScopeNetwork, false},
		{ScopeElectionID, true},
		{ScopeTrusteeSelectionID, true},
		{Scope("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.scope), func(t *testing.T) {
			if got := ScopeIDRequired(tt.scope); got != tt.want {
				t.Fatalf("ScopeIDRequired(%q) = %v; want %v", tt.scope, got, tt.want)
			}
		})
	}
}

func TestValidateScopeForObjectTypeScopeID(t *testing.T) {
	tests := []struct {
		name       string
		objectType ObjectType
		scope      Scope
		scopeID    string
		wantErr    string
	}{
		{
			name:       "network allows empty scope id",
			objectType: ObjectTypeAnonymousElection,
			scope:      ScopeNetwork,
		},
		{
			name:       "network rejects non-empty scope id",
			objectType: ObjectTypeAnonymousElection,
			scope:      ScopeNetwork,
			scopeID:    "election-1",
			wantErr:    "requires empty scope_id",
		},
		{
			name:       "election id accepts non-empty scope id",
			objectType: ObjectTypeBlindTokenRequest,
			scope:      ScopeElectionID,
			scopeID:    "election-1",
		},
		{
			name:       "election id rejects empty scope id",
			objectType: ObjectTypeBlindTokenRequest,
			scope:      ScopeElectionID,
			wantErr:    "requires non-empty scope_id",
		},
		{
			name:       "trustee selection id accepts non-empty scope id",
			objectType: ObjectTypeTrusteeVote,
			scope:      ScopeTrusteeSelectionID,
			scopeID:    "selection-1",
		},
		{
			name:       "trustee selection id rejects empty scope id",
			objectType: ObjectTypeTrusteeVote,
			scope:      ScopeTrusteeSelectionID,
			wantErr:    "requires non-empty scope_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateScopeForObjectType(tt.objectType, tt.scope, tt.scopeID)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateScopeForObjectType() error = %v; want nil", err)
				}
				return
			}
			assertErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestValidateScopeForObjectTypeUnknownScope(t *testing.T) {
	err := ValidateScopeForObjectType(ObjectTypeAnonymousElection, Scope("unknown"), "")
	assertErrorContains(t, err, "unknown scope")
}

func TestValidateScopeForObjectTypeWrongScope(t *testing.T) {
	err := ValidateScopeForObjectType(ObjectTypeAnonymousElection, ScopeElectionID, "election-1")
	assertErrorContains(t, err, "requires scope")
}

func assertErrorContains(t *testing.T, err error, want string) {
	t.Helper()

	if err == nil {
		t.Fatalf("error = nil; want containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q; want containing %q", err.Error(), want)
	}
}
