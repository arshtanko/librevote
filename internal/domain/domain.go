package domain

import "fmt"

// ObjectType identifies a v1 domain object payload type.
type ObjectType string

const (
	ObjectTypeTrusteeSelectionElection ObjectType = "TrusteeSelectionElection"
	ObjectTypeElectionInvite           ObjectType = "ElectionInvite"
	ObjectTypeElectionAcceptance       ObjectType = "ElectionAcceptance"
	ObjectTypeElectionDecline          ObjectType = "ElectionDecline"
	ObjectTypeTrusteeNomination        ObjectType = "TrusteeNomination"
	ObjectTypeTrusteeVote              ObjectType = "TrusteeVote"
	ObjectTypeTrusteeSelectionResult   ObjectType = "TrusteeSelectionResult"
	ObjectTypeTrusteeConsent           ObjectType = "TrusteeConsent"
	ObjectTypeAnonymousElection        ObjectType = "AnonymousElection"
	ObjectTypeTallyKeyContribution     ObjectType = "TallyKeyContribution"
	ObjectTypeTallyKeySet              ObjectType = "TallyKeySet"
	ObjectTypeBlindTokenRequest        ObjectType = "BlindTokenRequest"
	ObjectTypeBlindTokenIssue          ObjectType = "BlindTokenIssue"
	ObjectTypeAnonymousBallot          ObjectType = "AnonymousBallot"
	ObjectTypeTallyDecryptionShare     ObjectType = "TallyDecryptionShare"
	ObjectTypeTallyResult              ObjectType = "TallyResult"
)

// Scope identifies the sync and indexing scope for an object envelope.
type Scope string

const (
	ScopeNetwork            Scope = "network"
	ScopeElectionID         Scope = "election_id"
	ScopeTrusteeSelectionID Scope = "trustee_selection_id"
)

// ValidationStatus identifies the local validation state for an object.
type ValidationStatus string

const (
	ValidationStatusPendingDependencies   ValidationStatus = "pending_dependencies"
	ValidationStatusPendingPayloadEvicted ValidationStatus = "pending_payload_evicted"
	ValidationStatusValid                 ValidationStatus = "valid"
	ValidationStatusValidForTally         ValidationStatus = "valid_for_tally"
	ValidationStatusValidButConflicted    ValidationStatus = "valid_but_conflicted"
	ValidationStatusInvalid               ValidationStatus = "invalid"
)

var objectTypeScopes = map[ObjectType]Scope{
	ObjectTypeTrusteeSelectionElection: ScopeNetwork,
	ObjectTypeElectionInvite:           ScopeNetwork,
	ObjectTypeElectionAcceptance:       ScopeNetwork,
	ObjectTypeElectionDecline:          ScopeNetwork,
	ObjectTypeTrusteeNomination:        ScopeTrusteeSelectionID,
	ObjectTypeTrusteeVote:              ScopeTrusteeSelectionID,
	ObjectTypeTrusteeSelectionResult:   ScopeTrusteeSelectionID,
	ObjectTypeAnonymousElection:        ScopeNetwork,
	ObjectTypeTrusteeConsent:           ScopeElectionID,
	ObjectTypeTallyKeyContribution:     ScopeElectionID,
	ObjectTypeTallyKeySet:              ScopeElectionID,
	ObjectTypeBlindTokenRequest:        ScopeElectionID,
	ObjectTypeBlindTokenIssue:          ScopeElectionID,
	ObjectTypeAnonymousBallot:          ScopeElectionID,
	ObjectTypeTallyDecryptionShare:     ScopeElectionID,
	ObjectTypeTallyResult:              ScopeElectionID,
}

// KnownObjectType reports whether objectType is a v1 domain object type.
func KnownObjectType(objectType ObjectType) bool {
	_, ok := objectTypeScopes[objectType]
	return ok
}

// ScopeForObjectType returns the documented scope for objectType.
func ScopeForObjectType(objectType ObjectType) (Scope, bool) {
	scope, ok := objectTypeScopes[objectType]
	return scope, ok
}

// ScopeIDRequired reports whether scope requires a non-empty scope_id.
func ScopeIDRequired(scope Scope) bool {
	return scope == ScopeElectionID || scope == ScopeTrusteeSelectionID
}

// ValidateScopeForObjectType validates the object type, scope, and scope_id tuple.
func ValidateScopeForObjectType(objectType ObjectType, scope Scope, scopeID string) error {
	expectedScope, ok := ScopeForObjectType(objectType)
	if !ok {
		return fmt.Errorf("unknown object type %q", objectType)
	}
	if !knownScope(scope) {
		return fmt.Errorf("unknown scope %q", scope)
	}
	if scope != expectedScope {
		return fmt.Errorf("object type %q requires scope %q, got %q", objectType, expectedScope, scope)
	}
	if ScopeIDRequired(scope) {
		if scopeID == "" {
			return fmt.Errorf("scope %q requires non-empty scope_id", scope)
		}
		return nil
	}
	if scopeID != "" {
		return fmt.Errorf("scope %q requires empty scope_id", scope)
	}
	return nil
}

func knownScope(scope Scope) bool {
	switch scope {
	case ScopeNetwork, ScopeElectionID, ScopeTrusteeSelectionID:
		return true
	default:
		return false
	}
}
