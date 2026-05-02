package storage

import (
	"context"
	"testing"
)

func TestValidateListServableParams(t *testing.T) {
	tests := []struct {
		name    string
		scope   string
		scopeID string
		wantErr bool
		errMsg  string
	}{
		{name: "network scope with empty scope_id", scope: "network", scopeID: "", wantErr: false},
		{name: "network scope with non-empty scope_id", scope: "network", scopeID: "ts-1", wantErr: true, errMsg: `scope "network" requires empty scope_id`},
		{name: "trustee_selection_id with scope_id", scope: "trustee_selection_id", scopeID: "ts-1", wantErr: false},
		{name: "trustee_selection_id without scope_id", scope: "trustee_selection_id", scopeID: "", wantErr: true, errMsg: `scope "trustee_selection_id" requires non-empty scope_id`},
		{name: "election_id with scope_id", scope: "election_id", scopeID: "el-1", wantErr: false},
		{name: "election_id without scope_id", scope: "election_id", scopeID: "", wantErr: true, errMsg: `scope "election_id" requires non-empty scope_id`},
		{name: "empty scope", scope: "", scopeID: "", wantErr: true, errMsg: "scope is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateListServableParams(tt.scope, tt.scopeID)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if err.Error() != tt.errMsg {
					t.Fatalf("error = %q, want %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestListServableObjectRefsScopeIDValidation(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	store, err := Open(ctx, Config{DataDir: dataDir, NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	tests := []struct {
		name    string
		scope   string
		scopeID string
		wantErr bool
		errMsg  string
	}{
		{name: "trustee_selection_id without scope_id", scope: "trustee_selection_id", scopeID: "", wantErr: true, errMsg: `scope "trustee_selection_id" requires non-empty scope_id`},
		{name: "network scope with scope_id", scope: "network", scopeID: "ts-1", wantErr: true, errMsg: `scope "network" requires empty scope_id`},
		{name: "network scope with empty scope_id ok", scope: "network", scopeID: "", wantErr: false},
		{name: "trustee_selection_id with scope_id ok", scope: "trustee_selection_id", scopeID: "ts-1", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.ListServableObjectRefs(ctx, tt.scope, tt.scopeID, nil)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if err.Error() != tt.errMsg {
					t.Fatalf("error = %q, want %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}
