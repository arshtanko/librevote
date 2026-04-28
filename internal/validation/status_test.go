package validation

import "testing"

func TestStatusLiteralStringAndParse(t *testing.T) {
	tests := []struct {
		name   string
		status Status
		want   string
	}{
		{"pending dependencies", StatusPendingDependencies, "pending_dependencies"},
		{"pending payload evicted", StatusPendingPayloadEvicted, "pending_payload_evicted"},
		{"valid", StatusValid, "valid"},
		{"valid for tally", StatusValidForTally, "valid_for_tally"},
		{"valid but conflicted", StatusValidButConflicted, "valid_but_conflicted"},
		{"invalid", StatusInvalid, "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.String(); got != tt.want {
				t.Fatalf("String() = %q; want %q", got, tt.want)
			}

			got, err := ParseStatus(tt.want)
			if err != nil {
				t.Fatalf("ParseStatus(%q) error = %v; want nil", tt.want, err)
			}
			if got != tt.status {
				t.Fatalf("ParseStatus(%q) = %q; want %q", tt.want, got, tt.status)
			}
		})
	}
}

func TestParseStatusRejectsUnknown(t *testing.T) {
	if _, err := ParseStatus("stale"); err == nil {
		t.Fatal("ParseStatus(stale) error = nil; want error")
	}
}

func TestStatusHelpers(t *testing.T) {
	tests := []struct {
		status    Status
		valid     bool
		final     bool
		republish bool
		reacquire bool
	}{
		{StatusPendingDependencies, true, false, false, false},
		{StatusPendingPayloadEvicted, true, false, false, true},
		{StatusValid, true, true, true, false},
		{StatusValidForTally, true, true, true, false},
		{StatusValidButConflicted, true, true, true, false},
		{StatusInvalid, true, true, false, false},
		{Status("unknown"), false, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.status.String(), func(t *testing.T) {
			if got := tt.status.Valid(); got != tt.valid {
				t.Fatalf("Valid() = %v; want %v", got, tt.valid)
			}
			if got := tt.status.Final(); got != tt.final {
				t.Fatalf("Final() = %v; want %v", got, tt.final)
			}
			if got := tt.status.RepublishEligible(); got != tt.republish {
				t.Fatalf("RepublishEligible() = %v; want %v", got, tt.republish)
			}
			if got := tt.status.PayloadReacquireRequired(); got != tt.reacquire {
				t.Fatalf("PayloadReacquireRequired() = %v; want %v", got, tt.reacquire)
			}
		})
	}
}
