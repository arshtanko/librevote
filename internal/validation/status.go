package validation

import "fmt"

// Status identifies the local validation state assigned to an object.
type Status string

const (
	StatusPendingDependencies   Status = "pending_dependencies"
	StatusPendingPayloadEvicted Status = "pending_payload_evicted"
	StatusValid                 Status = "valid"
	StatusValidForTally         Status = "valid_for_tally"
	StatusValidButConflicted    Status = "valid_but_conflicted"
	StatusInvalid               Status = "invalid"
)

// String returns the documented storage literal for status.
func (s Status) String() string {
	return string(s)
}

// ParseStatus parses a documented validation status literal.
func ParseStatus(value string) (Status, error) {
	status := Status(value)
	if !status.Valid() {
		return "", fmt.Errorf("unknown validation status %q", value)
	}
	return status, nil
}

// Valid reports whether status is one of the documented v1 validation statuses.
func (s Status) Valid() bool {
	switch s {
	case StatusPendingDependencies,
		StatusPendingPayloadEvicted,
		StatusValid,
		StatusValidForTally,
		StatusValidButConflicted,
		StatusInvalid:
		return true
	default:
		return false
	}
}

// Final reports whether status does not wait for dependencies or reacquired payload.
func (s Status) Final() bool {
	switch s {
	case StatusValid, StatusValidForTally, StatusValidButConflicted, StatusInvalid:
		return true
	default:
		return false
	}
}

// RepublishEligible reports whether objects with status may be republished as announcements.
func (s Status) RepublishEligible() bool {
	switch s {
	case StatusValid, StatusValidForTally, StatusValidButConflicted:
		return true
	default:
		return false
	}
}

// PayloadReacquireRequired reports whether payload must be fetched again through sync.
func (s Status) PayloadReacquireRequired() bool {
	return s == StatusPendingPayloadEvicted
}
