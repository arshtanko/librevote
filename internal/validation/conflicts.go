package validation

import "sort"

// ClassifyConflicts applies the documented v1 conflict-group rule to already
// validated outcomes. Object-specific validators supply ConflictKeys; this
// stage only classifies groups by distinct otherwise-usable object IDs.
func ClassifyConflicts(outcomes []Outcome) []Outcome {
	classified := make([]Outcome, len(outcomes))
	for i, outcome := range outcomes {
		classified[i] = cloneOutcome(outcome)
	}

	eligibleByGroup := make(map[ConflictKey]map[string]struct{})
	for _, outcome := range classified {
		if !conflictEligible(outcome.Status) || outcome.ObjectID == "" {
			continue
		}
		for _, key := range outcome.ConflictKeys {
			if key.Group == "" || key.Key == "" {
				continue
			}
			members := eligibleByGroup[key]
			if members == nil {
				members = make(map[string]struct{})
				eligibleByGroup[key] = members
			}
			members[outcome.ObjectID] = struct{}{}
		}
	}

	for i := range classified {
		if !conflictEligible(classified[i].Status) {
			continue
		}
		for _, key := range classified[i].ConflictKeys {
			if len(eligibleByGroup[key]) > 1 {
				classified[i].Status = StatusValidButConflicted
				classified[i].ShouldRepublish = StatusValidButConflicted.RepublishEligible()
				break
			}
		}
	}

	sort.Slice(classified, func(i, j int) bool {
		return outcomeLess(classified[i], classified[j])
	})
	return classified
}

func conflictEligible(status Status) bool {
	return status == StatusValid || status == StatusValidForTally
}

func cloneOutcome(outcome Outcome) Outcome {
	out := outcome
	out.Dependencies = append([]Dependency(nil), outcome.Dependencies...)
	out.ConflictKeys = append([]ConflictKey(nil), outcome.ConflictKeys...)
	return out
}

func outcomeLess(a, b Outcome) bool {
	if a.ObjectID != b.ObjectID {
		return a.ObjectID < b.ObjectID
	}
	if a.Status != b.Status {
		return a.Status < b.Status
	}
	if a.ValidationErrorCode != b.ValidationErrorCode {
		return a.ValidationErrorCode < b.ValidationErrorCode
	}
	if a.ValidationErrorReason != b.ValidationErrorReason {
		return a.ValidationErrorReason < b.ValidationErrorReason
	}
	if len(a.Dependencies) != len(b.Dependencies) {
		return len(a.Dependencies) < len(b.Dependencies)
	}
	for i := range a.Dependencies {
		if a.Dependencies[i] != b.Dependencies[i] {
			if a.Dependencies[i].Type != b.Dependencies[i].Type {
				return a.Dependencies[i].Type < b.Dependencies[i].Type
			}
			return a.Dependencies[i].ID < b.Dependencies[i].ID
		}
	}
	if len(a.ConflictKeys) != len(b.ConflictKeys) {
		return len(a.ConflictKeys) < len(b.ConflictKeys)
	}
	for i := range a.ConflictKeys {
		if a.ConflictKeys[i] != b.ConflictKeys[i] {
			if a.ConflictKeys[i].Group != b.ConflictKeys[i].Group {
				return a.ConflictKeys[i].Group < b.ConflictKeys[i].Group
			}
			return a.ConflictKeys[i].Key < b.ConflictKeys[i].Key
		}
	}
	if a.AffectedScope.Scope != b.AffectedScope.Scope {
		return a.AffectedScope.Scope < b.AffectedScope.Scope
	}
	if a.AffectedScope.ScopeID != b.AffectedScope.ScopeID {
		return a.AffectedScope.ScopeID < b.AffectedScope.ScopeID
	}
	if a.ShouldRepublish != b.ShouldRepublish {
		return !a.ShouldRepublish && b.ShouldRepublish
	}
	return !a.ShouldRecomputeState && b.ShouldRecomputeState
}
