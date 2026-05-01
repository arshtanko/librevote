# Validation Layer

Validation is deterministic, local and implementation-friendly. It protects the MVP from malformed data and duplicate actions; it does not provide strong adversarial security.

## Pipeline

1. Decode `ObjectEnvelope`.
2. Verify envelope fields and object type.
3. Recompute `object_id` from canonical bytes.
4. Verify payload structure.
5. Check scope and dependency existence.
6. Apply contextual rules for the object type.
7. Assign conflict keys.
8. Recompute result objects before accepting them.
9. Store status, dependencies and derived cache updates in one transaction.

## Envelope Rules

- `object_id` must match canonical bytes.
- Envelope `pow` is outside canonical object bytes.
- MVP may accept zero-difficulty or disabled PoW.
- Source peer is ignored by validation.
- Local metadata is ignored by validation.

## Dependencies

Objects that reference missing parents become `pending_dependencies`. Their payloads are retained locally in the MVP so affected objects can be revalidated when dependencies arrive or statuses change.

Important dependencies:

- Trustee votes depend on trustee-selection election and nominations.
- `TrusteeSelectionResult` depends on valid nominations and votes.
- `TrusteeConsent` depends on `TrusteeSelectionResult` and `AnonymousElection`.
- `TallyKeyContribution` depends on accepted trustee consents.
- `TallyKeySet` depends on ranking, consents and contributions.
- Ballots depend on active `AnonymousElection` and `TallyKeySet`.
- `TallyResult` depends on valid ballots and any placeholder tally prerequisites.

## Result Validation

Result objects are accepted when local recomputation produces the same payload-relevant values.

For MVP this means:

- Recompute `candidate_ranking[]` for `TrusteeSelectionResult`.
- Recompute final trustee set from ranking plus valid non-conflicted consents.
- Recompute deterministic placeholder key-set data for `TallyKeySet`.
- Recompute vote counts for `TallyResult`.

## Conflicts

Conflict handling is deterministic. A conflict group with more than one otherwise valid object becomes `valid_but_conflicted`; conflicted objects are excluded from tallies and result recomputation.
