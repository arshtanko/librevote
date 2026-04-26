# Trustee Selection Protocol

This document defines the initial trustee selection protocol for LibreVote anonymous elections.

The protocol is used before the main anonymous election. Its purpose is to select a small group of trustees for the anonymous voting setup and tally process.

## Goals

- Avoid appointing trustees by a single organizer.
- Let eligible voters publicly choose trustees.
- Require every selected trustee to explicitly consent before the anonymous election starts.
- Keep trustee selection simple and deterministic for the first implementation.
- Use `blind_token_v1` as the v1 anonymous voting mode.

## Non-Goals

- Trustee selection is not anonymous in the first version.
- Trustee selection is not fully trustless.
- This document does not define the full anonymous ballot format.
- This document does not define the low-level threshold key setup equations.

## Overview

The trustee selection flow has the following phases:

```text
1. Create a trustee selection election.
2. Candidates self-nominate as potential trustees.
3. Eligible voters cast non-anonymous votes for trustee candidates.
4. Nodes deterministically compute the preliminary candidate ranking.
5. A structural `AnonymousElection` is created and bound to the preliminary result.
6. Ranked candidates publish `TrusteeConsent` for the concrete `election_id`.
7. The final trustee set is derived as the top `n` consenting candidates.
8. Final trustees run threshold key setup and publish `TallyKeySet`.
9. A valid `TallyKeySet` activates the anonymous election for issuance and voting.
```

## Parameters

The initial default trustee configuration is:

```text
n = 3 trustees
t = 2 required trustee shares
threshold = 2-of-3
```

This gives the first implementation a simple balance:

- The election can complete if one trustee is unavailable during tally.
- Privacy depends on fewer than two trustees colluding.
- All three selected trustees must consent before the anonymous election starts.

## Candidate Nomination

Trustee candidates self-nominate by publishing a signed nomination object.

```text
TrusteeNomination {
  trustee_selection_id
  candidate_public_key
  candidate_blind_token_public_key
  candidate_node_peer_id
  statement
  signature
}
```

Validation rules:

- The nomination signature must be valid for `candidate_public_key`.
- The nomination must reference an existing trustee selection election.
- `ObjectEnvelope.created_at` must be within the nomination window.
- Repeated nominations with the same `candidate_public_key` form a conflict group.
- Repeated nominations with the same `candidate_blind_token_public_key` form a conflict group.
- The proof-of-work must satisfy the required difficulty for nomination objects.

If the conflict group contains more than one valid `TrusteeNomination`, the whole group is excluded from trustee selection.

## Trustee Voting

Trustee voting is non-anonymous in the first version.

Each eligible voter may select up to `n` candidates. The top `n` candidates win, subject to the consent phase.

For the initial default configuration, each voter may select up to 3 candidates.

```text
TrusteeVote {
  trustee_selection_id
  voter_public_key
  selected_candidate_keys[]
  signature
}
```

Validation rules:

- `voter_public_key` must be included in the trustee selection voter allowlist.
- The vote signature must be valid for `voter_public_key`.
- The vote must reference an existing trustee selection election.
- `ObjectEnvelope.created_at` must be within the voting window.
- `selected_candidate_keys` must contain no duplicates.
- `selected_candidate_keys` must contain at most `n` candidates.
- Every selected candidate must have a valid nomination.
- Repeated votes from the same voter are handled by the conflict rule below.
- The proof-of-work must satisfy the required difficulty for trustee vote objects.

For the first implementation, revoting is not supported as a user-facing feature.

If one `voter_public_key` publishes multiple valid `TrusteeVote` objects for the same `trustee_selection_id`, they form a conflict group.

```text
trustee_vote_conflict_key = trustee_selection_id || voter_public_key
```

If the conflict group contains more than one valid `TrusteeVote`, no vote from that group is included in the tally. This rule does not depend on delivery order and prevents revoting through hash grinding.

## Tally Rule

Trustee election tally uses simple approval-style counting with a maximum of `n` selected candidates per voter.

Each selected candidate receives one point from a valid trustee vote.

Candidates are ranked by:

```text
1. Higher score first.
2. Lower deterministic candidate key hash first as tie-breaker.
```

The candidate key hash is computed using the canonical candidate public key encoding.

```text
candidate_rank_hash = HASH("librevote-trustee-rank-v1" || candidate_public_key)
```

The first `n` candidates in the deterministic ranking become the initially selected trustees for UI and initial consent targeting.

`TrusteeSelectionResult` fixes the full `candidate_ranking[]`, not the final trustee set. The final trustee set depends on valid consents for a concrete `AnonymousElection`.

## Trustee Consent

Ranked candidates must explicitly consent for a concrete anonymous election.

Consent is published as a signed object:

```text
TrusteeConsent {
  trustee_selection_id
  trustee_selection_result_hash
  election_id
  election_parameters_hash
  trustee_public_key
  trustee_tally_setup_public_key
  threshold_t
  trustee_count_n
  signature
}
```

Validation rules:

- The consent signature must be valid for `trustee_public_key`.
- `trustee_public_key` must have a valid `TrusteeNomination`.
- `trustee_public_key` must be present in `TrusteeSelectionResult.candidate_ranking[]`.
- `election_id` must reference a structurally valid `AnonymousElection`.
- `election_parameters_hash` must match the canonical hash of `AnonymousElection` parameters.
- `threshold_t` must equal `2` for the initial default configuration.
- `trustee_count_n` must equal `3` for the initial default configuration.
- `trustee_selection_result_hash` must match the deterministic trustee selection result.
- `trustee_tally_setup_public_key` must have a valid format.
- `trustee_tally_setup_public_key` must be unique among valid non-conflicted consents for this `election_id`.
- `ObjectEnvelope.created_at` must be within the consent window.
- The proof-of-work must satisfy the required difficulty for consent objects.

The final trustee set for `election_id` is derived after the consent phase.

```text
final_trustee_set = first n candidates from candidate_ranking with valid non-conflicted TrusteeConsent for election_id
```

For the initial threshold configuration, this means:

```text
3 selected trustees
3 required consent signatures
2 trustee shares required for tally
```

## Non-Consenting Trustees

If a candidate does not publish valid consent during the consent window, that candidate cannot enter the final trustee set for this `election_id`.

Replacement rule:

```text
1. Take `candidate_ranking[]` from the valid `TrusteeSelectionResult`.
2. Exclude candidates without valid non-conflicted `TrusteeConsent` for `election_id`.
3. Select the first n remaining candidates.
4. If fewer than n candidates remain, trustee selection does not activate the anonymous election.
```

If the consenting candidate list contains fewer than `n` trustees, the anonymous election does not get a valid `TallyKeySet` and does not become active.

## Anonymous Election Binding

The main anonymous election must bind itself to the preliminary trustee selection result. The final trustee set is fixed in `TallyKeySet`.

```text
AnonymousElection {
  election_id
  trustee_selection_id
  trustee_selection_result_hash
  threshold_t
  trustee_count_n
  eligibility_scheme
  issuance_starts_at
  issuance_ends_at
  voting_starts_at
  voting_ends_at
  tally_starts_at
  signature
}
```

Initial anonymous voting scheme:

```text
eligibility_scheme = blind_token_v1
```

`AnonymousElection` becomes operationally active only after a valid `TallyKeySet` exists. The `TallyKeySet` contains the final trustee set, consent object ids, DKG contribution object ids and `tally_public_key`.

The eligibility layer is verified with `blind_token_v1`.

## Validation Summary

A node accepts an anonymous election only if:

- The referenced trustee selection election exists.
- The trustee nominations are valid.
- The trustee votes are valid.
- The trustee ranking is computed deterministically.
- The final trustee set contains exactly `n = 3` trustees.
- The threshold is exactly `t = 2` for the initial version.
- Every selected trustee has published valid consent.
- The anonymous election references the preliminary trustee selection result.
- A valid `TallyKeySet` fixes the finalized trustee set hash and activates the anonymous election.
- The anonymous election uses a supported eligibility scheme.

## Security Notes

Trustee selection reduces reliance on a single organizer, but it does not make trustee choice fully trustless.

The system still assumes:

- The voter allowlist for trustee selection is valid.
- Fewer than `t` trustees collude before or during tally.
- At least `t` trustees remain available for the tally phase.
- The P2P network can eventually propagate all valid trustee selection objects.

Proof-of-work is used only as an anti-spam and anti-Sybil cost mechanism. It does not prove voting eligibility and does not replace signatures, allowlists, eligibility proofs, or threshold cryptography.
