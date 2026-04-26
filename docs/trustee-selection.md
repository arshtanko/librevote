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
- This document does not define the final threshold cryptography implementation.

## Overview

The trustee selection flow has the following phases:

```text
1. Create a trustee selection election.
2. Candidates self-nominate as potential trustees.
3. Eligible voters cast non-anonymous votes for trustee candidates.
4. Nodes deterministically compute the top candidates.
5. Selected trustees explicitly confirm participation.
6. If a selected trustee does not consent, the next ranked candidate is substituted.
7. Once all selected trustees consent, the anonymous election can be created.
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
  created_at
  pow
  signature
}
```

Validation rules:

- The nomination signature must be valid for `candidate_public_key`.
- The nomination must reference an existing trustee selection election.
- The nomination must be submitted within the nomination window.
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
  created_at
  pow
  signature
}
```

Validation rules:

- `voter_public_key` must be included in the trustee selection voter allowlist.
- The vote signature must be valid for `voter_public_key`.
- The vote must reference an existing trustee selection election.
- The vote must be submitted within the voting window.
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

The first `n` candidates in the deterministic ranking become the initially selected trustees.

## Trustee Consent

All selected trustees must explicitly consent before the anonymous election can start.

Consent is published as a signed object:

```text
TrusteeConsent {
  trustee_selection_id
  trustee_selection_result_hash
  anonymous_election_id
  trustee_public_key
  selected_trustees_hash
  threshold_t
  trustee_count_n
  consented_at
  pow
  signature
}
```

Validation rules:

- The consent signature must be valid for `trustee_public_key`.
- `trustee_public_key` must be in the current selected trustee set.
- `threshold_t` must equal `2` for the initial default configuration.
- `trustee_count_n` must equal `3` for the initial default configuration.
- `selected_trustees_hash` must match the canonical selected trustee set.
- `trustee_selection_result_hash` must match the deterministic trustee selection result.
- The consent must be submitted within the consent window.
- The proof-of-work must satisfy the required difficulty for consent objects.

The anonymous election is valid only if every trustee in the final selected trustee set has a valid consent object.

```text
required_consents = all selected trustees
```

For the initial threshold configuration, this means:

```text
3 selected trustees
3 required consent signatures
2 trustee shares required for tally
```

## Non-Consenting Trustees

If a selected trustee does not publish valid consent during the consent window, that candidate is replaced by the next candidate in the deterministic ranking.

Replacement rule:

```text
1. Remove the non-consenting selected trustee.
2. Select the next highest-ranked candidate not already in the trustee set.
3. Require consent from the replacement candidate.
4. Repeat until the trustee set has n consenting trustees or the candidate list is exhausted.
```

If the candidate list is exhausted before `n` trustees consent, the trustee selection fails and the anonymous election cannot be created from that selection result.

## Anonymous Election Binding

The main anonymous election must bind itself to the finalized trustee selection result.

```text
AnonymousElection {
  election_id
  trustee_selection_id
  trustee_selection_result_hash
  trustees[]
  threshold_t
  trustee_count_n
  eligibility_scheme
  eligibility_config
  tally_public_key
  starts_at
  ends_at
  rules
  signature
}
```

Initial anonymous voting scheme:

```text
eligibility_scheme = blind_token_v1
```

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
- The anonymous election references the finalized trustee set hash.
- The anonymous election uses a supported eligibility scheme.

## Security Notes

Trustee selection reduces reliance on a single organizer, but it does not make trustee choice fully trustless.

The system still assumes:

- The voter allowlist for trustee selection is valid.
- Fewer than `t` trustees collude before or during tally.
- At least `t` trustees remain available for the tally phase.
- The P2P network can eventually propagate all valid trustee selection objects.

Proof-of-work is used only as an anti-spam and anti-Sybil cost mechanism. It does not prove voting eligibility and does not replace signatures, allowlists, eligibility proofs, or threshold cryptography.
