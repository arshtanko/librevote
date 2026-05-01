# Trustee Selection

Trustee selection is public and deterministic in the MVP.

## Flow

1. Create `TrusteeSelectionElection`.
2. Create `TrusteeNomination` objects for candidates.
3. Create `TrusteeVote` objects.
4. Build `TrusteeSelectionResult` with `candidate_ranking[]`.
5. Create `TrusteeConsent` objects for ranked candidates who agree to serve.
6. Derive the final trustee set from ranking plus valid non-conflicted consents.

## Ranking

Votes are counted according to the simplest rule supported by the implementation. Ties must be broken deterministically.

`TrusteeSelectionResult` is accepted only when local recomputation matches the stored ranking.

## MVP Consents

Consents are simple affirmative objects. They do not need advanced trustee identity proofs beyond fields already required by the current schema.

## Contributions

`TallyKeyContribution` objects are deterministic placeholders. They exist to preserve the activation flow that leads to `TallyKeySet`.
