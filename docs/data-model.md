# Data Model

The MVP keeps the existing object model and validation vocabulary while simplifying security semantics.

## Scopes

- `network`: root objects, including `TrusteeSelectionElection` and `AnonymousElection`.
- `trustee_selection_id`: trustee selection child objects and results tied to a trustee selection.
- `election_id`: election child objects tied to an anonymous election, such as consents, key contributions, key sets, ballots and tally artifacts.

## Validation Statuses

- `pending_dependencies`: dependencies are missing or not validated yet.
- `pending_payload_evicted`: metadata exists but payload must be reacquired before revalidation.
- `valid`: object is structurally and contextually valid.
- `valid_for_tally`: object is valid and included in local tally inputs.
- `valid_but_conflicted`: object is well formed but conflicts with another object in the same conflict group.
- `invalid`: object must not be used.

These statuses are retained because they match current validation and storage foundation work.

## Conflict Keys

The MVP uses conflict keys to reject duplicate local actions deterministically:

- One nomination per trustee candidate per trustee-selection election if the schema requires uniqueness.
- One trustee-selection vote per voter per trustee-selection election.
- One trustee consent per trustee candidate per anonymous election.
- One tally key contribution per trustee per anonymous election.
- One ballot per local voter identity or ballot token, depending on the available implementation.
- One tally result per anonymous election result variant.

If more than one valid object exists for the same conflict key, the group becomes `valid_but_conflicted` and is excluded from result computation.

## Trustee Phase Objects

`TrusteeSelectionElection` defines the public trustee-selection contest.

`TrusteeNomination` registers a trustee candidate.

`TrusteeVote` ranks or selects candidates according to the implemented payload.

`TrusteeSelectionResult` stores deterministic `candidate_ranking[]`. It is not authority by itself; validators recompute it from valid nominations and votes.

## Ballot Phase Objects

`AnonymousElection` is the structural root for the ballot phase. In MVP it may be simple and local.

`TrusteeConsent` records that a ranked candidate agrees to serve.

`TallyKeyContribution` is a deterministic placeholder contribution for MVP.

`TallyKeySet` marks the election ready for ballot casting. It is accepted only when local recomputation from ranking, consents and contributions matches.

`BlindTokenRequest` and `BlindTokenIssue` are compatibility objects. MVP may skip them or create deterministic local placeholders.

`AnonymousBallot` stores a simple vote choice. MVP does not claim full anonymity.

`TallyDecryptionShare` is a placeholder if the current schema requires it.

`TallyResult` stores the local deterministic tally. `invalid_ballot_count` is local diagnostic state, not authoritative result data.
