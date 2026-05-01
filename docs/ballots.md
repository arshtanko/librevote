# Ballots

MVP ballots are simple local vote objects. They demonstrate casting, validation, conflict handling and tallying; they do not provide full anonymity.

## Ballot Readiness

Ballots may be cast when:

- `AnonymousElection` is valid.
- `TallyKeySet` is valid.
- The election is within any configured local voting window, if the schema has one.

## Ballot Contents

`AnonymousBallot` should contain the implemented election reference and vote choice fields. MVP may store plaintext choices or deterministic encoded choices.

The object should not depend on network peer metadata.

## Duplicate Handling

Use a conflict key to prevent accidental duplicate ballots. The key may be based on local voter id, local token id or another deterministic field available in the current schema.

Conflicted ballots are excluded from tallying.
