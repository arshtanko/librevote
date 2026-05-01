# LibreVote MVP Architecture

LibreVote MVP is a course-project voting application with mandatory minimal peer-to-peer object synchronization. The goal is to finish a working end-to-end demo quickly while preserving the already implemented foundation: object envelopes, canonical IDs, SQLite storage, validation statuses, dependencies and conflict handling.

The MVP may be demonstrated on one machine with multiple local nodes, but P2P synchronization is part of the MVP. Hard transport security, production networking hardening, blind-token privacy, DKG, threshold cryptography and full anonymity are out of MVP. They may remain as documented names or placeholders where that keeps the current object model compatible.

## Core Decisions

- One CLI binary: `librevote`.
- Each node uses one local SQLite database for objects and derived state.
- CLI commands may call local application services directly.
- A long-running node process is required for MVP P2P sync; direct CLI service calls remain acceptable for local development and tests.
- MVP P2P uses static peer configuration or simple discovery.
- MVP P2P exchanges object announcements or inventory, fetches missing objects directly from peers, stores received objects in SQLite and validates after receipt.
- All domain records are stored as immutable `ObjectEnvelope` values.
- `object_id` is content-addressed and deterministic.
- Validation is deterministic and local.
- Result objects are convenience objects and are accepted only when local recomputation matches.
- Trustee selection is public and simple.
- Ballots are simple local objects; MVP does not guarantee voter anonymity.
- Tallying is local and deterministic.

## MVP Workflow

```text
initialize node/storage
configure peers
start node P2P sync
create election
nominate trustee candidates
cast trustee-selection votes
produce TrusteeSelectionResult
create TrusteeConsent objects
create deterministic TallyKeyContribution objects
create deterministic TallyKeySet
cast simple ballots
tally locally
display result through CLI
```

## Object Envelope

Every domain object is wrapped in `ObjectEnvelope`:

```text
ObjectEnvelope {
  object_id
  object_type
  protocol_version
  network_id
  scope
  scope_id
  payload
  pow
  created_at
}
```

`object_id` is computed from canonical object bytes:

```text
object_id = HASH("librevote-object-id-v1" || canonical_object_bytes)
```

Canonical object bytes include protocol version, network id, object type, scope, scope id, created time and canonical payload. They do not include `object_id`, envelope `pow`, source peer, storage metadata or validation metadata.

## Domain Objects

The MVP keeps these object types so existing implementation work remains useful:

- `TrusteeSelectionElection`
- `TrusteeNomination`
- `TrusteeVote`
- `TrusteeSelectionResult`
- `TrusteeConsent`
- `AnonymousElection`
- `TallyKeyContribution`
- `TallyKeySet`
- `BlindTokenRequest`
- `BlindTokenIssue`
- `AnonymousBallot`
- `TallyDecryptionShare`
- `TallyResult`

For MVP, blind-token and threshold-related objects are compatibility shells. They are validated structurally and may be produced by deterministic local placeholder logic.

## Minimal P2P Sync

MVP networking is intentionally small:

- Nodes connect to configured static peers or peers found by simple local discovery.
- Nodes announce known object IDs or exchange compact object inventories.
- Nodes fetch missing `ObjectEnvelope` payloads directly from peers.
- Received objects are persisted to SQLite before or during validation according to the storage rules.
- Validation statuses, dependency tracking and conflict keys determine whether received objects become usable.
- Source peer is transport metadata and never domain authorship.

## Out Of MVP

- Full GossipSub mesh behavior.
- Peer scoring, NAT traversal, advanced sync cursors and production transport hardening.
- Blind-token issuance privacy.
- DKG and threshold cryptography.
- Encrypted ballots and decryption shares.
- Strong anonymity, coercion resistance or receipt-freeness.
- Adversarial network threat resistance.
