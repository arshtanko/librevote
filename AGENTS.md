# AGENTS.md

Instructions for coding agents working in this repository.

## Project

LibreVote is a decentralized P2P internet voting system.

The current repository state is architecture-first. The `docs/` directory is the source of truth for v1 design decisions. Implementation work must preserve the documented architecture unless the user explicitly asks to change the architecture.

## Authoritative Documents

Start with:

- `docs/architecture.md`: top-level v1 architecture and invariants.
- `docs/data-model.ru.md`: domain objects, scopes, validation statuses and object graph.
- `docs/validation-layer.ru.md`: validation pipeline, dependencies, conflicts and revalidation.
- `docs/protocol-messages.ru.md`: object envelope, direct protocols and message schemas.
- `docs/network-layer.ru.md`: discovery, gossip, direct sync and peer behavior.
- `docs/storage-layer.ru.md`: SQLite storage, retention and local state.
- `docs/crypto-layer.ru.md`: canonical bytes, signatures, PoW, blind tokens, DKG and tally crypto.
- `docs/blind-token-issuance.ru.md`: issuance flow and privacy limits.
- `docs/tally-layer.ru.md`: trustee selection tally and anonymous tally.
- `docs/node-lifecycle.ru.md`: node startup, workers and local roles.
- `docs/cli.ru.md`: CLI boundary and command behavior.
- `docs/threat-model.ru.md`: trust assumptions and residual risks.

## Required Architecture Invariants

Do not violate these invariants:

- `AnonymousElection` is a structural root object.
- `TallyKeySet` activates an anonymous election.
- `TrusteeSelectionResult` is preliminary and fixes `candidate_ranking[]`, not the final trustee set.
- Final trustee set is derived from `candidate_ranking[]` plus valid non-conflicted `TrusteeConsent` objects.
- `TallyKeySet` is accepted only by local recomputation of activation data.
- All threshold checks require distinct trustees.
- `ObjectEnvelope.pow` is the only object PoW location; domain payloads do not contain PoW.
- `object_id` is computed from canonical object bytes without `object_id`, envelope `pow`, source peer or local metadata.
- GossipSub carries only `ObjectAnnouncement`; full payloads are fetched by direct sync.
- `pending_payload_evicted` must be reacquirable through sync and must not be blocked by duplicate suppression.
- `invalid_ballot_count` is local diagnostic state and is not part of authoritative `TallyResult`.
- `AnonymousBallot` must not contain `voter_public_key`, `peer_id` or `node_public_key`.
- `BlindTokenIssue` public fields must bind to the referenced `BlindTokenRequest`.
- Public validators do not decrypt `BlindTokenIssue.encrypted_payload`.
- CLI mutating domain operations go through the running node local control API.

## Documentation Rules

- Keep v1 docs decisive and normative.
- Do not add speculative sections such as future work, optional paths, fallback behavior, open questions or TODOs.
- Prefer Russian for architecture documents unless editing an existing English file.
- Keep terminology consistent with `docs/architecture.md`.
- If changing one architectural invariant, update all affected layer docs in the same change.

## Engineering Rules

- Inspect the relevant docs before implementing or changing behavior.
- Prefer the smallest correct change.
- Do not introduce backwards-compatibility code unless there is a concrete need.
- Do not revert or overwrite unrelated user changes.
- Do not commit unless the user explicitly asks.
- Use `apply_patch` for manual edits.
- Run targeted verification after changes.

## Implementation Notes

- Treat local derived state as cache.
- Treat result objects as convenience objects, not authority.
- Treat source peer as network metadata, never as domain authorship.
- Keep object validation deterministic and independent of delivery order.
- Keep storage retention behavior aligned with validation statuses.
- Keep CLI, node lifecycle and storage process-lock behavior aligned.
