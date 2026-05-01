# AGENTS.md

Instructions for coding agents working in this repository.

## Project

LibreVote is now scoped as a fast course-project MVP. The MVP includes mandatory minimal peer-to-peer object synchronization plus SQLite storage, deterministic validation, CLI workflow, local tallying and simple result display.

The English `docs/*.md` files are authoritative. Legacy `docs/*.ru.md` files are kept only for reference and must be ignored unless the user explicitly asks to use or update them.

## Authoritative Documents

Start with:

- `docs/architecture.md`: MVP architecture, workflow and scope.
- `docs/data-model.md`: object model, statuses and dependencies retained for implementation compatibility.
- `docs/validation-layer.md`: deterministic local validation rules.
- `docs/storage-layer.md`: SQLite object log and local derived state.
- `docs/network-layer.md`: required minimal MVP P2P object synchronization.
- `docs/cli.md`: CLI-first MVP workflow.
- `docs/implementation-plan.md`: short MVP milestone plan.

Read the other English layer docs when working in that area.

## MVP Invariants

- Do not modify Go code when the user asks for documentation-only work.
- Preserve the existing object-envelope, canonical object ID, validation status, dependency and conflict-key concepts.
- `ObjectEnvelope.pow` remains the only object PoW location; MVP PoW may be disabled or trivially configured.
- `object_id` is computed from canonical object bytes without `object_id`, envelope `pow`, source peer or local metadata.
- Result objects are convenience objects and are verified by deterministic local recomputation.
- `AnonymousElection` remains the structural root for the ballot phase.
- `TallyKeySet` marks an anonymous election as ready for MVP ballot casting, but it may be produced by deterministic placeholder logic.
- `TrusteeSelectionResult` fixes `candidate_ranking[]`; final MVP trustees are derived from that ranking plus valid `TrusteeConsent` objects.
- MVP nodes must support minimal P2P sync using static peers or simple discovery, announcements or inventory exchange, direct object fetch, SQLite storage of received objects and validation after receipt.
- CLI operations may call local services directly for local commands and tests, but direct CLI mode does not remove the required node sync path.

## Documentation Rules

- Keep MVP docs decisive, short and implementation-oriented.
- Keep P2P as a core MVP requirement while avoiding full GossipSub, production network hardening, DKG-first, blind-token-first or hard-security requirements unless the user asks.
- All authoritative docs are English.
- If a concept is out of MVP, describe the local placeholder or mark it out of MVP.

## Engineering Rules

- Inspect relevant English docs before implementing or changing behavior.
- Prefer the smallest correct change.
- Avoid rewrites of already implemented foundation code unless required.
- Do not introduce backward-compatibility code unless there is a concrete need.
- Do not revert or overwrite unrelated user changes.
- Do not commit unless the user explicitly asks.
- Use `apply_patch` for manual edits.
- Run targeted verification after changes.
