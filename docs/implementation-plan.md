# MVP Implementation Plan

This plan prioritizes finishing a course-project demo with mandatory minimal peer-to-peer object synchronization. Existing foundation work should be reused rather than rewritten.

## Rules

- Do documentation and implementation in English.
- Keep Go code compatible with existing object envelopes, canonical IDs, storage and validation statuses.
- Include minimal P2P object sync in MVP.
- Do not block MVP on GossipSub, production networking hardening, blind tokens, DKG, threshold crypto or full anonymity.
- Prefer direct CLI-to-service calls for command implementation when that is faster, while still providing node mode for MVP P2P sync.

## Stage 1. Foundation Already In Place

Status: implemented or partially implemented on `implementation/foundation`.

Keep and use:

- Project layout and Go module foundation.
- `ObjectEnvelope` and object type definitions.
- Canonical object bytes and `object_id` calculation.
- Validation statuses, dependency records and conflict keys.
- SQLite storage and retained object payloads.
- Basic validation/storage APIs.

Do not rewrite this stage unless a focused bug blocks the MVP workflow.

## Stage 2. Local Application Services

Goal: expose simple service functions that create, ingest, validate and query MVP objects.

Build services for:

- Initialize storage and local demo identity.
- Create elections.
- Create nominations and trustee-selection votes.
- Build trustee-selection result.
- Create trustee consents, placeholder contributions and key set.
- Cast ballots.
- Build tally result.

Completion criteria:

- Each service can be called directly for local tests and can also ingest objects received from P2P sync.
- Each mutating service persists objects through existing storage/validation paths.

## Stage 3. CLI Workflow

Goal: provide a short end-to-end CLI demo.

Commands must cover the workflow in `docs/cli.md`.

Completion criteria:

- A user can run the full election flow from an empty data directory.
- Created object IDs and final results are printed clearly.
- The CLI can operate without a daemon protocol, but node mode is still required for P2P sync.

## Stage 4. Minimal P2P Object Sync

Goal: synchronize immutable `ObjectEnvelope` values between MVP nodes.

Build:

- Static peer configuration or simple discovery.
- Object announcements or inventory exchange.
- Direct object fetch for missing object IDs.
- Storage of received objects in SQLite.
- Validation after receipt using existing statuses, dependencies and conflict keys.

Completion criteria:

- Two or more local nodes can exchange election, trustee-selection, consent, ballot and result objects.
- A node that receives an unknown object persists it and validates or marks dependencies deterministically.
- P2P sync is required for the MVP demo, but advanced GossipSub behavior and hardening are not required.

## Stage 5. Ballots And Local Tally

Goal: make ballot casting and tallying work reliably.

Implementation may use plaintext choices or simple encoded choices.

Completion criteria:

- Duplicate ballots are handled by conflict keys.
- Invalid/conflicted ballots are excluded.
- `TallyResult` is verified by local recomputation.

## Stage 6. Demo Polish

Goal: make the course-project presentation reliable.

Work:

- Add concise help text and examples.
- Add targeted tests for the MVP happy path and duplicate/conflict cases.
- Add a sample script or documented command sequence if useful.
- Keep advanced networking hardening and advanced crypto disabled or stubbed.
