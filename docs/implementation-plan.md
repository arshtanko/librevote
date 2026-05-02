# MVP Implementation Plan

This plan prioritizes finishing a course-project demo with mandatory minimal peer-to-peer object synchronization. Existing foundation work should be reused rather than rewritten.

## Rules

- Do documentation and implementation in English.
- Keep Go code compatible with existing object envelopes, canonical IDs, storage and validation statuses.
- Include minimal P2P object sync in MVP.
- Keep the local demo unblocked by advanced networking, but implement Kademlia DHT discovery and GossipSub announcements as follow-up networking milestones.
- Do not block the local MVP demo on production networking hardening, blind tokens, DKG, threshold crypto or full anonymity.
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

## Stage 7. Kademlia DHT Peer Discovery

Goal: replace static-only peers with libp2p Kademlia discovery while preserving the existing object sync API.

Build:

- Node identity based on a persistent local libp2p private key.
- libp2p host creation with listen addresses and bootstrap peer configuration.
- Kademlia DHT initialization in server mode for reachable nodes and client mode for local/demo nodes when needed.
- Rendezvous namespace for LibreVote MVP nodes, such as `/librevote/<network_id>/v1`.
- Peer discovery loop that finds peers through the DHT and adds them to the sync peer set.
- CLI flags for `node serve` or a future `node start`: listen address, bootstrap peers, rendezvous string and optional private key path.

Completion criteria:

- Two nodes started with a shared bootstrap peer can discover each other without manually passing every peer URL.
- Discovery produces peer addresses that the existing HTTP/object sync layer or its replacement can use.
- Peer identity is stored locally and remains stable across restarts.
- Failure to reach the DHT does not corrupt local storage or validation state.

Implementation notes:

- Keep object validation and storage unchanged; Kademlia only discovers peers.
- Do not treat peer ID or DHT records as domain authority.
- Keep static peers as a fallback for demos and tests.
- Add integration tests with in-process libp2p hosts where practical; otherwise keep unit tests around peer-set updates and configuration parsing.

## Stage 8. GossipSub Object Announcements

Goal: use GossipSub for live object announcements while keeping direct object fetch and validation as the authority path.

Build:

- GossipSub topic per network, such as `librevote.<network_id>.objects.v1`.
- Compact object announcement message containing `object_id`, `object_type`, `scope`, `scope_id` and `created_at`.
- Announcement publisher for newly valid, valid-for-tally or valid-but-conflicted local objects.
- Announcement subscriber that checks local storage and requests missing objects through direct fetch.
- Duplicate suppression by `object_id` without blocking re-fetch of retained pending or previously evicted payloads.
- Basic message size limits and malformed announcement rejection.

Completion criteria:

- When node A creates an object, node B learns the object ID through GossipSub and fetches the full envelope through direct sync.
- GossipSub never carries full domain payloads.
- Receiving an announcement does not mark an object valid; only fetched envelopes that pass validation can become usable.
- The existing HTTP/static sync can still be used as a fallback and for initial catch-up.

Implementation notes:

- Start with announcements only; keep inventory sync for catch-up after reconnects.
- Do not add scoring, mesh tuning or adversarial hardening until after the course-project demo works.
- Tests should cover publish/subscribe with two in-process nodes and verify full payload fetch still goes through `IngestSyncEnvelope`.

## Stage 9. Networking Integration Demo

Goal: demonstrate the full P2P path with discovery, announcements and direct fetch.

Work:

- Extend the demo script to start two or three nodes with libp2p identities.
- Use Kademlia to discover peers or join through one bootstrap peer.
- Use GossipSub announcements for newly created election, ballot and tally objects.
- Keep direct HTTP/static sync or direct libp2p fetch as the recovery path for missed announcements.

Completion criteria:

- A fresh node can join, discover peers, receive announcements, fetch objects and display the final tally.
- The old local CLI workflow still works for deterministic test setup.
