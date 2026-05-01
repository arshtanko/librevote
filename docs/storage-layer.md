# Storage Layer

SQLite is the MVP source of local persistence. Domain authority still comes from retained object bytes plus deterministic validation, not from hand-edited derived tables.

## Responsibilities

- Store `ObjectEnvelope` metadata.
- Store retained payload bytes.
- Store validation status and errors.
- Store dependency edges.
- Store conflict keys and conflict-group status.
- Store derived caches for fast CLI queries.
- Store local identities and simple key material if needed by the implementation.

## Process Lock

The storage layer should keep a process lock for safe local mutation. For MVP, direct CLI commands and node mode must coordinate so two mutating processes do not write the same database at the same time.

## Retention

- Keep payloads for `pending_dependencies` objects so they can be revalidated when dependencies arrive or statuses change.
- Keep payloads for `valid`, `valid_for_tally` and `valid_but_conflicted` objects.
- Invalid payload retention is optional for diagnostics.
- `pending_payload_evicted` remains a supported legacy/foundation status. MVP nodes may reacquire missing payloads through direct object fetch, but should not proactively evict pending payloads.

## Derived State

Derived state is cache. Rebuild must be possible from retained valid objects.
