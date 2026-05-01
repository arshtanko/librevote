# CLI

The CLI is the primary MVP interface. It may call local services directly and does not need a daemon/control API, but MVP P2P synchronization is provided by node mode.

## Required Workflow Commands

Names may follow the existing command style, but the workflow must support:

- Initialize storage and local identity.
- Start a node with static peers or simple discovery for MVP P2P sync.
- Create trustee-selection election and anonymous election records.
- Nominate trustee candidates.
- Cast trustee-selection votes.
- Build and display `TrusteeSelectionResult`.
- Create trustee consents.
- Create placeholder tally contributions and `TallyKeySet`.
- Cast ballots.
- Build and display `TallyResult`.

## Command Behavior

- Mutating commands create domain objects, ingest them, validate them and update derived state.
- Read commands query derived state or recompute from retained objects when practical.
- Commands should print object IDs for created objects.
- Demo commands may combine several low-level steps when that shortens the course-project workflow.
- CLI-created objects must be persisted through the same storage and validation paths used for objects received from peers.

## Example MVP Flow

```text
librevote init
librevote node start --peer <addr>
librevote election create
librevote trustee nominate Alice
librevote trustee nominate Bob
librevote trustee vote --voter voter1 --candidate Alice
librevote trustee result build
librevote trustee consent Alice
librevote tally-key build
librevote ballot cast --voter voter1 --choice yes
librevote tally build
librevote tally show
```

The exact flags may differ from implementation, but the end-to-end flow must stay this short.
