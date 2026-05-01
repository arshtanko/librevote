# Node Lifecycle

The MVP requires a runnable node mode for peer-to-peer object synchronization. Direct CLI service calls remain valid for local development, tests and commands that operate on one node's SQLite database.

## Direct CLI Mode

Each command may:

1. Open the SQLite database.
2. Acquire the process lock for mutating operations.
3. Run the local service.
4. Validate and persist generated objects.
5. Release the lock.

Direct CLI mode does not replace MVP P2P sync. Objects created this way become available to peers when the node mode announces or lists retained objects.

## Node Mode

A node process keeps storage, validation and network sync open.

It must:

1. Open the SQLite database.
2. Acquire the process lock for mutating local state.
3. Start minimal transport listeners or outbound peer connections.
4. Connect to static peers or run simple discovery.
5. Announce local object IDs or exchange object inventories.
6. Fetch missing objects directly from peers.
7. Store received objects in SQLite.
8. Validate received objects and update local derived state.

A local control API is acceptable but not required for MVP if CLI commands can otherwise create local objects.

## Startup Checks

- Ensure data directory exists.
- Ensure SQLite schema is migrated.
- Ensure local identity or demo keys exist if the workflow needs them.
- Ensure only one mutating process owns the lock.
- Ensure peer configuration or simple discovery settings are loaded for node mode.
