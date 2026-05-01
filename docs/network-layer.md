# Network Layer

Networking is a core MVP requirement. The MVP network layer is a minimal peer-to-peer object synchronization layer, not a hardened production network.

## MVP Behavior

- A node connects to peers from static configuration or simple discovery.
- Peers exchange object announcements or compact inventories containing `object_id`, object type, scope and scope ID.
- A node requests missing objects directly from a peer that announced or listed them.
- Direct fetch returns full `ObjectEnvelope` values.
- Received objects are stored in SQLite and passed to validation.
- Validation statuses, dependency records and conflict keys decide whether received objects are valid, pending, conflicted or rejected.
- Source peer is local network metadata and never domain authorship.

## Required MVP Protocol Shape

The exact transport can be simple, but the network layer must support:

- Peer configuration or simple discovery.
- Object announcement or inventory exchange.
- Direct object fetch by `object_id`.
- Optional bulk fetch for a small list of object IDs.
- Re-announcing or re-listing locally retained objects so a late peer can catch up.

## Out Of MVP

- Full GossipSub mesh behavior.
- Peer scoring and reputation.
- NAT traversal.
- Advanced anti-entropy cursors.
- Production denial-of-service hardening.
- Strong metadata privacy.

## Compatibility

Existing object, storage and validation packages remain the authority for object meaning. Network code only moves envelopes between nodes and must not bypass validation.
