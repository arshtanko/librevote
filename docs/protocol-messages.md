# Protocol Messages

For MVP, protocol messages cover both local service requests and minimal peer-to-peer object synchronization around `ObjectEnvelope`.

## ObjectEnvelope

`ObjectEnvelope` is the stable boundary between CLI/application services, validation and storage.

Required fields:

- `object_id`
- `object_type`
- `protocol_version`
- `network_id`
- `scope`
- `scope_id`
- `payload`
- `pow`
- `created_at`

`payload` is encoded canonically according to the existing implementation rules.

## Local Service Messages

CLI commands may pass typed request structs directly to local services. They do not need a daemon protocol for MVP unless a local control API is implemented.

Useful local operations:

- Initialize storage.
- Create and ingest an object.
- Validate or revalidate objects.
- Query elections, trustees, ballots and results.
- Build deterministic result objects.

## Network Messages

Minimal P2P messages are required for MVP.

Required message types:

- `ObjectAnnouncement`: advertises one known object by `object_id`, object type, scope and scope ID.
- `ObjectInventory`: advertises a small list of known objects for catch-up or reconnect.
- `GetObject`: requests one object by `object_id`.
- `ObjectResponse`: returns the requested full `ObjectEnvelope` or a not-found result.

GossipSub is not required for MVP. Announcements and inventory may be sent over direct peer connections.
