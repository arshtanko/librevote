# Transport Layer

Transport is required only to support minimal MVP P2P object synchronization. It can be simple and local-demo oriented.

## MVP Requirements

- Open outbound connections to configured peers or peers found by simple discovery.
- Accept inbound connections when running as a node.
- Carry object announcement, inventory and direct fetch messages.
- Transfer full `ObjectEnvelope` payloads for requested objects.
- Surface peer identity only as local metadata.

## Out Of MVP

- Full libp2p hardening.
- GossipSub mesh management.
- Peer scoring.
- NAT traversal.
- TLS/noise hardening beyond what the chosen simple transport already provides.
- Production rate limiting and denial-of-service resistance.

Existing transport code may stay minimal, but it must support the MVP network-layer sync path.
