# Threat Model

The MVP threat model is intentionally weak because the goal is a working course-project demo.

## Assumptions

- The demo may run multiple nodes on one trusted local machine or a small trusted LAN.
- The SQLite database is trusted unless manually edited.
- CLI users are honest enough for demonstration.
- Local validation catches malformed objects and accidental duplicates.
- Peers may send malformed or duplicate objects, which must be handled by validation statuses and conflict keys.

## Not Protected In MVP

- Active network attackers beyond basic validation rejection.
- Malicious peers beyond malformed-object rejection and duplicate/conflict handling.
- Strong ballot anonymity.
- Coercion or vote buying.
- Receipt-freeness.
- Trustee collusion.
- Database tampering by an administrator.
- Denial of service.

## MVP Security Goal

The MVP should demonstrate deterministic object validation, minimal P2P object synchronization and reproducible local tallying, not production election security.
