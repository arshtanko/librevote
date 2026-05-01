# Crypto Layer

Crypto is minimized for MVP. Keep deterministic hashing, canonical bytes and any signatures already implemented. Advanced privacy and threshold cryptography are placeholders.

## Required For MVP

- Canonical object bytes.
- `object_id` hashing.
- Stable domain-separated hashes used by result recomputation.
- Basic local signing if already implemented or required by existing schemas.
- Optional envelope PoW with zero or low difficulty.

## Placeholders

- Blind signatures may be replaced by deterministic local token strings.
- DKG may be replaced by deterministic local key-set data.
- Threshold encryption may be replaced by plaintext ballot choices or simple encoded choices.
- Decryption shares may be omitted or represented by deterministic placeholder objects.

## Rule

Do not block the MVP workflow on cryptography that is not needed for a local course-project demo.
