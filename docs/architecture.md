# LibreVote Architecture

Этот документ фиксирует верхнеуровневую архитектуру LibreVote v1.

LibreVote v1 является децентрализованной P2P-системой интернет-голосования. Каждый участник запускает локальный node process, хранит immutable object log, валидирует доменные объекты локально и независимо пересчитывает результаты. Система не использует центральный сервер, blockchain или глобальный consensus layer.

Детальные правила слоев описаны в отдельных документах `docs/*.ru.md`. Этот документ задает end-to-end модель, границы слоев и главные инварианты.

## Core Decisions

- Один запущенный экземпляр программы является одним P2P node.
- Один CLI binary: `librevote`.
- Node process является долгоживущим процессом: `librevote node start`.
- CLI управляет running node через local control API over Unix socket.
- Все сетевые доменные объекты являются immutable content-addressed objects.
- Каждый node валидирует объекты самостоятельно.
- Result objects являются publishable convenience objects, но не являются authority.
- Trustee selection является публичным и неанонимным.
- Основное голосование является анонимным через `blind_token_v1`.
- Threshold trustees в v1 фиксированы: `n = 3`, `t = 2`.
- Anonymous election становится operationally active только после valid `TallyKeySet`.
- GossipSub переносит только announcements, full payload догружается через direct sync.
- SQLite является локальным хранилищем, а не источником доменной истины.

## Non-Goals

LibreVote v1 не обеспечивает:

- глобальный consensus;
- blockchain ordering;
- strong network metadata anonymity;
- coercion resistance;
- receipt-freeness;
- trustless model без trustee assumptions;
- доступность tally без `2` доступных final trustees;
- скрытие факта участия в issuance phase.

## Layer Model

```text
CLI
-> local control API over Unix socket
-> application services in running node
-> validation / crypto / storage / network / tally
-> libp2p transport
```

Границы:

- CLI не выполняет доменную криптографию, validation, tally или P2P publication самостоятельно.
- Network layer доставляет данные, но не решает доменную валидность.
- Storage layer хранит bytes, validation records и derived caches, но не является authority.
- Validation layer определяет, какие retained objects используются протоколом.
- Tally layer пересчитывает результаты из locally valid objects.
- Crypto layer задает canonical bytes, signatures, PoW, blind tokens, encryption и threshold operations.

## Domain Objects

Все доменные объекты передаются и хранятся в `ObjectEnvelope`.

```text
ObjectEnvelope {
  object_id
  object_type
  protocol_version
  network_id
  scope
  scope_id
  payload
  pow
  created_at
}
```

`object_id` вычисляется по canonical object bytes:

```text
object_id = HASH("librevote-object-id-v1" || canonical_object_bytes)
```

В canonical object bytes входят:

- `protocol_version`;
- `network_id`;
- `object_type`;
- `scope`;
- `scope_id`;
- `created_at`;
- canonical payload with signatures.

В canonical object bytes не входят:

- `object_id`;
- envelope `pow`;
- source peer;
- local validation metadata;
- storage metadata.

PoW находится только в envelope. Domain payload не содержит PoW.

## Object Types

Доменные object types v1:

```text
TrusteeSelectionElection
TrusteeNomination
TrusteeVote
TrusteeSelectionResult
TrusteeConsent
AnonymousElection
TallyKeyContribution
TallyKeySet
BlindTokenRequest
BlindTokenIssue
AnonymousBallot
TallyDecryptionShare
TallyResult
```

## Scope Mapping

```text
TrusteeSelectionElection -> network / empty scope_id
TrusteeNomination -> trustee_selection_id / trustee_selection_id
TrusteeVote -> trustee_selection_id / trustee_selection_id
TrusteeSelectionResult -> trustee_selection_id / trustee_selection_id
AnonymousElection -> network / empty scope_id
TrusteeConsent -> election_id / election_id
TallyKeyContribution -> election_id / election_id
TallyKeySet -> election_id / election_id
BlindTokenRequest -> election_id / election_id
BlindTokenIssue -> election_id / election_id
AnonymousBallot -> election_id / election_id
TallyDecryptionShare -> election_id / election_id
TallyResult -> election_id / election_id
```

`network` scope является discovery root. Inventory по `network` scope возвращает root objects `TrusteeSelectionElection` и `AnonymousElection`. После загрузки root payload node открывает scoped sync по `trustee_selection_id` или `election_id`.

## Validation Statuses

```text
pending_dependencies
pending_payload_evicted
valid
valid_for_tally
valid_but_conflicted
invalid
```

Значения:

- `pending_dependencies`: объект ожидает связанные объекты.
- `pending_payload_evicted`: pending payload удален по retention limit и должен быть reacquired через sync.
- `valid`: объект прошел доменную проверку, но не является ballot input.
- `valid_for_tally`: ballot участвует в tally.
- `valid_but_conflicted`: объект криптографически корректен, но исключен из protocol use из-за conflict group.
- `invalid`: объект не используется, не republish-ится и не served через sync.

`stale` не является validation status. Это local derived result state.

## Conflict Policy

LibreVote v1 не выбирает победителя внутри conflict group.

```text
valid conflict group size = 1 -> object can be used
valid conflict group size > 1 -> every object in group becomes valid_but_conflicted
```

Conflict resolution не использует:

- delivery order;
- source peer;
- `created_at`;
- PoW nonce;
- `object_id` grinding.

Основные conflict keys:

```text
trustee_nomination_candidate_conflict_key = trustee_selection_id || candidate_public_key
trustee_nomination_blind_token_conflict_key = trustee_selection_id || candidate_blind_token_public_key
trustee_vote_conflict_key = trustee_selection_id || voter_public_key
trustee_consent_conflict_key = election_id || trustee_public_key
trustee_consent_tally_setup_conflict_key = election_id || trustee_tally_setup_public_key
tally_key_contribution_conflict_key = election_id || trustee_public_key
blind_token_request_conflict_key = election_id || voter_public_key
blind_token_issue_conflict_key = election_id || trustee_public_key || voter_public_key
anonymous_ballot_conflict_key = election_id || token_nullifier
tally_decryption_share_conflict_key = election_id || encrypted_tally_hash || trustee_public_key
```

## End-To-End Flow

### Trustee Selection

```text
1. TrusteeSelectionElection is published.
2. Trustee candidates publish TrusteeNomination.
3. Eligible voters publish public TrusteeVote.
4. Nodes compute deterministic candidate_ranking.
5. Any node publishes TrusteeSelectionResult.
6. TrusteeSelectionResult is accepted only if local recomputation matches it.
```

Trustee selection tally:

- approval-style voting;
- each voter selects up to `3` candidates;
- candidates ranked by score descending;
- ties broken by `candidate_rank_hash` ascending.

`TrusteeSelectionResult` is preliminary. It fixes `candidate_ranking[]`, not final trustee set.

### Anonymous Election Creation

`AnonymousElection` is a structural root object.

It contains:

- `election_id`;
- public options;
- public voter allowlist;
- `trustee_selection_id`;
- `trustee_selection_result_hash`;
- issuance, voting and tally windows;
- `eligibility_scheme = blind_token_v1`.

`AnonymousElection` does not contain final trustee set or `tally_public_key`. It becomes operationally active only after valid `TallyKeySet` exists.

### Consent And Activation

Ranked trustee candidates publish `TrusteeConsent` for a concrete `election_id`.

`TrusteeConsent` binds:

- `trustee_selection_id`;
- `trustee_selection_result_hash`;
- `election_id`;
- `election_parameters_hash`;
- `trustee_public_key`;
- `trustee_tally_setup_public_key`.

Final trustee set is derived deterministically:

```text
final_trustee_set = first 3 candidates from candidate_ranking
                    with valid non-conflicted TrusteeConsent
                    and unique trustee_tally_setup_public_key
```

If fewer than `3` candidates satisfy this rule, the anonymous election does not become active.

### Threshold Key Setup

Each derived final trustee publishes `TallyKeyContribution`.

```text
TallyKeyContribution {
  election_id
  trustee_public_key
  trustee_tally_setup_public_key
  dkg_commitments[]
  dkg_encrypted_shares[]
  setup_proof
  signature
}
```

Each `DKGEncryptedShare` is bound to:

- sender trustee;
- recipient trustee;
- recipient tally setup key id;
- recipient index;
- encrypted share;
- share encryption proof.

`TallyKeySet` activates the election.

```text
TallyKeySet {
  election_id
  trustee_selection_result_hash
  trustee_set[]
  trustee_consent_object_ids[]
  tally_key_contribution_object_ids[]
  trustee_set_hash
  threshold_t
  trustee_count_n
  tally_public_key
  trustee_key_commitments[]
  setup_proofs[]
  tally_key_set_hash
  reporter_public_key
  signature
}
```

Any node can publish `TallyKeySet`. It is accepted only if local recomputation matches `tally_key_set_hash`.

### Blind Token Issuance

Issuance starts only for operationally active `AnonymousElection`.

Voter side:

```text
1. Generate one-time anonymous token keypair.
2. Blind token_public_key.
3. Publish BlindTokenRequest signed by voter key.
4. Receive encrypted BlindTokenIssue objects.
5. Decrypt issue payload locally.
6. Verify trustee blind token signatures.
7. Store valid unblinded signatures encrypted-at-rest.
```

Trustee side:

```text
1. Watch valid BlindTokenRequest.
2. Ignore pending, conflicted and invalid requests.
3. Sign blinded token message.
4. Encrypt BlindTokenIssuePayload for voter_encryption_public_key.
5. Publish BlindTokenIssue after local validation.
```

Public validators do not decrypt `BlindTokenIssue.encrypted_payload`. Recipient voter verifies decrypted payload locally.

`BlindTokenIssue` must bind to referenced request:

```text
BlindTokenIssue.election_id == BlindTokenRequest.election_id
BlindTokenIssue.voter_public_key == BlindTokenRequest.voter_public_key
recipient_key_id == key_id(BlindTokenRequest.recipient_encryption_public_key)
```

### Anonymous Voting

`AnonymousBallot` contains no `voter_public_key`, no `peer_id` and no `node_public_key`.

It contains:

```text
election_id
encrypted_choice
choice_validity_proof
eligibility_proof
```

Validation requires:

- operationally active `AnonymousElection`;
- active voting window using `ObjectEnvelope.created_at`;
- valid `choice_validity_proof`;
- `token_nullifier = HASH("librevote-token-nullifier-v1" || election_id || token_public_key)`;
- at least `2` valid blind token signatures from distinct trustees in `TallyKeySet.trustee_set[]`;
- valid `token_holder_signature` over canonical ballot payload without `token_holder_signature` and envelope `pow`.

Repeated anonymous ballots with the same `token_nullifier` form a conflict group and are all excluded from tally.

### Tally

Anonymous tally starts after `tally_starts_at`.

```text
1. Sync election scope.
2. Revalidate pending objects.
3. Resolve ballot conflicts.
4. Build valid_for_tally ballot set.
5. Compute encrypted tally.
6. Compute encrypted_tally_hash.
7. Collect TallyDecryptionShare objects.
8. Decrypt result when at least 2 valid shares from distinct trustees exist.
9. Verify or publish TallyResult.
```

`encrypted_tally_hash` binds:

- `election_id`;
- `tally_key_set_hash`;
- `tally_public_key`;
- sorted valid ballot object ids;
- aggregate ciphertexts.

`TallyResult` is accepted only if local recomputation matches it.

`invalid_ballot_count` is local diagnostic state and does not enter `TallyResult` or `result_hash`.

## Network Architecture

LibreVote v1 uses libp2p over QUIC v1.

Network components:

- static bootstrap peers from config;
- Kademlia DHT discovery;
- one global GossipSub topic `/librevote/<network_id>/v1/objects`;
- direct request/response protocols.

GossipSub carries only:

```text
ObjectAnnouncement
```

Direct protocols:

```text
/librevote/v1/hello
/librevote/v1/inventory
/librevote/v1/get-object
/librevote/v1/get-objects
/librevote/v1/get-election-state
```

Inventory returns `ObjectRef`, not full payloads. Full objects are fetched with `GetObject` or `GetObjects`.

Sync treats `pending_payload_evicted` as missing payload and requests it again. Duplicate suppression does not block reacquire for this status.

## Storage Architecture

Local storage uses SQLite in WAL mode.

Storage contains:

- object metadata;
- retained payloads;
- validation records;
- dependency records;
- derived state caches;
- encrypted key store;
- encrypted local issuance secrets;
- peer metadata;
- sync metadata.

Retention v1:

```text
valid payloads -> retained indefinitely
valid_for_tally payloads -> retained indefinitely
valid_but_conflicted payloads -> retained indefinitely
pending_dependencies payloads -> retained until final status or retention limit
pending_payload_evicted payloads -> not retained, reacquire allowed
invalid payloads -> not retained durably
```

Derived state is cache. Rebuild derives it from retained objects and validation records.

Offline mutating SQLite access requires process lock:

```text
<data_dir>/librevote.lock
```

## Node Lifecycle

Startup order:

```text
1. Load config.
2. Acquire process lock.
3. Open SQLite.
4. Verify schema_version.
5. Verify database network_id.
6. Unlock node key.
7. Start local control API over Unix socket in starting mode.
8. Start transport layer.
9. Register direct protocol handlers.
10. Start network layer.
11. Start validation worker.
12. Rebuild local derived state.
13. Connect bootstrap peers.
14. Run peer Hello and peer admission.
15. Run initial sync.
16. Start background role workers.
17. Enter running state.
```

Initial sync:

```text
1. Run Inventory for network scope with empty scope_id.
2. Download missing root payloads.
3. Store and validate root TrusteeSelectionElection and AnonymousElection objects.
4. Extract trustee_selection_id and election_id from valid root payloads.
5. Open scoped sync for discovered ids.
6. Download missing scoped payloads and pending_payload_evicted payloads.
7. Validate downloaded objects.
```

Background workers:

```text
discovery worker
sync worker
validation worker
republish worker
trustee selection result worker
issuance worker
trustee worker
activation worker
tally worker
cleanup worker
```

## Local Roles

Roles are derived locally from keys and valid objects. `Hello` does not advertise capabilities.

```text
observer
- validates objects
- syncs with peers
- verifies results

republisher
- republishes valid announcements
- serves retained valid/conflicted payloads

trustee candidate
- publishes TrusteeNomination

ranked trustee candidate
- publishes TrusteeConsent for a concrete AnonymousElection

derived final trustee
- publishes TallyKeyContribution
- decrypts DKG shares and stores trustee_tally_share encrypted-at-rest

activated final trustee
- issues BlindTokenIssue
- publishes TallyDecryptionShare

voter
- publishes BlindTokenRequest
- decrypts BlindTokenIssue payloads
- casts AnonymousBallot
```

## CLI Architecture

CLI commands use running node through Unix socket.

Unix socket rules:

```text
permissions = 0600
owner = local user running node
```

Read-only commands support `--json`.

Direct SQLite access is limited to:

```text
librevote init
librevote key create ... when node is stopped
read-only recovery/debug inspection when node is stopped
```

Mutating domain commands use local control API and do not open SQLite directly while node is running.

## Security Assumptions

LibreVote v1 requires:

- correct voter allowlists;
- correct implementation of cryptographic primitives;
- fewer than `2` of `3` trustees colluding for fraudulent credential issuance;
- fewer than `2` of `3` trustees colluding before tally phase for choice privacy;
- at least `2` of `3` final trustees available in tally phase;
- eventual synchronization with at least one honest reachable peer;
- local user device protecting unlocked secrets during use.

Threshold trustees can decrypt individual ballot ciphertexts if `2` trustees collude, because anonymous ballots are public ciphertexts. LibreVote v1 provides cryptographic unlinkability between `voter_public_key` and `AnonymousBallot`, not aggregate-only trustee decryption.

## Authoritative Invariants

- `AnonymousElection` is structural; `TallyKeySet` activates it.
- `TrusteeSelectionResult` is preliminary; `TallyKeySet` fixes final trustee set.
- Final trustee set is derived from candidate ranking and valid non-conflicted consents.
- `TallyKeySet` is accepted only by local recomputation.
- `BlindTokenRequest` exposes participation in issuance phase.
- `AnonymousBallot` never contains voter identity or transport identity.
- Tally includes only `valid_for_tally` ballots.
- Conflicted valid objects are retained and propagated, but excluded from protocol use.
- Invalid payloads are not retained durably.
- Results are independently recomputed by every node.
