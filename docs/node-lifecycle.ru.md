# Node Lifecycle

Этот документ описывает жизненный цикл одного экземпляра LibreVote node.

Каждый запущенный экземпляр программы является отдельным P2P-узлом. Роли узла определяются локальными ключами, локальным object log и валидными доменными объектами. Узел не объявляет роли через `Hello` capabilities.

## Принятые Решения

- Узел стартует с одним разблокированным `node key` как observer/republisher.
- Voter-роль активируется автоматически при наличии разблокированных voter keys.
- Trustee-роль активируется автоматически при наличии разблокированных trustee keys.
- Клиент автоматически публикует `BlindTokenRequest` для каждого eligible voter key, доступного в локальном key store.
- Final trustee автоматически публикует `BlindTokenIssue` для valid requests, если нужные trustee keys разблокированы.
- Final trustee автоматически публикует `TallyKeyContribution`, если trustee tally setup key разблокирован.
- Final trustee автоматически публикует `TallyDecryptionShare` после `tally_starts_at`, если trustee tally key разблокирован.
- Manual approval mode для trustee actions в v1 отсутствует.
- Derived state пересчитывается при старте и после revalidation.
- Shutdown не обязан завершать все pending validations.
- Running node открывает local control API через Unix socket для CLI.

## Локальные Роли Узла

Один node выполняет несколько ролей одновременно.

```text
observer
- хранит и валидирует объекты
- синхронизируется с peers
- проверяет результаты

republisher
- перепубликует valid announcements
- отдает retained objects через direct sync

voter
- имеет unlocked voter signing key
- имеет unlocked voter encryption key
- публикует BlindTokenRequest
- расшифровывает BlindTokenIssue
- создает AnonymousBallot

trustee candidate
- имеет trustee signing key
- публикует TrusteeNomination

ranked trustee candidate
- входит в `TrusteeSelectionResult.candidate_ranking[]`
- публикует TrusteeConsent для конкретного AnonymousElection

derived final trustee
- имеет valid consent и входит в derived final trustee set до публикации TallyKeySet
- публикует TallyKeyContribution

activated final trustee
- входит в `TallyKeySet.trustee_set[]`
- выпускает encrypted BlindTokenIssue
- публикует TallyDecryptionShare

result verifier
- пересчитывает TrusteeSelectionResult и TallyResult
- помечает локальный result state как verified или stale
```

Роль активна только при наличии нужных локальных ключей и валидных доменных объектов.

## Node States

Локальный lifecycle node:

```text
created
initialized
starting
storage_ready
transport_ready
network_joining
syncing
running
shutting_down
stopped
```

Error states:

```text
start_failed
db_error
key_locked
network_unavailable
```

Эти состояния являются локальными. Они не публикуются в P2P-сеть и не участвуют в доменной валидации.

## Init

Init создает локальное окружение узла.

Действия:

```text
1. Create config.
2. Set network_id.
3. Create SQLite database.
4. Initialize schema_metadata.
5. Generate node key.
6. Store node key encrypted-at-rest.
7. Initialize empty peer and sync state.
```

Результат:

```text
node state = initialized
```

Init не подключается к P2P-сети и не запускает фоновые workers.

## Startup Order

Старт узла выполняется в фиксированном порядке.

```text
1. Load config.
2. Acquire process lock.
3. Open SQLite.
4. Verify schema_version.
5. Verify database network_id.
6. Unlock node key.
7. Start local control API over Unix socket in `starting` mode.
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

Validation worker запускается до initial sync, чтобы объекты, полученные во время sync, сразу попадали в очередь валидации.

## Local Control API

Running node принимает CLI-команды через Unix socket. Во время `starting` и `syncing` control API принимает только limited commands.

Пример default path:

```text
~/.local/share/librevote/librevote.sock
```

Local control API используется только локальным CLI и не публикуется в P2P-сеть.

Через local control API выполняются:

- key unlock и lock;
- node status;
- sync commands;
- создание доменных объектов;
- vote cast;
- tally compute;
- result verify;
- object inspection.

Limited commands до `running`:

```text
node status
node stop
object status
sync status
```

Socket permissions:

```text
0600
owner = local user running node
```

Каждый request содержит command id, request id и protocol version. Responses возвращают request id, status и structured error code.

Mutating CLI-команды используют local control API и не открывают SQLite напрямую при работающем node.

## Key Unlock Policy

Узел стартует с разблокированным `node key`.

Остальные ключи разблокируются явно и активируют соответствующие роли.

```text
node key
- обязателен для start
- нужен transport layer

voter signing key
- нужен для BlindTokenRequest
- нужен для TrusteeVote

voter encryption key
- нужен для расшифровки BlindTokenIssue

trustee signing key
- нужен для TrusteeNomination
- нужен для TrusteeConsent
- нужен для BlindTokenIssue envelope
- нужен для TallyDecryptionShare envelope

trustee blind-token key
- нужен для blind Schnorr signature в BlindTokenIssuePayload

trustee tally setup key
- нужен для TrusteeConsent
- нужен для расшифровки encrypted DKG shares
- нужен для TallyKeyContribution

trustee tally share key
- нужен для TallyDecryptionShare

anonymous token key
- нужен для AnonymousBallot
```

Правила:

- Узел без voter/trustee keys работает как observer/republisher.
- Разблокировка voter keys запускает voter role worker.
- Разблокировка trustee keys запускает trustee role worker.
- Plaintext private keys не пишутся в SQLite и не логируются.

## Storage Startup

Storage startup:

```text
1. Open SQLite in WAL mode.
2. Enable foreign_keys.
3. Check schema_metadata.network_id.
4. Check schema_metadata.schema_version.
5. Load retained object metadata.
6. Load validation records.
7. Load sync state.
8. Load encrypted key records.
```

Если `network_id` базы не совпадает с config, node переходит в `db_error` и не стартует.

## Transport Startup

Transport startup:

```text
1. Load unlocked node key.
2. Start libp2p host over QUIC v1.
3. Bind configured listen addresses.
4. Expose local Peer ID.
5. Emit transport events to network layer.
```

Transport layer не запускает discovery, GossipSub или validation.

## Network Startup

Network startup:

```text
1. Register direct protocol handlers.
2. Connect configured bootstrap peers.
3. Run Hello with connected peers.
4. Verify peer admission proof.
5. Start Kademlia DHT discovery.
6. Join /librevote/<network_id>/v1/objects GossipSub topic.
7. Start announcement handling.
```

Network layer не доверяет peer'ам как источнику истины. Все полученные objects проходят validation layer.

## Local Rebuild

После storage и validation worker startup узел пересчитывает локальное состояние.

Rebuild выполняет:

```text
1. Load retained objects.
2. Check validator_version.
3. Revalidate retained records with old validator_version.
4. Revalidate pending_dependencies where dependencies exist.
5. Rebuild election_state.
6. Rebuild trustee_selection_state.
7. Rebuild tally_state.
```

Rebuild не изменяет retained payload bytes.

Invalid records without retained payload are not revalidated during rebuild. They require reacquire through sync.

## Initial Sync

Initial sync запускается после подключения к bootstrap peers.

Порядок:

```text
1. Run Inventory for network scope with empty scope_id.
2. Download missing root payloads with GetObjects.
3. Store and validate root `TrusteeSelectionElection` and `AnonymousElection` objects.
4. Extract trustee_selection_id and election_id from valid root payloads.
5. Open scopes for discovered trustee_selection_id and election_id values.
6. Run Inventory for known trustee_selection_id scopes.
7. Run Inventory for known election_id scopes.
8. Download missing payloads and `pending_payload_evicted` payloads with GetObjects.
9. Store downloaded objects transactionally as retained pending after envelope checks.
10. Validate downloaded objects.
11. Repeat until sync budget is exhausted.
```

Узел переходит в `running` после initial sync budget. Background sync продолжает догрузку объектов.

## Background Workers

В `running` состоянии работают фоновые workers.

```text
discovery worker
  sync worker
  validation worker
  republish worker
  trustee selection result worker
  issuance worker
trustee worker
  tally worker
  activation worker
  cleanup worker
```

## Discovery Worker

Discovery worker:

```text
1. Maintains Kademlia DHT discovery.
2. Refreshes known peers.
3. Connects to discovered peers through transport layer.
4. Runs Hello and peer admission.
5. Updates peer records.
```

## Sync Worker

Sync worker:

```text
1. Processes unknown ObjectAnnouncement.
2. Requests missing objects with GetObject or GetObjects.
3. Runs periodic Inventory sync per scope.
4. Runs sync before tally.
5. Updates sync_state cursors.
6. Stores downloaded objects as retained pending after envelope checks.
7. Enqueues objects for validation.
```

Sync worker does not mark objects as valid.

## Validation Worker

Validation worker:

```text
1. Reads new retained objects.
2. Runs validation stages.
3. Writes validation_records.
4. Writes object_dependencies.
5. Resolves conflict groups.
6. Triggers derived state recompute.
7. Enqueues valid announcements for republish.
```

Validation worker is the only worker that changes validation status.

## Republish Worker

Republish worker publishes only `ObjectAnnouncement`.

Rules:

```text
valid -> republish
valid_for_tally -> republish
valid_but_conflicted -> republish
pending_dependencies -> do not republish
invalid -> do not republish
```

Republish worker never sends full object payload through GossipSub.

## Trustee Selection Result Worker

Trustee selection result worker publishes preliminary `TrusteeSelectionResult`.

For each valid `TrusteeSelectionElection` after `voting_ends_at`:

```text
1. Run sync for trustee_selection_id.
2. Revalidate pending nominations and votes.
3. Compute candidate_ranking and initial_selected_trustees.
4. Compute result_hash.
5. Store and synchronously validate TrusteeSelectionResult.
6. Publish ObjectAnnouncement after validation succeeds.
```

Any node can publish `TrusteeSelectionResult`. The object is accepted only if local recomputation matches it.

## Issuance Worker

Issuance worker has voter-side and trustee-side behavior.

### Voter-Side Issuance

For each operationally active `AnonymousElection` in issuance window:

```text
1. Find local unlocked voter signing keys.
2. Match keys against election voter_allowlist.
3. Verify matching voter encryption key is unlocked.
4. Generate anonymous token keypair if none exists.
5. Generate blinded_token_message.
6. Publish BlindTokenRequest if no local valid request exists.
7. Watch BlindTokenIssue objects for local voter key.
8. Decrypt encrypted_payload.
9. Verify and unblind trustee signatures.
10. Store valid unblinded token signatures encrypted-at-rest.
```

This behavior is automatic for each eligible local voter key.

### Trustee-Side Issuance

For each operationally active `AnonymousElection` in issuance window where local trustee key is in `TallyKeySet.trustee_set[]`:

```text
1. Watch valid BlindTokenRequest.
2. Ignore pending, conflicted and invalid requests.
3. Check trustee is in trustee_set.
4. Check no valid issue exists for election_id || trustee_public_key || voter_public_key.
5. Create blind token signature over blinded_token_message.
6. Encrypt BlindTokenIssuePayload to voter_encryption_public_key.
7. Store and synchronously validate BlindTokenIssue.
8. Publish ObjectAnnouncement after local validation succeeds.
```

Trustee-side issuance is automatic when `trustee_signing_key` and `trustee_blind_token_key` are unlocked.

## Voting Worker

Voting worker creates `AnonymousBallot` for local voter actions.

It requires:

```text
valid AnonymousElection
valid TallyKeySet
voting window active
anonymous token key unlocked
at least 2 valid unblinded trustee token signatures from distinct trustees
user-selected choice
```

Actions:

```text
1. Encrypt choice under TallyKeySet.tally_public_key.
2. Generate choice_validity_proof.
3. Compute token_nullifier.
4. Create token_holder_signature.
5. Compute object PoW.
6. Store AnonymousBallot locally.
7. Synchronously validate local AnonymousBallot.
8. Publish ObjectAnnouncement after validation succeeds, random delay and batching.
```

Choice selection is a user action. Token issuance is automatic.

## Trustee Worker

Trustee worker handles trustee election and consent actions.

Automatic behavior:

```text
1. If local trustee nomination command created TrusteeNomination, monitor TrusteeSelectionResult.
2. If structural AnonymousElection references that result and local trustee is in candidate_ranking, publish TrusteeConsent.
3. If local trustee is in derived final trustee set, publish TallyKeyContribution.
4. If local trustee is in derived final trustee set, decrypt DKG shares and store trustee_tally_share encrypted-at-rest.
5. If local trustee is in TallyKeySet.trustee_set[], run trustee-side issuance.
6. If tally phase starts, publish TallyDecryptionShare.
```

Trustee actions are automatic after the corresponding trustee keys are unlocked and the node has valid context objects.

## Activation Worker

Activation worker derives final trustee set and publishes `TallyKeySet`.

For each structurally valid `AnonymousElection`:

```text
1. Load valid TrusteeSelectionResult.
2. Collect valid non-conflicted TrusteeConsent objects.
3. Derive final trustee set as top 3 consenting ranked candidates.
4. Wait for valid non-conflicted TallyKeyContribution from all final trustees.
5. Compute tally_public_key and tally_key_set_hash.
6. Store and synchronously validate TallyKeySet.
7. Publish ObjectAnnouncement after validation succeeds.
```

Any node can publish `TallyKeySet`. The object is accepted only if local recomputation matches it.

## Tally Worker

Tally worker processes anonymous election tally.

For each operationally active `AnonymousElection`:

```text
1. Wait until now >= tally_starts_at.
2. Run sync for election_id.
3. Revalidate pending objects.
4. Build valid_for_tally ballot set.
5. Compute encrypted tally.
6. Compute encrypted_tally_hash.
7. If local final trustee tally key is unlocked, store and validate TallyDecryptionShare.
8. Publish TallyDecryptionShare announcement after validation succeeds.
9. Collect valid TallyDecryptionShare objects.
10. If at least 2 valid shares from distinct trustees exist, decrypt tally.
11. Verify or publish TallyResult.
12. Mark result stale if late valid objects affect tally.
```

Tally worker does not trust published `TallyResult` without local recomputation.

## Cleanup Worker

Cleanup worker removes only non-authoritative local metadata.

Allowed cleanup:

```text
message_cache expired rows
old invalid_object_records metadata
pending payloads that exceeded mandatory retention limits
stale sync_state for unreachable peers
old peer_addresses
completed in-memory work queue checkpoints
```

Cleanup worker does not remove retained valid or conflicted payloads. Pending payloads are retained until final validation status or mandatory pending retention limit.

## Election Local State

Node tracks local election state as derived state.

```text
unknown
discovered
pending_dependencies
valid
awaiting_consents
key_setup_active
activated
issuance_active
voting_active
tally_waiting
tally_active
result_verified
result_stale
```

This state is not a domain object and is rebuilt from object log and validation records.

## Graceful Shutdown

Shutdown order:

```text
1. Enter shutting_down state.
2. Stop accepting new CLI commands.
3. Stop creating new local domain objects.
4. Stop publishing new announcements.
5. Cancel active sync requests.
6. Finish active SQLite transactions.
7. Persist worker checkpoints.
8. Stop background workers.
9. Leave GossipSub topic.
10. Stop DHT discovery.
11. Close transport host.
12. Close SQLite.
13. Zero in-memory secrets.
14. Enter stopped state.
```

Shutdown does not wait for all pending validations. Pending objects are recovered through storage on next start.

## Crash Recovery

After crash:

```text
1. SQLite WAL recovers committed transactions.
2. Uncommitted transactions are discarded.
3. Retained objects remain immutable.
4. Validation records are checked against validator_version.
5. Pending dependencies are revalidated.
6. Derived state is rebuilt.
7. Sync resumes from sync_state cursors.
```

No network object is considered locally retained unless its storage transaction committed.

## Publication Ordering

For locally created domain objects:

```text
1. Build canonical payload.
2. Sign or prove required cryptographic fields.
3. Compute object_id.
4. Compute object PoW.
5. Store object transactionally.
6. Validate local object.
7. Publish ObjectAnnouncement only after successful local storage and validation.
```

This rule prevents announcing objects that the local node cannot serve through `GetObject`.
