# Storage Layer

Этот документ описывает локальное хранилище LibreVote v1.

Storage layer хранит доменные объекты, результаты локальной валидации, производное состояние, ключи, peers и sync metadata. Он не является источником истины протокола. Источник истины — immutable domain objects и детерминированная локальная валидация.

## Принятые Решения

- Локальное хранилище v1 использует `SQLite`.
- SQLite работает в `WAL` mode.
- Доменные объекты хранятся через object log.
- Payload доменного объекта immutable, пока он retained.
- Validation metadata хранится отдельно от payload.
- Derived state хранится как cache и пересчитывается из object log.
- Key store находится в той же SQLite базе.
- Приватные ключи хранятся только как `encrypted_private_key`.
- Quarantine для невалидных объектов не используется.
- Invalid payloads не хранятся долговременно.
- Валидные и conflicted payloads хранятся бессрочно в v1.
- Pending payloads хранятся до финального validation status или до mandatory pending retention limit.
- Invalid payload не revalidatable без повторного получения payload из сети.
- Source peer хранится только как локальная сетевая metadata и не входит в доменную модель.

## Граница Слоя

Storage layer отвечает за:

- атомарное сохранение объектов;
- чтение объектов по `object_id`;
- индексацию объектов по scope и type;
- хранение validation records;
- хранение dependencies для pending объектов;
- хранение derived state;
- хранение encrypted local keys;
- хранение encrypted local issuance secrets;
- хранение peer и sync metadata.

Storage layer не отвечает за:

- проверку подписей;
- проверку PoW;
- проверку blind token proofs;
- подсчет tally;
- P2P-доставку;
- выбор peers для gossip или sync.

## SQLite Configuration

База открывается с настройками:

```text
journal_mode = WAL
foreign_keys = ON
synchronous = NORMAL
busy_timeout = configured value
```

Все записи, меняющие object log, validation records или derived state, выполняются внутри транзакций.

## Process Lock

Перед открытием SQLite для mutating access node или offline CLI берет single-instance lock.

```text
lock_path = <data_dir>/librevote.lock
```

Правила:

- running node удерживает lock до shutdown;
- offline mutating CLI commands получают lock перед открытием базы;
- если lock удерживается живым process, offline mutating command завершается ошибкой;
- stale lock проверяется по PID и socket ownership;
- stale lock удаляется только если PID не существует и Unix socket не принадлежит running node.

## Schema Metadata

```text
schema_metadata {
  key primary key
  value
}
```

Обязательные ключи:

```text
schema_version
network_id
created_at
updated_at
```

`network_id` в базе должен совпадать с `network_id` запущенного узла.

## Object Metadata

`objects` хранит metadata доменного объекта.

```text
objects {
  object_id primary key
  object_type
  protocol_version
  network_id
  scope
  scope_id
  created_at
  first_seen_at
  last_seen_at
  object_pow
  payload_hash
  payload_size
  payload_retained
}
```

Правила:

- `object_id` уникален.
- `payload_hash` вычисляется по retained payload bytes.
- `payload_retained = true` означает, что payload доступен в `object_payloads`.
- Повторное получение известного `object_id` обновляет только `last_seen_at` и сетевую metadata.
- Для `validation_status = pending_payload_evicted` повторное получение того же `object_id` с matching payload hash заново сохраняет payload и переводит объект в validation queue.
- Payload mismatch для известного `object_id` отклоняется.
- `scope_id` содержит `election_id`, `trustee_selection_id` или пустое значение для `scope = network`.

Индексы:

```text
objects(scope, scope_id, object_type, created_at)
objects(object_type, created_at)
objects(network_id, created_at)
```

## Object Payloads

`object_payloads` хранит canonical payload bytes.

```text
object_payloads {
  object_id primary key
  payload_bytes
}
```

Правила:

- `payload_bytes` immutable после вставки.
- Для `payload_retained = true` запись в `object_payloads` обязательна.
- Для `payload_retained = false` запись в `object_payloads` отсутствует.
- `GetObject` и `GetObjects` возвращают retained payload только для статусов `valid`, `valid_for_tally` и `valid_but_conflicted`.
- `pending_dependencies` payload не advertised и не served; direct response использует `pending_not_served`.

## Validation Records

Валидация хранится отдельно от payload.

```text
validation_records {
  object_id primary key
  validation_status
  validation_error_code
  validation_error_message
  validator_version
  last_checked_at
}
```

Поддерживаемые статусы:

```text
pending_dependencies
pending_payload_evicted
valid
valid_for_tally
valid_but_conflicted
invalid
```

Правила:

- `validator_version` фиксирует версию правил валидации.
- `invalid` объекты не возвращаются через sync APIs.
- `pending_payload_evicted` не возвращается через sync APIs, но может быть reacquired from peers.
- `invalid` объекты не перепубликовываются.
- Для `invalid` объектов payload не хранится долговременно.
- Подробные ошибки используются только локально и не отправляются как protocol validation trace.

Индексы:

```text
validation_records(validation_status, last_checked_at)
validation_records(validator_version)
```

## Object Dependencies

`object_dependencies` хранит зависимости pending объектов.

```text
object_dependencies {
  object_id
  dependency_type
  dependency_id
}
```

Примеры `dependency_type`:

```text
election
trustee_selection
trustee_selection_result
trustee_consent
blind_token_request
tally_key_set
tally_decryption_share
```

Правила:

- Pending объект имеет минимум одну dependency.
- При появлении объекта с matching `dependency_id` зависимый объект ставится в очередь revalidation.
- После успешной валидации зависимости удаляются.
- После перехода объекта в `invalid` зависимости удаляются.

Индексы:

```text
object_dependencies(dependency_type, dependency_id)
object_dependencies(object_id)
```

## Invalid Object Records

Quarantine не используется. Invalid payloads не хранятся долговременно.

Для rate limits и диагностики сохраняется только metadata.

```text
invalid_object_records {
  object_id primary key
  object_type
  network_id
  scope
  scope_id
  first_seen_at
  last_seen_at
  seen_count
  validation_error_code
}
```

Правила:

- `payload_bytes` для invalid объекта не сохраняется.
- Повторное получение invalid `object_id` обновляет `last_seen_at` и `seen_count`.
- `scope` и `scope_id` используются только для локальной диагностики и rate limits.
- Invalid object metadata используется для duplicate suppression, peer scoring и локальной диагностики.
- Invalid object metadata не является доменным объектом.

## Object Ingestion Transaction

Прием объекта выполняется атомарно.

```text
1. Run cheap envelope checks before transaction.
2. Begin transaction.
3. Check existing object_id.
4. Insert or update objects metadata.
5. Insert payload into object_payloads when payload is retained.
6. Write validation_records.
7. Write object_dependencies for pending objects.
8. Drop payload for invalid objects.
9. Update derived state.
10. Commit transaction.
```

Правила:

- Если транзакция не завершилась, объект не считается сохраненным.
- Нельзя сохранить validation record без metadata object record.
- Нельзя обновить derived state до сохранения object metadata и validation record.
- Если объект признан invalid в той же транзакции, payload не остается в `object_payloads`.
- Если pending объект при повторной проверке становится invalid, его payload удаляется, а `payload_retained` становится `false`.
- Downloaded object с missing dependencies сохраняется как `pending_dependencies` с retained payload, если pending retention budget не превышен.
- Downloaded object с invalid envelope не сохраняется как domain object.

## Derived State

Derived state является cache.

```text
election_state {
  election_id primary key
  phase
  valid_object_count
  invalid_object_count
  pending_object_count
  computed_state_hash
  updated_at
}

trustee_selection_state {
  trustee_selection_id primary key
  candidate_ranking_hash
  initial_selected_trustees_hash
  valid_vote_count
  conflicted_vote_count
  updated_at
}

tally_state {
  election_id primary key
  encrypted_tally_hash
  valid_ballot_count
  conflicted_ballot_count
  invalid_ballot_count_diagnostic
  result_status
  result_hash
  updated_at
}
```

Правила:

- Derived state пересчитывается из retained domain objects.
- Derived state не используется как единственный источник результата.
- Поврежденный derived state удаляется и строится заново из object log.
- `TallyResult` и `TrusteeSelectionResult` проверяются локальным пересчетом, а не доверием к cached state.
- `invalid_ballot_count_diagnostic` не входит в authoritative `TallyResult.result_hash`.

## Key Store

Key store хранится в той же SQLite базе.

```text
keys {
  key_id primary key
  key_type
  public_key
  encrypted_private_key
  encryption_metadata
  created_at
}
```

Поддерживаемые `key_type`:

```text
node
voter_signing
voter_encryption
trustee_signing
trustee_blind_token
trustee_tally_setup
trustee_tally_share
anonymous_token
```

Правила:

- `encrypted_private_key` создается криптографическим слоем.
- SQLite не хранит plaintext private keys.
- Passphrase не хранится.
- Raw secrets не логируются.
- Удаление ключа делает невозможным новые подписи, новые decrypt operations и новые proof generation операции для этого ключа.

## Local Issuance State

Local issuance state хранит секреты и промежуточные данные, нужные voter для выпуска `AnonymousBallot` после получения blind token signatures.

```text
local_issuance_state {
  election_id
  voter_key_id
  token_key_id
  encrypted_blinding_factor
  encrypted_unblinded_token_signatures
  completed_at
  updated_at
}
```

Правила:

- `encrypted_blinding_factor` хранится encrypted-at-rest.
- `encrypted_unblinded_token_signatures` хранится encrypted-at-rest до публикации `AnonymousBallot`.
- `token_key_id` ссылается на local key store record с `key_type = anonymous_token`.
- `local_issuance_state` не является доменным объектом.
- `local_issuance_state` не синхронизируется по P2P.
- Удаление записи делает невозможным завершить issuance для связанного local token material.

## Peer Records

Peer state является локальной сетевой metadata.

```text
peers {
  peer_id primary key
  score
  admission_status
  first_seen_at
  last_seen_at
}

peer_addresses {
  peer_id
  address
  first_seen_at
  last_seen_at
}
```

Правила:

- Peer state не входит в доменную модель.
- Peer score не влияет на право голоса или tally.
- Peer addresses используются transport и network layers.

## Sync State

```text
sync_state {
  peer_id
  scope
  scope_id
  cursor
  last_sync_at
  failed_attempts
}
```

Правила:

- `cursor` является opaque значением direct protocol.
- `failed_attempts` используется для backoff и peer scoring.
- Sync state удаляется без потери доменной истины.

## Message Cache

`message_cache` подавляет повторную обработку announcements.

```text
message_cache {
  object_id primary key
  first_seen_at
  last_seen_at
  seen_count
}
```

Правила:

- Cache не является object log.
- Потеря cache не влияет на корректность.
- Cache влияет только на эффективность и rate limits.

## Source Peer Metadata

Источник объекта хранится отдельно от доменного объекта.

```text
object_sources {
  object_id
  peer_id
  first_seen_at
  last_seen_at
}
```

Правила:

- `object_sources` не используется в доменной валидации.
- `object_sources` не участвует в `object_id`.
- `object_sources` используется для peer scoring и диагностики.

## Retention Policy

Retention v1:

```text
valid payloads -> retained indefinitely
valid_for_tally payloads -> retained indefinitely
valid_but_conflicted payloads -> retained indefinitely
pending_dependencies payloads -> retained until final validation status or pending retention limit
pending_payload_evicted payloads -> not retained, reacquire allowed
invalid payloads -> not retained durably
```

Для завершенных голосований валидные и conflicted объекты остаются в локальном хранилище бессрочно.

Mandatory pending retention limits:

```text
max_pending_payload_bytes
max_pending_objects_per_scope
max_pending_age
```

Если pending object превышает retention limit, payload удаляется, `payload_retained = false`, а validation record получает `pending_payload_evicted`. Такой объект восстанавливается повторным получением payload через sync; duplicate suppression не блокирует reacquire для этого статуса.

## Rebuild Rules

Узел восстанавливает локальное состояние из retained objects.

Rebuild выполняет:

```text
1. Clear derived state tables.
2. Clear non-final validation records produced by old validator_version.
3. Revalidate retained objects in dependency order.
4. Rebuild election_state.
5. Rebuild trustee_selection_state.
6. Rebuild tally_state.
```

Object payloads не изменяются во время rebuild.

Invalid objects без retained payload не revalidated during rebuild. Если новая validator version исправляет false-invalid, узел должен получить payload повторно через sync.
