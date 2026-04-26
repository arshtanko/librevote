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
- Pending payloads хранятся до финального validation status.
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
- `GetObject` и `GetObjects` возвращают только объекты с `payload_retained = true`.

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
valid
valid_for_tally
valid_but_conflicted
invalid
```

Правила:

- `validator_version` фиксирует версию правил валидации.
- `invalid` объекты не возвращаются через sync APIs.
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
  first_seen_at
  last_seen_at
  seen_count
  validation_error_code
}
```

Правила:

- `payload_bytes` для invalid объекта не сохраняется.
- Повторное получение invalid `object_id` обновляет `last_seen_at` и `seen_count`.
- Invalid object metadata используется для duplicate suppression, peer scoring и локальной диагностики.
- Invalid object metadata не является доменным объектом.

## Object Ingestion Transaction

Прием объекта выполняется атомарно.

```text
1. Begin transaction.
2. Check existing object_id.
3. Insert or update objects metadata.
4. Insert payload into object_payloads when retained.
5. Write validation_records.
6. Write object_dependencies for pending objects.
7. Drop payload for invalid objects.
8. Update derived state.
9. Commit transaction.
```

Правила:

- Если транзакция не завершилась, объект не считается сохраненным.
- Нельзя сохранить validation record без metadata object record.
- Нельзя обновить derived state до сохранения object metadata и validation record.
- Если объект признан invalid в той же транзакции, payload не остается в `object_payloads`.
- Если pending объект при повторной проверке становится invalid, его payload удаляется, а `payload_retained` становится `false`.

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
  selected_trustees_hash
  valid_vote_count
  conflicted_vote_count
  consent_count
  updated_at
}

tally_state {
  election_id primary key
  encrypted_tally_hash
  valid_ballot_count
  conflicted_ballot_count
  invalid_ballot_count
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
trustee_tally_share
anonymous_token
```

Правила:

- `encrypted_private_key` создается криптографическим слоем.
- SQLite не хранит plaintext private keys.
- Passphrase не хранится.
- Raw secrets не логируются.
- Удаление ключа делает невозможным новые подписи, новые decrypt operations и новые proof generation операции для этого ключа.

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
pending_dependencies payloads -> retained until final validation status
invalid payloads -> not retained durably
```

Для завершенных голосований валидные и conflicted объекты остаются в локальном хранилище бессрочно.

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
