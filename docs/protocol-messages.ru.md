# Protocol Messages

Этот документ описывает сообщения протокола LibreVote v1.

Документ разделяет неизменяемые доменные объекты, которые попадают в object log, и служебные сетевые сообщения, которые используются для discovery, announcements и direct sync.

## Принятые Решения

- Основной формат сериализации сетевых сообщений: Protocol Buffers.
- Доменные объекты используют canonical protobuf profile из `docs/crypto-layer.ru.md`.
- Служебные request/response сообщения не являются доменными объектами.
- `GossipSub` передает только object announcements, без полного payload объекта.
- Полные объекты передаются только через direct sync protocols.
- `InventoryResponse` возвращает только `ObjectRef`, а не полные объекты.
- `Hello` в v1 не содержит capabilities.
- Direct protocol errors используют единый `ProtocolError`.
- `BlindTokenIssue.encrypted_payload` является частью доменного объекта `BlindTokenIssue`.

## Категории Сообщений

LibreVote v1 использует две категории сообщений.

```text
domain objects
- имеют object_id
- имеют object_type
- сохраняются в object log
- проходят canonical hashing
- проходят доменную валидацию

network messages
- не имеют собственного content-addressed object_id
- не сохраняются в object log
- используются для handshake, announcements и sync
- валидируются сетевым слоем
```

Примеры:

```text
AnonymousBallot = domain object
BlindTokenIssue = domain object
TallyResult = domain object
ObjectAnnouncement = network message
GetObjectRequest = network message
GetObjectResponse = network message
```

## Domain Object Envelope

Все доменные объекты передаются и хранятся через `ObjectEnvelope`.

```text
ObjectEnvelope {
  object_id
  object_type
  protocol_version
  network_id
  scope
  payload
  pow
  created_at
}
```

Правила:

- `object_id` вычисляется по правилу из `docs/crypto-layer.ru.md`.
- `object_type` определяет структуру `payload`.
- `protocol_version` определяет версию формата объекта.
- `network_id` должен совпадать с локальной сетью.
- `scope` используется для sync и индексации.
- `payload` является canonical protobuf payload доменного объекта.
- `pow` является object PoW.
- `created_at` используется для временных проверок.

`ObjectEnvelope` используется в:

- локальном object log;
- `GetObjectResponse`;
- `GetObjectsResponse`;
- доменной валидации.

## Object Types

Поддерживаемые `object_type` в v1:

```text
TrusteeSelectionElection
TrusteeNomination
TrusteeVote
TrusteeSelectionResult
TrusteeConsent
AnonymousElection
TallyKeySet
BlindTokenRequest
BlindTokenIssue
AnonymousBallot
TallyDecryptionShare
TallyResult
```

Узел отклоняет неизвестный `object_type` и не распространяет его дальше.

## Scope

Поддерживаемые значения `scope`:

```text
network
election_id
trustee_selection_id
```

Правила:

- `network` используется для объектов и запросов уровня сети.
- `election_id` используется для объектов основного голосования.
- `trustee_selection_id` используется для объектов выбора trustees.

## GossipSub ObjectAnnouncement

`GossipSub` передает только `ObjectAnnouncement`.

```text
ObjectAnnouncement {
  network_id
  protocol_version
  object_id
  object_type
  scope
  election_id
  trustee_selection_id
  object_pow
  created_at
}
```

Назначение:

```text
peer сообщает: "у меня есть object_id такого-то типа"
```

Правила проверки:

- `network_id` совпадает с локальной сетью.
- `protocol_version` поддерживается локальным узлом.
- `object_type` известен.
- `scope` согласован с `object_type`.
- `object_pow` валиден для `object_id` и `object_type`.
- `created_at` находится в допустимом clock skew.
- `object_id` не находится в recent duplicate cache.

`ObjectAnnouncement` не подтверждает валидность доменного объекта. Получатель догружает полный объект через `GetObject` или `GetObjects` и только затем выполняет domain validation.

`GossipSub message id` вычисляется из `object_id`.

## Direct Protocols

Direct protocols работают поверх transport streams.

Поддерживаемые protocol IDs:

```text
/librevote/v1/hello
/librevote/v1/inventory
/librevote/v1/get-object
/librevote/v1/get-objects
/librevote/v1/get-election-state
```

Все direct request/response сообщения содержат `network_id` и `protocol_version`.

## Hello

`Hello` используется для первичного protocol handshake.

```text
HelloRequest {
  network_id
  protocol_version
  peer_admission_proof
  node_time
}

HelloResponse {
  network_id
  protocol_version
  peer_admission_status
  node_time
  error
}
```

Правила:

- `network_id` должен совпадать.
- `protocol_version` должен поддерживаться обеими сторонами.
- `peer_admission_proof` должен пройти проверку.
- `node_time` используется для оценки clock skew.
- `Hello` не содержит capabilities в v1.

Поддерживаемые значения `peer_admission_status`:

```text
accepted
rejected
rate_limited
```

## Inventory

`Inventory` используется для обмена списком известных объектов.

```text
InventoryRequest {
  network_id
  protocol_version
  scope
  object_types[]
  cursor
  limit
  request_pow
}

InventoryResponse {
  network_id
  protocol_version
  scope
  object_refs[]
  next_cursor
  error
}
```

`InventoryResponse` возвращает только ссылки на объекты.

```text
ObjectRef {
  object_id
  object_type
  scope
  created_at
}
```

Правила:

- `request_pow` обязателен.
- `limit` ограничивает количество `ObjectRef` в ответе.
- `cursor` является opaque cursor для постраничной синхронизации.
- `object_types[]` ограничивает типы объектов в ответе.
- Полные объекты не возвращаются через `InventoryResponse`.

## GetObject

`GetObject` используется для точечной догрузки одного объекта.

```text
GetObjectRequest {
  network_id
  protocol_version
  object_id
  request_pow
}

GetObjectResponse {
  network_id
  protocol_version
  object_id
  status
  object
  error
}
```

Поддерживаемые значения `status`:

```text
found
not_found
rejected
rate_limited
```

Правила:

- `request_pow` обязателен.
- `object` заполняется только при `status = found`.
- `object.object_id` должен совпадать с запрошенным `object_id`.
- Получатель заново проверяет `object_id`, `object_pow` и domain validity.

## GetObjects

`GetObjects` используется для пакетной догрузки объектов.

```text
GetObjectsRequest {
  network_id
  protocol_version
  object_ids[]
  limit_bytes
  request_pow
}

GetObjectsResponse {
  network_id
  protocol_version
  objects[]
  missing_object_ids[]
  rejected_object_ids[]
  error
}
```

Правила:

- `request_pow` обязателен.
- `limit_bytes` ограничивает суммарный размер ответа.
- `objects[]` содержит только найденные объекты.
- `missing_object_ids[]` содержит неизвестные peer'у объекты.
- `rejected_object_ids[]` содержит объекты, которые peer не отдает из-за лимитов или политики.
- Получатель проверяет каждый объект независимо.

## GetElectionState

`GetElectionState` используется для первичной синхронизации по конкретному голосованию.

```text
GetElectionStateRequest {
  network_id
  protocol_version
  election_id
  known_object_ids[]
  limit
  request_pow
}

GetElectionStateResponse {
  network_id
  protocol_version
  election_id
  object_refs[]
  state_summary_hash
  has_more
  error
}
```

Правила:

- `request_pow` обязателен.
- `object_refs[]` содержит только ссылки на объекты.
- `known_object_ids[]` позволяет peer'у не возвращать уже известные ссылки.
- `state_summary_hash` является подсказкой для сравнения локального состояния.
- `state_summary_hash` не является авторитетным результатом голосования.
- Полные объекты догружаются через `GetObject` или `GetObjects`.

## ProtocolError

Direct protocol errors используют единый формат.

```text
ProtocolError {
  code
  message
  retry_after_ms
}
```

Поддерживаемые `code`:

```text
invalid_network
unsupported_version
invalid_request
invalid_pow
not_found
rate_limited
rejected
internal_error
```

Правила:

- `message` предназначен для диагностики, а не для доменной логики.
- Узел не отправляет подробные domain validation traces в `ProtocolError`.
- `retry_after_ms` заполняется для `rate_limited`.

## Encoding Rules

Сетевые request/response messages сериализуются обычным protobuf encoding.

Доменные объекты внутри `ObjectEnvelope.payload` сериализуются canonical protobuf profile.

```text
network messages -> protobuf
domain objects -> canonical protobuf profile
```

Криптографические операции выполняются только над canonical domain object bytes или явно заданными canonical signing/proof payloads.

## Versioning Rules

Каждое сетевое сообщение содержит:

```text
network_id
protocol_version
```

Каждый доменный объект содержит:

```text
network_id
protocol_version
object_type
```

Правила:

- Неизвестная major version отклоняется.
- Неизвестный `object_type` отклоняется.
- Объект с неизвестным `object_type` не сохраняется как валидный и не распространяется дальше.
- `protocol_version` участвует в canonical payload доменного объекта.

## BlindTokenIssue Payload

`BlindTokenIssue.encrypted_payload` является частью доменного объекта `BlindTokenIssue`.

```text
BlindTokenIssue {
  election_id
  trustee_public_key
  voter_public_key
  request_object_id
  recipient_key_id
  encrypted_payload
  created_at
  pow
  signature
}
```

Публичная часть `BlindTokenIssue` входит в object log и аудируется всеми узлами.

`encrypted_payload` расшифровывается только избирателем, владеющим соответствующим `voter_encryption_private_key`.

```text
BlindTokenIssuePayload {
  blinded_token_signature
  trustee_blind_token_key_id
}
```

## Validation Boundaries

Сетевой слой проверяет:

- `network_id`;
- `protocol_version`;
- размер сообщения;
- `request_pow`;
- наличие обязательных полей;
- rate limits;
- duplicate cache.

Доменный слой проверяет:

- `object_id`;
- object PoW;
- подписи;
- blind token proofs;
- encrypted choice proofs;
- trustee selection rules;
- tally rules.

Protocol messages не должны смешивать эти границы.
