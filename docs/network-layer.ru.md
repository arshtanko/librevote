# Сетевой слой

Этот документ описывает сетевой слой LibreVote.

Сетевой слой работает поверх транспортного слоя, описанного в `docs/transport-layer.ru.md`. Он отвечает за обнаружение peers, сетевые protocol messages, GossipSub propagation, direct sync, peer admission, PoW, rate limits и базовые меры против сетевой деанонимизации.

Сетевой слой не управляет transport protocol details, parsing адресов, lifecycle низкоуровневых соединений или host internals напрямую. Эти детали принадлежат транспортному слою.

## Принятые Решения

- Discovery для первой версии: bootstrap peers + `Kademlia DHT`.
- `GossipSub` используется для быстрой доставки object announcements.
- `GossipSub` не считается механизмом гарантированной доставки.
- Надежность достигается через локальный object log, direct sync, повторные запросы и периодический anti-entropy sync.
- Семантика доставки: eventual at-least-once delivery с дедупликацией по `object_id`.
- PoW используется для peer admission и object spam protection.
- Для анонимных бюллетеней v1 применяются базовые меры против сетевой деанонимизации, но сильная анонимность сетевых метаданных не гарантируется.

## Зависимость От Транспортного Слоя

Сетевой слой использует транспортный слой как абстракцию:

```text
local_peer_id
listen_addresses
dial(peer_addr)
open_stream(peer_id, protocol_id)
accept_stream(protocol_id)
connection_events
peer_reachability_status
```

Транспортный слой предоставляет защищенные соединения и streams. Сетевой слой поверх них реализует протокол LibreVote.

## Цели

- Позволить новым узлам находить сеть через bootstrap peers и DHT.
- Распространять новые объекты с малой задержкой.
- Позволить узлам догружать пропущенные объекты после offline периода или потери gossip-сообщений.
- Не доверять peer'ам при проверке голосов, результатов или trustee selection.
- Сохранять сетевой слой независимым от конкретной схемы голосования.

## Не Цели

- Сетевой слой не определяет право голоса.
- Сетевой слой не выполняет финальный подсчет.
- Сетевой слой не решает доменные конфликты бюллетеней.
- Сетевой слой не заменяет доменную валидацию.
- Сетевой слой не является blockchain или consensus layer.
- Сетевой слой не описывает transport protocol details.
- Сетевой слой v1 не гарантирует сильную анонимность сетевых метаданных.

## Базовая Модель

LibreVote использует модель eventual consistency.

```text
1. Узел получает object announcement через GossipSub.
2. Узел догружает объект через direct sync, если payload отсутствует локально.
3. Узел выполняет дешевые сетевые проверки.
4. Узел передает объект в domain validation pipeline.
5. Валидный объект сохраняется в локальный append-only object log.
6. Узел перепубликует announcement о валидном объекте.
7. Локальное состояние и tally пересчитываются детерминированно из object log.
```

Сеть помогает доставить данные. Валидность данных определяет не сеть, а локальная проверка каждого узла.

## Идентичности

Сетевой слой видит transport peer identity как `peer_id`.

`peer_id` используется для:

- connection tracking;
- peer admission;
- peer scoring;
- rate limits;
- sync scheduling.

`peer_id` не должен использоваться как:

- voter identity;
- trustee identity;
- подпись доменного объекта;
- доказательство авторства анонимного бюллетеня.

Анонимный бюллетень не должен содержать `peer_id`, `node_public_key` или другой transport-level идентификатор узла.

## Network ID

Каждая сеть LibreVote должна иметь `network_id`.

```text
network_id = mainnet | testnet | local | custom group id
```

`network_id` используется для:

- Разделения production, test и локальных сетей.
- Формирования DHT rendezvous keys.
- Формирования GossipSub topics.
- Проверки совместимости peers.
- Предотвращения случайного смешивания несовместимых сетей.

Узел не должен выполнять protocol sync с peer'ом, если `network_id` не совпадает.

## Peer Discovery

Первая версия использует:

```text
bootstrap peers + Kademlia DHT
```

Стартовый поток:

```text
1. Узел получает bootstrap peers из конфигурации.
2. Сетевой слой просит transport layer подключиться к bootstrap peers.
3. Узел запускает Kademlia DHT в namespace LibreVote.
4. Узел объявляет себя как участника network_id.
5. Узел ищет других peers через DHT.
6. Найденные peers проходят hello и peer admission checks.
```

Bootstrap peers не являются доверенными серверами. Они помогают найти сеть, но не подтверждают право голоса, результаты, trustee selection или валидность объектов.

## DHT Usage

DHT используется только для discovery.

Она не используется как источник доменной истины и не хранит критичные данные голосования.

Рекомендуемая модель:

```text
rendezvous_key = HASH("librevote-dht-rendezvous-v1" || network_id)
```

Узел публикует provider record для `rendezvous_key`, а другие узлы ищут providers по этому ключу.

Ограничения:

- DHT records не считаются доверенными.
- DHT уязвима к спаму со стороны Sybil-узлов.
- DHT-запросы раскрывают интерес узла к сети LibreVote участникам DHT-маршрута.
- Узел должен применять peer admission и rate limits к найденным peers.

Режим DHT server/client выбирается с учетом reachability status, который предоставляет transport layer.

## Peer Admission

Перед активным protocol exchange peer должен пройти admission-проверку LibreVote.

```text
PeerAdmissionProof {
  network_id
  peer_id
  protocol_version
  pow
  expires_at
}
```

Проверка:

- `network_id` должен совпадать с локальной сетью.
- `peer_id` должен соответствовать transport peer identity соединения.
- `protocol_version` должен быть совместим с локальным узлом.
- `pow` должен удовлетворять текущей сложности peer admission.
- `expires_at` не должен быть в прошлом.

Peer admission PoW не доказывает право голоса. Он только повышает стоимость массового создания сетевых идентичностей.

## GossipSub Role

`GossipSub` используется как low-latency propagation layer.

Его задача:

```text
быстро сообщить сети, что появился новый объект
```

Его задача не состоит в том, чтобы гарантировать доставку каждому узлу.

В открытой P2P-сети строгая гарантированная доставка невозможна без дополнительных предположений. Узлы бывают offline, сеть бывает partitioned, peers отказываются пересылать данные, а часть узлов недоступна для входящих соединений.

Реалистичное свойство LibreVote:

```text
Честный узел, который подключен к сети и периодически синхронизируется, со временем получает все валидные объекты, если хотя бы один честный peer продолжает их хранить и отдавать.
```

## GossipSub Topics

Схема topics должна быть простой и не раскрывать лишний интерес узла к конкретным голосованиям через topic subscriptions.

Базовый topic:

```text
/librevote/<network_id>/v1/objects
```

Этот topic используется для:

- Object announcements.
- Сигналов о новых election metadata.
- Сигналов о новых trustee selection объектах.
- Сигналов о новых ballot/tally объектах.

В v1 используется только общий `/objects` topic. Отдельные topics по `election_id` не используются, чтобы подписка на topic не раскрывала интерес peer'а к конкретному голосованию.

## Gossip Messages

GossipSub должен передавать `ObjectAnnouncement`.

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

Правила сетевой проверки до доменной валидации:

- `network_id` совпадает с локальной сетью.
- `protocol_version` поддерживается локальным узлом.
- `object_type` известен.
- `scope` согласован с `object_type`.
- Размер сообщения не превышает лимит для типа сообщения.
- `object_id` считается неподтвержденной ссылкой до успешного `get-object`.
- `object_pow` валиден для `object_id` и `object_type`.
- `created_at` не выходит за допустимый clock skew.
- Сообщение не было недавно обработано тем же узлом.

После этих проверок узел догружает неизвестный `object_id` через direct sync. Полученный `ObjectEnvelope` передается в domain validation pipeline.

`GossipSub message id` должен вычисляться из `object_id`, а не из transport source peer. Это снижает дублирование в gossip mesh и сохраняет content-addressed модель распространения.

## Object Announcements

Для защиты от DoS и поддержки больших proof objects используется announcement-first распространение.

```text
object announcement
- gossip передает object_id и metadata
- полный объект догружается через get-object
- безопаснее для больших anonymous proof objects
```

Полные объекты догружаются через direct sync. GossipSub не передает полный payload доменного объекта.

## Direct Sync Protocols

GossipSub не гарантирует доставку. Поэтому сетевой слой должен иметь direct request/response протоколы поверх transport streams.

Минимальный набор:

```text
/librevote/v1/hello
/librevote/v1/inventory
/librevote/v1/get-object
/librevote/v1/get-objects
/librevote/v1/get-election-state
```

### Hello

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

### Inventory

`Inventory` используется для обмена известными object ids.

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

ObjectRef {
  object_id
  object_type
  scope
  created_at
}
```

Поддерживаемые значения `scope`:

```text
network
election_id
trustee_selection_id
```

### Get Object

`GetObject` используется для точечной догрузки объекта.

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

### Get Objects

`GetObjects` используется для пакетной догрузки.

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

### Get Election State

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

## Delivery Semantics

LibreVote не требует exactly-once доставки.

Требуемая модель:

```text
at-least-once delivery
deduplication by object_id
idempotent validation
eventual sync
```

Если один и тот же объект пришел много раз, узел проверяет `object_id` и игнорирует дубликаты.

Если разные объекты конфликтуют на доменном уровне, например два голоса с одним nullifier, конфликт решается domain validation rules, а не сетевым слоем.

## Synchronization Strategy

Узел выполняет sync в следующих случаях:

- После подключения к новому peer.
- После получения неизвестного object announcement.
- После обнаружения неизвестного `state_summary_hash`.
- После восстановления соединения с сетью.
- Периодически для активных голосований.
- Перед отображением финального результата пользователю.

Минимальная стратегия:

```text
1. Запросить inventory по нужному scope.
2. Сравнить object_ids с локальным object log.
3. Запросить отсутствующие объекты через get-object или get-objects.
4. Выполнить сетевую и доменную валидацию.
5. Сохранить валидные объекты в object log.
6. Повторить до отсутствия новых object ids или достижения лимитов.
```

Для первой версии не требуется глобальный consensus. Достаточно, чтобы честные узлы со временем получили один и тот же набор валидных объектов.

## Object Log

Надежность сети зависит от того, что узлы хранят и отдают валидные объекты.

Object log должен быть append-only на логическом уровне.

```text
StoredObject {
  object_id
  object_type
  scope
  payload
  first_seen_at
  validation_status
  source
}
```

Правила:

- Объект адресуется по hash канонического payload.
- Payload не должен изменяться после сохранения.
- Повторное получение того же `object_id` не создает новый объект.
- Source peer хранится только как сетевое служебное состояние.
- Source peer не должен становиться частью доменной модели.

Для активных и недавно завершенных голосований узел должен отдавать валидные объекты другим peers, если это не нарушает локальные rate limits.

## Validation Boundaries

Сетевой слой выполняет только дешевые и общие проверки.

```text
network validation
- network_id
- protocol version
- message size
- message type
- payload encoding
- object hash
- PoW
- duplicate cache
- basic time skew

domain validation
- election exists
- signature validity
- voter eligibility
- trustee selection rules
- blind token validity
- nullifier uniqueness
- encrypted ballot validity proof
- tally share validity
```

Это разделение позволяет добавлять новые eligibility schemes без переработки P2P-сетевого слоя.

## Proof-of-Work

PoW используется как cost mechanism.

Домены PoW:

```text
peer admission pow
- усложняет массовое создание peer identities

object pow
- усложняет спам доменными объектами

request pow
- применяется к дорогим sync-запросам
```

Базовый формат:

```text
pow_input = domain_separator || target_hash || difficulty || nonce
pow_hash = HASH(pow_input)

valid if leading_zero_bits(pow_hash) >= difficulty
```

Примеры domain separators:

```text
librevote-peer-admission-pow-v1
librevote-object-pow-v1
librevote-sync-request-pow-v1
```

Начальная рекомендация по сложности:

```text
PeerAdmissionProof: medium
TrusteeNomination: medium
TrusteeVote: low
TrusteeConsent: low
ElectionCreated: medium/high
AnonymousBallot: low/medium
TallyShare: low
SyncRequest: low
```

PoW не доказывает право голоса и не заменяет подписи, allowlists, blind tokens, nullifiers или threshold cryptography.

## Peer Scoring And Rate Limits

Узел должен ограничивать protocol-level нагрузку от peers.

Минимальные механизмы:

- Лимит сообщений в секунду на peer.
- Лимит байт protocol payload в секунду на peer.
- Лимит неизвестных object announcements.
- Лимит параллельных sync requests.
- Лимит запрашиваемых объектов в `get-objects`.
- Временный ban для peers, которые систематически отправляют невалидные protocol messages.

Connection-level лимиты находятся в транспортном слое.

Peer score должен учитывать:

- Валидные доставленные объекты.
- Дубли и устаревшие announcements.
- Невалидный PoW.
- Невалидные подписи в protocol messages.
- Превышение protocol rate limits.
- Невалидные protocol versions.
- Полезность peer'а при sync.

Peer scoring используется только для сетевого поведения. Он не должен влиять на право голоса или результат голосования.

## Network Privacy

Криптографическая анонимность бюллетеня не означает полную сетевую анонимность.

Анонимный бюллетень не содержит `voter_public_key`, но peers все равно наблюдают сетевые метаданные.

Основные риски:

- Peer, первым распространивший ballot, вероятностно связывается с автором наблюдателем.
- Соседние peers видят, от какого peer пришел новый объект.
- Timing correlation связывает действие пользователя с появлением объекта в сети.
- Direct sync запросы раскрывают, какие объекты или голосования интересуют узел.
- Bootstrap peers и DHT peers видят сетевую активность узла в рамках LibreVote.

Transport-level privacy risks, такие как IP address и connection timing, описаны в `docs/transport-layer.ru.md`.

LibreVote v1 принимает ограничение:

```text
LibreVote v1 aims for cryptographic ballot anonymity, but it does not provide strong network metadata anonymity.
```

## Basic Metadata Protections

Для первой версии обязательны базовые меры.

Анонимный бюллетень:

- Не содержит `voter_public_key`.
- Не содержит `peer_id`.
- Не содержит `node_public_key`.
- Не валидируется через transport peer identity.
- Валидируется через anonymous eligibility proof, nullifier, object hash и PoW.

Сетевое поведение:

- Узел добавляет случайную задержку перед публикацией собственного anonymous ballot.
- Узел перепубликует чужие валидные anonymous ballots так же, как собственные.
- Узел использует batching для совместной публикации нескольких announcements.
- Узел не сохраняет source peer как часть доменного объекта.
- Узел не использует pubsub author identity для доменной валидации anonymous ballot.
- Узел использует общий `/objects` topic, чтобы не раскрывать интерес через election-specific subscriptions.

PubSub-level identity является сетевой/transport metadata. Даже если библиотека требует подпись или author field на уровне pubsub, эти данные не должны попадать в доменную модель и не должны использоваться как доказательство авторства бюллетеня.

## Failure Handling

Сетевой слой должен нормально обрабатывать частичные protocol-level сбои.

Сценарии:

- Bootstrap peer доступен на transport уровне, но не отвечает на `hello`.
- Peer разорвал stream во время sync.
- Gossip announcement пришел раньше, чем election metadata.
- Узел получил announcement, но `get-object` не нашел payload.
- Несколько peers прислали разные payload для одного `object_id`.
- Часы peer отличаются от локальных.

Правила:

- Отложить объект в pending, если не хватает зависимостей.
- Повторить sync с другим peer.
- Никогда не принимать payload, `object_id` которого не совпадает с правилом из `docs/crypto-layer.ru.md`.
- Не считать peer злонамеренным за одиночный сбой.
- Понижать score за повторяющиеся protocol violations.

Transport failures, например dial timeout или stream open timeout, обрабатываются транспортным слоем и передаются сетевому слою как events/errors.

## Versioning

Все сетевые протоколы должны содержать версию.

Начальный namespace:

```text
/librevote/v1/...
```

Правила:

- Узел отклоняет неизвестную major version.
- Узел отклоняет неизвестный `object_type`.
- Объект с неизвестным `object_type` не сохраняется как валидный и не распространяется дальше.
- Изменения формата protocol messages требуют нового protocol namespace.

## Scope

Для первой реализации сетевого слоя достаточно:

```text
1. Static bootstrap peers from config.
2. Kademlia DHT discovery.
3. Global /objects GossipSub topic.
4. Object announcements.
5. Hello direct protocol.
6. Inventory direct protocol.
7. GetObject direct protocol.
8. GetObjects direct protocol.
9. Peer admission PoW.
10. Object PoW validation.
11. Request PoW for sync requests.
12. Basic peer scoring and protocol rate limits.
13. Random delay for publishing anonymous ballots.
14. Batching for anonymous ballot announcements.
15. Republishing of validated anonymous ballot announcements.
```

Transport-specific scope описан в `docs/transport-layer.ru.md`.
