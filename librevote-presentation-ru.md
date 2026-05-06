---
marp: true
title: LibreVote - архитектура проверяемого P2P-голосования
theme: default
paginate: true
---


# LibreVote

## Проверяемое P2P-голосование с анонимными бюллетенями

**Тайминг: около 10 минут.** От CLI до результата, через каждый слой системы.

`Object log + локальная валидация + blind tokens + threshold tally`

<!-- speaker: 20 секунд. Главная мысль: LibreVote не просит доверять серверу. Каждый узел хранит объекты, сам их проверяет и сам пересчитывает результат. -->

---

# Главный Тезис

LibreVote строит доверие не через центральный сервер, а через три механизма:

1. **Immutable object log:** все важные события являются неизменяемыми объектами.
2. **Детерминированная локальная проверка:** каждый узел сам решает, что валидно.
3. **Криптографическая приватность:** право голоса отделяется от личности через blind tokens, а выбор шифруется threshold-ключом.

```mermaid
flowchart LR
  A[Пользователь] --> B[Публикует объект]
  B --> C[P2P сеть разносит ссылку]
  C --> D[Узел догружает payload]
  D --> E[Локально валидирует]
  E --> F[Пересчитывает derived state]
  F --> G[Показывает проверенный результат]
```

<!-- speaker: 30 секунд. Подчеркнуть: сеть только доставляет, но не делает объект истинным. Результат тоже не авторитетен, пока узел не пересчитал его сам. -->

---

# Карта Слоев

```mermaid
flowchart TB
  subgraph UX[Пользовательский контур]
    CLI[CLI]
    UI[Frontend / Result display]
  end

  subgraph NODE[Node lifecycle]
    Workers[Workers: sync, validation, issuance, voting, tally]
    Control[Local Control API]
  end

  subgraph DOMAIN[Доменная логика]
    Data[Data model]
    Validation[Validation layer]
    Trustee[Trustee selection]
    Blind[Blind token issuance]
    Ballots[Ballots]
    Tally[Tally layer]
  end

  subgraph CORE[Локальное ядро]
    Crypto[Crypto layer]
    Storage[SQLite storage]
  end

  subgraph P2P[P2P доставка]
    Protocol[Protocol messages]
    Transport[Transport layer]
  end

  CLI --> Control --> Workers
  UI --> Control
  Workers --> DOMAIN
  DOMAIN --> Crypto
  DOMAIN --> Storage
  Workers --> Protocol --> Transport
```

<!-- speaker: 45 секунд. Это главный слайд про слои. Снизу транспорт, выше протокол сообщений, рядом локальное ядро, сверху доменная логика и CLI. -->

---

# 1. CLI И Local Control API

**Роль:** безопасная точка входа для оператора, избирателя и trustee.

CLI не должен напрямую менять SQLite и не должен обходить node process. Он вызывает локальный control API работающего узла.

```mermaid
sequenceDiagram
  participant User as Пользователь
  participant CLI as CLI
  participant API as Local Control API
  participant Node as Node workers
  participant Store as SQLite

  User->>CLI: vote cast / tally compute / result show
  CLI->>API: локальная команда
  API->>Node: задача для worker'а
  Node->>Store: читает object log и ключи
  Node-->>API: проверенный статус
  API-->>CLI: machine-readable output
  CLI-->>User: понятный результат
```

**Почему отдельный слой важен:** команды пользователя остаются воспроизводимыми, а вся доменная логика проходит через один node lifecycle.

<!-- speaker: 20 секунд. У CLI роль интерфейса, а не источника истины. Это снижает риск, что разные команды создадут разные правила работы с данными. -->

---

# 2. Node Lifecycle

**Роль:** собрать транспорт, сеть, хранилище, ключи и фоновые процессы в один управляемый узел.

```mermaid
stateDiagram-v2
  [*] --> Init
  Init --> StorageReady: process lock + schema
  StorageReady --> KeysReady: unlock policy
  KeysReady --> TransportReady: node identity + QUIC
  TransportReady --> SyncReady: discovery + sync protocols
  SyncReady --> Rebuild: пересчет local state
  Rebuild --> Running

  Running --> SyncWorker
  Running --> ValidationWorker
  Running --> IssuanceWorker
  Running --> VotingWorker
  Running --> TallyWorker
  Running --> Shutdown
  Shutdown --> [*]
```

**Ключевая идея:** после падения узел может восстановиться из object log и заново построить derived state.

<!-- speaker: 20 секунд. Node lifecycle отвечает за порядок запуска и восстановление. Derived state не является источником истины, поэтому rebuild безопасен. -->

---

# 3. Transport Layer

**Роль:** соединять узлы, не зная ничего о голосованиях.

```mermaid
flowchart LR
  A[Node identity key] --> B[libp2p peer id]
  B --> C[Multiaddr]
  C --> D[QUIC connection]
  D --> E[Streams]
  E --> F[/librevote/... protocols]
```

**Что делает слой:**

- node identity, QUIC, multiaddr, streams;
- таймауты, лимиты, connection lifecycle;
- базовая reachability и NAT-реальность.

**Что не делает:** не проверяет бюллетени, не считает результат, не знает voter keys.

<!-- speaker: 20 секунд. Важно отделить node key от voter/trustee keys: сетевой peer не равен избирателю. -->

---

# 4. Protocol Messages

**Роль:** разделить доменные объекты и служебные сетевые сообщения.

```mermaid
flowchart LR
  subgraph Domain[Domain objects]
    OE[ObjectEnvelope]
    Payload[Canonical payload]
    ID[object_id]
    Log[Object log]
    OE --> Payload --> ID --> Log
  end

  subgraph Sync[Sync messages]
    Hello[Hello]
    Inv[Inventory]
    Ann[ObjectAnnouncement]
    Get[GetObject/GetObjects]
  end

  Ann -. object_id only .-> OE
  Get -. returns full object .-> OE
```

**Правило:** `ObjectAnnouncement` говорит только: «у меня есть объект». Он не доказывает, что объект валиден.

<!-- speaker: 25 секунд. Это предотвращает смешивание delivery и truth. Истина появляется только после canonical hash, подписи, зависимостей и конфликтов. -->

---

# 5. Storage Layer

**Роль:** сохранить все полученные объекты и локальные выводы, не превращая derived state в источник истины.

```mermaid
flowchart TB
  A[Object ingestion transaction] --> B[object_metadata]
  A --> C[object_payloads]
  A --> D[validation_records]
  A --> E[object_dependencies]
  A --> F[source_peer_metadata]

  C --> G[Immutable object log]
  D --> H[Revalidation queue]
  G --> I[Derived state rebuild]
  H --> I
  I --> J[ElectionState / TallyState / UI]

  K[Encrypted key store] --> L[voter, trustee, node keys]
```

**Инвариант:** если derived state поврежден или устарел, его можно пересчитать из retained objects.

<!-- speaker: 30 секунд. SQLite хранит payload, metadata, validation records, dependencies, sync state и зашифрованные ключи. Но главное - object log. -->

---

# 6. Data Model

**Роль:** описать неизменяемые объекты, зависимости и конфликтные ключи.

```mermaid
flowchart LR
  TSE[TrusteeSelectionElection]
  TN[TrusteeNomination]
  TV[TrusteeVote]
  TSR[TrusteeSelectionResult]

  AE[AnonymousElection]
  TC[TrusteeConsent]
  TKC[TallyKeyContribution]
  TKS[TallyKeySet]
  BTR[BlindTokenRequest]
  BTI[BlindTokenIssue]
  AB[AnonymousBallot]
  TDS[TallyDecryptionShare]
  TR[TallyResult]

  TSE --> TN --> TSR
  TSE --> TV --> TSR
  TSR --> AE
  AE --> TC --> TKC --> TKS
  TKS --> BTR --> BTI --> AB --> TDS --> TR
```

**Главное:** `TrusteeSelectionResult` и `TallyResult` публикуются для удобства, но принимаются только после локального пересчета.

<!-- speaker: 35 секунд. Data model фиксирует две большие части: выбор trustees и основное анонимное голосование. -->

---

# 7. Crypto Layer

**Роль:** дать проверяемую идентичность объектов, подписи, приватность бюллетеня и threshold-раскрытие результата.

```mermaid
flowchart TB
  A[Canonical protobuf bytes] --> B[SHA-256 object_id]
  B --> C[ObjectEnvelope]
  D[Ed25519 signatures] --> C
  E[Object PoW] --> C

  F[Blind Schnorr token] --> G[Eligibility proof]
  H[HPKE encrypted issue] --> G
  I[Threshold ElGamal] --> J[Encrypted choice]
  J --> K[Homomorphic tally]
  K --> L[2-of-3 decryption shares]
```

**Ключевая граница:** криптографические проверки выполняются над canonical bytes и явно заданными signing/proof payloads, а приватные ключи не попадают в сетевые объекты.

<!-- speaker: 35 секунд. Набор примитивов: canonical hashing, Ed25519, PoW, blind tokens, HPKE, threshold ElGamal и local key encryption. -->

---

# 8. Validation Layer

**Роль:** превратить «получен объект» в один из локальных статусов.

```mermaid
flowchart LR
  A[Received ObjectEnvelope] --> B[Envelope validation]
  B --> C[Structural validation]
  C --> D{Dependencies ready?}
  D -- нет --> E[pending_dependencies]
  D -- да --> F[Contextual validation]
  F --> G[Conflict resolution]
  G --> H[Derived verification]
  H --> I{Outcome}
  I --> V[valid]
  I --> T[valid_for_tally]
  I --> C2[valid_but_conflicted]
  I --> X[invalid]
```

**Конфликтное правило:** если в conflict group больше одного валидного объекта, вся группа исключается. Нет победителя по времени, peer, PoW или hash.

<!-- speaker: 40 секунд. Валидация стадийная: envelope, структура, зависимости, контекст, конфликты, derived verification. Это сердце локального консенсуса без блокчейна. -->

---

# 9. Trustee Selection Layer

**Роль:** публично и детерминированно выбрать trustees для анонимного голосования.

```mermaid
flowchart TD
  A[TrusteeSelectionElection] --> B[Nomination window]
  B --> C[TrusteeNomination]
  A --> D[Voting window]
  D --> E[TrusteeVote]
  C --> F[Deterministic candidate ranking]
  E --> F
  F --> G[TrusteeSelectionResult]
  G --> H[AnonymousElection привязывается к result_hash]
  H --> I[TrusteeConsent]
  I --> J[Final trustee set: first 3 with valid consent]
```

**Параметры:** `n = 3`, `t = 2`, `max_choices_per_vote = 3`.

<!-- speaker: 30 секунд. Trustee selection публичный и неанонимный. Его задача - получить упорядоченный список кандидатов, а затем финальный набор из тех, кто дал consent. -->

---

# 10. Blind Token Issuance

**Роль:** выдать право анонимного голосования так, чтобы trustees знали eligibility, но не знали будущий token.

```mermaid
sequenceDiagram
  participant V as Voter
  participant P2P as P2P object log
  participant T1 as Trustee 1
  participant T2 as Trustee 2
  participant T3 as Trustee 3

  V->>V: генерирует token keypair
  V->>V: blind(token_public_key)
  V->>P2P: BlindTokenRequest(voter_public_key, blinded_message)
  P2P->>T1: валидный request
  P2P->>T2: валидный request
  P2P->>T3: валидный request
  T1->>P2P: encrypted BlindTokenIssue
  T2->>P2P: encrypted BlindTokenIssue
  T3->>P2P: encrypted BlindTokenIssue
  V->>V: decrypt + unblind signatures
  V->>V: получает >= 2 signatures от разных trustees
```

**Privacy split:** `BlindTokenRequest` публично показывает участие voter, но `AnonymousBallot` уже не содержит `voter_public_key`.

<!-- speaker: 40 секунд. Это мост между публичным allowlist и анонимным бюллетенем. Trustees подписывают blinded message, поэтому не узнают token_public_key. -->

---

# 11. Ballots Layer

**Роль:** принять один анонимный encrypted vote от holder'а валидного token proof.

```mermaid
flowchart LR
  subgraph Public[Что видно всем]
    A[encrypted_choice]
    B[choice_validity_proof]
    C[token_public_key]
    D[token_nullifier]
    E[eligibility_proof]
    F[token_holder_signature]
  end

  subgraph Hidden[Чего нет в бюллетене]
    G[voter_public_key]
    H[node_peer_id]
    I[source peer как авторитет]
  end

  J[AnonymousBallot] --> Public
  Hidden -. не включается .-> J
```

**Double voting policy:** один `election_id || token_nullifier` должен иметь один валидный ballot. Несколько валидных бюллетеней с тем же nullifier исключаются все.

<!-- speaker: 35 секунд. Анонимность здесь криптографическая, не сетевая. Timing и первый распространитель могут оставаться metadata-риском. -->

---

# 12. Tally Layer

**Роль:** посчитать результат из `valid_for_tally` бюллетеней и проверить опубликованный `TallyResult`.

```mermaid
flowchart TD
  A[valid_for_tally AnonymousBallots] --> B[Homomorphic encrypted tally]
  B --> C[encrypted_tally_hash]
  C --> D[TallyDecryptionShare от trustee A]
  C --> E[TallyDecryptionShare от trustee B]
  C --> F[TallyDecryptionShare от trustee C]
  D --> G{>= 2 valid shares?}
  E --> G
  F --> G
  G -- да --> H[Decrypt aggregate result]
  H --> I[result_hash]
  I --> J[Verify / accept TallyResult]
  G -- нет --> K[result unavailable]
```

**Важно:** поздние валидные объекты могут сделать результат stale, тогда tally пересчитывается.

<!-- speaker: 40 секунд. TallyResult не авторитетен. Узел проверяет decryption shares и сверяет result_hash с локально пересчитанным результатом. -->

---

# End-to-End Timeline

```mermaid
gantt
  title LibreVote election lifecycle
  dateFormat  X
  axisFormat %s
  section Trustee selection
  Nomination                 :a1, 0, 10
  Public trustee voting      :a2, 10, 20
  Result verification        :a3, 20, 25
  Consent                    :a4, 25, 35
  section Activation
  DKG contributions          :b1, 35, 45
  TallyKeySet                :b2, 45, 50
  section Anonymous election
  Blind token issuance       :c1, 50, 65
  Anonymous voting           :c2, 65, 85
  section Results
  Decryption shares          :d1, 85, 95
  TallyResult verification   :d2, 95, 100
```

**Переходы фаз задаются объектами и временными окнами.** Голосование становится operationally active только после валидного `TallyKeySet`.

<!-- speaker: 35 секунд. Здесь связать все слои в один сценарий: сначала выбираем trustees, потом активируем anonymous election, потом issuance, voting и tally. -->

---

# Threat Model: Что Защищаем

```mermaid
quadrantChart
  title Security goals vs residual risks
  x-axis Низкая приватность --> Высокая приватность
  y-axis Низкая проверяемость --> Высокая проверяемость
  quadrant-1 Сильная сторона
  quadrant-2 Аудит без полной приватности
  quadrant-3 Не цель
  quadrant-4 Приватно, но зависит от trustee threshold
  Object log audit: [0.30, 0.90]
  Result recomputation: [0.35, 0.95]
  Anonymous ballot crypto: [0.80, 0.75]
  Сетевая анонимность: [0.25, 0.35]
  Coercion resistance: [0.20, 0.25]
  Local device compromise: [0.15, 0.20]
```

**Защищаем:** подмену объектов, result forgery, double voting, invalid decryption shares.

**Не обещаем:** coercion resistance, receipt-freeness, сильную сетевую анонимность, защиту при компрометации локального устройства.

<!-- speaker: 40 секунд. Честно проговорить границы. Если 2 из 3 trustees сговорились, они могут нарушить privacy threshold. Если меньше 2 доступны на tally, результат не раскрывается. -->

---

# Финальная Схема: Где Возникает Доверие

```mermaid
flowchart TB
  A[Content-addressed objects] --> B[Immutable object log]
  B --> C[Deterministic validation]
  C --> D[Conflict exclusion]
  D --> E[Derived state rebuild]
  E --> F[Local result recomputation]

  G[Blind tokens] --> H[Eligibility without voter in ballot]
  I[Threshold encryption] --> J[2-of-3 result reveal]
  H --> F
  J --> F

  K[P2P доставка] --> A
  K -. только доставка .-> B
```

