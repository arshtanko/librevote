# Модель данных

Этот документ описывает доменную модель данных LibreVote v1.

Модель данных описывает проверяемые объекты, их связи, локальные производные состояния и инварианты. Она не описывает Go-структуры, protobuf-схемы или формат таблиц базы данных дословно.

## Принятые Решения

- В v1 нет отдельного `PublicElection`.
- Неанонимное голосование используется для выбора trustees через `TrusteeSelectionElection`.
- Основное голосование описывается через `AnonymousElection`.
- `AnonymousElection` содержит публичный `voter_allowlist`.
- `TrusteeSelectionResult` является публикуемым объектом.
- `TallyResult` является публикуемым объектом.
- Result-объекты не являются авторитетными: каждый узел проверяет их локальным пересчетом.
- `BlindTokenIssue` распространяется через P2P как зашифрованный payload.
- Приватные ключи хранятся локально только в encrypted-at-rest виде.
- Все доменные объекты неизменяемы после публикации.

## Object Envelope

Все сетевые доменные объекты хранятся как content-addressed objects.

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
- `object_type` определяет конкретную структуру `payload`.
- `protocol_version` определяет версию формата объекта.
- `network_id` отделяет production, test и local сети.
- `scope` используется для sync, индексации и фильтрации.
- `payload` сериализуется через canonical protobuf profile.
- `pow` проверяется до доменной валидации.
- `created_at` используется для проверки временных окон и clock skew.

Поддерживаемые значения `scope`:

```text
network
election_id
trustee_selection_id
```

## Object Types

Доменные object types v1:

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

## Voter Entry

Allowlist голосования содержит публичные записи избирателей.

```text
VoterEntry {
  voter_id
  voter_signing_public_key
  voter_encryption_public_key
}
```

Назначение полей:

- `voter_id` является локальным идентификатором записи в allowlist.
- `voter_signing_public_key` используется для публичных подписей и проверки права запросить blind token.
- `voter_encryption_public_key` используется trustees для шифрования `BlindTokenIssue`.

`voter_signing_public_key` и `voter_encryption_public_key` являются разными ключами.

## TrusteeSelectionElection

`TrusteeSelectionElection` описывает публичное неанонимное голосование за trustees.

```text
TrusteeSelectionElection {
  trustee_selection_id
  network_id
  title
  description
  voter_allowlist[]
  nomination_starts_at
  nomination_ends_at
  voting_starts_at
  voting_ends_at
  consent_starts_at
  consent_ends_at
  trustee_count_n
  threshold_t
  max_choices_per_vote
  created_at
  creator_public_key
  signature
}
```

Инварианты v1:

- `trustee_count_n = 3`.
- `threshold_t = 2`.
- `max_choices_per_vote = 3`.
- `voter_allowlist[]` содержит уникальные `voter_signing_public_key`.
- Временные окна идут в порядке nomination, voting, consent.
- `signature` валидна для `creator_public_key`.

## TrusteeNomination

`TrusteeNomination` публикуется кандидатом в trustees.

```text
TrusteeNomination {
  trustee_selection_id
  candidate_public_key
  candidate_blind_token_public_key
  candidate_node_peer_id
  statement
  created_at
  pow
  signature
}
```

Инварианты:

- `trustee_selection_id` ссылается на существующее `TrusteeSelectionElection`.
- `signature` валидна для `candidate_public_key`.
- `created_at` находится внутри nomination window.

Конфликтные ключи:

```text
trustee_nomination_candidate_conflict_key = trustee_selection_id || candidate_public_key
trustee_nomination_blind_token_conflict_key = trustee_selection_id || candidate_blind_token_public_key
```

Если любая конфликтная группа содержит больше одного валидного `TrusteeNomination`, вся группа исключается из выбора trustees.

## TrusteeVote

`TrusteeVote` является публичным неанонимным голосом за кандидатов в trustees.

```text
TrusteeVote {
  trustee_selection_id
  voter_public_key
  selected_candidate_keys[]
  created_at
  pow
  signature
}
```

Инварианты:

- `voter_public_key` входит в `voter_allowlist[]`.
- `selected_candidate_keys[]` содержит не более `max_choices_per_vote` элементов.
- Каждый выбранный кандидат имеет валидный `TrusteeNomination`.
- `signature` валидна для `voter_public_key`.
- `created_at` находится внутри voting window.

Конфликтный ключ:

```text
trustee_vote_conflict_key = trustee_selection_id || voter_public_key
```

Если для одного `trustee_vote_conflict_key` существует больше одного валидного `TrusteeVote`, вся конфликтная группа исключается из подсчета.

## TrusteeSelectionResult

`TrusteeSelectionResult` является публикуемым результатом выбора trustees.

```text
TrusteeSelectionResult {
  trustee_selection_id
  selected_trustees[]
  threshold_t
  trustee_count_n
  candidate_scores[]
  conflicted_vote_count
  valid_vote_count
  result_hash
  created_at
  reporter_public_key
  signature
}
```

Правила:

- Объект удобен для распространения результата и UI.
- Объект не является авторитетным сам по себе.
- Узел принимает результат только если локальный пересчет совпадает с `result_hash`.
- `selected_trustees[]` содержит ровно `3` trustees.
- Каждый selected trustee содержит signing public key и blind-token public key из валидного `TrusteeNomination`.
- `threshold_t = 2`.

## TrusteeConsent

`TrusteeConsent` подтверждает согласие выбранного trustee участвовать в основном анонимном голосовании.

```text
TrusteeConsent {
  trustee_selection_id
  trustee_selection_result_hash
  anonymous_election_id
  trustee_public_key
  selected_trustees_hash
  threshold_t
  trustee_count_n
  consented_at
  pow
  signature
}
```

Инварианты:

- `trustee_public_key` входит в финальный trustee set.
- Все `3` trustees из финального trustee set публикуют валидный consent.
- `threshold_t = 2`.
- `trustee_count_n = 3`.
- `signature` валидна для `trustee_public_key`.

## AnonymousElection

`AnonymousElection` описывает основное анонимное голосование.

```text
AnonymousElection {
  election_id
  network_id
  title
  description
  options[]
  voter_allowlist[]
  trustee_selection_id
  trustee_selection_result_hash
  trustee_set[]
  threshold_t
  trustee_count_n
  eligibility_scheme
  tally_key_set_object_id
  tally_public_key
  issuance_starts_at
  issuance_ends_at
  voting_starts_at
  voting_ends_at
  tally_starts_at
  created_at
  creator_public_key
  signature
}
```

Инварианты v1:

- `eligibility_scheme = blind_token_v1`.
- `trustee_count_n = 3`.
- `threshold_t = 2`.
- `trustee_set[]` совпадает с финальным результатом `TrusteeSelectionResult`.
- Все trustees из `trustee_set[]` имеют валидный `TrusteeConsent`.
- `voter_allowlist[]` является публичным списком `VoterEntry`.
- `options[]` содержит минимум два варианта.
- `tally_public_key` соответствует валидному `TallyKeySet`.
- Временные окна идут в порядке issuance, voting, tally.

## TallyKeySet

`TallyKeySet` публикует threshold tally key для anonymous election.

```text
TallyKeySet {
  election_id
  trustee_set_hash
  threshold_t
  trustee_count_n
  tally_public_key
  trustee_key_commitments[]
  setup_proofs[]
}
```

Инварианты:

- `election_id` ссылается на `AnonymousElection`.
- `trustee_set_hash` соответствует `trustee_set[]`.
- `threshold_t = 2`.
- `trustee_count_n = 3`.
- `setup_proofs[]` валидны для `tally_public_key`.

## BlindTokenRequest

`BlindTokenRequest` публикуется избирателем для получения blind token signatures от trustees.

```text
BlindTokenRequest {
  election_id
  voter_public_key
  blinded_token_message
  recipient_encryption_public_key
  created_at
  pow
  signature
}
```

Инварианты:

- `election_id` ссылается на `AnonymousElection`.
- `voter_public_key` входит в публичный `voter_allowlist[]`.
- `recipient_encryption_public_key` совпадает с encryption key в соответствующем `VoterEntry`.
- `signature` валидна для `voter_public_key`.
- `created_at` находится внутри issuance window.

Конфликтный ключ запроса:

```text
blind_token_request_conflict_key = election_id || voter_public_key
```

Если для одного `blind_token_request_conflict_key` существует больше одного валидного `BlindTokenRequest`, вся конфликтная группа исключается из issuance. Trustees не публикуют `BlindTokenIssue` для конфликтной группы.

Каждый trustee выдает не более одного `BlindTokenIssue` для пары:

```text
election_id || voter_public_key
```

## BlindTokenIssue

`BlindTokenIssue` публикуется trustee в P2P-сеть как зашифрованный ответ на `BlindTokenRequest`.

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

Зашифрованный payload:

```text
BlindTokenIssuePayload {
  blinded_token_signature
  trustee_blind_token_key_id
}
```

Инварианты публичной части:

- `trustee_public_key` входит в `trustee_set[]`.
- `voter_public_key` входит в `voter_allowlist[]`.
- `request_object_id` указывает на валидный `BlindTokenRequest`.
- `recipient_key_id` соответствует `recipient_encryption_public_key` из request.
- `signature` валидна для `trustee_public_key`.

Конфликтный ключ issue:

```text
blind_token_issue_conflict_key = election_id || trustee_public_key || voter_public_key
```

Если для одного `blind_token_issue_conflict_key` существует больше одного криптографически валидного `BlindTokenIssue`, вся конфликтная группа исключается из issuance.

Инварианты зашифрованного payload проверяются избирателем после расшифровки:

- `blinded_token_signature` валидна для исходного blinded token request.
- `trustee_blind_token_key_id` принадлежит trustee из `trustee_set[]`.

Публикация encrypted issue через P2P позволяет всем узлам аудировать факт выдачи без раскрытия blind token signature содержимого.

## AnonymousBallot

`AnonymousBallot` описан в `docs/ballots.ru.md`.

```text
AnonymousBallot {
  election_id
  encrypted_choice
  choice_validity_proof
  token_public_key
  token_nullifier
  eligibility_proof
  token_holder_signature
  created_at
  pow
}
```

Конфликтный ключ:

```text
anonymous_ballot_conflict_key = election_id || token_nullifier
```

Если для одного `anonymous_ballot_conflict_key` существует больше одного валидного `AnonymousBallot`, вся конфликтная группа исключается из tally.

## TallyDecryptionShare

`TallyDecryptionShare` публикуется trustee после завершения voting window.

```text
TallyDecryptionShare {
  election_id
  trustee_public_key
  encrypted_tally_hash
  decryption_share
  decryption_proof
  created_at
  signature
}
```

Инварианты:

- `trustee_public_key` входит в `trustee_set[]`.
- `encrypted_tally_hash` соответствует локально вычисленному encrypted tally.
- `decryption_proof` валиден для `decryption_share`.
- `signature` валидна для `trustee_public_key`.

Конфликтный ключ:

```text
tally_decryption_share_conflict_key = election_id || encrypted_tally_hash || trustee_public_key
```

Если для одного `tally_decryption_share_conflict_key` существует больше одного валидного `TallyDecryptionShare`, вся конфликтная группа исключается из tally decryption.

## TallyResult

`TallyResult` является публикуемым результатом основного голосования.

```text
TallyResult {
  election_id
  encrypted_tally_hash
  decryption_share_object_ids[]
  option_results[]
  valid_ballot_count
  conflicted_ballot_count
  invalid_ballot_count
  result_hash
  created_at
  reporter_public_key
  signature
}
```

Правила:

- Объект удобен для распространения результата и UI.
- Объект не является авторитетным сам по себе.
- Узел принимает результат только если локальный пересчет совпадает с `result_hash`.
- `decryption_share_object_ids[]` содержит минимум `2` валидных shares.
- `option_results[]` соответствует расшифрованному tally.

## Локальные Статусы Валидации

Validation status не является сетевым объектом.

```text
ValidationRecord {
  object_id
  validation_status
  validation_errors[]
  dependencies[]
  first_seen_at
  last_checked_at
}
```

Статусы:

```text
pending_dependencies
valid
valid_for_tally
valid_but_conflicted
invalid
```

Правила:

- `pending_dependencies` означает, что объект ожидает election metadata, trustee set или связанные объекты.
- `valid` означает, что объект прошел доменную проверку, но не является бюллетенем для tally.
- `valid_for_tally` означает, что бюллетень участвует в tally.
- `valid_but_conflicted` означает, что объект криптографически корректен, но исключен из protocol use из-за конфликтной группы.
- `invalid` означает, что объект не используется и не перепубликовывается.

## Локальное Хранение Ключей

Приватные ключи хранятся локально в encrypted-at-rest виде.

```text
KeyRecord {
  key_id
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

- `encrypted_private_key` не сериализуется в сетевые доменные объекты.
- `encryption_metadata` содержит параметры локального шифрования ключа.
- Сырые private keys не логируются.
- Удаление ключа делает невозможным создание новых подписей или расшифровку связанных encrypted payloads.

## Derived State

Derived state не является источником истины.

```text
ElectionState {
  election_id
  phase
  known_object_ids[]
  validation_summary
  computed_result_hash
}

TrusteeSelectionState {
  trustee_selection_id
  nominations[]
  votes[]
  selected_trustees[]
  consent_status[]
}

TallyState {
  election_id
  encrypted_tally_hash
  valid_ballot_count
  conflicted_ballot_count
  invalid_ballot_count
  decryption_shares[]
  option_results[]
}
```

Derived state всегда пересчитывается из object log.

## Связи Объектов

Основной граф объектов:

```text
TrusteeSelectionElection
-> TrusteeNomination[]
-> TrusteeVote[]
-> TrusteeSelectionResult
-> TrusteeConsent[]

AnonymousElection
-> TrusteeSelectionResult
-> TrusteeConsent[]
-> TallyKeySet
-> BlindTokenRequest[]
-> BlindTokenIssue[]
-> AnonymousBallot[]
-> TallyDecryptionShare[]
-> TallyResult
```

Узел не доверяет ссылкам между объектами без локальной проверки каждого связанного объекта.
