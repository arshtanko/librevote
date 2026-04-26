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
- `AnonymousElection` является структурным корневым объектом основного голосования.
- Основное голосование становится активным только при наличии валидного `TallyKeySet`.
- `TallyKeySet` фиксирует финальный trustee set, valid consents и threshold tally key setup.
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
  scope_id
  payload
  pow
  created_at
}
```

Правила:

- `object_id` вычисляется по canonical envelope bytes без `object_id` и `pow`.
- `object_type` определяет конкретную структуру `payload`.
- `protocol_version` определяет версию формата объекта.
- `network_id` отделяет production, test и local сети.
- `scope` используется для sync, индексации и фильтрации.
- `scope_id` содержит `election_id`, `trustee_selection_id` или пустое значение для `scope = network`.
- `payload` сериализуется через canonical protobuf profile.
- `pow` находится только в envelope и проверяется до доменной валидации.
- `created_at` используется для проверки временных окон и clock skew.

Поддерживаемые значения `scope`:

```text
network
election_id
trustee_selection_id
```

Обязательное соответствие object type и scope:

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

`network` scope является discovery root. Inventory по `network` scope возвращает root objects, включая `TrusteeSelectionElection` и `AnonymousElection`.

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
  signature
}
```

Инварианты:

- `trustee_selection_id` ссылается на существующее `TrusteeSelectionElection`.
- `signature` валидна для `candidate_public_key`.
- `ObjectEnvelope.created_at` находится внутри nomination window.

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
  signature
}
```

Инварианты:

- `voter_public_key` входит в `voter_allowlist[]`.
- `selected_candidate_keys[]` содержит не более `max_choices_per_vote` элементов.
- Каждый выбранный кандидат имеет валидный `TrusteeNomination`.
- `signature` валидна для `voter_public_key`.
- `ObjectEnvelope.created_at` находится внутри voting window.

Конфликтный ключ:

```text
trustee_vote_conflict_key = trustee_selection_id || voter_public_key
```

Если для одного `trustee_vote_conflict_key` существует больше одного валидного `TrusteeVote`, вся конфликтная группа исключается из подсчета.

## TrusteeSelectionResult

`TrusteeSelectionResult` является публикуемым предварительным результатом выбора trustees.

```text
TrusteeSelectionResult {
  trustee_selection_id
  candidate_ranking[]
  initial_selected_trustees[]
  threshold_t
  trustee_count_n
  candidate_scores[]
  conflicted_vote_count
  valid_vote_count
  result_hash
  reporter_public_key
  signature
}
```

Правила:

- Объект удобен для распространения результата и UI.
- Объект не является авторитетным сам по себе.
- Узел принимает результат только если локальный пересчет совпадает с `result_hash`.
- `candidate_ranking[]` содержит всех candidates с валидным `TrusteeNomination`, отсортированных deterministic ranking.
- `initial_selected_trustees[]` содержит первые `3` trustees из `candidate_ranking[]` для UI и initial consent targeting.
- Каждый ranked trustee содержит signing public key и blind-token public key из валидного `TrusteeNomination`.
- `threshold_t = 2`.

## TrusteeConsent

`TrusteeConsent` подтверждает согласие candidate trustee участвовать в конкретном основном анонимном голосовании.

```text
TrusteeConsent {
  trustee_selection_id
  trustee_selection_result_hash
  election_id
  election_parameters_hash
  trustee_public_key
  trustee_tally_setup_public_key
  threshold_t
  trustee_count_n
  signature
}
```

Инварианты:

- `trustee_public_key` имеет валидный `TrusteeNomination` в referenced trustee selection.
- `trustee_selection_result_hash` указывает на валидный preliminary `TrusteeSelectionResult` для того же `trustee_selection_id`.
- `election_id` указывает на структурно валидный `AnonymousElection`.
- `election_parameters_hash` совпадает с canonical hash параметров `AnonymousElection`.
- `trustee_tally_setup_public_key` используется для encrypted DKG shares этого election.
- `threshold_t = 2`.
- `trustee_count_n = 3`.
- `signature` валидна для `trustee_public_key`.

Конфликтный ключ consent:

```text
trustee_consent_conflict_key = election_id || trustee_public_key
trustee_consent_tally_setup_conflict_key = election_id || trustee_tally_setup_public_key
```

Если для одного consent conflict key существует больше одного валидного `TrusteeConsent`, вся группа получает `valid_but_conflicted`, и candidate не может попасть в финальный trustee set этого election.

Финальный trustee set для `election_id` выводится детерминированно как первые `3` candidates из `candidate_ranking[]`, которые имеют valid non-conflicted `TrusteeConsent` для этого `election_id` и уникальные `trustee_tally_setup_public_key`.

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
  threshold_t
  trustee_count_n
  eligibility_scheme
  issuance_starts_at
  issuance_ends_at
  voting_starts_at
  voting_ends_at
  tally_starts_at
  creator_public_key
  signature
}
```

Инварианты v1:

- `eligibility_scheme = blind_token_v1`.
- `trustee_count_n = 3`.
- `threshold_t = 2`.
- `trustee_selection_result_hash` указывает на валидный preliminary `TrusteeSelectionResult` для того же `trustee_selection_id`.
- `voter_allowlist[]` является публичным списком `VoterEntry`.
- `options[]` содержит минимум два варианта.
- Временные окна идут в порядке issuance, voting, tally.
- `signature` валидна для `creator_public_key`.

`AnonymousElection` сам по себе не активирует issuance или voting. Election считается operationally active только если существует валидный `TallyKeySet` для `election_id`.

## TallyKeyContribution

`TallyKeyContribution` публикуется каждым trustee из финального trustee set во время threshold key setup.

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

DKG commitment entry:

```text
DKGCommitment {
  sender_trustee_public_key
  coefficient_index
  commitment
}
```

Encrypted share entry:

```text
DKGEncryptedShare {
  sender_trustee_public_key
  recipient_trustee_public_key
  recipient_tally_setup_key_id
  recipient_index
  encrypted_share
  share_encryption_proof
}
```

Инварианты:

- `election_id` указывает на структурно валидный `AnonymousElection`.
- `trustee_public_key` имеет valid non-conflicted `TrusteeConsent` для `election_id`.
- `trustee_tally_setup_public_key` совпадает с ключом из `TrusteeConsent`.
- `dkg_commitments[]` задают вклад trustee в distributed key generation и отсортированы по `coefficient_index`.
- `dkg_encrypted_shares[]` содержит ровно один share для каждого trustee из derived final trustee set.
- Каждый `DKGEncryptedShare` привязан к sender, recipient, recipient setup key id и recipient index.
- `share_encryption_proof` публично доказывает, что encrypted share согласован с `dkg_commitments[]` и recipient setup key.
- `setup_proof` валиден для `dkg_commitments[]`.
- `signature` валидна для `trustee_public_key`.

Конфликтный ключ contribution:

```text
tally_key_contribution_conflict_key = election_id || trustee_public_key
```

Если для одного `tally_key_contribution_conflict_key` существует больше одного valid `TallyKeyContribution`, вся группа получает `valid_but_conflicted`, и `TallyKeySet` для этого election не валиден.

## TallyKeySet

`TallyKeySet` публикует финальный trustee set и threshold tally key для anonymous election.

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

Инварианты:

- `election_id` ссылается на структурно валидный `AnonymousElection`.
- `trustee_selection_result_hash` совпадает с `AnonymousElection.trustee_selection_result_hash`.
- `trustee_set[]` содержит первые `3` ranked candidates с valid non-conflicted `TrusteeConsent`.
- `trustee_consent_object_ids[]` содержит ровно `3` valid non-conflicted consents для `trustee_set[]`.
- `tally_key_contribution_object_ids[]` содержит ровно `3` valid non-conflicted contributions от trustees из `trustee_set[]`.
- `trustee_set[]` имеет уникальные trustee signing keys, blind-token keys и tally setup keys.
- `trustee_set_hash` соответствует canonical `trustee_set[]`.
- `threshold_t = 2`.
- `trustee_count_n = 3`.
- `tally_public_key` детерминированно выводится из valid DKG commitments.
- `setup_proofs[]` валидны для `tally_public_key` и `trustee_key_commitments[]`.
- `tally_key_set_hash` совпадает с локально вычисленным hash activation data: `election_id`, `trustee_selection_result_hash`, canonical `trustee_set[]`, sorted consent object ids, sorted contribution object ids, canonical DKG commitments и `tally_public_key`.
- `signature` валидна для `reporter_public_key`.

`TallyKeySet` не использует trusted dealer. Ни один одиночный trustee или creator не должен знать полный tally private key.

Несколько reporters могут опубликовать equivalent `TallyKeySet` objects. Узел использует локально пересчитанный `tally_key_set_hash`, а не доверие к reporter.

## BlindTokenRequest

`BlindTokenRequest` публикуется избирателем для получения blind token signatures от trustees.

```text
BlindTokenRequest {
  election_id
  voter_public_key
  blinded_token_message
  recipient_encryption_public_key
  signature
}
```

Инварианты:

- `election_id` ссылается на operationally active `AnonymousElection` с валидным `TallyKeySet`.
- `voter_public_key` входит в публичный `voter_allowlist[]`.
- `recipient_encryption_public_key` совпадает с encryption key в соответствующем `VoterEntry`.
- `signature` валидна для `voter_public_key`.
- `ObjectEnvelope.created_at` находится внутри issuance window.

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
- `election_id` совпадает с `BlindTokenRequest.election_id`.
- `voter_public_key` совпадает с `BlindTokenRequest.voter_public_key`.
- `recipient_key_id` соответствует `recipient_encryption_public_key` из request.
- `signature` валидна для `trustee_public_key`.
- `ObjectEnvelope.created_at` находится внутри issuance window.

Конфликтный ключ issue:

```text
blind_token_issue_conflict_key = election_id || trustee_public_key || voter_public_key
```

Если для одного `blind_token_issue_conflict_key` существует больше одного криптографически валидного `BlindTokenIssue`, вся конфликтная группа исключается из issuance.

Инварианты зашифрованного payload проверяются избирателем после расшифровки:

- `blinded_token_signature` валидна для исходного blinded token request.
- `trustee_blind_token_key_id` принадлежит тому же trustee, который подписал public envelope.

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
  signature
}
```

Инварианты:

- `trustee_public_key` входит в `trustee_set[]`.
- `ObjectEnvelope.created_at >= AnonymousElection.tally_starts_at` с учетом clock skew policy.
- `encrypted_tally_hash` соответствует локально вычисленному encrypted tally или ожидает matching tally recompute как pending dependency.
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
  tally_key_set_hash
  encrypted_tally_hash
  decryption_share_object_ids[]
  option_results[]
  valid_ballot_count
  conflicted_ballot_count
  result_hash
  reporter_public_key
  signature
}
```

Правила:

- Объект удобен для распространения результата и UI.
- Объект не является авторитетным сам по себе.
- Узел принимает результат только если локальный пересчет совпадает с `result_hash`.
- `decryption_share_object_ids[]` содержит минимум `2` валидных shares.
- `decryption_share_object_ids[]` содержит shares от distinct trustees.
- `option_results[]` соответствует расшифрованному tally.
- Invalid ballot count является локальной диагностикой и не входит в `TallyResult`.

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
pending_payload_evicted
valid
valid_for_tally
valid_but_conflicted
invalid
```

Правила:

- `pending_dependencies` означает, что объект ожидает election metadata, trustee set или связанные объекты.
- `pending_payload_evicted` означает, что pending payload удален по retention limit и должен быть reacquired через sync.
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
trustee_tally_setup
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
  candidate_ranking[]
  initial_selected_trustees[]
}

TallyState {
  election_id
  encrypted_tally_hash
  valid_ballot_count
  conflicted_ballot_count
  invalid_ballot_count_diagnostic
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

AnonymousElection
-> TrusteeSelectionResult
-> TrusteeConsent[]
-> TallyKeyContribution[]
-> TallyKeySet
-> BlindTokenRequest[]
-> BlindTokenIssue[]
-> AnonymousBallot[]
-> TallyDecryptionShare[]
-> TallyResult
```

Узел не доверяет ссылкам между объектами без локальной проверки каждого связанного объекта.
