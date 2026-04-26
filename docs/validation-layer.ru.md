# Validation Layer

Этот документ описывает слой валидации LibreVote v1.

Validation layer присваивает локальный validation status доменным объектам, разрешает зависимости, обрабатывает конфликты и запускает пересчет derived state. Сетевой слой доставляет объекты, но не решает, какие объекты участвуют в голосовании или tally.

## Принятые Решения

- Валидация выполняется по стадиям.
- Missing dependencies дают статус `pending_dependencies`.
- Конфликтные повторные объекты исключаются всей группой.
- `stale` не является validation status объекта.
- `stale` относится только к derived result state.
- `TrusteeSelectionResult` и `TallyResult` проверяются локальным пересчетом.
- Public validators не расшифровывают `BlindTokenIssue.encrypted_payload`.
- Invalid payloads не хранятся долговременно.
- Revalidation является штатной частью работы узла.

## Validation Statuses

Validation layer использует статусы из `docs/data-model.ru.md` и `docs/storage-layer.ru.md`.

```text
pending_dependencies
valid
valid_for_tally
valid_but_conflicted
invalid
```

Значения:

- `pending_dependencies`: объект структурно обработан, но не хватает связанных объектов.
- `valid`: объект прошел доменную проверку, но не является входом tally.
- `valid_for_tally`: бюллетень участвует в tally.
- `valid_but_conflicted`: объект криптографически корректен, но исключен из protocol use из-за конфликтной группы.
- `invalid`: объект не используется, не перепубликовывается и не отдается через sync.

`stale` не записывается в `validation_records`. Он хранится только в derived state, например в `tally_state.result_status`.

## Validation Stages

Валидация выполняется в пять стадий.

```text
1. Envelope validation
2. Structural validation
3. Contextual validation
4. Conflict resolution
5. Derived verification
```

Стадии являются порядком выполнения проверки. Они не являются отдельными публичными статусами объекта.

## Envelope Validation

Envelope validation выполняет дешевые общие проверки `ObjectEnvelope`.

Проверки:

- `network_id` совпадает с локальной сетью.
- `protocol_version` поддерживается.
- `object_type` известен.
- `scope` согласован с `object_type`.
- `payload` декодируется canonical protobuf profile.
- `object_id` соответствует правилу из `docs/crypto-layer.ru.md`.
- object PoW валиден.
- `created_at` находится в допустимом clock skew.

Если envelope validation не проходит, объект получает `invalid`. Payload такого объекта не хранится долговременно.

## Structural Validation

Structural validation проверяет объект без полного доменного контекста.

Проверки:

- обязательные поля присутствуют;
- enum значения известны;
- массивы не превышают допустимые лимиты;
- повторяющиеся поля, которые являются множествами, не содержат дублей;
- публичные ключи имеют корректный формат;
- подписи над собственным payload валидны;
- proof containers имеют корректный формат;
- `token_holder_signature` валидна для `token_public_key`;
- encrypted payloads имеют корректный контейнерный формат без расшифровки.

Если structural validation не проходит, объект получает `invalid`.

## Contextual Validation

Contextual validation проверяет объект относительно других объектов и текущего состояния election.

Проверки:

- referenced election существует;
- referenced trustee selection существует;
- referenced request/result/key set существует;
- voter входит в `voter_allowlist`;
- trustee входит в финальный `trustee_set`;
- candidate имеет валидный `TrusteeNomination`;
- object `created_at` находится в правильном временном окне;
- `threshold_t = 2`;
- `trustee_count_n = 3`;
- `eligibility_scheme = blind_token_v1`;
- `tally_public_key` соответствует `TallyKeySet`;
- cryptographic proofs валидны относительно election context.

Если обязательная зависимость отсутствует, объект получает `pending_dependencies`, а storage layer записывает dependency records.

## Structural Dependencies

Некоторые объекты образуют циклы контекстной зависимости.

Пример:

```text
AnonymousElection -> TrusteeConsent[]
TrusteeConsent -> AnonymousElection

AnonymousElection -> TallyKeySet
TallyKeySet -> AnonymousElection
```

Чтобы такие циклы не блокировали валидацию, validation layer различает структурное наличие объекта и его финальный validation status.

Структурная зависимость считается удовлетворенной, если referenced object прошел envelope validation и structural validation.

Финальная зависимость считается удовлетворенной, если referenced object имеет итоговый статус `valid` или `valid_for_tally`.

Правила:

- `TrusteeConsent` требует структурно существующий `AnonymousElection`.
- `TallyKeySet` требует структурно существующий `AnonymousElection`.
- `AnonymousElection` требует финально валидные `TrusteeConsent[]` и `TallyKeySet`.
- Result objects требуют финально валидные входные объекты.

## Conflict Resolution

Conflict resolution выполняется после envelope, structural и contextual validation.

Поддерживаемые конфликтные группы:

```text
trustee_nomination_candidate_conflict_key = trustee_selection_id || candidate_public_key
trustee_nomination_blind_token_conflict_key = trustee_selection_id || candidate_blind_token_public_key
trustee_vote_conflict_key = trustee_selection_id || voter_public_key
blind_token_request_conflict_key = election_id || voter_public_key
blind_token_issue_conflict_key = election_id || trustee_public_key || voter_public_key
anonymous_ballot_conflict_key = election_id || token_nullifier
public_ballot_conflict_key = election_id || voter_public_key
tally_decryption_share_conflict_key = election_id || encrypted_tally_hash || trustee_public_key
```

Правило v1:

```text
valid conflict group size = 1 -> object can be used
valid conflict group size > 1 -> every object in group becomes valid_but_conflicted
```

Conflict resolution не использует порядок доставки, source peer, `created_at`, PoW nonce или `object_id` для выбора победителя.

## Derived Verification

Derived verification применяется к публикуемым result objects.

Объекты:

```text
TrusteeSelectionResult
TallyResult
```

Правила:

- result object проверяется локальным пересчетом;
- подпись reporter проверяется, но не делает результат авторитетным;
- несовпадающий `result_hash` дает `invalid`;
- совпадающий результат дает `valid`;
- поздний объект, влияющий на результат, меняет derived result state на `stale`, но не превращает ранее валидный result object в `invalid`.

## Validation Outcome

Validation layer возвращает outcome для storage и derived state слоев.

```text
ValidationOutcome {
  object_id
  validation_status
  validation_error_code
  dependencies[]
  conflict_key
  affected_scope
  should_republish
  should_recompute_state
}
```

Правила:

- `should_republish = true` только для объектов, прошедших envelope, structural и contextual validation.
- `invalid` объекты не перепубликовываются.
- `pending_dependencies` не перепубликовываются до успешной revalidation.
- `should_recompute_state = true`, если объект влияет на trustee selection, issuance, ballots или tally.

## TrusteeSelectionElection Validation

Проверки:

- `trustee_selection_id` корректен.
- `network_id` совпадает.
- `trustee_count_n = 3`.
- `threshold_t = 2`.
- `max_choices_per_vote = 3`.
- `voter_allowlist[]` не пуст.
- `voter_allowlist[]` содержит уникальные `voter_signing_public_key`.
- Временные окна идут в порядке nomination, voting, consent.
- `creator_public_key` имеет корректный формат.
- `signature` валидна для `creator_public_key`.

Итоговый статус:

```text
valid
```

## TrusteeNomination Validation

Проверки:

- `trustee_selection_id` существует.
- `created_at` находится внутри nomination window.
- `candidate_public_key` имеет корректный формат.
- `candidate_blind_token_public_key` имеет корректный формат.
- `signature` валидна для `candidate_public_key`.
- conflict group проверена по `trustee_nomination_candidate_conflict_key`.
- conflict group проверена по `trustee_nomination_blind_token_conflict_key`.

Missing dependency:

```text
TrusteeSelectionElection
```

Итоговый статус:

```text
valid
valid_but_conflicted
pending_dependencies
invalid
```

## TrusteeVote Validation

Проверки:

- `trustee_selection_id` существует.
- `voter_public_key` входит в `voter_allowlist[]`.
- `created_at` находится внутри voting window.
- `selected_candidate_keys[]` не содержит дублей.
- `len(selected_candidate_keys) <= max_choices_per_vote`.
- каждый selected candidate имеет валидный `TrusteeNomination`.
- `signature` валидна для `voter_public_key`.
- conflict group проверена по `trustee_vote_conflict_key`.

Missing dependencies:

```text
TrusteeSelectionElection
TrusteeNomination[]
```

Итоговые статусы:

```text
valid_for_tally
valid_but_conflicted
pending_dependencies
invalid
```

## TrusteeSelectionResult Validation

Проверки:

- `trustee_selection_id` существует.
- локальный trustee selection tally пересчитан.
- `candidate_scores[]` совпадает с локальным пересчетом.
- `selected_trustees[]` совпадает с локальным deterministic ranking и replacement rules.
- `valid_vote_count` совпадает.
- `conflicted_vote_count` совпадает.
- `threshold_t = 2`.
- `trustee_count_n = 3`.
- `result_hash` совпадает с локально вычисленным.
- `signature` валидна для `reporter_public_key`.

Missing dependencies:

```text
TrusteeSelectionElection
TrusteeNomination[]
TrusteeVote[]
```

Итоговый статус:

```text
valid
```

## TrusteeConsent Validation

Проверки:

- `trustee_selection_result_hash` указывает на валидный `TrusteeSelectionResult`.
- `anonymous_election_id` указывает на структурно валидный `AnonymousElection`.
- `trustee_public_key` входит в selected trustee set.
- `selected_trustees_hash` совпадает с финальным trustee set.
- `threshold_t = 2`.
- `trustee_count_n = 3`.
- `consented_at` находится внутри consent window.
- `signature` валидна для `trustee_public_key`.

Missing dependencies:

```text
TrusteeSelectionResult
AnonymousElection structural object
```

Итоговый статус:

```text
valid
```

## AnonymousElection Validation

Проверки:

- `election_id` корректен.
- `network_id` совпадает.
- `options[]` содержит минимум два варианта.
- `voter_allowlist[]` не пуст.
- `voter_allowlist[]` содержит уникальные `voter_signing_public_key`.
- `voter_allowlist[]` содержит уникальные `voter_encryption_public_key`.
- `eligibility_scheme = blind_token_v1`.
- `trustee_count_n = 3`.
- `threshold_t = 2`.
- `trustee_selection_result_hash` указывает на валидный `TrusteeSelectionResult`.
- `trustee_set[]` совпадает с финальным trustee selection result.
- все `3` trustees имеют валидный `TrusteeConsent`.
- `TallyKeySet` существует и валиден.
- `tally_public_key` совпадает с `TallyKeySet`.
- Временные окна идут в порядке issuance, voting, tally.
- `signature` валидна для `creator_public_key`.

Missing dependencies:

```text
TrusteeSelectionResult
TrusteeConsent[]
TallyKeySet
```

Итоговый статус:

```text
valid
```

## TallyKeySet Validation

Проверки:

- `election_id` указывает на структурно валидный `AnonymousElection`.
- `trustee_set_hash` соответствует `trustee_set[]` из `AnonymousElection`.
- `threshold_t = 2`.
- `trustee_count_n = 3`.
- `tally_public_key` имеет корректный формат.
- `setup_proofs[]` валидны.

Missing dependency:

```text
AnonymousElection structural object
```

Итоговый статус:

```text
valid
```

## BlindTokenRequest Validation

Проверки:

- `election_id` существует и указывает на валидный `AnonymousElection`.
- `voter_public_key` входит в `voter_allowlist[]`.
- `recipient_encryption_public_key` совпадает с `VoterEntry`.
- `blinded_token_message` имеет корректный формат.
- `created_at` находится внутри issuance window.
- `signature` валидна для `voter_public_key`.
- conflict group проверена по `blind_token_request_conflict_key`.

Missing dependency:

```text
AnonymousElection
```

Итоговые статусы:

```text
valid
valid_but_conflicted
pending_dependencies
invalid
```

## BlindTokenIssue Validation

Проверки публичной части:

- `election_id` существует и указывает на валидный `AnonymousElection`.
- `trustee_public_key` входит в `trustee_set[]`.
- `voter_public_key` входит в `voter_allowlist[]`.
- `request_object_id` указывает на валидный `BlindTokenRequest`.
- referenced `BlindTokenRequest` не имеет статус `valid_but_conflicted`.
- `recipient_key_id` соответствует `recipient_encryption_public_key` из request.
- `encrypted_payload` имеет корректный контейнерный формат.
- `signature` валидна для `trustee_public_key`.
- conflict group проверена по `blind_token_issue_conflict_key`.

Public validators не расшифровывают `encrypted_payload`.

Избиратель после расшифровки дополнительно проверяет:

- `blinded_token_signature` валидна для исходного blinded token request.
- `trustee_blind_token_key_id` принадлежит trustee из `trustee_set[]`.

Missing dependencies:

```text
AnonymousElection
BlindTokenRequest
```

Итоговые статусы публичной валидации:

```text
valid
valid_but_conflicted
pending_dependencies
invalid
```

## AnonymousBallot Validation

Проверки:

- `election_id` существует и указывает на валидный `AnonymousElection`.
- `created_at` находится внутри voting window.
- `token_public_key` имеет корректный формат.
- `token_nullifier` соответствует `election_id` и `token_public_key`.
- минимум `2` trustee blind token signatures валидны.
- подписавшие trustees входят в финальный trustee set.
- `token_holder_signature` валидна для `token_public_key`.
- `encrypted_choice` зашифрован под `tally_public_key`.
- количество ciphertexts равно количеству options.
- `choice_validity_proof` валиден.
- conflict group проверена по `anonymous_ballot_conflict_key`.

Missing dependency:

```text
AnonymousElection
```

Итоговые статусы:

```text
valid_for_tally
valid_but_conflicted
pending_dependencies
invalid
```

## TallyDecryptionShare Validation

Проверки:

- `election_id` существует и указывает на валидный `AnonymousElection`.
- `now >= tally_starts_at`.
- `trustee_public_key` входит в `trustee_set[]`.
- `encrypted_tally_hash` совпадает с локально вычисленным encrypted tally.
- `decryption_proof` валиден для `decryption_share`.
- `signature` валидна для `trustee_public_key`.
- conflict group проверена по `tally_decryption_share_conflict_key`.

Missing dependency:

```text
AnonymousElection
local encrypted tally
```

Итоговый статус:

```text
valid
valid_but_conflicted
pending_dependencies
invalid
```

## TallyResult Validation

Проверки:

- `election_id` существует и указывает на валидный `AnonymousElection`.
- local encrypted tally вычислен.
- `encrypted_tally_hash` совпадает с локальным.
- `decryption_share_object_ids[]` содержит минимум `2` валидных shares distinct trustees.
- `option_results[]` совпадает с локально расшифрованным результатом.
- `valid_ballot_count` совпадает с локальным count.
- `conflicted_ballot_count` совпадает с локальным count.
- `invalid_ballot_count` совпадает с локальным count.
- `result_hash` совпадает с локально вычисленным.
- `signature` валидна для `reporter_public_key`.

Missing dependencies:

```text
AnonymousElection
AnonymousBallot[]
TallyDecryptionShare[]
```

Итоговый статус:

```text
valid
```

## Revalidation Triggers

Revalidation запускается при событиях:

- появилась missing dependency;
- появился новый объект в conflict group;
- изменился validation status объекта, от которого зависят другие объекты;
- появился `TallyKeySet`;
- появился `TrusteeConsent`;
- появился `TallyDecryptionShare`;
- появился новый ballot;
- изменился `validator_version`.

Revalidation меняет только:

- `validation_records`;
- `object_dependencies`;
- derived state.

Revalidation не меняет retained payload.

## Invalid Handling

Если объект получает `invalid`:

- он не перепубликовывается;
- он не возвращается через `GetObject` и `GetObjects`;
- его payload не хранится долговременно;
- storage layer сохраняет только invalid metadata;
- peer source используется только для peer scoring и диагностики.

## Pending Handling

Если объект получает `pending_dependencies`:

- payload хранится до финального validation status;
- dependencies записываются в `object_dependencies`;
- объект не участвует в tally;
- объект не используется как финальная dependency для других объектов;
- при появлении dependencies объект проходит revalidation.

## Republishing Rules

Узел перепубликует announcement только для объектов, прошедших contextual validation.

Правила:

- `valid` перепубликуется.
- `valid_for_tally` перепубликуется.
- `valid_but_conflicted` перепубликуется, чтобы другие узлы видели conflict group.
- `pending_dependencies` не перепубликуется.
- `invalid` не перепубликуется.

Перепубликация выполняется только как `ObjectAnnouncement`, без полного payload.
