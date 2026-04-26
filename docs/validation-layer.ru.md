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
pending_payload_evicted
valid
valid_for_tally
valid_but_conflicted
invalid
```

Значения:

- `pending_dependencies`: объект структурно обработан, но не хватает связанных объектов.
- `pending_payload_evicted`: pending payload удален по retention limit и должен быть reacquired через sync.
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
- `scope_id` согласован с `scope` и `object_type`.
- `payload` декодируется canonical protobuf profile.
- `object_id` соответствует canonical envelope bytes из `docs/crypto-layer.ru.md`.
- envelope `pow` валиден.
- `ObjectEnvelope.created_at` находится в допустимом clock skew.

Если envelope validation не проходит, объект получает `invalid`. Payload такого объекта не хранится долговременно.

## Structural Validation

Structural validation проверяет объект без полного доменного контекста.

Проверки:

- обязательные поля присутствуют;
- enum значения известны;
- массивы не превышают допустимые лимиты;
- повторяющиеся поля, которые являются множествами, не содержат дублей;
- публичные ключи имеют корректный формат;
- подписи над canonical signing context валидны;
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
- trustee входит в финальный `TallyKeySet.trustee_set[]`;
- candidate имеет валидный `TrusteeNomination`;
- `ObjectEnvelope.created_at` находится в правильном временном окне;
- `threshold_t = 2`;
- `trustee_count_n = 3`;
- `eligibility_scheme = blind_token_v1`;
- `tally_public_key` соответствует `TallyKeySet`;
- cryptographic proofs валидны относительно election context.

Если обязательная зависимость отсутствует, объект получает `pending_dependencies`, а storage layer записывает dependency records.

## Structural Dependencies

Validation layer различает структурный root object и operational activation state.

Правила:

- `AnonymousElection` является структурным root object для основного голосования.
- `AnonymousElection` не требует `TrusteeConsent`, `TallyKeyContribution` или `TallyKeySet` для собственного статуса `valid`.
- Operationally active election означает `AnonymousElection` со статусом `valid` и валидным `TallyKeySet` для того же `election_id`.
- `TrusteeConsent` требует структурно валидный `AnonymousElection` и валидный preliminary `TrusteeSelectionResult`.
- `TallyKeyContribution` требует structurally valid `AnonymousElection` и valid non-conflicted `TrusteeConsent` от того же trustee.
- `TallyKeySet` требует structurally valid `AnonymousElection`, валидный preliminary `TrusteeSelectionResult`, `3` valid non-conflicted `TrusteeConsent` и `3` valid non-conflicted `TallyKeyContribution`.
- `BlindTokenRequest`, `BlindTokenIssue`, `AnonymousBallot`, `TallyDecryptionShare` и `TallyResult` требуют operationally active election.
- Result objects требуют финально валидные входные объекты.

## Conflict Resolution

Conflict resolution выполняется после envelope, structural и contextual validation.

Поддерживаемые конфликтные группы:

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
- `pending_payload_evicted` не перепубликовываются и требуют reacquire payload через sync.
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
- `ObjectEnvelope.created_at` находится внутри nomination window.
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
- `ObjectEnvelope.created_at` находится внутри voting window.
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
- `candidate_ranking[]` совпадает с локальным deterministic ranking.
- `initial_selected_trustees[]` совпадает с первыми `3` candidates из `candidate_ranking[]`.
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

Итоговые статусы:

```text
valid
pending_dependencies
invalid
```

## TrusteeConsent Validation

Проверки:

- `trustee_selection_id` существует.
- `trustee_selection_result_hash` указывает на валидный preliminary `TrusteeSelectionResult`.
- `election_id` указывает на структурно валидный `AnonymousElection`.
- `TrusteeSelectionResult.trustee_selection_id` совпадает с `trustee_selection_id`.
- `AnonymousElection.trustee_selection_id` совпадает с `trustee_selection_id`.
- `AnonymousElection.trustee_selection_result_hash` совпадает с `trustee_selection_result_hash`.
- `election_parameters_hash` совпадает с canonical hash параметров `AnonymousElection`.
- `trustee_public_key` имеет валидный `TrusteeNomination` в referenced trustee selection.
- `trustee_public_key` присутствует в `TrusteeSelectionResult.candidate_ranking[]`.
- `trustee_tally_setup_public_key` имеет корректный формат.
- `threshold_t = 2`.
- `trustee_count_n = 3`.
- `ObjectEnvelope.created_at` находится внутри consent window.
- `signature` валидна для `trustee_public_key`.
- conflict group проверена по `trustee_consent_conflict_key`.
- conflict group проверена по `trustee_consent_tally_setup_conflict_key`.

Missing dependencies:

```text
TrusteeSelectionElection
TrusteeSelectionResult
AnonymousElection structural object
TrusteeNomination
```

Итоговые статусы:

```text
valid
valid_but_conflicted
pending_dependencies
invalid
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
- `TrusteeSelectionResult.trustee_selection_id` совпадает с `trustee_selection_id`.
- Временные окна идут в порядке issuance, voting, tally.
- `signature` валидна для `creator_public_key`.

Missing dependencies:

```text
TrusteeSelectionResult
```

Итоговые статусы:

```text
valid
pending_dependencies
invalid
```

`AnonymousElection` со статусом `valid` является структурно валидным, но не operationally active до появления валидного `TallyKeySet`.

## TallyKeyContribution Validation

Проверки:

- `election_id` указывает на структурно валидный `AnonymousElection`.
- `trustee_public_key` имеет valid non-conflicted `TrusteeConsent` для `election_id`.
- `trustee_tally_setup_public_key` совпадает с `TrusteeConsent.trustee_tally_setup_public_key`.
- `dkg_commitments[]` имеют корректный формат и отсортированы по `coefficient_index`.
- `dkg_encrypted_shares[]` содержит ровно один share для каждого trustee из locally derived final trustee set.
- Каждый `DKGEncryptedShare.sender_trustee_public_key` совпадает с `trustee_public_key`.
- Каждый `DKGEncryptedShare.recipient_trustee_public_key` входит в locally derived final trustee set.
- Каждый `DKGEncryptedShare.recipient_tally_setup_key_id` совпадает с key id consent-а recipient trustee.
- Каждый `DKGEncryptedShare.recipient_index` совпадает с canonical index recipient trustee в final trustee set.
- Каждый `share_encryption_proof` валиден относительно `dkg_commitments[]`, recipient setup key и encrypted share.
- `setup_proof` валиден для `dkg_commitments[]`.
- `signature` валидна для `trustee_public_key`.
- conflict group проверена по `tally_key_contribution_conflict_key`.

Missing dependencies:

```text
AnonymousElection structural object
TrusteeSelectionResult
TrusteeConsent[]
```

Итоговые статусы:

```text
valid
valid_but_conflicted
pending_dependencies
invalid
```

## TallyKeySet Validation

Проверки:

- `election_id` указывает на структурно валидный `AnonymousElection`.
- `trustee_selection_result_hash` совпадает с `AnonymousElection.trustee_selection_result_hash`.
- `TrusteeSelectionResult.trustee_selection_id` совпадает с `AnonymousElection.trustee_selection_id`.
- `trustee_set[]` совпадает с локально derived final trustee set.
- final trustee set содержит первые `3` ranked candidates с valid non-conflicted `TrusteeConsent` для `election_id`.
- `trustee_consent_object_ids[]` содержит ровно `3` valid non-conflicted consents от trustees из `trustee_set[]`.
- `tally_key_contribution_object_ids[]` содержит ровно `3` valid non-conflicted `TallyKeyContribution` от trustees из `trustee_set[]`.
- `trustee_set[]` имеет уникальные trustee signing keys, blind-token keys и tally setup keys.
- `trustee_set_hash` соответствует canonical `trustee_set[]`.
- `threshold_t = 2`.
- `trustee_count_n = 3`.
- `tally_public_key` детерминированно выводится из valid DKG commitments.
- `setup_proofs[]` валидны для `tally_public_key` и `trustee_key_commitments[]`.
- `tally_key_set_hash` совпадает с локально вычисленным hash activation data.
- `signature` валидна для `reporter_public_key`.

Несколько `TallyKeySet` objects для одного `election_id` допустимы, если они имеют один и тот же локально вычисленный `tally_key_set_hash`. Объект с несовпадающим activation data получает `invalid`.

Missing dependencies:

```text
AnonymousElection structural object
TrusteeSelectionResult
TrusteeConsent[]
TallyKeyContribution[]
```

Итоговые статусы:

```text
valid
pending_dependencies
invalid
```

## BlindTokenRequest Validation

Проверки:

- `election_id` существует и указывает на operationally active `AnonymousElection`.
- `voter_public_key` входит в `voter_allowlist[]`.
- `recipient_encryption_public_key` совпадает с `VoterEntry`.
- `blinded_token_message` имеет корректный формат.
- `ObjectEnvelope.created_at` находится внутри issuance window.
- `signature` валидна для `voter_public_key`.
- conflict group проверена по `blind_token_request_conflict_key`.

Missing dependency:

```text
AnonymousElection
TallyKeySet
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

- `election_id` существует и указывает на operationally active `AnonymousElection`.
- `trustee_public_key` входит в `TallyKeySet.trustee_set[]`.
- `voter_public_key` входит в `voter_allowlist[]`.
- `request_object_id` указывает на валидный `BlindTokenRequest`.
- `BlindTokenIssue.election_id == BlindTokenRequest.election_id`.
- `BlindTokenIssue.voter_public_key == BlindTokenRequest.voter_public_key`.
- referenced `BlindTokenRequest` не имеет статус `valid_but_conflicted`.
- `recipient_key_id == key_id(BlindTokenRequest.recipient_encryption_public_key)`.
- `encrypted_payload` имеет корректный контейнерный формат.
- `ObjectEnvelope.created_at` находится внутри issuance window.
- `signature` валидна для `trustee_public_key`.
- conflict group проверена по `blind_token_issue_conflict_key`.

Public validators не расшифровывают `encrypted_payload`.

Избиратель после расшифровки дополнительно проверяет:

- `blinded_token_signature` валидна для исходного blinded token request.
- `trustee_blind_token_key_id` принадлежит тому же trustee, который подписал public envelope.

Missing dependencies:

```text
AnonymousElection
TallyKeySet
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

- `election_id` существует и указывает на operationally active `AnonymousElection`.
- `ObjectEnvelope.created_at` находится внутри voting window.
- `token_public_key` имеет корректный формат.
- `token_nullifier` соответствует `election_id` и `token_public_key`.
- минимум `2` trustee blind token signatures валидны от distinct trustees.
- подписавшие trustees входят в `TallyKeySet.trustee_set[]`.
- `token_holder_signature` валидна для `token_public_key`.
- `encrypted_choice` зашифрован под `TallyKeySet.tally_public_key`.
- количество ciphertexts равно количеству options.
- `choice_validity_proof` валиден.
- conflict group проверена по `anonymous_ballot_conflict_key`.

Missing dependency:

```text
AnonymousElection
TallyKeySet
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

- `election_id` существует и указывает на operationally active `AnonymousElection`.
- `ObjectEnvelope.created_at >= tally_starts_at` с учетом clock skew policy.
- `trustee_public_key` входит в `TallyKeySet.trustee_set[]`.
- `encrypted_tally_hash` совпадает с локально вычисленным encrypted tally.
- `decryption_proof` валиден для `decryption_share`.
- `signature` валидна для `trustee_public_key`.
- conflict group проверена по `tally_decryption_share_conflict_key`.

Missing dependency:

```text
AnonymousElection
TallyKeySet
local encrypted tally
```

Если local encrypted tally еще не вычислен или текущий local tally стал `stale`, share получает `pending_dependencies`, а не `invalid`.

Итоговые статусы:

```text
valid
valid_but_conflicted
pending_dependencies
invalid
```

## TallyResult Validation

Проверки:

- `election_id` существует и указывает на operationally active `AnonymousElection`.
- `tally_key_set_hash` совпадает с локальным валидным `TallyKeySet`.
- local encrypted tally вычислен.
- `encrypted_tally_hash` совпадает с локальным.
- `decryption_share_object_ids[]` содержит минимум `2` валидных shares от distinct trustees.
- `option_results[]` совпадает с локально расшифрованным результатом.
- `valid_ballot_count` совпадает с локальным count.
- `conflicted_ballot_count` совпадает с локальным count.
- `result_hash` совпадает с локально вычисленным.
- `signature` валидна для `reporter_public_key`.

Missing dependencies:

```text
AnonymousElection
TallyKeySet
AnonymousBallot[]
TallyDecryptionShare[]
```

Итоговые статусы:

```text
valid
pending_dependencies
invalid
```

## Revalidation Triggers

Revalidation запускается при событиях:

- появилась missing dependency;
- появился новый объект в conflict group;
- изменился validation status объекта, от которого зависят другие объекты;
- появился `TallyKeySet`;
- появился `TrusteeConsent`;
- появился `TallyKeyContribution`;
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

Invalid object без retained payload не revalidated при смене `validator_version`. Для повторной проверки узел должен заново получить payload через sync.

## Pending Handling

Если объект получает `pending_dependencies`:

- payload хранится до финального validation status или mandatory pending retention limit;
- dependencies записываются в `object_dependencies`;
- объект не участвует в tally;
- объект не используется как финальная dependency для других объектов;
- при появлении dependencies объект проходит revalidation.

Если pending payload evicted по retention limit, объект получает `pending_payload_evicted` и может быть восстановлен повторной загрузкой payload через sync. Duplicate suppression не блокирует reacquire для этого статуса.

## Republishing Rules

Узел перепубликует announcement только для объектов, прошедших contextual validation.

Правила:

- `valid` перепубликуется.
- `valid_for_tally` перепубликуется.
- `valid_but_conflicted` перепубликуется, чтобы другие узлы видели conflict group.
- `pending_dependencies` не перепубликуется.
- `pending_payload_evicted` не перепубликуется.
- `invalid` не перепубликуется.

Перепубликация выполняется только как `ObjectAnnouncement`, без полного payload.
