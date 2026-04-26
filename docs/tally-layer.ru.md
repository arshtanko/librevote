# Tally Layer

Этот документ описывает слой подсчета LibreVote v1.

Tally layer строит проверяемый результат из локального object log и validation records. Он не доверяет опубликованным `TrusteeSelectionResult` или `TallyResult` без локального пересчета.

## Принятые Решения

- Trustee selection tally является публичным и детерминированным.
- Anonymous election tally является encrypted tally с threshold decryption.
- В tally включаются только объекты со статусом `valid_for_tally`.
- `valid_but_conflicted`, `invalid` и `pending_dependencies` не включаются в tally.
- Конфликтная группа повторных бюллетеней исключается полностью.
- Входы tally сортируются по `object_id` ascending.
- Anonymous tally стартует только после `tally_starts_at`.
- Перед tally узел выполняет sync по `election_id`.
- `TallyResult` публикуется как доменный объект, но не является авторитетным.
- Поздно полученный валидный объект делает ранее проверенный результат `stale`.

## Граница Слоя

Tally layer отвечает за:

- выбор valid inputs из object log;
- исключение conflicted и invalid объектов;
- deterministic ordering;
- подсчет trustee selection results;
- построение encrypted tally;
- вычисление `encrypted_tally_hash`;
- проверку `TallyDecryptionShare`;
- расшифровку aggregate result при наличии `2-of-3` shares;
- проверку опубликованного `TallyResult`.

Tally layer не отвечает за:

- P2P-доставку объектов;
- хранение payload;
- проверку сетевых лимитов;
- генерацию trustee keys;
- issuance blind tokens;
- UI-отображение результата.

## Result Statuses

Локальный статус результата является derived state.

```text
not_started
syncing
waiting_for_shares
computed
published
verified
stale
```

Значения:

- `not_started`: tally phase еще не началась.
- `syncing`: узел выполняет sync перед подсчетом.
- `waiting_for_shares`: encrypted tally вычислен, но валидных shares меньше `2`.
- `computed`: локальный результат вычислен.
- `published`: узел видел `TallyResult` object.
- `verified`: опубликованный `TallyResult` совпал с локальным пересчетом.
- `stale`: после вычисления результата появился новый валидный объект, влияющий на tally.

Status не является сетевым объектом и хранится только как локальный derived state.

## Trustee Selection Tally

Trustee selection использует публичные `TrusteeVote`.

Входы:

```text
TrusteeSelectionElection
TrusteeNomination[]
TrusteeVote[]
```

Правила включения vote:

- `TrusteeVote` имеет статус `valid_for_tally`.
- Голос не входит в конфликтную группу.
- Все выбранные candidates имеют валидный `TrusteeNomination`.
- `selected_candidate_keys[]` содержит не более `max_choices_per_vote`.

Конфликтное правило:

```text
trustee_vote_conflict_key = trustee_selection_id || voter_public_key
```

Если для одного `trustee_vote_conflict_key` существует больше одного валидного `TrusteeVote`, вся конфликтная группа исключается из подсчета.

## Trustee Candidate Scoring

Каждый included `TrusteeVote` дает `1` point каждому выбранному candidate.

```text
candidate_score = count(valid_for_tally votes selecting candidate)
```

Кандидаты сортируются так:

```text
1. score descending
2. candidate_rank_hash ascending
```

`candidate_rank_hash`:

```text
candidate_rank_hash = HASH("librevote-trustee-rank-v1" || candidate_public_key)
```

Первые `3` candidates становятся selected trustees.

Если selected trustee не публикует valid `TrusteeConsent`, он заменяется следующим candidate в deterministic ranking. Финальный trustee set должен содержать `3` trustees с valid consent.

## TrusteeSelectionResult Verification

`TrusteeSelectionResult` публикуется как удобный result object.

Узел принимает его только если локальный пересчет совпадает с объектом.

Проверка:

- `trustee_selection_id` существует.
- Все referenced nominations и votes доступны или синхронизированы.
- Локальный candidate scoring совпадает с `candidate_scores[]`.
- Локальный selected trustee set совпадает с `selected_trustees[]`.
- `valid_vote_count` совпадает.
- `conflicted_vote_count` совпадает.
- `threshold_t = 2`.
- `trustee_count_n = 3`.
- `result_hash` совпадает с локально вычисленным.
- `signature` валидна для `reporter_public_key`.

`reporter_public_key` не делает результат авторитетным.

## Anonymous Tally Start

Anonymous tally не начинается сразу после `voting_ends_at`.

Условие старта:

```text
now >= tally_starts_at
```

Перед вычислением encrypted tally узел выполняет sync по `election_id`.

Минимальный порядок:

```text
1. Sync election state.
2. Revalidate pending objects.
3. Resolve ballot conflicts.
4. Build tally inputs.
5. Compute encrypted tally.
```

`tally_starts_at` задает propagation window между окончанием voting phase и началом tally phase.

## Anonymous Tally Inputs

Входы anonymous tally:

```text
AnonymousElection
TallyKeySet
AnonymousBallot[]
TallyDecryptionShare[]
```

В tally включается только `AnonymousBallot` со статусом `valid_for_tally`.

Исключаются:

- `pending_dependencies`;
- `invalid`;
- `valid_but_conflicted`;
- ballots с invalid `choice_validity_proof`;
- ballots с invalid `token_holder_signature`;
- ballots с invalid `eligibility_proof`;
- ballots за пределами voting window.

Порядок входов:

```text
sort valid_for_tally AnonymousBallot by object_id ascending
```

Этот порядок используется для deterministic hashes и воспроизводимого tally state.

## Encrypted Tally

Каждый `AnonymousBallot` содержит `encrypted_choice` как массив ciphertexts длиной `options_count`.

Encrypted tally строится homomorphic aggregation по каждому option index.

```text
aggregated_ciphertexts[j] = sum_encrypted(
  ballot.encrypted_choice.ciphertexts[j]
  for ballot in sorted_valid_ballots
)
```

Правила:

- Все included ballots имеют одинаковый `options_count`.
- Все ciphertexts зашифрованы под `tally_public_key` election.
- Все included ballots прошли `choice_validity_proof`.
- Aggregation выполняется в порядке sorted input list.

## Encrypted Tally Hash

`encrypted_tally_hash` однозначно связывает набор входных бюллетеней и aggregate ciphertexts.

```text
encrypted_tally_hash = HASH(
  "librevote-encrypted-tally-v1" ||
  election_id ||
  tally_public_key ||
  sorted_valid_ballot_object_ids ||
  aggregated_ciphertexts
)
```

Этот hash используется:

- в `TallyDecryptionShare`;
- в `TallyResult`;
- для проверки, что trustees расшифровывают тот же encrypted tally, который локально вычислил узел.

## TallyDecryptionShare Verification

Trustee публикует share:

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

Проверка:

- `election_id` ссылается на существующий `AnonymousElection`.
- `trustee_public_key` входит в финальный `trustee_set[]`.
- `encrypted_tally_hash` совпадает с локально вычисленным.
- `decryption_proof` валиден для `decryption_share`.
- `signature` валидна для `trustee_public_key`.
- Если один trustee публикует больше одного valid share для одного `encrypted_tally_hash`, вся conflict group исключается из tally decryption.

Результат расшифровывается при наличии:

```text
2 valid shares from distinct trustees
```

## Decrypted Result

После получения `2` valid decryption shares узел расшифровывает aggregate result.

```text
option_results[] = ThresholdDecrypt(
  aggregated_ciphertexts,
  valid_decryption_shares
)
```

Проверки результата:

- `len(option_results) = len(options)`.
- Каждый result является неотрицательным целым числом.
- Сумма `option_results[]` равна `valid_ballot_count`.

Если сумма не совпадает, tally state получает статус `invalid` и опубликованный `TallyResult` не принимается.

## TallyResult Verification

`TallyResult` является публикуемым result object.

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

Узел принимает `TallyResult` только если:

- `election_id` существует.
- `encrypted_tally_hash` совпадает с локальным.
- `decryption_share_object_ids[]` содержит минимум `2` valid shares.
- Все shares относятся к distinct trustees.
- `option_results[]` совпадает с локально расшифрованным результатом.
- `valid_ballot_count` совпадает с локальным count.
- `conflicted_ballot_count` совпадает с локальным count.
- `invalid_ballot_count` совпадает с локальным count.
- `result_hash` совпадает с локально вычисленным.
- `signature` валидна для `reporter_public_key`.

`reporter_public_key` не делает результат авторитетным.

## Result Hash

`result_hash` фиксирует проверяемый результат.

```text
result_hash = HASH(
  "librevote-tally-result-v1" ||
  election_id ||
  encrypted_tally_hash ||
  sorted_decryption_share_object_ids ||
  option_results ||
  valid_ballot_count ||
  conflicted_ballot_count ||
  invalid_ballot_count
)
```

`sorted_decryption_share_object_ids` сортируется по `object_id` ascending.

## Late Objects And Stale Results

После `verified` result узел продолжает принимать валидные объекты, если они соответствуют protocol rules.

Если появился новый объект, влияющий на tally input, локальный result получает статус `stale`.

Объекты, влияющие на anonymous tally:

- новый `AnonymousBallot` со статусом `valid_for_tally`;
- новый `AnonymousBallot`, который создает conflict group;
- объект, переводящий pending ballot в `valid_for_tally`;
- объект, переводящий included ballot в `valid_but_conflicted` или `invalid`.

После `stale` узел пересчитывает encrypted tally, `encrypted_tally_hash`, decryption share applicability и result.

Предыдущий `TallyResult` остается в object log, но больше не считается verified для текущего локального состояния.

## Counts

Counts вычисляются по текущему локальному validation state.

```text
valid_ballot_count = count(AnonymousBallot where validation_status = valid_for_tally)
conflicted_ballot_count = count(AnonymousBallot where validation_status = valid_but_conflicted)
invalid_ballot_count = count(AnonymousBallot where validation_status = invalid)
```

`pending_dependencies` не входит в `invalid_ballot_count`.

## Recompute Rules

Tally layer пересчитывает state при изменении:

- validation status любого ballot;
- `TallyKeySet`;
- `TallyDecryptionShare`;
- `TrusteeSelectionResult`;
- `TrusteeConsent`;
- result object status.

Recompute не изменяет retained domain objects. Он обновляет только validation records и derived tally state.
