# Логика бюллетеней

Этот документ описывает доменную логику бюллетеней LibreVote.

Бюллетень является самостоятельным проверяемым объектом. Peer доставляет бюллетень по сети, но не становится его автором в доменной модели.

## Принятые Решения

- В v1 используются два типа бюллетеней: `PublicBallot` и `AnonymousBallot`.
- `PublicBallot` используется для неанонимных голосований, включая выбор trustees.
- `AnonymousBallot` используется для основного анонимного голосования.
- Анонимное голосование v1 использует `blind_token_v1` для проверки права голоса.
- Анонимный бюллетень не содержит `voter_public_key`, `peer_id` или `node_public_key`.
- Выбор в анонимном бюллетене шифруется под `tally_public_key` голосования.
- Повторное голосование не поддерживается как пользовательская функция.
- Конфликтующие повторные бюллетени не включаются в tally.

## Не Цели

- Бюллетень не определяет правила создания голосования.
- Бюллетень не определяет выбор trustees.
- Бюллетень не выполняет сетевую доставку.
- Бюллетень не доверяет transport peer identity.
- Бюллетень не заменяет tally phase и threshold decryption.

## Общая Модель

Каждый бюллетень относится к одному голосованию.

```text
ballot -> election_id
```

Узел принимает бюллетень к рассмотрению только если:

- Голосование существует.
- Голосование находится в фазе приема бюллетеней.
- Тип бюллетеня соответствует типу голосования.
- Бюллетень проходит PoW.
- Бюллетень проходит криптографическую проверку права голоса.
- Выбор соответствует правилам голосования.
- Бюллетень не входит в конфликтную группу повторного голосования.

## Идентификаторы И Конфликты

Для бюллетеней используются два разных доменных идентификатора.

```text
object_id
- сетевой content-addressed identifier
- используется object log и sync layer
- вычисляется по каноническому payload объекта без `object_id` и `pow`

ballot_conflict_key
- доменный ключ права голоса в рамках election_id
- используется для обнаружения повторных бюллетеней
- не зависит от source peer и порядка доставки
```

Если для одного `ballot_conflict_key` существует ровно один валидный бюллетень, он получает статус `valid_for_tally`.

Если для одного `ballot_conflict_key` существует несколько криптографически валидных бюллетеней, вся конфликтная группа получает статус `valid_but_conflicted` и не участвует в tally.

Это правило предотвращает double voting и не дает избирателю выполнить revote через подбор `object_id`, `created_at`, encryption randomness или PoW nonce.

```text
valid conflict group size = 1 -> include ballot in tally
valid conflict group size > 1 -> include no ballots from this group
```

## PublicBallot

`PublicBallot` используется там, где личность голосующего публична.

Пример: голосование за trustees.

```text
PublicBallot {
  election_id
  voter_public_key
  choices[]
  created_at
  pow
  signature
}
```

Подпись создается ключом `voter_public_key` поверх канонического тела бюллетеня.

```text
public_ballot_signing_payload = HASH(
  "librevote-public-ballot-sign-v1" ||
  election_id ||
  voter_public_key ||
  choices ||
  created_at
)
```

Правила валидации:

- `election_id` ссылается на существующее публичное или trustee-selection голосование.
- `voter_public_key` входит в allowlist голосования.
- `signature` валидна для `voter_public_key`.
- `choices[]` соответствует правилам голосования.
- `created_at` находится внутри voting window.
- `pow` валиден для `PublicBallot`.

Конфликтный ключ публичного бюллетеня:

```text
public_ballot_conflict_key = election_id || voter_public_key
```

Если один `voter_public_key` публикует несколько валидных `PublicBallot` для одного `election_id`, они образуют конфликтную группу. Ни один бюллетень из такой группы не включается в tally.

## AnonymousBallot

`AnonymousBallot` используется для основного анонимного голосования.

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

Анонимный бюллетень не имеет доменной подписи `voter_public_key`. Право голоса проверяется через `eligibility_proof`.

`token_holder_signature` доказывает, что отправитель бюллетеня владеет приватным ключом, соответствующим `token_public_key`. Это предотвращает кражу раскрытого token proof из сети и публикацию измененного бюллетеня другим peer'ом.

Правила валидации:

- `election_id` ссылается на существующее анонимное голосование.
- Голосование использует `blind_token_v1`.
- `eligibility_proof` валиден для trustee set этого голосования.
- `eligibility_proof` содержит достаточное подтверждение `2-of-3` trustees.
- `token_holder_signature` валидна для `token_public_key`.
- `token_nullifier` корректно связан с `token_public_key`.
- `token_nullifier` относится к данному `election_id`.
- `encrypted_choice` зашифрован под `tally_public_key` этого голосования.
- `choice_validity_proof` доказывает, что `encrypted_choice` кодирует допустимый выбор.
- `created_at` находится внутри voting window.
- `pow` валиден для `AnonymousBallot`.

Конфликтный ключ анонимного бюллетеня:

```text
anonymous_ballot_conflict_key = election_id || token_nullifier
```

Если один `token_nullifier` встречается в нескольких валидных `AnonymousBallot` для одного `election_id`, они образуют конфликтную группу. Ни один бюллетень из такой группы не включается в tally.

## Blind Token Eligibility

`blind_token_v1` доказывает, что бюллетень создан участником, получившим право голоса, но не раскрывает `voter_public_key`.

В бюллетене публикуется:

```text
eligibility_proof {
  trustee_token_signatures[]
}
```

Проверка:

- Blind token signatures проверяются поверх `election_id` и `token_public_key`.
- `trustee_token_signatures[]` содержит минимум `threshold_t = 2` валидные blind token signatures trustees.
- Подписавшие trustees входят в финальный trustee set голосования.
- `token_nullifier` вычислен из `token_public_key` и `election_id` по каноническому правилу.
- `token_holder_signature` доказывает владение приватным token key.

```text
token_nullifier = HASH("librevote-token-nullifier-v1" || election_id || token_public_key)
```

Trustees подписывают blinded `token_public_key` на этапе выдачи права голоса. В момент публикации бюллетеня узлы проверяют уже раскрытый token proof и не узнают, какой `voter_public_key` получил этот token.

## Encrypted Choice

В анонимном голосовании выбор не публикуется открытым текстом.

```text
encrypted_choice {
  election_id
  tally_public_key
  ciphertexts[]
}
```

`choice_validity_proof` должен доказывать:

- каждый ciphertext зашифрован под `tally_public_key` голосования;
- каждый ciphertext кодирует `0` или `1`;
- сумма зашифрованного one-hot vector равна `1`;
- количество ciphertexts равно количеству options этого голосования.

Бюллетень с некорректным `choice_validity_proof` не включается в tally.

## Хранение Конфликтов

Узел хранит все полученные объекты в object log после сетевой проверки.

Доменная модель различает статусы:

```text
valid_for_tally
valid_but_conflicted
invalid
pending_dependencies
```

Правила:

- `valid_for_tally` участвует в подсчете.
- `valid_but_conflicted` криптографически корректен, но входит в конфликтную группу с тем же `ballot_conflict_key`.
- `invalid` не участвует в подсчете и не должен перепубликовываться.
- `pending_dependencies` используется, когда еще не получены election metadata, trustee set или другие зависимости.

## Validation Pipeline

Рекомендуемый порядок проверки бюллетеня:

```text
1. Decode canonical payload.
2. Check object_id.
3. Check object type.
4. Check election existence.
5. Check voting window.
6. Check PoW.
7. Check ballot-specific cryptographic proof.
8. Check choice validity.
9. Compute conflict key.
10. Resolve conflict group deterministically.
11. Store validation status.
12. Recompute local tally state.
```

Сетевой source peer не участвует ни в одном шаге доменной валидации бюллетеня.

## Tally Inclusion

В tally включаются только бюллетени со статусом `valid_for_tally`.

Для `PublicBallot` tally использует открытый `choices[]`.

Для `AnonymousBallot` tally использует `encrypted_choice`. Расшифровка результата выполняется в tally phase с участием trustees. Бюллетень считается включенным в tally до расшифровки, если его encrypted choice и eligibility proof валидны.
