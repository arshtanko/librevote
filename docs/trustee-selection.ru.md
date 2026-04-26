# Протокол выбора trustees

Этот документ описывает начальный протокол выбора trustees для анонимных голосований LibreVote.

Протокол выполняется перед основным анонимным голосованием. Его задача — выбрать небольшую группу trustees для настройки анонимного голосования и процесса подсчета.

## Цели

- Не назначать trustees единоличным решением организатора.
- Дать допущенным избирателям возможность публично выбрать trustees.
- Требовать явного согласия каждого выбранного trustee перед запуском анонимного голосования.
- Сохранить простой и детерминированный процесс выбора для первой реализации.
- Использовать `blind_token_v1` как режим анонимного голосования v1.

## Не Цели

- Выбор trustees в первой версии не является анонимным.
- Выбор trustees не является полностью trustless.
- Этот документ не определяет полный формат анонимного бюллетеня.
- Этот документ не определяет низкоуровневые equations threshold key setup.

## Обзор

Процесс выбора trustees состоит из следующих фаз:

```text
1. Создается голосование по выбору trustees.
2. Кандидаты самовыдвигаются как потенциальные trustees.
3. Допущенные избиратели подают неанонимные голоса за кандидатов.
4. Узлы детерминированно вычисляют preliminary ranking кандидатов.
5. Создается структурный `AnonymousElection`, привязанный к preliminary result.
6. Candidates из ranking публикуют `TrusteeConsent` для конкретного `election_id`.
7. Финальный trustee set выводится как top `n` consenting candidates.
8. Финальные trustees выполняют threshold key setup и публикуют `TallyKeySet`.
9. Валидный `TallyKeySet` активирует anonymous election для issuance и voting.
```

## Параметры

Начальная конфигурация trustees по умолчанию:

```text
n = 3 trustees
t = 2 required trustee shares
threshold = 2-of-3
```

Эта конфигурация дает первой реализации простой баланс:

- Голосование может завершиться, если один trustee недоступен во время подсчета.
- Приватность сохраняется при условии, что менее двух trustees вступили в сговор.
- Все три выбранных trustees должны дать согласие перед запуском анонимного голосования.

## Самовыдвижение Кандидатов

Кандидаты в trustees самовыдвигаются, публикуя подписанный объект nomination.

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

Правила валидации:

- Подпись nomination должна быть валидна для `candidate_public_key`.
- Nomination должен ссылаться на существующее голосование по выбору trustees.
- `ObjectEnvelope.created_at` должен находиться в пределах окна самовыдвижения.
- Повторные nominations с тем же `candidate_public_key` образуют конфликтную группу.
- Повторные nominations с тем же `candidate_blind_token_public_key` образуют конфликтную группу.
- Proof-of-work должен удовлетворять требуемой сложности для nomination-объектов.

Если конфликтная группа содержит больше одного валидного `TrusteeNomination`, вся группа исключается из выбора trustees.

## Голосование За Trustees

Голосование за trustees в первой версии является неанонимным.

Каждый допущенный избиратель может выбрать до `n` кандидатов. Побеждают top `n` кандидатов с учетом последующей фазы согласия.

Для начальной конфигурации по умолчанию каждый избиратель может выбрать до 3 кандидатов.

```text
TrusteeVote {
  trustee_selection_id
  voter_public_key
  selected_candidate_keys[]
  signature
}
```

Правила валидации:

- `voter_public_key` должен входить в allowlist избирателей для выбора trustees.
- Подпись голоса должна быть валидна для `voter_public_key`.
- Голос должен ссылаться на существующее голосование по выбору trustees.
- `ObjectEnvelope.created_at` должен находиться в пределах окна голосования.
- `selected_candidate_keys` не должен содержать дубликатов.
- `selected_candidate_keys` должен содержать не более `n` кандидатов.
- У каждого выбранного кандидата должен быть валидный nomination.
- Повторные голоса того же избирателя обрабатываются правилом конфликтов ниже.
- Proof-of-work должен удовлетворять требуемой сложности для trustee vote объектов.

Для первой реализации повторное голосование не поддерживается как пользовательская функция.

Если один `voter_public_key` публикует несколько валидных `TrusteeVote` для одного `trustee_selection_id`, они образуют конфликтную группу.

```text
trustee_vote_conflict_key = trustee_selection_id || voter_public_key
```

Если конфликтная группа содержит больше одного валидного `TrusteeVote`, ни один голос из этой группы не включается в подсчет. Это правило не зависит от порядка доставки и не позволяет выполнить revote через подбор hash.

## Правило Подсчета

Подсчет голосования за trustees использует простую approval-style схему с максимум `n` выбранными кандидатами на одного избирателя.

Каждый выбранный кандидат получает один балл от валидного trustee vote.

Кандидаты ранжируются так:

```text
1. Сначала более высокий score.
2. При равенстве — меньший детерминированный hash публичного ключа кандидата.
```

Hash ключа кандидата вычисляется по каноническому представлению публичного ключа кандидата.

```text
candidate_rank_hash = HASH("librevote-trustee-rank-v1" || candidate_public_key)
```

Первые `n` кандидатов в детерминированном рейтинге становятся initial selected trustees для UI и initial consent targeting.

`TrusteeSelectionResult` фиксирует весь `candidate_ranking[]`, а не финальный trustee set. Финальный trustee set зависит от valid consents для конкретного `AnonymousElection`.

## Согласие Trustees

Candidates из deterministic ranking должны явно подтвердить согласие для конкретного anonymous election.

Согласие публикуется как подписанный объект:

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

Правила валидации:

- Подпись consent должна быть валидна для `trustee_public_key`.
- `trustee_public_key` должен иметь валидный `TrusteeNomination`.
- `trustee_public_key` должен входить в `TrusteeSelectionResult.candidate_ranking[]`.
- `election_id` должен ссылаться на структурно валидный `AnonymousElection`.
- `election_parameters_hash` должен совпадать с canonical hash параметров `AnonymousElection`.
- `threshold_t` должен быть равен `2` для начальной конфигурации по умолчанию.
- `trustee_count_n` должен быть равен `3` для начальной конфигурации по умолчанию.
- `trustee_selection_result_hash` должен соответствовать детерминированному результату выбора trustees.
- `trustee_tally_setup_public_key` должен иметь корректный формат.
- `trustee_tally_setup_public_key` должен быть уникальным среди valid non-conflicted consents этого `election_id`.
- `ObjectEnvelope.created_at` должен находиться в пределах окна согласия.
- Proof-of-work должен удовлетворять требуемой сложности для consent-объектов.

Финальный trustee set для `election_id` выводится после consent phase.

```text
final_trustee_set = first n candidates from candidate_ranking with valid non-conflicted TrusteeConsent for election_id
```

Для начальной threshold-конфигурации это означает:

```text
3 selected trustees
3 required consent signatures
2 trustee shares required for tally
```

## Trustees Без Согласия

Если candidate не публикует валидное согласие в пределах окна согласия, он не может попасть в финальный trustee set для этого `election_id`.

Правило замены:

```text
1. Взять candidate_ranking[] из валидного TrusteeSelectionResult.
2. Исключить candidates без valid non-conflicted TrusteeConsent для election_id.
3. Выбрать первые n оставшихся candidates.
4. Если осталось меньше n candidates, trustee selection не активирует anonymous election.
```

Если список consenting candidates содержит меньше `n` trustees, анонимное голосование не получает валидный `TallyKeySet` и не становится active.

## Привязка Анонимного Голосования

Основное анонимное голосование должно ссылаться на preliminary trustee selection result. Финальный trustee set фиксируется в `TallyKeySet`.

```text
AnonymousElection {
  election_id
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
  signature
}
```

Начальная схема анонимного голосования:

```text
eligibility_scheme = blind_token_v1
```

`AnonymousElection` становится operationally active только после валидного `TallyKeySet`, который содержит final trustee set, consent object ids, DKG contribution object ids и `tally_public_key`.

Eligibility layer проверяется по схеме `blind_token_v1`.

## Сводка Валидации

Узел принимает анонимное голосование только если:

- Существуют данные по указанному голосованию выбора trustees.
- Trustee nominations валидны.
- Trustee votes валидны.
- Trustee ranking вычислен детерминированно.
- Финальный trustee set содержит ровно `n = 3` trustees.
- Threshold равен `t = 2` для начальной версии.
- Каждый выбранный trustee опубликовал валидное согласие.
- Анонимное голосование ссылается на preliminary trustee selection result.
- Валидный `TallyKeySet` фиксирует финальный trustee set hash и активирует anonymous election.
- Анонимное голосование использует поддерживаемую eligibility scheme.

## Заметки По Безопасности

Выбор trustees снижает зависимость от одного организатора, но не делает выбор trustees полностью trustless.

Система все еще предполагает:

- Allowlist избирателей для выбора trustees корректен.
- Менее `t` trustees вступили в сговор до или во время подсчета.
- Как минимум `t` trustees остаются доступны для фазы tally.
- P2P-сеть в конечном итоге распространяет все валидные объекты выбора trustees.

Proof-of-work используется только как anti-spam и anti-Sybil механизм стоимости. Он не доказывает право голоса и не заменяет подписи, allowlists, eligibility proofs или threshold-криптографию.
