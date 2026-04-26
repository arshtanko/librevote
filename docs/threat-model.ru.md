# Threat Model

Этот документ описывает threat model LibreVote v1.

LibreVote v1 является trust-minimized и independently verifiable системой голосования. Она не является полностью trustless системой и не обеспечивает сильную анонимность сетевых метаданных или coercion resistance.

## Цели Безопасности

LibreVote v1 защищает:

- право голоса в рамках публичного `voter_allowlist`;
- анонимность связи `voter_public_key -> AnonymousBallot`;
- тайну выбора до tally phase;
- целостность доменных объектов;
- защиту от double voting;
- корректность локального tally;
- проверяемость trustee selection;
- проверяемость blind token issuance;
- проверяемость trustee decryption shares;
- локальные приватные ключи;
- P2P-сеть от дешевого spam, Sybil и resource exhaustion.

## Не Цели

LibreVote v1 не обеспечивает:

- абсолютную trustless-модель без доверительных допущений;
- сильную анонимность сетевых метаданных;
- coercion resistance;
- receipt-freeness;
- защиту от продажи голоса;
- защиту от голосования под физическим наблюдением;
- защиту от компрометации устройства пользователя во время голосования;
- скрытие факта участия в issuance phase;
- автоматическое исправление плохого governance-выбора trustees;
- доступность tally при недоступности quorum trustees.

## Trust Assumptions

LibreVote v1 требует следующие допущения:

- `voter_allowlist` сформирован корректно.
- Trustee selection проведен по правилам протокола.
- Большинство voting power не выбрало заведомо сговорившихся trustees.
- Менее `2` из `3` trustees сговорились до tally phase для раскрытия выбора.
- Минимум `2` из `3` trustees доступны в tally phase.
- Пользовательское устройство защищает локальные секреты во время использования.
- Криптографические primitives реализованы корректно.
- Узлы могут в конечном итоге синхронизировать валидные объекты хотя бы с одним честным peer.

## Protected Assets

Критичные активы:

```text
voter signing private key
voter encryption private key
anonymous token private key
trustee signing private key
trustee blind-token private key
trustee tally share key
blind token blinding factors
ElGamal encryption randomness
canonical domain objects
object log
validation records
tally public key
decryption shares
```

Публичные, но проверяемые данные:

```text
voter_allowlist
trustee nominations
trustee votes
trustee selection result
trustee consent objects
blind token requests
encrypted blind token issues
anonymous ballots
tally decryption shares
tally result objects
```

## Adversary Model

### Malicious Peer

Malicious peer атакует сетевой слой.

Возможности:

- рассылает мусорные announcements;
- отвечает неверными objects;
- не отдает запрошенные objects;
- нарушает direct protocol;
- перегружает `GetObject` и `GetObjects`;
- пытается занять peer slots;
- отправляет объекты с invalid PoW;
- повторно рассылает старые announcements.

Mitigations:

- peer admission PoW;
- object PoW;
- request PoW;
- rate limits;
- peer scoring;
- duplicate cache;
- проверка `object_id`;
- локальная доменная валидация каждого объекта;
- отсутствие доверия к peer как источнику истины.

### Malicious Voter

Malicious voter имеет валидное право голоса и пытается нарушить правила.

Возможности:

- пытается получить несколько blind token signatures;
- публикует несколько `BlindTokenRequest`;
- публикует несколько `AnonymousBallot` с одним `token_nullifier`;
- публикует invalid encrypted choice;
- публикует конфликтующие публичные trustee votes;
- пытается выполнить revote через подбор hash, nonce или encryption randomness.

Mitigations:

- trustees выдают не более одного `BlindTokenIssue` на `election_id || voter_public_key`;
- конфликтные `BlindTokenRequest` исключаются из issuance;
- `token_nullifier` обнаруживает повторные anonymous ballots;
- конфликтные повторные ballots исключаются из tally всей группой;
- `token_holder_signature` защищает token proof от кражи другим peer;
- `choice_validity_proof` отклоняет некорректный encrypted choice;
- PoW повышает стоимость spam.

Residual risk:

- избиратель с valid token key сам отменяет свой голос публикацией второго валидного бюллетеня с тем же `token_nullifier`;
- это self-cancellation, а не внешняя подделка, потому что внешний peer не имеет `token_private_key`.

### Malicious Trustee

Malicious trustee атакует issuance, key setup или tally.

Возможности:

- не публикует `BlindTokenIssue`;
- публикует invalid `BlindTokenIssue`;
- публикует несколько conflicting `BlindTokenIssue`;
- отказывается участвовать в key setup;
- не публикует `TallyDecryptionShare`;
- публикует invalid decryption share;
- пытается повлиять на tally result object.

Mitigations:

- trustees выбираются публичным trustee selection;
- все selected trustees публикуют `TrusteeConsent`;
- `BlindTokenIssue` публично аудируется как encrypted domain object;
- conflicting `BlindTokenIssue` исключается из issuance;
- decryption shares имеют cryptographic proof;
- tally result проверяется локальным пересчетом;
- result objects не являются авторитетными.

Residual risk:

- при доступности менее `2` trustees tally не раскрывается;
- malicious trustee снижает liveness, но не подделывает валидный tally без прохождения локальной проверки.

### Colluding Trustees

Сговор trustees атакует privacy.

Возможности:

- `2` trustees объединяют decryption shares и раскрывают encrypted choices до официальной tally phase;
- trustees сопоставляют timing issuance requests и ballots;
- trustees отказываются выдавать blind token signatures отдельным voters.

Mitigations:

- trustee selection публичен;
- trustee set выбран голосованием;
- threshold `2-of-3` явно зафиксирован;
- blind token signatures скрывают связь `voter_public_key -> token_public_key`;
- anonymous ballots не содержат `voter_public_key`;
- encrypted choices не раскрывают выбор без threshold shares.

Trust assumption:

- privacy выбора до tally phase сохраняется только если менее `2` trustees сговорились.

### Network Observer

Network observer анализирует сетевые метаданные.

Возможности:

- наблюдает timing появления announcements;
- видит peer, первым распространивший ballot;
- видит DHT и bootstrap активность;
- видит direct sync interest;
- коррелирует `BlindTokenRequest`, `BlindTokenIssue` и последующие anonymous ballots.

Mitigations v1:

- anonymous ballot не содержит `voter_public_key`;
- anonymous ballot не содержит `peer_id`;
- используется общий `/objects` topic;
- собственные anonymous ballot announcements публикуются со случайной задержкой;
- anonymous ballot announcements публикуются batching-ом;
- узлы перепубликуют чужие валидные anonymous ballot announcements;
- source peer не входит в доменную модель.

Residual risk:

- LibreVote v1 не обеспечивает сильную сетевую metadata anonymity;
- timing correlation остается применимой атакой;
- peer, первым распространивший ballot, вероятностно связывается с автором.

### Local Attacker

Local attacker получил доступ к файлам узла.

Возможности:

- копирует SQLite базу;
- пытается расшифровать локальные ключи;
- читает object log;
- читает peer и sync metadata.

Mitigations:

- private keys хранятся encrypted-at-rest;
- key encryption использует `Argon2id` и `XChaCha20-Poly1305`;
- passphrase не хранится;
- raw private keys не логируются;
- invalid payloads не хранятся долговременно.

Residual risk:

- attacker с доступом к разблокированному процессу или passphrase получает возможность использовать ключи;
- encrypted-at-rest не защищает от malware, работающего во время голосования.

## Participation Privacy

`BlindTokenRequest` является публичным и подписан `voter_public_key`.

Следствие:

```text
сеть видит, какой voter запросил право получить anonymous ballot token
```

Blind token unblinding скрывает связь между `voter_public_key` и `token_public_key`, но не скрывает сам факт участия в issuance phase.

V1 behavior:

```text
клиент запрашивает blind token для каждого eligible voter при доступности ключа voter_signing_private_key
```

Это снижает participation leakage внутри группы: запрос token не означает, что voter фактически отправил final anonymous ballot.

Ограничение:

```text
если voter не запускает клиент или не предоставляет ключ для issuance, его отсутствие в issuance metadata видно сети
```

## Ballot Privacy

Anonymous ballot privacy строится на следующих свойствах:

- `AnonymousBallot` не содержит `voter_public_key`;
- `AnonymousBallot` содержит `token_public_key`;
- `token_public_key` получил blind signatures trustees без раскрытия trustees связи с `voter_public_key`;
- `token_nullifier` предотвращает double voting;
- `token_holder_signature` доказывает владение `token_private_key`;
- `encrypted_choice` скрывает выбор до tally phase.

Privacy сохраняется при выполнении trust assumptions:

- менее `2` trustees сговорились до tally;
- устройство voter не скомпрометировано;
- blind token blinding factors не раскрыты;
- token private key не раскрыт.

## Tally Integrity

Tally integrity обеспечивается тем, что каждый узел локально проверяет:

- все included ballots имеют статус `valid_for_tally`;
- conflicted ballots исключены;
- encrypted tally построен из одного и того же набора valid ballots;
- decryption shares имеют валидные proofs;
- `TallyResult` совпадает с локальным пересчетом.

`TallyResult` является публикуемым объектом, но не является авторитетным сам по себе.

## Trustee Selection Integrity

Trustee selection integrity обеспечивается тем, что каждый узел локально проверяет:

- nominations;
- public trustee votes;
- конфликтные trustee votes;
- deterministic ranking;
- replacement при отсутствии consent;
- наличие consent от всех `3` selected trustees.

`TrusteeSelectionResult` является публикуемым объектом, но не является авторитетным сам по себе.

## Governance Risk

LibreVote v1 не исправляет плохой governance-выбор.

Если eligible voters выбирают trustees, которые затем сговариваются или саботируют tally, протокол сохраняет проверяемость, но не гарантирует privacy или liveness сверх threshold assumptions.

Это governance-риск, а не ошибка криптографической проверки.

## Attack Scenarios

### Подмена Доменных Объектов

Атака:

```text
peer отдает payload, не соответствующий object_id
```

Защита:

- canonical `object_id`;
- проверка payload после `GetObject` и `GetObjects`;
- payload mismatch отклоняется;
- peer score снижается при повторяющихся нарушениях.

### Spam Через GossipSub

Атака:

```text
peer рассылает большое количество announcements
```

Защита:

- object PoW;
- peer admission PoW;
- duplicate cache;
- rate limits;
- peer scoring.

### Double Voting

Атака:

```text
voter публикует несколько valid ballots с одним правом голоса
```

Защита:

- `public_ballot_conflict_key` для public ballots;
- `token_nullifier` для anonymous ballots;
- конфликтная группа исключается из tally полностью.

### Кража Раскрытого Token Proof

Атака:

```text
peer копирует token proof из anonymous ballot и публикует измененный ballot
```

Защита:

- `token_holder_signature`;
- attacker не имеет `token_private_key`;
- измененный ballot не проходит проверку подписи holder key.

### Invalid Decryption Share

Атака:

```text
trustee публикует неверный decryption share
```

Защита:

- `decryption_proof`;
- локальная проверка share;
- invalid share не участвует в tally result.

### Result Forgery

Атака:

```text
peer публикует ложный TrusteeSelectionResult или TallyResult
```

Защита:

- result object не авторитетен;
- каждый узел локально пересчитывает result hash;
- несовпадающий result получает статус `invalid`.

## Residual Risks

Оставшиеся риски v1:

- нет coercion resistance;
- нет receipt-freeness;
- participation metadata видна через `BlindTokenRequest`;
- сильная сетевая metadata anonymity не гарантируется;
- `2` colluding trustees раскрывают выбор до tally phase;
- менее `2` доступных trustees блокируют раскрытие результата;
- compromised local device нарушает privacy и integrity пользователя;
- governance majority выбирает плохих trustees;
- malicious voter выполняет self-cancellation своего голоса через повторный valid ballot.
