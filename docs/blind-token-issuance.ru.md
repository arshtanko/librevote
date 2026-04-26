# Blind Token Issuance

Этот документ описывает фазу выдачи blind tokens для анонимного голосования LibreVote v1.

Issuance phase позволяет eligible voter получить threshold-набор blind token signatures от trustees. Эти signatures затем используются в `AnonymousBallot` для доказательства права голоса без раскрытия `voter_public_key`.

## Принятые Решения

- Anonymous election v1 использует `blind_token_v1`.
- Issuance выполняется только внутри issuance window.
- `BlindTokenRequest` является публичным доменным объектом.
- `BlindTokenRequest` подписывается `voter_signing_private_key`.
- `BlindTokenRequest` не раскрывает `token_public_key`.
- `BlindTokenIssue` является публичным доменным объектом.
- `BlindTokenIssue.encrypted_payload` зашифрован для `voter_encryption_public_key`.
- Public validators не расшифровывают `BlindTokenIssue.encrypted_payload`.
- Voter локально расшифровывает и проверяет `BlindTokenIssuePayload`.
- Для создания valid `AnonymousBallot` требуется минимум `2` valid trustee blind token signatures от distinct trustees.
- Повторные requests и issues образуют conflict groups и исключаются всей группой.
- Клиент автоматически публикует `BlindTokenRequest` для каждого eligible voter key, доступного в локальном key store.

## Участники

Issuance phase использует следующие роли.

```text
voter
- имеет voter_signing_key из voter_allowlist
- имеет voter_encryption_key из voter_allowlist
- генерирует одноразовый anonymous token keypair
- публикует BlindTokenRequest
- расшифровывает BlindTokenIssue payloads
- unblind'ит trustee signatures

trustee
- выбран через trustee selection
- имеет trustee_signing_key
- имеет trustee_blind_token_key
- проверяет BlindTokenRequest
- публикует encrypted BlindTokenIssue

public validator
- проверяет публичную часть request и issue
- не расшифровывает encrypted issue payload
- аудирует issuance metadata через object log
```

## Ключи

Voter keys:

```text
voter_signing_key
- Ed25519
- входит в voter_allowlist
- подписывает BlindTokenRequest

voter_encryption_key
- X25519
- входит в voter_allowlist
- используется для расшифровки BlindTokenIssue.encrypted_payload

anonymous token key
- Ristretto255 Schnorr keypair
- создается отдельно для каждого AnonymousElection
- token_public_key не публикуется в BlindTokenRequest
- token_public_key публикуется только в AnonymousBallot
```

Trustee keys:

```text
trustee_signing_key
- Ed25519
- подписывает BlindTokenIssue envelope

trustee_blind_token_key
- Ristretto255 blind Schnorr signing key
- подписывает blinded token message
```

Ключи разных ролей не переиспользуются.

## Phase Window

Issuance выполняется в окне:

```text
issuance_starts_at <= ObjectEnvelope.created_at <= issuance_ends_at
```

Правила:

- `BlindTokenRequest` вне issuance window получает `invalid`.
- `BlindTokenIssue` вне issuance window получает `invalid`.
- `AnonymousBallot` создается только после получения threshold-набора valid unblinded signatures.
- Issuance window предшествует voting window.

## Voter Client Behavior

Клиент автоматически запрашивает blind token для каждого eligible voter key, доступного в локальном key store.

Условия автоматического request:

- локальный key store содержит `voter_signing_private_key`;
- локальный key store содержит соответствующий `voter_encryption_private_key`;
- `voter_signing_public_key` входит в `AnonymousElection.voter_allowlist[]`;
- `voter_encryption_public_key` совпадает с `VoterEntry`;
- текущий момент находится внутри issuance window;
- для пары `election_id || voter_public_key` локально не опубликован valid `BlindTokenRequest`;
- election имеет валидный `TallyKeySet` и считается operationally active.

Назначение:

```text
BlindTokenRequest показывает участие в issuance phase, но не должен означать факт финального голосования.
```

Автоматическая публикация request для каждого локально доступного eligible voter key снижает participation leakage внутри группы.

## Token Key Generation

Перед созданием request voter генерирует одноразовый anonymous token keypair.

```text
token_private_key = random_scalar()
token_public_key = token_private_key * G
```

Правила:

- token keypair создается отдельно для каждого `election_id`.
- `token_private_key` хранится локально как encrypted-at-rest secret.
- `token_public_key` не публикуется в `BlindTokenRequest`.
- `token_public_key` раскрывается только в `AnonymousBallot`.

## Blind Token Message

Voter строит token message:

```text
blind_token_message = HASH(
  "librevote-blind-token-message-v1" ||
  election_id ||
  token_public_key
)
```

Затем voter применяет blind Schnorr blinding и получает:

```text
blinded_token_message
blinding_factor
```

Правила:

- `blinding_factor` не публикуется.
- `blinding_factor` не логируется.
- `blinded_token_message` публикуется в `BlindTokenRequest`.

## BlindTokenRequest

`BlindTokenRequest` публикуется в P2P-сеть как доменный объект.

```text
BlindTokenRequest {
  election_id
  voter_public_key
  blinded_token_message
  recipient_encryption_public_key
  signature
}
```

Публично раскрывается:

- `voter_public_key`;
- факт запроса blind token;
- `recipient_encryption_public_key`;
- `blinded_token_message`.

Публично не раскрывается:

- `token_public_key`;
- `token_private_key`;
- `blinding_factor`;
- связанный `AnonymousBallot`;
- выбор voter.

Validation rules:

- `election_id` указывает на operationally active `AnonymousElection` с валидным `TallyKeySet`.
- `AnonymousElection.eligibility_scheme = blind_token_v1`.
- `voter_public_key` входит в `voter_allowlist[]`.
- `recipient_encryption_public_key` совпадает с `VoterEntry.voter_encryption_public_key`.
- `ObjectEnvelope.created_at` находится внутри issuance window.
- envelope `pow` валиден для `BlindTokenRequest`.
- `signature` валидна для `voter_public_key`.
- conflict group проверена по `blind_token_request_conflict_key`.

Конфликтный ключ:

```text
blind_token_request_conflict_key = election_id || voter_public_key
```

Если для одного `blind_token_request_conflict_key` существует больше одного valid `BlindTokenRequest`, вся группа получает `valid_but_conflicted` и исключается из issuance.

## Trustee Request Processing

Trustee обрабатывает только `BlindTokenRequest` со статусом `valid`.

Trustee не публикует `BlindTokenIssue`, если request:

- `pending_dependencies`;
- `valid_but_conflicted`;
- `invalid`;
- находится вне issuance window;
- относится к другому `network_id`;
- относится к election, где trustee не входит в `TallyKeySet.trustee_set[]`.

Для каждого trustee действует ограничение:

```text
one issue per election_id || trustee_public_key || voter_public_key
```

## BlindTokenIssue

Trustee публикует encrypted issue как доменный объект.

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

Публичная validation проверяет:

- `election_id` указывает на operationally active `AnonymousElection` с валидным `TallyKeySet`;
- `trustee_public_key` входит в `TallyKeySet.trustee_set[]`;
- `voter_public_key` входит в `voter_allowlist[]`;
- `request_object_id` указывает на valid `BlindTokenRequest`;
- `BlindTokenIssue.election_id == BlindTokenRequest.election_id`;
- `BlindTokenIssue.voter_public_key == BlindTokenRequest.voter_public_key`;
- referenced `BlindTokenRequest` не имеет статус `valid_but_conflicted`;
- `recipient_key_id == key_id(BlindTokenRequest.recipient_encryption_public_key)`;
- `encrypted_payload` имеет корректный контейнерный формат;
- `ObjectEnvelope.created_at` находится внутри issuance window;
- envelope `pow` валиден для `BlindTokenIssue`;
- `signature` валидна для `trustee_public_key`;
- conflict group проверена по `blind_token_issue_conflict_key`.

Конфликтный ключ:

```text
blind_token_issue_conflict_key = election_id || trustee_public_key || voter_public_key
```

Если для одного `blind_token_issue_conflict_key` существует больше одного valid `BlindTokenIssue`, вся группа получает `valid_but_conflicted` и исключается из issuance.

## Encrypted Issue Payload

`encrypted_payload` шифруется на `voter_encryption_public_key` из `VoterEntry`.

```text
encrypted_payload = HPKE.Seal(
  recipient_public_key = voter_encryption_public_key,
  info = "librevote-blind-token-issue-encryption-v1" || election_id || request_object_id,
  aad = canonical_public_issue_header,
  plaintext = canonical_blind_token_issue_payload
)
```

`canonical_public_issue_header` содержит только public metadata issue:

```text
protocol_version
network_id
object_type = BlindTokenIssue
scope = election_id
scope_id = election_id
ObjectEnvelope.created_at
election_id
trustee_public_key
voter_public_key
request_object_id
recipient_key_id
```

`object_id`, envelope `pow`, `encrypted_payload` и `signature` не входят в AAD.

Правила:

- public validators не расшифровывают payload;
- public validators проверяют только envelope, подпись trustee и ссылки;
- voter расшифровывает payload локально;
- decrypted payload не публикуется;
- decrypted payload не логируется.

## Voter Issue Processing

Voter отслеживает `BlindTokenIssue`, где:

```text
recipient_key_id == key_id(voter_encryption_public_key)
voter_public_key == local voter_signing_public_key
election_id == target election_id
```

Для каждого issue voter выполняет:

```text
1. Verify public BlindTokenIssue status.
2. Decrypt encrypted_payload with voter_encryption_private_key.
3. Verify trustee_blind_token_key_id belongs to the same trustee that signed the public envelope.
4. Verify blinded_token_signature against original blinded_token_message.
5. Unblind blinded_token_signature.
6. Verify unblinded signature against token_public_key.
7. Store valid trustee token signature locally.
```

Invalid decrypted payload отбрасывается локально. Public validation status issue при этом не меняется, потому что другие узлы не видят decrypted payload.

## Threshold Completion

Issuance считается завершенной для voter, когда локально получено:

```text
2 valid unblinded trustee token signatures from distinct trustees
```

Если valid signatures меньше `2`, voter не создает valid `AnonymousBallot`.

Если valid signatures равно `2` или `3`, voter создает `AnonymousBallot` с любыми `2` valid signatures от distinct trustees. Подписи сортируются по trustee public key canonical byte order.

## AnonymousBallot Construction

После завершения issuance voter создает `AnonymousBallot`.

В ballot раскрываются:

```text
token_public_key
token_nullifier
eligibility_proof.trustee_token_signatures[]
token_holder_signature
```

`token_nullifier`:

```text
token_nullifier = HASH("librevote-token-nullifier-v1" || election_id || token_public_key)
```

`token_holder_signature` доказывает владение `token_private_key` и защищает раскрытый token proof от кражи из сети.

## Issuance Audit

P2P object log позволяет аудировать issuance metadata.

Публично проверяется:

- сколько voters опубликовали `BlindTokenRequest`;
- какие requests conflicted;
- какие trustees опубликовали `BlindTokenIssue`;
- какие issues conflicted;
- какие trustees не опубликовали issue для valid request.

Публично не проверяется содержимое encrypted issue payload и корректность encrypted blind signature. Эта корректность проверяется только recipient voter после расшифровки.

## Participation Privacy

Issuance phase не скрывает факт запроса token.

Публично видно:

```text
voter_public_key опубликовал BlindTokenRequest
trustees опубликовали BlindTokenIssue
```

Публично не видно:

```text
token_public_key
token_private_key
unblinded trustee token signatures
связь voter_public_key -> AnonymousBallot
выбор voter
```

Автоматическая публикация `BlindTokenRequest` для каждого локально доступного eligible voter key снижает participation leakage, но не скрывает отсутствие voters, которые не запустили клиент или не разблокировали ключи.

## Failure Cases

```text
no BlindTokenRequest
-> voter не получает token signatures

conflicted BlindTokenRequest
-> trustees не публикуют BlindTokenIssue
-> voter не получает valid threshold token

request стал conflicted после публикации issue
-> зависимый BlindTokenIssue перестает использоваться для issuance

less than 2 valid BlindTokenIssue payloads
-> voter не создает valid AnonymousBallot

invalid encrypted issue payload
-> voter игнорирует issue от этого trustee

duplicate BlindTokenIssue from one trustee
-> вся issue conflict group исключается

late BlindTokenRequest
-> invalid

late BlindTokenIssue
-> invalid
```

## Storage Requirements

Локально voter хранит:

- `token_private_key` encrypted-at-rest;
- `token_public_key`;
- `blinding_factor` encrypted-at-rest до завершения unblinding;
- valid unblinded trustee token signatures encrypted-at-rest;
- связь local token material с `election_id`.

Сетевой object log хранит:

- `BlindTokenRequest`;
- `BlindTokenIssue` с encrypted payload;
- validation records;
- conflict metadata.

Raw secrets не логируются и не сериализуются в сетевые доменные объекты.
