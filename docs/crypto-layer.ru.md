# Криптографический слой

Этот документ описывает криптографический слой LibreVote v1.

Криптографический слой отвечает за ключи, подписи, хеширование, proof-of-work, blind tokens, шифрование анонимных бюллетеней и threshold tally. Он не отвечает за P2P-доставку, хранение объектов или пользовательский интерфейс.

## Принятые Решения

- `HASH` в v1 означает `SHA-256`.
- Все хеши, подписи и proof inputs используют явные domain separators.
- Все подписываемые и хешируемые структуры сериализуются через canonical protobuf profile.
- Публичные подписи используют `Ed25519`.
- Зашифрованные P2P payloads используют `HPKE X25519-SHA256-ChaCha20Poly1305`.
- Blind tokens используют blind Schnorr signatures over `Ristretto255`.
- Token holder signatures используют Schnorr signatures over `Ristretto255`.
- Анонимные бюллетени используют threshold ElGamal over `Ristretto255`.
- Threshold tally использует схему `2-of-3` для выбранных trustees.
- Proof-of-work использует SHA-256 leading-zero-bits проверку.
- Local key encryption использует `Argon2id` и `XChaCha20-Poly1305`.
- Ключи node, voter signing, voter encryption, trustee, blind-token и tally-decryption разделены.

## Не Цели

- Криптографический слой не определяет сетевую доставку.
- Криптографический слой не выбирает trustees.
- Криптографический слой не хранит object log.
- Криптографический слой не доверяет transport peer identity как автору бюллетеня.
- Криптографический слой не использует порядок доставки объектов для принятия доменных решений.

## Canonical Encoding

Все криптографические операции используют canonical bytes.

```text
canonical_bytes = CanonicalProtobuf(type_url, version, payload)
```

Правила canonical protobuf profile:

- Unknown fields отклоняются до проверки подписи или hash.
- Map fields не используются в подписываемых структурах.
- Повторяющиеся поля, которые являются множествами, сортируются по canonical byte order.
- Временные значения кодируются как Unix milliseconds в `int64`.
- Floating point поля не используются.
- Отсутствующее поле и поле со значением по умолчанию имеют один допустимый canonical representation.
- Все enum значения должны быть известны текущей версии протокола.

## Domain Separation

Каждый криптографический контекст использует отдельный domain separator.

Примеры:

```text
librevote-object-id-v1
librevote-public-ballot-sign-v1
librevote-trustee-nomination-sign-v1
librevote-trustee-vote-sign-v1
librevote-trustee-consent-sign-v1
librevote-peer-admission-pow-v1
librevote-object-pow-v1
librevote-sync-request-pow-v1
librevote-blind-token-message-v1
librevote-blind-token-issue-encryption-v1
librevote-token-holder-sign-v1
librevote-token-nullifier-v1
librevote-choice-encryption-v1
librevote-tally-share-proof-v1
librevote-key-encryption-v1
```

Один и тот же ключ не должен подписывать payload без domain separator.

## Object ID

Каждый доменный объект имеет content-addressed `object_id`.

```text
object_id = HASH(
  "librevote-object-id-v1" ||
  object_type ||
  canonical_payload_without_object_id_and_pow
)
```

`object_id` используется для:

- дедупликации;
- object log;
- GossipSub announcements;
- direct sync;
- проверки неизменности payload.

`object_id` не является proof права голоса.

## Ключи

LibreVote v1 использует разные ключи для разных ролей.

```text
node key
- libp2p identity key
- принадлежит транспортному слою
- не используется для доменной подписи бюллетеней

voter signing key
- Ed25519
- используется для PublicBallot и trustee selection votes
- входит в voter allowlist

voter encryption key
- X25519
- используется для расшифровки BlindTokenIssue payloads
- входит в voter allowlist

trustee signing key
- Ed25519
- используется для TrusteeNomination, TrusteeConsent и служебных trustee objects

trustee blind-token key
- Ristretto255 Schnorr blind-signing key
- используется для blind_token_v1 issuance

trustee tally share key
- Ristretto255 threshold ElGamal share
- используется для tally decryption shares

anonymous token key
- Ristretto255 Schnorr keypair
- создается избирателем отдельно для каждого anonymous election
- не раскрывает voter signing key
```

Ключи разных ролей не переиспользуются между схемами.

## Key IDs

Публичные ключи адресуются через key id.

```text
key_id = HASH("librevote-key-id-v1" || key_type || canonical_public_key)
```

`key_type` входит в hash, чтобы исключить смешивание ключей разных ролей.

## Ed25519 Signatures

Ed25519 используется для публично проверяемых доменных объектов.

Примеры:

- `PublicBallot`;
- `TrusteeNomination`;
- `TrusteeVote`;
- `TrusteeConsent`;
- election metadata objects.

Общая форма подписи:

```text
signing_payload = HASH(domain_separator || canonical_payload_without_signature_and_pow)
signature = Ed25519.Sign(private_key, signing_payload)
```

Проверка:

```text
Ed25519.Verify(public_key, signing_payload, signature)
```

Подпись `voter signing key` раскрывает личность голосующего и не используется в `AnonymousBallot`.

## Proof-of-Work

PoW используется как cost mechanism для сети и объектов.

```text
pow_input = domain_separator || target_hash || difficulty || nonce
pow_hash = SHA256(pow_input)

valid if leading_zero_bits(pow_hash) >= difficulty
```

Домены PoW:

```text
peer admission pow -> librevote-peer-admission-pow-v1
object pow -> librevote-object-pow-v1
sync request pow -> librevote-sync-request-pow-v1
```

PoW не доказывает право голоса и не заменяет подписи, blind tokens, nullifiers или threshold cryptography.

## Blind Token v1

`blind_token_v1` доказывает право на анонимный бюллетень без раскрытия `voter_public_key`.

Каждый избиратель для каждого anonymous election создает одноразовый token keypair:

```text
token_private_key = random_scalar()
token_public_key = token_private_key * G
```

Trustees подписывают blinded `token_public_key` через blind Schnorr signatures.

Сообщение blind token:

```text
blind_token_message = HASH(
  "librevote-blind-token-message-v1" ||
  election_id ||
  token_public_key
)
```

Каждый trustee выдает не более одной blind token signature для пары:

```text
election_id || voter_public_key
```

После unblinding избиратель получает trustee signatures, которые публично проверяются по `token_public_key`, но не связываются с исходным `voter_public_key`.

## Encrypted Blind Token Issue Payload

`BlindTokenIssue` публикуется в P2P-сеть с зашифрованным payload.

Публичная часть объекта содержит:

```text
election_id
trustee_public_key
voter_public_key
request_object_id
recipient_key_id
encrypted_payload
created_at
pow
signature
```

Payload шифруется на `voter_encryption_public_key` из `VoterEntry`.

```text
encrypted_payload = HPKE.Seal(
  recipient_public_key = voter_encryption_public_key,
  info = "librevote-blind-token-issue-encryption-v1" || election_id || request_object_id,
  aad = canonical_public_issue_header,
  plaintext = canonical_blind_token_issue_payload
)
```

Зашифрованный payload содержит:

```text
BlindTokenIssuePayload {
  blinded_token_signature
  trustee_blind_token_key_id
}
```

Публичные узлы проверяют подпись trustee, `request_object_id`, `recipient_key_id` и уникальность issue. Избиратель дополнительно расшифровывает payload и проверяет `blinded_token_signature`.

## Anonymous Ballot Authorization

В `AnonymousBallot` публикуются:

```text
token_public_key
token_nullifier
eligibility_proof.trustee_token_signatures[]
token_holder_signature
```

`eligibility_proof.trustee_token_signatures[]` должен содержать минимум `2` валидные blind token signatures от trustees из финального trustee set.

`token_nullifier` вычисляется так:

```text
token_nullifier = HASH("librevote-token-nullifier-v1" || election_id || token_public_key)
```

`token_holder_signature` доказывает владение `token_private_key` и защищает раскрытый token proof от повторного использования другим peer'ом.

```text
token_holder_payload = HASH(
  "librevote-token-holder-sign-v1" ||
  election_id ||
  encrypted_choice ||
  choice_validity_proof ||
  token_nullifier ||
  created_at
)

token_holder_signature = Schnorr.Sign(token_private_key, token_holder_payload)
```

Проверка anonymous ballot authorization:

- `token_nullifier` соответствует `election_id` и `token_public_key`.
- Минимум `2` trustee blind token signatures валидны для `blind_token_message`.
- Подписавшие trustees входят в финальный trustee set.
- `token_holder_signature` валидна для `token_public_key`.

## Threshold Tally Key

Основное анонимное голосование использует threshold ElGamal key setup для выбранных trustees.

Параметры v1:

```text
trustee_count_n = 3
threshold_t = 2
group = Ristretto255
```

Key setup публикует:

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

Узел принимает anonymous election только если `TallyKeySet` валиден для финального trustee set и threshold `2-of-3`.

## Encrypted Choice

Анонимный бюллетень шифрует выбор под `tally_public_key`.

Для single-choice голосования используется one-hot vector длиной `options_count`.

```text
choice_vector[i] = 1, если выбран option i
choice_vector[j] = 0, если option j не выбран
sum(choice_vector) = 1
```

Каждый элемент vector шифруется отдельным ElGamal ciphertext:

```text
ciphertext_j = ElGamalEncrypt(tally_public_key, choice_vector[j], randomness_j)
```

`encrypted_choice` содержит массив ciphertexts длиной `options_count`.

```text
EncryptedChoice {
  election_id
  tally_public_key
  ciphertexts[]
}
```

## Choice Validity Proof

`choice_validity_proof` доказывает без раскрытия выбора:

- каждый ciphertext шифрует `0` или `1`;
- сумма зашифрованного vector равна `1`;
- количество ciphertexts равно количеству options в election metadata;
- все ciphertexts зашифрованы под `tally_public_key` этого election.

Бюллетень без валидного `choice_validity_proof` получает статус `invalid`.

## Tally Decryption Shares

После завершения voting window trustees публикуют decryption shares.

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

Проверка:

- `trustee_public_key` входит в финальный trustee set.
- Подпись trustee валидна.
- `encrypted_tally_hash` соответствует локально вычисленному encrypted tally.
- `decryption_proof` валиден для `decryption_share`.

Результат раскрывается при наличии минимум `2` валидных decryption shares.

## Randomness

Все секреты и nonces генерируются из криптографически стойкого генератора случайных чисел операционной системы.

Случайность требуется для:

- node key generation;
- voter key generation;
- voter encryption key generation;
- trustee key generation;
- anonymous token key generation;
- blind token blinding factors;
- HPKE ephemeral keys;
- ElGamal encryption randomness;
- Schnorr signature nonces;
- PoW nonces;
- local key encryption nonces.

Schnorr nonces генерируются через CSPRNG. Повтор nonce для одного ключа запрещен.

## Secret Handling

Приватные ключи и token secrets не сериализуются в доменные объекты.

Запрещено логировать:

- private keys;
- token_private_key;
- voter encryption private key;
- blind token blinding factors;
- ElGamal randomness;
- trustee tally shares;
- raw seed material.

Локальное хранение секретов выполняется key store слоем. Криптографический слой получает секреты только через явный API подписи, расшифровки или proof generation.

## Local Key Encryption

Приватные ключи хранятся в encrypted-at-rest виде.

```text
key_encryption_key = Argon2id(passphrase, salt, memory, iterations, parallelism)

encrypted_private_key = XChaCha20Poly1305.Seal(
  key = key_encryption_key,
  nonce = random_nonce,
  aad = "librevote-key-encryption-v1" || key_id || key_type || public_key,
  plaintext = private_key_bytes
)
```

`salt`, `nonce`, `memory`, `iterations` и `parallelism` хранятся в `encryption_metadata` локального `KeyRecord`.

## Verification Boundary

Криптографический слой предоставляет чистые проверки:

```text
VerifyObjectID(object) -> valid/invalid
VerifyPoW(pow, target_hash, difficulty) -> valid/invalid
VerifyEd25519Signature(public_key, payload, signature) -> valid/invalid
VerifyBlindTokenIssueEnvelope(issue) -> valid/invalid
DecryptBlindTokenIssuePayload(issue, voter_encryption_private_key) -> payload/error
VerifyBlindTokenProof(election, ballot) -> valid/invalid
VerifyTokenHolderSignature(ballot) -> valid/invalid
VerifyChoiceValidityProof(election, ballot) -> valid/invalid
VerifyTallyDecryptionShare(election, encrypted_tally, share) -> valid/invalid
```

Эти функции не читают сеть, не изменяют object log и не принимают решения о сетевой репутации peer'ов.
