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
librevote-trustee-nomination-sign-v1
librevote-trustee-vote-sign-v1
librevote-trustee-consent-sign-v1
librevote-tally-key-contribution-sign-v1
librevote-tally-key-set-sign-v1
librevote-peer-admission-pow-v1
librevote-object-pow-v1
librevote-sync-request-pow-v1
librevote-blind-token-message-v1
librevote-blind-token-issue-encryption-v1
librevote-token-holder-sign-v1
librevote-token-nullifier-v1
librevote-choice-encryption-v1
librevote-tally-share-proof-v1
librevote-election-parameters-v1
librevote-dkg-share-encryption-v1
librevote-tally-key-set-hash-v1
librevote-key-encryption-v1
```

Один и тот же ключ не должен подписывать payload без domain separator.

## Object ID

Каждый доменный объект имеет content-addressed `object_id`.

`object_id` вычисляется по canonical object bytes.

```text
canonical_object_bytes = CanonicalObjectEnvelope(
  protocol_version,
  network_id,
  object_type,
  scope,
  scope_id,
  created_at,
  payload_with_signatures
)

object_id = HASH("librevote-object-id-v1" || canonical_object_bytes)
```

В `canonical_object_bytes` не входят:

- `object_id`;
- envelope `pow`;
- source peer;
- local validation metadata;
- storage metadata.

Domain payload не содержит PoW. PoW находится только в `ObjectEnvelope.pow`.

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
- используется для `TrusteeVote` и `BlindTokenRequest`
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

trustee tally setup key
- Ristretto255 DKG encryption key
- публикуется в TrusteeConsent
- используется для verifiable encrypted DKG shares

trustee tally share key
- Ristretto255 threshold ElGamal share
- создается локально после successful DKG contribution processing
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

- `TrusteeNomination`;
- `TrusteeVote`;
- `TrusteeConsent`;
- `TallyKeyContribution`;
- `TallyKeySet`;
- election metadata objects.

Общая форма подписи:

```text
signing_payload = HASH(
  domain_separator ||
  protocol_version ||
  network_id ||
  object_type ||
  scope ||
  scope_id ||
  created_at ||
  canonical_payload_without_signature
)
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

Для object PoW `target_hash = object_id`. Для sync request PoW `target_hash` задается canonical request body hash.

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

### Blind Schnorr Transcript

Blind token issuance использует один фиксированный transcript format.

```text
transcript = Transcript("librevote-blind-schnorr-v1")
transcript.append("network_id", network_id)
transcript.append("election_id", election_id)
transcript.append("trustee_blind_token_key_id", trustee_blind_token_key_id)
transcript.append("blinded_token_message", blinded_token_message)
```

Правила nonce и challenge:

- trustee генерирует fresh Schnorr nonce для каждого issuance request;
- nonce reuse для одного `trustee_blind_token_key` запрещен;
- challenge выводится только из transcript bytes;
- unblinded signature проверяется над `blind_token_message` и `token_public_key`;
- parallel issuance не переиспользует nonce state между requests;
- implementation должна иметь test vectors для transcript, blinding, unblinding и verification.

Любой decrypted issue payload, не проходящий unblinded signature verification, не используется voter client.

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

`canonical_public_issue_header` задается как:

```text
canonical_public_issue_header = CanonicalProtobuf(BlindTokenIssueAAD {
  protocol_version
  network_id
  object_type = BlindTokenIssue
  scope = election_id
  scope_id = election_id
  created_at = ObjectEnvelope.created_at
  election_id
  trustee_public_key
  voter_public_key
  request_object_id
  recipient_key_id
})
```

В AAD не входят `object_id`, envelope `pow`, `encrypted_payload` и `signature`.

Зашифрованный payload содержит:

```text
BlindTokenIssuePayload {
  blinded_token_signature
  trustee_blind_token_key_id
}
```

Публичные узлы проверяют подпись trustee, `request_object_id`, `recipient_key_id`, issuance window и уникальность issue. Избиратель дополнительно расшифровывает payload и проверяет, что `blinded_token_signature` создан blind-token key того же trustee, который подписал public envelope.

## Anonymous Ballot Authorization

В `AnonymousBallot` публикуются:

```text
token_public_key
token_nullifier
eligibility_proof.trustee_token_signatures[]
token_holder_signature
```

`eligibility_proof.trustee_token_signatures[]` должен содержать минимум `2` валидные blind token signatures от distinct trustees из финального trustee set.

`token_nullifier` вычисляется так:

```text
token_nullifier = HASH("librevote-token-nullifier-v1" || election_id || token_public_key)
```

`token_holder_signature` доказывает владение `token_private_key` и защищает раскрытый token proof от повторного использования другим peer'ом.

```text
token_holder_payload = HASH(
  "librevote-token-holder-sign-v1" ||
  election_id ||
  canonical_bytes(encrypted_choice) ||
  canonical_bytes(choice_validity_proof) ||
  token_public_key ||
  token_nullifier ||
  canonical_bytes(eligibility_proof) ||
  ObjectEnvelope.created_at
)

token_holder_signature = Schnorr.Sign(token_private_key, token_holder_payload)
```

`canonical_bytes(...)` использует canonical protobuf profile. Эквивалентная implementation может подписывать canonical `AnonymousBallot` payload без `token_holder_signature` и envelope `pow`.

Проверка anonymous ballot authorization:

- `token_nullifier` соответствует `election_id` и `token_public_key`.
- Минимум `2` trustee blind token signatures от distinct trustees валидны для `blind_token_message`.
- Подписавшие trustees входят в финальный trustee set из валидного `TallyKeySet`.
- `token_holder_signature` валидна для `token_public_key`.

Публичная проверка `AnonymousBallot` не доказывает, что trustees выдали signatures только через публично видимые `BlindTokenRequest`. Integrity против fraudulent extra issuance требует допущение, что менее `2` из `3` trustees сговорились выпускать credentials вне протокола.

## Threshold Tally Key

Основное анонимное голосование использует distributed threshold ElGamal key setup для финальных trustees.

Параметры v1:

```text
trustee_count_n = 3
threshold_t = 2
group = Ristretto255
```

Каждый final trustee публикует `TallyKeyContribution`:

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

`dkg_encrypted_shares[]` шифруются для `trustee_tally_setup_public_key` получателей из final trustee set. Public commitments, setup proofs и share encryption proofs позволяют проверить, что aggregate `tally_public_key` выводится из published contributions.

DKG encrypted share AAD:

```text
dkg_share_aad = HASH(
  "librevote-dkg-share-encryption-v1" ||
  network_id ||
  election_id ||
  trustee_selection_result_hash ||
  trustee_set_hash ||
  sender_trustee_public_key ||
  recipient_trustee_public_key ||
  recipient_tally_setup_key_id ||
  recipient_index
)
```

`share_encryption_proof` публично привязывает encrypted share к sender commitments, recipient setup key и `dkg_share_aad`. Recipient trustee после decrypt проверяет share against commitments before storing local `trustee_tally_share`.

Key setup завершается публикуемым `TallyKeySet`:

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
}
```

`tally_key_set_hash`:

```text
tally_key_set_hash = HASH(
  "librevote-tally-key-set-hash-v1" ||
  election_id ||
  trustee_selection_result_hash ||
  canonical_trustee_set ||
  sorted_trustee_consent_object_ids ||
  sorted_tally_key_contribution_object_ids ||
  canonical_dkg_commitments ||
  tally_public_key
)
```

Узел принимает anonymous election как operationally active только если `TallyKeySet` валиден для финального trustee set и threshold `2-of-3`.

`TallyKeySet` не создается trusted dealer. Полный private tally key не существует как локальный secret у creator или одного trustee.

## Encrypted Choice

Анонимный бюллетень шифрует выбор под `TallyKeySet.tally_public_key`.

Для single-choice голосования используется one-hot vector длиной `options_count`.

```text
choice_vector[i] = 1, если выбран option i
choice_vector[j] = 0, если option j не выбран
sum(choice_vector) = 1
```

Каждый элемент vector шифруется отдельным ElGamal ciphertext:

```text
ciphertext_j = ElGamalEncrypt(TallyKeySet.tally_public_key, choice_vector[j], randomness_j)
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
- все ciphertexts зашифрованы под `TallyKeySet.tally_public_key` этого election.

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
- `ObjectEnvelope.created_at >= tally_starts_at` с учетом clock skew policy.
- `encrypted_tally_hash` соответствует локально вычисленному encrypted tally.
- `decryption_proof` валиден для `decryption_share`.

Результат раскрывается при наличии минимум `2` валидных decryption shares от distinct trustees.

Threshold decryption раскрывает aggregate ciphertexts. Если `2` trustees сговариваются, они технически могут расшифровать individual ballot ciphertexts, потому что anonymous ballots публичны. Это является явным privacy limitation v1.

## Tally Count Decoding

После threshold decryption каждый option result декодируется как bounded discrete log в малом диапазоне.

```text
decoded_count_j = DecodePointAsCount(point_j, 0..valid_ballot_count)
```

Правила:

- допустимый диапазон декодирования равен `[0, valid_ballot_count]`;
- если point не соответствует ни одному count в диапазоне, tally verification fails;
- сумма decoded counts должна равняться `valid_ballot_count`;
- implementations используют deterministic bounded search или precomputed table для диапазона election.

## Randomness

Все секреты и nonces генерируются из криптографически стойкого генератора случайных чисел операционной системы.

Случайность требуется для:

- node key generation;
- voter key generation;
- voter encryption key generation;
- trustee key generation;
- DKG polynomial randomness;
- DKG share encryption randomness;
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

Та же схема local secret encryption используется для `blinding_factor` и локально сохраненных unblinded token signatures в issuance state.

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
