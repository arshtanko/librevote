# План Реализации LibreVote v1

Этот документ задает порядок реализации LibreVote v1. План следует архитектуре из `docs/architecture.md` и не меняет протокольные решения.

Основной принцип реализации: сначала deterministic local correctness, затем P2P delivery, затем end-to-end multi-node behavior.

## Правила Реализации

- Реализация следует `docs/architecture.md` и layer documents.
- Изменение архитектурного инварианта выполняется только вместе с обновлением всех затронутых документов.
- Каждый доменный объект валидируется локально до publication.
- Каждый result object проверяется локальным пересчетом.
- Network source peer не участвует в доменной валидации.
- Derived state реализуется как cache.
- Storage retention согласуется с validation status.
- CLI mutating domain operations идут через running node local control API.

## Этап 1. Repository Foundation

Цель: подготовить базовый executable project layout и повторяемую проверку качества.

Работы:

- Создать основной бинарник `librevote`.
- Создать разделение модулей по слоям: domain, crypto, storage, validation, network, transport, tally, node, cli.
- Настроить protobuf generation для network messages и domain payloads.
- Настроить unit test runner.
- Настроить integration test runner для локальных multi-node сценариев.
- Настроить static checks и formatting.
- Создать test fixtures directory для canonical bytes и validation cases.

Критерии завершения:

- `librevote --help` запускается.
- Unit tests запускаются одной командой.
- Generated protobuf files воспроизводимы.
- Empty repository bootstrap не требует running node.

## Этап 2. Domain Schema And Canonical Encoding

Цель: реализовать domain object model и canonical byte rules.

Работы:

- Описать protobuf schemas для всех `object_type` v1.
- Реализовать `ObjectEnvelope`.
- Реализовать canonical protobuf profile.
- Реализовать `canonical_object_bytes`.
- Реализовать `object_id` calculation.
- Реализовать `scope` и `scope_id` validation.
- Реализовать object type -> scope mapping.
- Добавить canonical test vectors для каждого object type.

Критерии завершения:

- `object_id` не зависит от source peer, storage metadata или validation metadata.
- Envelope `pow` не входит в `object_id`.
- Domain payloads не содержат PoW.
- Unknown fields и unknown enum values отклоняются.
- Repeated set-like fields имеют deterministic ordering.

## Этап 3. Cryptographic Foundation

Цель: реализовать криптографические primitives и shared signing/hash contexts.

Работы:

- Реализовать `HASH = SHA-256` wrappers с domain separators.
- Реализовать key id derivation.
- Реализовать Ed25519 signing contexts для public domain objects.
- Реализовать object PoW.
- Реализовать sync request PoW.
- Реализовать encrypted-at-rest key encryption: `Argon2id` + `XChaCha20-Poly1305`.
- Реализовать key separation для node, voter, trustee, tally setup, tally share и anonymous token keys.
- Добавить test vectors для signatures, hashes, PoW и key ids.

Критерии завершения:

- Один и тот же payload дает одинаковый signing payload на всех platforms.
- Любое изменение signed field ломает signature verification.
- PoW проверяется только по envelope location.
- Private keys не сериализуются в domain objects.

## Этап 4. SQLite Storage Layer

Цель: реализовать local persistent object log, validation records и encrypted key store.

Работы:

- Реализовать SQLite schema metadata.
- Реализовать process lock `<data_dir>/librevote.lock`.
- Реализовать object metadata tables.
- Реализовать retained payload table.
- Реализовать validation records.
- Реализовать object dependencies.
- Реализовать invalid object metadata.
- Реализовать derived state tables.
- Реализовать encrypted key store.
- Реализовать local issuance state.
- Реализовать peer and sync metadata.
- Реализовать object ingestion transaction.
- Реализовать retention policy.
- Реализовать `pending_payload_evicted` reacquire path.

Критерии завершения:

- Valid, valid_for_tally и valid_but_conflicted payloads retained indefinitely.
- Invalid payloads не retained durably.
- Pending payload eviction не блокирует повторную загрузку через sync.
- Payload mismatch для известного `object_id` отклоняется.
- Rebuild восстанавливает derived state из retained objects.
- Offline mutating access невозможен при active process lock.

## Этап 5. Validation Layer

Цель: реализовать deterministic validation pipeline.

Работы:

- Реализовать validation statuses.
- Реализовать envelope validation.
- Реализовать structural validation.
- Реализовать contextual validation.
- Реализовать dependency recording.
- Реализовать conflict group resolution.
- Реализовать revalidation triggers.
- Реализовать republish eligibility flags.
- Реализовать validation outcome API для storage и workers.

Критерии завершения:

- `AnonymousElection` valid без `TallyKeySet` и остается structural root.
- Operationally active election определяется valid `AnonymousElection` + valid `TallyKeySet`.
- Conflict group size > 1 переводит всю группу в `valid_but_conflicted`.
- Result objects accepted только при совпадении локального recomputation.
- Threshold checks требуют distinct trustees.
- `pending_payload_evicted` не republish-ится и reacquire-ится через sync.

## Этап 6. Trustee Selection Tally

Цель: реализовать публичный deterministic trustee selection.

Работы:

- Реализовать `TrusteeSelectionElection` creation validation.
- Реализовать `TrusteeNomination` validation.
- Реализовать `TrusteeVote` validation.
- Реализовать conflict handling для nominations и votes.
- Реализовать candidate scoring.
- Реализовать deterministic `candidate_ranking[]`.
- Реализовать `TrusteeSelectionResult` recomputation.
- Реализовать `TrusteeSelectionResult` publication worker.

Критерии завершения:

- Same retained inputs produce same `candidate_ranking[]`.
- `TrusteeSelectionResult` accepted только при совпадении `result_hash`.
- `TrusteeSelectionResult` не фиксирует final trustee set.
- Conflicted votes не входят в scoring.

## Этап 7. Local Control API And CLI Skeleton

Цель: реализовать CLI boundary без обхода running node.

Работы:

- Реализовать Unix socket server в node process.
- Реализовать request id, command id, protocol version и structured errors.
- Реализовать socket permissions `0600`.
- Реализовать limited commands до `running`: `node status`, `node stop`, `object status`, `sync status`.
- Реализовать CLI command groups.
- Реализовать `--json` для read-only commands.
- Реализовать `init` без running node.
- Реализовать offline key creation только при process lock.

Критерии завершения:

- Mutating domain command fails when node socket is unavailable.
- Running node receives mutating commands through local control API.
- CLI does not publish GossipSub messages directly.
- CLI does not mutate validation records directly.

## Этап 8. Transport Layer

Цель: поднять libp2p transport без доменной логики.

Работы:

- Реализовать persistent node key.
- Реализовать libp2p host over QUIC v1.
- Реализовать listen addresses and multiaddr handling.
- Реализовать connection lifecycle events.
- Реализовать transport stream open/accept API для network layer.
- Реализовать graceful shutdown для host.

Критерии завершения:

- Node exposes stable peer id from node key.
- Transport does not know elections or ballots.
- Transport tests can open bidirectional streams between local nodes.

## Этап 9. Network Protocols And Sync

Цель: реализовать discovery, announcements и direct object sync.

Работы:

- Реализовать `Hello` protocol.
- Реализовать peer admission PoW.
- Реализовать Kademlia DHT discovery.
- Реализовать GossipSub topic `/librevote/<network_id>/v1/objects`.
- Реализовать `ObjectAnnouncement` validation.
- Реализовать `Inventory` with `scope` and `scope_id`.
- Реализовать `GetObject`.
- Реализовать `GetObjects` with `limit_count` and `limit_bytes`.
- Реализовать `GetElectionState`.
- Реализовать sync state cursors.
- Реализовать root discovery through network scope.
- Реализовать scoped sync for trustee selection and election scopes.
- Реализовать reacquire for `pending_payload_evicted`.

Критерии завершения:

- GossipSub никогда не переносит full object payload.
- Root objects discoverable by a fresh node after missing gossip.
- Scoped sync downloads missing payloads and evicted pending payloads.
- Inventory returns only valid, valid_for_tally and valid_but_conflicted object refs.
- GetObject/GetObjects serve retained valid/conflicted payloads only.

## Этап 10. Node Lifecycle And Workers

Цель: реализовать node process lifecycle and background workers.

Работы:

- Реализовать startup state machine.
- Реализовать initial sync order.
- Реализовать local rebuild.
- Реализовать discovery worker.
- Реализовать sync worker.
- Реализовать validation worker.
- Реализовать republish worker.
- Реализовать trustee selection result worker.
- Реализовать cleanup worker.
- Реализовать graceful shutdown.
- Реализовать crash recovery behavior.

Критерии завершения:

- Control API starts in `starting` mode before long sync work.
- Validation worker is the only worker changing validation status.
- Republish worker publishes announcements only for valid, valid_for_tally and valid_but_conflicted objects.
- Shutdown stops publication before closing transport.
- Rebuild never mutates retained payload bytes.

## Этап 11. Consent, DKG And Election Activation

Цель: реализовать переход от structural `AnonymousElection` к operationally active election.

Работы:

- Реализовать `AnonymousElection` creation.
- Реализовать `election_parameters_hash`.
- Реализовать `TrusteeConsent` creation and validation.
- Реализовать uniqueness conflict for `trustee_tally_setup_public_key`.
- Реализовать final trustee set derivation.
- Реализовать `TallyKeyContribution` creation and validation.
- Реализовать DKG commitments.
- Реализовать DKG encrypted shares.
- Реализовать share encryption AAD.
- Реализовать share encryption proofs.
- Реализовать trustee local tally share reconstruction.
- Реализовать `TallyKeySet` creation and validation.
- Реализовать activation worker.

Критерии завершения:

- `TrusteeConsent` binds to `AnonymousElection` and matching `TrusteeSelectionResult`.
- Final trustee set uses first `3` consenting ranked candidates with unique setup keys.
- `TallyKeySet` accepted only when local activation recomputation matches.
- No trusted dealer holds full tally private key.
- Activated election exposes `TallyKeySet.tally_public_key`.

## Этап 12. Blind Token Issuance

Цель: реализовать privacy-preserving credential issuance.

Работы:

- Реализовать anonymous token key generation.
- Реализовать blind Schnorr transcript.
- Реализовать `BlindTokenRequest` creation and validation.
- Реализовать trustee request processing.
- Реализовать `BlindTokenIssue` public validation.
- Реализовать HPKE encryption for issue payload.
- Реализовать issue AAD.
- Реализовать recipient-side payload decryption and verification.
- Реализовать unblinding and local signature storage.
- Реализовать issuance worker voter-side.
- Реализовать issuance worker trustee-side.

Критерии завершения:

- `BlindTokenRequest` does not reveal `token_public_key`.
- Public validators do not decrypt issue payload.
- `BlindTokenIssue` public fields match referenced request.
- Recipient rejects issue payload if trustee blind-token key does not match envelope trustee.
- Local issuance completes only with `2` signatures from distinct final trustees.

## Этап 13. Anonymous Ballots

Цель: реализовать создание и валидацию анонимных бюллетеней.

Работы:

- Реализовать encrypted choice under `TallyKeySet.tally_public_key`.
- Реализовать choice validity proof.
- Реализовать `token_nullifier`.
- Реализовать `eligibility_proof` with trustee token signatures.
- Реализовать canonical `token_holder_payload`.
- Реализовать `token_holder_signature`.
- Реализовать `AnonymousBallot` validation.
- Реализовать ballot conflict handling.
- Реализовать vote cast command through node API.
- Реализовать random delay and batching for own anonymous ballot announcement.

Критерии завершения:

- `AnonymousBallot` contains no voter, peer or node identity.
- Ballot requires active voting window.
- Eligibility proof requires `2` distinct final trustees.
- Repeated `token_nullifier` excludes whole conflict group from tally.
- Local ballot is announced only after successful validation.

## Этап 14. Anonymous Tally And Results

Цель: реализовать encrypted tally, decryption shares and result verification.

Работы:

- Реализовать valid ballot set selection.
- Реализовать deterministic ballot ordering.
- Реализовать homomorphic encrypted tally.
- Реализовать `encrypted_tally_hash`.
- Реализовать `TallyDecryptionShare` creation and validation.
- Реализовать threshold decryption with distinct trustees.
- Реализовать bounded count decoding.
- Реализовать `TallyResult` creation and validation.
- Реализовать stale result detection.
- Реализовать tally worker.

Критерии завершения:

- Tally includes only `valid_for_tally` ballots.
- `valid_but_conflicted`, `invalid` and pending statuses excluded.
- Decryption requires `2` valid shares from distinct final trustees.
- `invalid_ballot_count` does not enter `TallyResult` or `result_hash`.
- Late valid objects mark local result as `stale`.

## Этап 15. End-To-End Multi-Node Scenarios

Цель: проверить полный протокол на локальной сети nodes.

Сценарии:

- Fresh node discovers existing trustee selection and anonymous election through network scope.
- Trustee selection completes from nominations and votes.
- `TrusteeSelectionResult` published by one node is accepted by others through recomputation.
- Structural `AnonymousElection` receives consents and activates through `TallyKeySet`.
- Eligible voters receive blind token signatures.
- Anonymous ballots propagate through announcement-first sync.
- Duplicate anonymous ballots become `valid_but_conflicted` and are excluded.
- Final trustees publish decryption shares.
- Nodes compute and verify the same `TallyResult`.
- A late valid ballot changes local result state to `stale`.
- `pending_payload_evicted` object is reacquired through sync.

Критерии завершения:

- At least three local nodes complete an election end-to-end.
- A fourth node joining after gossip events reconstructs state through direct sync.
- All honest nodes converge to the same valid object set and result hash.
- Restarted node rebuilds derived state from retained objects.

## Этап 16. Hardening And Release Gate

Цель: довести v1 до надежного executable state.

Работы:

- Добавить fuzz tests for protobuf decoding and envelope validation.
- Добавить property tests for conflict resolution.
- Добавить deterministic test vectors for canonical bytes.
- Добавить storage crash recovery tests.
- Добавить sync rate limit tests.
- Добавить CLI JSON contract tests.
- Добавить threat-model regression scenarios.
- Проверить logs на отсутствие secrets.
- Проверить process lock behavior.
- Проверить shutdown ordering.

Критерии завершения:

- Test suite passes locally.
- Multi-node scenario passes repeatedly.
- CLI commands match `docs/cli.ru.md`.
- No plaintext private key or blinding factor appears in logs or SQLite.
- Architecture invariants from `docs/architecture.md` have direct test coverage.

## Реализационный Порядок

```text
1. Repository Foundation
2. Domain Schema And Canonical Encoding
3. Cryptographic Foundation
4. SQLite Storage Layer
5. Validation Layer
6. Trustee Selection Tally
7. Local Control API And CLI Skeleton
8. Transport Layer
9. Network Protocols And Sync
10. Node Lifecycle And Workers
11. Consent, DKG And Election Activation
12. Blind Token Issuance
13. Anonymous Ballots
14. Anonymous Tally And Results
15. End-To-End Multi-Node Scenarios
16. Hardening And Release Gate
```

Этап считается завершенным только после targeted tests и обновления документации при изменении поведения.
