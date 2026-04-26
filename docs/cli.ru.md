# CLI

Этот документ описывает текстовый командный интерфейс LibreVote v1.

CLI является интерфейсом управления локальным узлом. Он не реализует криптографию, P2P, storage, validation или tally самостоятельно. CLI вызывает application services работающего node process через локальный control API.

## Принятые Решения

- В v1 используется один бинарник: `librevote`.
- Узел работает как долгоживущий process: `librevote node start`.
- CLI-команды управления работающим узлом обращаются к node process через Unix socket.
- Unix socket path задается в config.
- Read-only команды поддерживают `--json`.
- Interactive TUI в v1 отсутствует.
- `trustee consent` не является ручной командой v1.
- Trustee consent публикуется автоматически ranked candidate trustee worker-ом, если trustee key разблокирован.
- `BlindTokenRequest` публикуется автоматически для каждого eligible local voter key.
- `BlindTokenIssue` публикуется автоматически final trustee при разблокированных trustee keys.
- `TallyKeyContribution` публикуется автоматически final trustee при разблокированном trustee tally setup key.
- `TallyDecryptionShare` публикуется автоматически после `tally_starts_at`, если trustee tally key разблокирован.
- Сетевые и доменные действия выполняются через running node.
- Прямой доступ CLI к SQLite разрешен только для `init` и offline key creation при остановленном node.

## Архитектурная Граница

CLI вызывает local application API.

```text
CLI command
-> local control API over Unix socket
-> application service
-> storage / validation / crypto / network / tally
```

CLI не выполняет:

- проверку подписей;
- проверку PoW;
- генерацию tally;
- прямую публикацию GossipSub announcements;
- прямую запись доменных объектов в SQLite при работающем node;
- прямое изменение validation records.

## Local Control API

Работающий node открывает Unix socket.

Пример default path:

```text
~/.local/share/librevote/librevote.sock
```

CLI использует socket для команд:

- node status;
- key unlock/lock/list;
- peer status;
- sync;
- trustee selection operations;
- election operations;
- token status;
- vote cast/status;
- tally/status/result;
- object inspection.

Если команда требует running node, а socket недоступен, CLI завершает выполнение с ошибкой.

Socket создается с permissions `0600` и принадлежит local user running node. Каждый request содержит command id, request id и protocol version.

## Output Rules

По умолчанию CLI выводит human-readable text.

Read-only команды поддерживают:

```text
--json
```

Правила:

- `--json` выводит один JSON object или JSON array.
- Ошибки в `--json` режиме выводятся как JSON error object.
- Mutating команды выводят созданный `object_id`, локальный status и краткое описание действия.
- CLI не выводит private keys, passphrases, blinding factors или raw secret material.

## Exit Codes

```text
0 success
1 general error
2 invalid arguments
3 node unavailable
4 key locked
5 validation failed
6 network timeout
7 not found
8 permission denied
```

## Command Groups

Поддерживаемые группы команд v1:

```text
librevote init
librevote node ...
librevote key ...
librevote peer ...
librevote sync ...
librevote trustee-selection ...
librevote trustee ...
librevote election ...
librevote token ...
librevote vote ...
librevote tally ...
librevote result ...
librevote object ...
```

## Init Commands

```text
librevote init --network <network_id>
```

Действия:

- создает config;
- создает SQLite database;
- записывает `schema_metadata`;
- генерирует node key;
- сохраняет node key encrypted-at-rest;
- создает директории для socket, database и config.

`init` выполняется без running node.

## Node Commands

```text
librevote node start
librevote node status [--json]
librevote node stop
```

### node start

Действия:

- берет process lock;
- открывает SQLite;
- проверяет `schema_version`;
- проверяет `network_id`;
- разблокирует node key;
- открывает Unix socket control API в `starting` mode;
- запускает transport layer;
- запускает network layer;
- запускает validation worker;
- выполняет local rebuild;
- подключается к bootstrap peers;
- запускает initial sync;
- запускает background workers.

### node status

Показывает:

- `network_id`;
- local `peer_id`;
- listen addresses;
- connected peers count;
- DHT status;
- sync status;
- active trustee selections;
- active elections;
- unlocked key roles;
- background worker status.

### node stop

Отправляет running node команду graceful shutdown.

## Key Commands

```text
librevote key create voter
librevote key create trustee
librevote key list [--json]
librevote key unlock <key_id> [--yes]
librevote key lock <key_id>
```

### key create voter

Создает пару ключей:

```text
voter_signing
voter_encryption
```

Ключи сохраняются encrypted-at-rest.

### key create trustee

Создает набор ключей:

```text
trustee_signing
trustee_blind_token
trustee_tally_setup
```

Ключи сохраняются encrypted-at-rest. `trustee_tally_share` появляется локально после successful threshold key setup и также хранится encrypted-at-rest.

### key unlock

Разблокирует ключ в running node process.

Эффекты:

- разблокированный voter key активирует voter-side issuance worker;
- разблокированный trustee key активирует trustee worker;
- разблокированный trustee tally setup key активирует `TallyKeyContribution`;
- разблокированный trustee tally share key активирует auto `TallyDecryptionShare` publication после `tally_starts_at`.

Для voter keys unlock является явным разрешением на auto issuance. CLI показывает elections, для которых будет опубликован `BlindTokenRequest`, и требует confirmation или `--yes`.

### key lock

Удаляет plaintext key material из памяти running node process.

## Peer Commands

```text
librevote peer list [--json]
librevote peer show <peer_id> [--json]
```

Показывают локальную peer metadata:

- peer id;
- addresses;
- score;
- admission status;
- last seen time.

Peer score не влияет на право голоса или tally.

## Sync Commands

```text
librevote sync now
librevote sync election <election_id>
librevote sync trustee-selection <trustee_selection_id>
librevote sync status [--json]
```

### sync now

Запускает network scope sync.

### sync election

Запускает sync для конкретного `election_id`.

### sync trustee-selection

Запускает sync для конкретного `trustee_selection_id`.

### sync status

Показывает:

- active sync jobs;
- last sync time;
- failed attempts;
- known object counts.

## Trustee Selection Commands

```text
librevote trustee-selection create --title <title> --voters <voters.json>
librevote trustee-selection list [--json]
librevote trustee-selection show <trustee_selection_id> [--json]
librevote trustee-selection result <trustee_selection_id> [--json]
```

### trustee-selection create

Создает `TrusteeSelectionElection`.

Параметры v1 фиксированы:

```text
trustee_count_n = 3
threshold_t = 2
max_choices_per_vote = 3
```

`voters.json` содержит публичные `VoterEntry`.

Команда создает доменный объект через running node и публикует `ObjectAnnouncement` после локальной валидации.

### trustee-selection result

Показывает локально пересчитанный result и опубликованные `TrusteeSelectionResult` objects. Публикация `TrusteeSelectionResult` выполняется автоматически node worker-ом после `voting_ends_at`.

## Trustee Commands

```text
librevote trustee nominate --selection <trustee_selection_id> --statement <text>
librevote trustee vote --selection <trustee_selection_id> --candidates <key1,key2,key3>
```

### trustee nominate

Создает `TrusteeNomination` для локального `trustee_signing` key.

Требует unlocked:

```text
trustee_signing
trustee_blind_token
```

### trustee vote

Создает `TrusteeVote` от локального voter key.

Требует unlocked:

```text
voter_signing
```

`trustee consent` отсутствует как ручная команда v1. Consent публикуется автоматически ranked candidate trustee worker-ом.

## Election Commands

```text
librevote election create --title <title> --options <options.json> --voters <voters.json> --trustee-selection <trustee_selection_id>
librevote election list [--json]
librevote election show <election_id> [--json]
librevote election status <election_id> [--json]
```

### election create

Создает structural `AnonymousElection`.

Требует:

- valid `TrusteeSelectionResult`;
- публичный `voter_allowlist` из `voters.json`;
- минимум два options.

После создания `AnonymousElection`:

- ranked trustee candidates автоматически публикуют `TrusteeConsent`, если trustee keys разблокированы;
- final trustees автоматически публикуют `TallyKeyContribution`;
- любой node может опубликовать `TallyKeySet` после локальной проверки DKG contributions;
- election становится active только после valid `TallyKeySet`.

### election status

Показывает local election state:

```text
unknown
discovered
pending_dependencies
valid
awaiting_consents
key_setup_active
activated
issuance_active
voting_active
tally_waiting
tally_active
result_verified
result_stale
```

## Token Commands

```text
librevote token status --election <election_id> [--json]
```

Token issuance является автоматической.

`token status` показывает:

- whether local eligible voter keys exist;
- whether `BlindTokenRequest` is published;
- request validation status;
- received `BlindTokenIssue` count;
- valid decrypted issue payload count;
- valid unblinded trustee signature count;
- readiness for `vote cast`.

CLI не имеет ручной команды `token request` в v1.

## Vote Commands

```text
librevote vote cast --election <election_id> --option <option_id>
librevote vote status --election <election_id> [--json]
```

### vote cast

Создает `AnonymousBallot`.

Требует:

- valid `AnonymousElection`;
- valid `TallyKeySet`;
- active voting window;
- unlocked anonymous token key;
- минимум `2` valid unblinded trustee token signatures от distinct trustees;
- valid selected `option_id`.

Действия:

- шифрует choice;
- создает `choice_validity_proof`;
- создает `token_nullifier`;
- создает `token_holder_signature`;
- считает object PoW;
- сохраняет объект локально;
- выполняет local validation;
- публикует `ObjectAnnouncement` после successful validation, random delay и batching.

### vote status

Показывает:

- readiness to vote;
- local anonymous token status;
- existing local ballot status;
- validation status;
- conflict status.

## Tally Commands

```text
librevote tally status --election <election_id> [--json]
librevote tally compute --election <election_id> [--json]
```

### tally status

Показывает local tally state:

```text
not_started
syncing
waiting_for_shares
computed
published
verified
stale
```

### tally compute

Запускает локальный пересчет tally.

Команда:

- выполняет sync по election;
- пересчитывает valid ballot set;
- считает encrypted tally;
- проверяет decryption shares;
- расшифровывает result при наличии `2` valid shares от distinct trustees;
- проверяет опубликованные `TallyResult` objects.

`TallyDecryptionShare` публикуется автоматически final trustee worker-ом, а не этой командой.

## Result Commands

```text
librevote result show --election <election_id> [--json]
librevote result verify --election <election_id> [--json]
```

### result show

Показывает последний локально verified или computed result.

### result verify

Выполняет локальный пересчет и проверяет опубликованный `TallyResult`.

Возвращает:

- result status;
- `result_hash`;
- ballot counts;
- option results;
- stale flag.

## Object Commands

```text
librevote object list --scope <scope> [--scope-id <scope_id>] [--json]
librevote object show <object_id> [--json]
librevote object status <object_id> [--json]
librevote object validate <object_id>
```

### object list

Показывает retained objects по `scope` и `scope_id`. Для `scope = network` `scope_id` не передается.

### object show

Показывает public object metadata и payload.

Команда не выводит local secrets и не расшифровывает `BlindTokenIssue.encrypted_payload`.

### object status

Показывает validation status, dependencies и conflict status.

### object validate

Ставит объект в очередь revalidation.

## Direct SQLite Access Rules

CLI открывает SQLite напрямую только для:

```text
librevote init
librevote key create ... when node is stopped
read-only recovery/debug inspection when node is stopped
```

Все сетевые и доменные действия выполняются через running node process.

Если node process запущен, mutating CLI-команды используют Unix socket и не открывают SQLite напрямую.

Offline SQLite access требует process lock:

```text
<data_dir>/librevote.lock
```

Если lock удерживается running node, offline mutating команда завершается с ошибкой. Stale lock удаляется только если PID не существует и Unix socket не принадлежит running node.

## Error Output

Human-readable error:

```text
error: node unavailable
hint: run `librevote node start`
```

JSON error:

```json
{
  "error": {
    "code": "node_unavailable",
    "message": "node control socket is not available"
  }
}
```

CLI не выводит подробные cryptographic secret values в ошибках.
