# Транспортный слой

Этот документ описывает транспортный слой LibreVote.

Транспортный слой отвечает за запуск libp2p host, сетевые адреса, установление защищенных соединений и открытие bidirectional streams между узлами. Он не знает о голосованиях, бюллетенях, trustee selection, object log или правилах доменной валидации.

## Граница Слоя

Транспортный слой предоставляет сетевому слою следующие примитивы:

```text
local_peer_id
listen_addresses
dial(peer_addr)
open_stream(peer_id, protocol_id)
accept_stream(protocol_id)
connection_events
peer_reachability_status
```

Сетевой слой поверх этих примитивов реализует discovery, GossipSub, direct sync, peer admission, PoW, object propagation и rate limits.

## Принятые Решения

- Основной transport stack: `libp2p`.
- Основной transport protocol: `QUIC`.
- Начальная версия ориентируется на `quic-v1` multiaddrs.
- Node identity для libp2p отделена от voter key и trustee key.
- Transport peer identity не является доказательством авторства бюллетеня.
- Transport metadata не должна попадать в доменную модель голосования.

## Цели

- Поднять локальный libp2p host.
- Слушать QUIC addresses.
- Подключаться к known peer addresses.
- Предоставить защищенные соединения и streams для сетевого слоя.
- Хранить и отдавать локальный `Peer ID`.
- Изолировать детали QUIC, multiaddr и connection lifecycle от сетевой логики голосования.

## Не Цели

- Транспортный слой не выполняет discovery через DHT.
- Транспортный слой не реализует GossipSub topics.
- Транспортный слой не реализует direct sync protocols.
- Транспортный слой не проверяет PoW.
- Транспортный слой не проверяет eligibility, подписи бюллетеней или nullifiers.
- Транспортный слой не решает, какие peers полезны или вредны на уровне протокола LibreVote.

## Node Identity

Каждый узел имеет libp2p node key.

```text
node key
- используется libp2p для peer identity
- определяет Peer ID
- используется для защищенного transport handshake
```

Node key должен храниться локально и переиспользоваться между запусками узла, иначе Peer ID будет меняться.

Node key не должен автоматически использоваться как:

- voter key;
- trustee key;
- подпись доменных объектов;
- доказательство авторства анонимного бюллетеня.

Такое разделение нужно, чтобы сетевой идентификатор узла не связывался с ролью избирателя или trustee.

## QUIC Transport

Основной транспорт первой версии:

```text
libp2p + QUIC v1
```

Требования:

- Узел слушает хотя бы один QUIC listen address.
- Узел подключается к QUIC addresses других peers.
- Соединения защищаются стандартными механизмами libp2p/QUIC.
- Повторные подключения должны обрабатываться connection manager'ом.
- Закрытие соединения не должно приводить к потере доменных объектов, уже сохраненных в object log.

Пример address:

```text
/ip4/203.0.113.10/udp/4001/quic-v1/p2p/<peer_id>
```

## Multiaddr

Transport layer работает с `multiaddr` как с адресным форматом libp2p.

Минимальные требования:

- Принимать listen addresses из конфигурации.
- Сохранять observed addresses, если libp2p сообщает о них.
- Возвращать сетевому слою список локальных addresses для анонса.
- Отбрасывать addresses с несовместимым transport protocol в v1.

Сетевой слой использует addresses для bootstrap и peer store, но не разбирает transport details глубже, чем требуется для подключения.

## Streams

Transport layer предоставляет bidirectional streams для protocol IDs сетевого слоя.

Примеры protocol IDs верхнего слоя:

```text
/librevote/v1/hello
/librevote/v1/inventory
/librevote/v1/get-object
/librevote/v1/get-objects
/librevote/v1/get-election-state
```

Transport layer не интерпретирует payload этих streams. Он только открывает stream, применяет базовые timeouts и сообщает об ошибках чтения/записи.

## Connection Lifecycle

Transport layer должен отдавать сетевому слою события:

```text
peer_connected
peer_disconnected
stream_opened
stream_closed
dial_failed
listen_address_changed
reachability_changed
```

Сетевой слой использует эти события для hello handshake, sync scheduling, peer scoring и rate limiting.

Transport layer не должен самостоятельно банить peer'ов за доменные ошибки. Бан или понижение score за невалидные объекты находится в сетевом слое.

## Timeouts And Limits

Transport layer должен иметь базовые защитные лимиты:

- Dial timeout.
- Stream open timeout.
- Idle connection timeout.
- Максимальное число соединений.
- Максимальное число соединений на peer.
- Максимальное число одновременно открытых streams.

Эти лимиты защищают transport resources. Более специфичные protocol limits, например лимит `get-objects`, находятся в сетевом слое.

## NAT And Reachability

Для первой версии transport layer должен корректно работать в двух режимах:

```text
reachable node
- узел имеет публичный reachable address
- принимает входящие соединения

non-reachable node
- узел находится за NAT/firewall
- подключается наружу
- имеет ограниченное участие в DHT server mode
```

Transport layer должен отдавать reachability status сетевому слою. Сетевой слой использует этот статус для DHT mode и bootstrap поведения.

## Transport Metadata And Privacy

Transport layer неизбежно раскрывает часть метаданных соседним peers:

- IP address;
- Peer ID;
- время подключения;
- факт открытия stream;
- transport protocol и addresses.

Эти данные не должны попадать в доменный anonymous ballot и не должны использоваться как доказательство авторства бюллетеня.

## API Для Сетевого Слоя

Минимальный интерфейс, который transport layer должен предоставить сетевому слою:

```text
TransportHost {
  LocalPeerID() PeerID
  ListenAddresses() []Multiaddr
  Dial(ctx, addr) Connection
  OpenStream(ctx, peer_id, protocol_id) Stream
  SetStreamHandler(protocol_id, handler)
  Events() <-chan TransportEvent
  Close()
}
```

Архитектурная граница должна сохраняться: transport layer не знает о LibreVote objects, а network layer не управляет QUIC internals напрямую.

## Scope

Для первой реализации транспортного слоя достаточно:

```text
1. Persistent libp2p node key.
2. libp2p host over QUIC v1.
3. Configurable listen addresses.
4. Dial by multiaddr.
5. Stream handlers for network protocols.
6. Basic connection manager limits.
7. Transport event forwarding to network layer.
8. Reachability status exposed to network layer.
```
