# `:transport` — BLE link layer

Implements the `Transport` contract from [`docs/interfaces.md`](../docs/interfaces.md):

```kotlin
val transport = BleTransport(context, onError = { Log.w("mesh", "ble", it) })
transport.start()
val handle = transport.onReceive { frame ->
    // frame.from.id is the direct neighbour, frame.bytes is one complete frame
}
transport.send(peer, meshPacket)   // suspends while connecting
transport.peers().collect { neighbours -> /* List<Peer> */ }
handle.close()
transport.close()
```

`BlePermissions.requiredPermissions()` lists the runtime permissions; the app shell owns the
request flow.

## BLE roles

Every phone runs both roles:

- **Peripheral:** advertises `BleUuids.SERVICE`, exposes RX (write-without-response) and TX
  (notify), and sends acks back as notifications. Frames arrive through
  `onCharacteristicWriteRequest`.
- **Central:** scans for the service, connects on demand, requests MTU 247, enables TX
  notifications, then writes frames to RX with write-without-response.

One connection is kept per neighbour. A dropped connection is recreated on the next
retransmission or send. Acks are routed over the central connection when it exists, otherwise
over the peripheral notification channel.

## Framing

Transport frames are at most **240 bytes**, which fits the 244-byte ATT payload of MTU 247 with
the 3-byte write header to spare. All integers are big-endian.

Chunk (15-byte header):

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | version `0x01` |
| 1 | 4 | transfer id (random per transfer) |
| 5 | 2 | sequence number, 0-based |
| 7 | 2 | total chunks |
| 9 | 2 | data length |
| 11 | 4 | CRC32 of the complete payload |
| 15 | 0..225 | data |

Ack (9-byte header + bitmap):

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | type `0xA1` |
| 1 | 4 | transfer id |
| 5 | 2 | total chunks |
| 7 | 2 | bitmap length |
| 9 | 0..225 | bitmap, bit `i` = chunk `i` received (LSB first) |

The bitmap is a full state, not a delta, so a lost ack is harmless. An ack is sent for every
received chunk; with 10% loss that is still cheap (a 15 KB clip is 69 chunks and 19-byte acks).
If reassembly CRC fails, the receiver clears the transfer and returns an all-zero ack, forcing a
full retransmit.

Limits: 128 KB payload, 1800 chunks, 240-byte frames. An MTU below 247 reduces the frame size
(`min(240, mtu - 3)`); a transfer whose ack bitmap cannot fit in that frame size is rejected with
`TransportException`.

## Reliability

- Sender keeps chunks until the receiver's bitmap marks them received.
- Missing chunks are retransmitted after `ackTimeoutMs` (default 800 ms), with jittered gaps
  from the BLE layer and a cap of `maxRetransmissions` (12).
- Receiver drops partial transfers after 30 s and remembers completed transfers for 2 min so
  duplicate packets are acked without a second delivery.
- Concurrent inbound transfers are capped at 16 (oldest evicted) and payload sizes are bounded
  before allocation, so malformed peers cannot exhaust memory.

## Tests

The JVM suite exercises the real fragmentation, ack, retransmit and reassembly code:

- `FragmenterTest` / `AckCodecTest` / `ReassemblerTest` — framing, bitmap, CRC, timeout, dupes.
- `TransferEngineTest` — selective retransmit, malformed frames, limits.
- `LossyLinkSimulationTest` — 15 KB through 10% loss in both directions (Agent C Phase 1
  acceptance without phones).
- `FakeTransportTest` — the Phase 0 in-memory transport.

CI runs these on GitHub Actions; nothing is built locally.

## Known limits / Phase 2 work

- Two-phone BLE transfer needs physical devices; the lossy JVM simulation is not a radio test.
- The scanner keeps discovered peers even if the device disappears; mesh dedup/store-and-forward
  handles stale neighbours, and reconnect happens lazily.
- Throughput is paced at 8 ms per frame (configurable). Tune from field-test metrics.
- Acks are per chunk rather than coalesced. Coalescing is an airtime optimisation, not a
  correctness requirement.
- The mesh layer must pass frames of at most 128 KB; larger voice notes need mesh-level
  chunking above this transport (the packet format already splits at 512-byte packets).
