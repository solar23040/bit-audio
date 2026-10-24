# Mesh Voice Notes: Build Plan (multi-agent)

Push-to-talk voice clips over a BLE mesh on Android. Opus-compressed, signed, encrypted, multi-hop, store-and-forward. No servers, no accounts.

**MVP goal:** 3 phones in a line (A-B-C), a 10s clip sent from the first to the last through the middle one, signed + encrypted.

---

## Agents

| Agent | Role | Owns |
|---|---|---|
| **Agent A** | Lead / orchestration | Interfaces, merging, acceptance checks, `/docs` |
| **Agent B** | Audio | `:audio` module |
| **Agent C** | Transport (BLE) | `:transport` module |
| **Agent D** | Mesh routing | `:mesh` module |
| **Agent E** | Crypto | `:crypto` module |
| **Agent F** | UI / app shell | `:app` module |
| **Agent G** | QA / simulator | `:sim`, `/test` |
| **Agent H** | Security | `/security` |

**Rules**
- Each agent works only in its own module. Cross-module changes go through Agent A.
- Modules talk via interfaces defined in Phase 0. No agent codes against another's internals.
- Each phase ends with an acceptance check before the next starts.
- Each agent commits on its own branch (`agent-<letter>/<phase>`); Agent A merges.

**Build rule: DO NOT compile or build locally.**
- No agent runs `./gradlew`, `assembleDebug`, `test`, NDK builds, or any local compile/test command on the user's hardware.
- All compiling, testing, and APK builds happen in cloud CI (GitHub Actions). Agents write code, push, and read CI results.
- Agent A sets up `.github/workflows/build.yml` in Phase 0 (checkout, JDK 17, Gradle, `./gradlew test assembleDebug`, upload APK as artifact).
- To check if code works: push to the branch, wait for the CI run, read the logs. Fix and push again.
- The user downloads the APK from the CI run's artifacts and sideloads it onto phones.
- Real BLE/multi-hop testing needs physical phones; everything else (unit tests, `:sim`) runs in CI.

---

## Phase 0: Foundations (Agent A, runs alone)

Blocks everything else.

**Agent A**
- [ ] Create Android multi-module project: `:app :audio :transport :mesh :crypto :sim`
- [ ] Write `/docs/interfaces.md` with Kotlin interfaces:
  - `AudioCodec { encode(pcm): ByteArray; decode(bytes): ShortArray }`
  - `Transport { send(peer, bytes); onReceive(cb); peers(): Flow<Peer> }`
  - `Mesh { publish(channel, payload); onMessage(cb) }`
  - `Crypto { sign; verify; seal; open }`
- [ ] Write `/docs/packet-format.md` (header: `version, type, msg_id(8B), sender_id(8B), ttl, chunk_idx, total_chunks, ts, sig`)
- [ ] Set up cloud CI on GitHub Actions (lint + unit tests + `assembleDebug` + APK artifact upload on every push). This is the only place anything gets compiled.
- [ ] Build `FakeTransport` (in-memory, configurable loss/latency) so other agents can work without hardware

**Acceptance:** project builds, interfaces compile, fakes exist.

---

## Phase 1: Isolated module builds (Agents B, C, D, E, G in parallel)

All code against interfaces/fakes. No inter-dependencies.

### Agent B: Audio
- [ ] Hold-to-record via `AudioRecord` (16 kHz mono PCM16)
- [ ] Opus encode (12 kbps, 20 ms frames) via libopus JNI wrapper
- [ ] Decode + `AudioTrack` playback
- [ ] Hard cap 15s per clip

**Done when:** 10s clip round-trips, is intelligible, and encodes to under ~20 KB. Unit test round-trips a sample WAV.

### Agent C: Transport
- [ ] BLE advertise + scan with a custom service UUID
- [ ] GATT server + client, request MTU 247, write-without-response
- [ ] Fragmenter: split payload into ~240B chunks with sequence numbers
- [ ] Reassembler with timeout
- [ ] Selective ack / retransmit for missing chunks

**Done when:** two phones transfer a 15 KB blob intact with 10% simulated loss.

### Agent D: Mesh
- [ ] Packet encode/decode per spec
- [ ] TTL flooding (default TTL 5)
- [ ] Seen-ID dedup cache (LRU + expiry)
- [ ] Jittered rebroadcast (random 20-200 ms)
- [ ] Store-and-forward: persist undelivered clips in Room/SQLite, hand off on new peer discovery, expire after N hours

**Done when:** in-memory 5-node line delivers end-to-end on `FakeTransport`; no loops; no duplicate deliveries.

### Agent E: Crypto
- [ ] Ed25519 identity keypair per install (Android Keystore where possible)
- [ ] Packet signing/verification
- [ ] Channel key from QR/passphrase (Argon2id to 32B), XChaCha20-Poly1305 AEAD for payloads
- [ ] Anti-replay: timestamp window + per-sender monotonic counter cache
- [ ] Rotating ephemeral sender IDs

**Done when:** tampered packets rejected, replays rejected, wrong-key payloads fail to open, test vectors pass.

### Agent G: Simulator
- [ ] N-node mesh simulator: configurable topology, loss, latency, malicious nodes
- [ ] Metrics: delivery rate, hops, latency, duplicate ratio, airtime
- [ ] Output CSV / simple graph of message spread

**Done when:** runs 50-100 nodes and outputs metrics Agent D can use for tuning.

**Phase 1 acceptance (Agent A):** all module tests green on CI, interface contracts unchanged or changes documented.

---

## Phase 2: Integration (Agents A, C, D, E, B)

Mostly sequential steps.

| Step | Agents | Task |
|---|---|---|
| 2.1 | D + C | Swap `FakeTransport` for real BLE, fix MTU/timing issues |
| 2.2 | D + E | Sign on send, verify before relay/deliver, drop bad packets silently, seal payloads per channel |
| 2.3 | B + D | Full pipeline: record, Opus, seal, sign, fragment, send; reverse on receive |
| 2.4 | A | Two-phone end-to-end test and sign-off |

**Acceptance:** 10s clip phone to phone, >=95% success over 20 tries.

---

## Phase 3: App shell + UX (Agent F, parallel with Phase 2 once interfaces are stable)

**Agent F**
- [ ] Foreground service holding BLE (needed for background reliability)
- [ ] Screens: channel list, create/join channel via QR, channel view with voice-note list (waveform, sender alias, hop count, delivery state), big hold-to-talk button
- [ ] Permissions flow (BLUETOOTH_SCAN/ADVERTISE/CONNECT, mic, notifications)
- [ ] Scan duty-cycling for battery
- [ ] Settings: TTL, retention, rotate identity

**Acceptance:** someone new can install, join a channel via QR, and send/play a clip with no instructions.

---

## Phase 4: Multi-hop field test + benchmarks (Agent G, with Agent A)

Needs 3+ phones.

**Agent G**
- [ ] Line topology A-B-C with C out of A's range; clip must relay via B
- [ ] Measure per-hop latency, delivery rate, battery drain/hour, duplicate ratio
- [ ] Stress tests: 10-clip burst, congested channel, node killed mid-transfer (store-and-forward must recover)
- [ ] Compare with simulator predictions

**Agent D** (support): tune TTL, jitter, chunk size from results.

**Acceptance:** end-to-end multi-hop delivery >=90%; latency and battery numbers documented.

---

## Phase 5: Security pass (Agent H, parallel with Phase 4)

**Agent H**
- [ ] `/security/threat-model.md`: assets, adversaries (passive sniffer, active spoofer, malicious relay, flooder), STRIDE table, trust boundaries
- [ ] Attack tests (scripts using `bleak` / ESP32 / second adapter):
  - Spoofing: forged sender, expect reject
  - Replay: capture and rebroadcast later, expect reject
  - Flood/DoS: high-rate packets, expect rate limiting
  - Metadata leaks: stable device IDs, advertisement fingerprinting, MAC rotation
  - Fuzzing: chunk index overflow, huge `total_chunks`, truncated headers
  - Malicious relay: drops/modifies packets, expect detection via signature
- [ ] `/security/findings.md`: severity, repro steps, fix status

**Agents D + E** (support): fix findings; Agent H re-runs until clean.

**Acceptance:** all high/critical findings fixed or documented; fuzzing runs 1 hour without crash.

---

## Phase 6: Polish + writeup (Agent A, all agents contribute)

- [ ] **Agent A:** README with architecture diagram, packet format, build/run instructions
- [ ] **Agent G:** benchmarks table, demo video
- [ ] **Agent H:** threat model summary for the writeup
- [ ] **Agent F:** demo GIFs, signed APK
- [ ] **Agent A:** tag release

**Stretch (not MVP):** live 1-2 hop streaming, WiFi-Direct bulk path, iOS interop.

---

## Dependency graph

```
Phase 0 (A)
   |
Phase 1 (B, C, D, E, G in parallel)
   |
   +--> Phase 2 integration (A, B, C, D, E)
   +--> Phase 3 UI (F, parallel with 2)
            |
       Phase 4 field test (G, A)  ||  Phase 5 security (H)
            |
       Phase 6 polish (all)
```

## Risks

| Risk | Mitigation | Owner |
|---|---|---|
| Android kills background BLE | Foreground service, battery-exemption prompt | F |
| Fragment loss under congestion | Selective retransmit, jitter, tune in sim first | C, D, G |
| OEM BLE quirks | Test on 2+ vendors early | C |
| Interface drift | Agent A owns `/docs/interfaces.md`, CI contract tests | A |
| Live voice too laggy multi-hop | Ship clips first, live streaming is stretch | D |

## Definition of done (MVP)

- [ ] Clip delivered across 3 phones via relay
- [ ] Signed + encrypted; spoof/replay tests fail as expected
- [ ] Threat model + findings documented
- [ ] Benchmarks table in README
- [ ] Demo video
