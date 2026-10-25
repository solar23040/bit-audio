# `:sim` — mesh simulator

N-node TTL-flood simulator built on `:transport`'s `FakeNetwork`. It is
independent of the `:mesh` implementation so Agent D can compare tuning choices
against a stable reference. No Android APIs are used.

## What it models

- Topologies: `LINE`, `GRID`, and connected `RANDOM` (Erdős–Rényi plus a
  deterministic spanning chain).
- Per-link loss, latency range, and per-relay jitter.
- Malicious nodes: `DROP` (receive but never relay) or `DUPLICATE` (relay each
  packet `duplicateFactor` times).
- TTL flooding with a per-node seen cache and origin echo suppression.
- Configurable message count, payload size, publish stagger, seed, and an
  overall simulation deadline.

## Metrics

| Field | Definition |
|---|---|
| `delivery_rate` | unique message/node deliveries / reachable message/node pairs |
| `avg_hops` | mean edges traversed by delivered copies |
| `avg_latency_ms`, `p95_latency_ms` | publish-to-delivery delay |
| `duplicate_ratio` | duplicate receptions / all receptions |
| `transmissions` | frames handed to the transport, including dropped ones |
| `airtime_bytes` | bytes offered to the radio over all hops |
| `airtime_ms` | `airtime_bytes / linkBytesPerSecond * 1000` |

`duplicate_ratio` is high in a line because every edge is flooded in both
directions; that is expected for pure flooding and is what the tuning metrics
should expose.

## Run it

The simulator runs in the normal unit-test job:

```bash
./gradlew :sim:test
```

`LargeMeshSimulationTest` runs the 50-100 node scenarios from
`SimulationScenarios.phase1()` under a 240 s JUnit timeout (virtual time, so it
is much faster in practice) and writes:

- `sim/build/reports/sim/mesh-sim-summary.csv`
- `sim/build/reports/sim/mesh-sim-messages.csv`

Unit tests assert the metric formulas directly in `MetricsCalculatorTest`, and
`MeshSimulatorTest` checks reliable delivery, loss, malicious drop/duplicate
behaviour, and the CSV layout.

## Using it from code

```kotlin
val config = SimConfig(
    name = "grid-60",
    nodes = 60,
    topology = Topology.GRID,
    lossRate = 0.10,
    maliciousNodeCount = 3,
    maliciousBehavior = MaliciousBehavior.DUPLICATE,
)
val network = FakeNetwork(seed = config.seed, externalScope = scope)
val result = MeshSimulator(config, network).run(scope)
val report = SimulationReport(listOf(result))
report.writeTo(File("build/reports/sim"))
```

For virtual-time tests pass `externalScope = backgroundScope` to `FakeNetwork`,
run inside `runTest`, and supply `clock = { testScheduler.currentTime }` so
latency and the simulation deadline use the test clock.
