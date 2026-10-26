# Security (Agent H)

Phase 5 security work for Mesh Voice Notes. Everything here follows the
authoritative contracts in [`docs/packet-format.md`](../docs/packet-format.md)
and [`docs/interfaces.md`](../docs/interfaces.md).

| Document | Contents |
|---|---|
| [`threat-model.md`](threat-model.md) | Assets, adversaries, STRIDE table, trust boundaries, privacy/resource limits, open questions |
| [`findings.md`](findings.md) | Tracked findings with severity, status, owner, repro and verification |
| [`attack-tests/`](attack-tests/) | Runnable BLE/simulator attack harness + self-check |

## Current status

- Threat model: v0.2, updated for the landed v1 packet format.
- Findings: 17 entries. Spoofing, replay, flood/reassembly bounds, TTL handling
  and relay tampering are verified in CI against the real `:mesh` + `:crypto`
  on `FakeNetwork`; BLE/Keystore/UI findings still need device or app tests.
- Harness: `security-harness` and `security-fuzz` jobs run on every push;
  self-check and dry-run paths also work locally.
- **Resolved:** SEC-016 — docs v1, `:crypto` and the committed contract vector
  now agree (run `40301889226`). Remaining open code findings: SEC-001
  (`MeshNode` dedup), SEC-004 (`MeshNode` ingress rate limit), SEC-017
  (`MeshNode` accepts `counter = 0`). See findings.md.

## Quick start

```bash
cd attack-tests
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python selfcheck.py
python fuzz_packets.py --self-check
python make_config.py --out config.json
```

See [`attack-tests/README.md`](attack-tests/README.md) for the test matrix,
safety rules and hardware prerequisites. Real-hardware runs need a CI APK, two
owned phones, and the app's debug channel-key export.

## Severity rubric

- **Critical** — breaks confidentiality/integrity for all users, or RCE.
- **High** — practical attack on one user/channel, silent suppression/
  tampering, or trivial DoS.
- **Medium** — needs a key/member, notable effort, or limited metadata/privacy
  impact.
- **Low** — hardening or process gap.
- **Info** — accepted limitation.

High/Critical findings block Phase 5 acceptance until fixed or explicitly
accepted by Agent A. Do not paste channel keys, identity seeds or captured
plaintext into findings or commits.

## Recording results

1. Run the relevant harness command against a test APK (never someone else's
   device).
2. Update the finding status: `Open — reproduced`, `Fixed — verified`,
   `Not reproducible`, or `Accepted`.
3. Attach the seed/capture path and exact command; redact secrets.
4. Add new findings with the next `SEC-0NN` ID.
