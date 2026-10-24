# Project rules (multi-agent)

The plan is in `pllan.md`. The user's global rules also apply.

## Ownership

| Path | Owner |
|---|---|
| `/settings.gradle.kts`, `/build.gradle.kts`, `/gradle/`, `/gradle.properties` | Agent A only |
| `/.github/`, `/docs/`, root `README.md` | Agent A only |
| `:audio`, `audio/` (including its build file) | Agent B |
| `:transport`, `transport/` | Agent C |
| `:mesh`, `mesh/` | Agent D |
| `:crypto`, `crypto/` | Agent E |
| `:app`, `app/` | Agent F |
| `:sim`, `sim/` | Agent G |
| `/security/` | Agent H |

Cross-module changes go through Agent A. Do not edit another agent's module.
If a build file needs a new dependency, add the alias to
`gradle/libs.versions.toml` only if Agent A has not already added it; never
remove entries or change versions that other modules use.

## Build rule

Never run Gradle locally. Push and use GitHub Actions (`build` workflow).

## Contract

`docs/interfaces.md` is authoritative. `docs/packet-format.md` is the wire
format. If an implementation disagrees with either, stop and tell Agent A
instead of changing the contract.

## Module namespaces (current)

- `:audio` -> `com.meshvoice.audio`
- `:transport` -> `com.meshvoice.transport`
- `:crypto` -> `com.bitaudio.crypto`
- `:mesh` -> `com.solar23040.bitaudio.mesh`
- `:app` -> `com.solar23040.bitaudio`
- `:sim` -> `com.solar23040.bitaudio.sim`

Package names are frozen for Phase 0/1. A single-package migration is a Phase 2
task for Agent A, not something individual agents should do.
