# Cryptographic dependency evidence

Status: dependencies resolved and verified locally on 2026-11-01 (`go mod verify`,
`npm install --ignore-scripts`, all Go and Vitest suites pass). **Still NOT
release-ready**: owner/publication gates and actual consumer release pins remain.
Exact external audit coverage is unknown; this document does not invent an audit
requirement or claim an application audit. The toolchain-verified module hashes
and cached Go proxy origin commit metadata are recorded below.

| Component | Exact requested version | Commit / content evidence | Review/audit status |
| --- | --- | --- | --- |
| Go stdlib Ed25519, SHA-256, HMAC-SHA512, X25519 low-order check | Go 1.24.2 | Installed toolchain reports go1.24.2 windows/amd64; distribution hash not independently verified | Exact toolchain audit status unknown |
| github.com/flynn/noise (agent/test peers only) | v1.1.0 | module h1:KjPQoQCEFdZDiP03phOvGi11+SVVhBG2wOWAorLsstg=; origin commit 4d9f71cd4ba1fe81415efac312664ccc4bc79b46 | Independent audit of this exact release unknown |
| filippo.io/edwards25519 (strict subgroup checks) | v1.1.0 | module h1:FNf4tywRC1HmFuKW5xopWpigGjJKiJSV0Cqo0cJWDaA=; origin commit 325f520de716c1d2d2b4e8dc2f82c7ccc5fac764 | Exact-release independent audit unknown; upstream documents its Go stdlib lineage |
| golang.org/x/image (WebP decoding) | v0.25.0 | module h1:Y6uW6rH1y5y/LK1J8BPWZtr6yZ7hrsy6hFrXjgsc2fQ=; origin commit e7e23ba50196f0b209e707121bd3fdfab8e7eea5 | Exact-release audit unknown |
| github.com/btcsuite/btcd/btcec/v2 (agent wallet-A derivation only) | v2.3.4 | Commit ff2e03e11233fa25c01cf4acbf76501fc008b31f; module h1:3EJjcN70HCu/mwqlUsGK8GcNVyLVxFDlWurTXGPFfiQ= | Exact-release independent audit unknown |
| github.com/decred/dcrd/dcrec/secp256k1/v4 (btcec dependency) | v4.0.1 | Module h1:YLtO71vCjJRCBcrPMtQ9nqBsqpA1m5sE92cU+pd5Mcc=; commit unknown | Exact-release independent audit unknown |
| @noble/curves (TS public-key verification only) | 1.9.7 | npm integrity sha512-gbKGcRUYIjA3/zCCNaWDciTMFI0dCkvou3TL8Zmy5Nc7sJ47a0jtOeZoTaMxkuqRo9cRhjOdZJXegxYE5FN/xw== (package-lock.json) | Upstream describes independent audits; coverage of this exact installed artifact is NOT verified |
| @noble/hashes (TS public-object SHA-256) | 1.8.0 | npm integrity sha512-jCs9ldd7NwzpgXDIf6P3+NrHh9/sD6CQdxHyjQI+h/6rDNo88ypBxxz45UDuZHz9r3tNz7N/VInSVoVdtXEI4A== (package-lock.json) | Exact-release audit unknown |

The cached btcec/secp256k1 content hashes above came from `go mod download -json`
using the specified scratch cache. Generator-only dependencies retain their exact
versions and checksums in `tools/vectorgen/go.mod` and `go.sum`; that module's
historical name is retained to preserve the seeded file bytes. It is not a
dependency on private source. Both generator reruns matched the frozen vectors.

Transitive Go modules (including `golang.org/x/crypto` and `golang.org/x/sys`) are
resolved by `go.work.sum`/`go.sum`; `go mod verify` passes. A release must re-run
`go mod tidy` against the published module path and commit the final sums.

## Verification choices and boundaries

Go signs/verifies the Ed25519 equation with stdlib. The pinned Edwards library
additionally rejects noncanonical encodings, identity and mixed-order public/R
points; scalars must be canonical. TS uses noble with `zip215:false`, canonical
re-encoding, `isSmallOrder` and `isTorsionFree` checks. Neither merely assumes that
ZIP215 disabled proves all subgroup requirements.

Only `Noise_NK_25519_ChaChaPoly_SHA256` is configured. The project prologue binds
Player, Land, sid and signed-card hash. Handshake payloads are empty. Each transport
authenticates the exact 31-byte received header; failure destroys session access.
Counters and byte budgets are serialized. Go secret erasure is best effort, not a
guarantee. The Hub imports only `protocol-go`, and `tools/checkdeps` rejects Noise
and agent packages in its resolved graph. TS has no Noise or private-key API.

`protocol/vectors/nk-transcript.json` contains the upstream standard known answers
plus the project transcript generated with the pinned library
(`GENERATE_NK_FIXTURE=1 go test ./internal/noisesession -run TestGenerateProjectFixture`);
generation is deterministic and its hash is pinned in `protocol/manifest.json`.

## Primary sources consulted

- [flynn/noise v1.1.0 source](https://github.com/flynn/noise/tree/v1.1.0)
  and [standard vectors](https://raw.githubusercontent.com/flynn/noise/v1.1.0/vectors.txt).
- [noble-curves 1.9.7 verification/security documentation](https://github.com/paulmillr/noble-curves/blob/1.9.7/README.md).
- [edwards25519 v1.1.0 lineage and API](https://github.com/FiloSottile/edwards25519/tree/v1.1.0).

Reading upstream documentation is not an audit of this application. Unknown
audit status stays unknown. Updates require review of exact artifacts and reruns
of standard/project transcripts, canonical negatives, subgroup and object parity.
