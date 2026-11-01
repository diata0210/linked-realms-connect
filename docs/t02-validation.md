# T01m / T02 validation and acceptance map

Updated 2026-11-01 during Codex takeover. The T02 implementation and the review
fixes below pass local Windows checks. Publication and consumer release pins
remain separate, unfinished gates. No live Hub deployment is claimed.

## Frozen artifacts and migration

The original spec/vector bytes remain unchanged:

| File | SHA-256 |
| --- | --- |
| protocol/v1.md | ea6378e35e552ec39a5a7baba91be11263c658c57893b1d3c6d6cc974125ee6a |
| protocol/vectors/v1.json | 495eddc75c2e30a26b7f1812a8acdfbfaeb7fb4e32f08cb2585f272f1b0f1450 |

The separately generated NK transcript retains its additive manifest pin. The
original manifest hash before that additive entry was
`13a6a972873b13932f7fdc70ff31d3fe6b709b4973cceb5352d25d9b940a7f88`.
`docs/migration-baseline.json` is the source-file inventory at migration time,
not a claim that later T02 implementations match those original tool hashes.
The source PLAN hash in that inventory is a source-checkout hash. Git normalizes
the public PLAN to LF without changing its text; its staged blob hash is
`fd350c84b2f4ed1758f2d66e1471eeef29e9ab280beff27412e2df3e81cdec18`. Do not equate these two byte representations.

## Verified locally

Environment: Go 1.24.2 windows/amd64, Node 24.16.0 for the Connect TS package,
and the pinned installed dependencies. Go caches are development-machine paths,
not release/build dependencies.

| Check | Result |
| --- | --- |
| Root `go vet ./...` and `go test -race ./...` in the development workspace | PASS, including identity, Noise and the full spec mutation suite |
| `go run ./tools/checkspec` | PASS, both original hashes and the additive transcript pin |
| Root `go mod verify` | PASS |
| Nested module `GOWORK=off go vet ./...`, `go test -race ./...`, `go mod verify` | PASS with its own generated go.sum |
| Nested `GOWORK=off go run ../tools/checkdeps/main.go` | PASS, protocol has no Noise/agent dependency |
| TS pinned Prettier, lint/typecheck, Vitest and build | PASS, 12 unit tests |
| Native Edge browser public-object conformance | PASS, 130 independent Go-oracle cases; matching accept/error/round-trip/hash |
| Removed Noise record guards in an isolated scratch copy | Both send and receive regression assertions fail as intended |
| Game G1 takeover verification | Node 26.13.0 typecheck, 114 tests, SDK/default and reciprocal-two-Land smoke PASS; separate Game evidence |

The 130 browser cases include valid and malformed signatures, Buffer-independent
public objects, origin spelling, port bounds, CRC/zlib/scan/pixel failures,
image dimensions/size bounds, signed PNG/JPEG/WebP trailing image bytes and a
truncated JPEG EOI. They do not prove complete equivalence for every possible
image accepted by different native decoder implementations.

## Review fixes

- Reader copies preserve Buffer/view offsets and the same ownership as ordinary
  Uint8Array inputs; explicit Buffer/nonzero-offset unit regressions pass.
- Signed origin spelling uses the frozen DNS/IP grammar instead of WHATWG's
  legacy numeric-host interpretation. Port zero and noncanonical ports fail.
- Profile decode/encode now return promises and await native image decoding.
  PNG CRC/container validation and JPEG scan/EOI checks precede pixel decoding.
  No native decoder means image profiles fail closed; preset profiles still work.
  Every in-repo caller was updated; no package has been published.
- Card reversed/excessive time errors match Go.
- Framed hop controls accept explicit authenticated author context; both Hub and
  peer ROUTE_CLOSE round-trip, and the wrong author variant is rejected.
- Noise budget tests use valid matching sequence/tag/header values at the actual
  limit, assert Busy, and verify failed sessions are closed in both directions.
- CI prepares/vets/tests the nested module with GOWORK=off. The TS job builds
  the package and runs native browser conformance on Ubuntu 24.04 Chrome.

The earlier two review reports remain historical evidence in the operator's
scratch area. Their reproduced findings were repaired and exercised with new
regressions. This is an implementation review, not an external cryptographic audit.

## Reproduce

```powershell
go vet ./...
go test -race ./...
go run ./tools/checkspec
go mod verify
# From protocol-go, with GOWORK=off:
go vet ./...
go test -race ./...
go run ../tools/checkdeps/main.go
go mod verify
# From packages/connect-protocol:
npm.cmd run format
npm.cmd run lint
npm.cmd run typecheck
npm.cmd test
npm.cmd run build
$env:CONNECT_TEST_BROWSER='C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'
npm.cmd run test:browser
```

The browser runner uses a fresh temporary profile and loopback test server, and
never reads a user's browser profile. On Linux set CONNECT_TEST_BROWSER to the
installed Chrome/Chromium command. Local checks here used Windows/Edge; the
modified GitHub workflow and Linux native-browser job have not run remotely.

## Remaining release gates

- Source-upload instruction received on 2026-11-01: existing namespace `diata0210/linked-realms-connect`, MIT, copyright diata0210. Binary/package publication is a separate gate.
- A real secrets/history/artifact scan and first publication, with the deliberately
  closed publication gate retained until real reviewed evidence exists.
- A real immutable protocol-go module version/hash for Hub and the public TS
  package integrity/manifest pin for Game. No fake release version is substituted.
- The root agent's development go.work resolution must become a real module pin
  before standalone release. Root sums now include the pinned dependency graph;
  passing nested standalone checks does not make the unpublished root releasable.
- Real private-Hub dependency checks and cross-repo runtime integration remain
  later tasks; no private implementation was copied into public source.
- Exact third-party audit coverage remains unknown as documented in
  crypto-dependencies.md. No application audit or production safety is claimed.
