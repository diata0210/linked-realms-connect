# Linked Realms Connect

Public wire contracts, Go protocol module, TypeScript object codecs and agent-only
Noise sessions. The directory/relay service is a separate private implementation;
building these packages requires no private source or service.

The local T02 implementation checks pass: Go race/spec suites, standalone
protocol-module boundary, TS unit checks and native-browser public-object parity.
Binary/package release remains gated on a real secrets/history/artifact scan
and actual immutable release pins. See `docs/t02-validation.md`.

The repository/module namespace is
`github.com/diata0210/linked-realms-connect`. The owner requested uploading the current work on 2026-11-01. This source snapshot
uses the existing MIT license with attribution to diata0210. Publishing source does
not claim the Hub/agent integration or binary/package release is complete.

`protocol-go/` is an independently importable module. It must never depend on
agent code or Noise. `internal/noisesession/` belongs only to the agent. TypeScript
contains public-object verification, never private keys or a Noise implementation.

Run `go run ./tools/checkspec` at the root. See
[validation](docs/t02-validation.md) for module commands, acceptance mapping and
unverified release gates. The development workspace resolves the unpublished
protocol module locally; releases must replace that workspace resolution with an
actual immutable `protocol-go/v...` tag and Go checksum, never a fabricated pin.

All seeds in protocol fixtures are deliberately public synthetic test inputs.
Do not use them for real identities. No deployment secrets belong in this tree.

## TypeScript profile images

`decodeProfile` and `encodeProfile` are asynchronous: callers must await them.
Image avatars require a native `createImageBitmap` decoder and fail closed when
it is unavailable. The public TS package never derives keys or implements Noise.
Run `npm run build` before consuming `dist`; native-browser conformance uses
`CONNECT_TEST_BROWSER=<installed Chrome/Chromium/Edge> npm run test:browser`.
