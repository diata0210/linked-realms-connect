# Spec / Task
Continue the owner-approved Hub Connect implementation from the existing Claude session. First close the reproducible T02 review findings before advancing dependent Hub/agent tasks. Keep private Hub code separate from public agent/protocol source, preserve the frozen wire artifacts, and do not publish.

## Context reviewed
- Hub docs/PLAN.md sections 3-4, 14, 17 and the public/private split decisions.
- Connect docs/t02-validation.md, protocol/v1.md and manifest.json.
- Existing T02 review A/B reports, source codecs, Noise transport budgets, tests and CI.
- G1 report: implementation exists in D:/tmp/lr-g1; separate verification remains pending.

## Decisions
1. Fix confirmed decoder/CI defects against the frozen specification; do not regenerate or repin the original spec/vector files. Changing the spec to accept implementation mistakes was rejected.
2. Respect Uint8Array byte offsets and copy reader slices so Node Buffer consumers get the same bytes and ownership as ordinary Uint8Array consumers.
3. Validate signed origin spelling using the normative DNS/IP grammar. URL parsing may validate canonical IPv6 literals, but must not reinterpret DNS labels as legacy numeric IPv4.
4. Expose authenticated author options for framed hop controls, preserving existing calls by an optional argument. Do not guess a sender role by trying alternate decoders.
5. Complete standalone nested-module checksums using Go commands. Keep unpublished root module resolution explicitly development-only; never invent release versions or hashes.
6. Make image-profile verification part of asynchronous TS profile decode/encode using native image decoding. Preserve strict structural bounds and PNG CRC verification; no custom image decompressor or new crypto/image dependency. Update every local caller and add native-browser coverage before claiming image acceptance.
7. Strengthen Noise budget tests with valid matching ciphertext, explicit Busy assertions and both directions; do not change the existing limits.
8. Apply existing pinned formatting tools to the TS package and update stale verification status with actual results only.

## Trade-offs
- Async profile codecs change the unreleased TS API but ensure callers cannot mistake header parsing for complete image validation. Native browser support is required for image avatars; missing decoders fail closed.
- A public release pin still requires the owner-gated namespace/license/publication work. Local workspace testing is not release readiness.
- Native image decode implementations may differ; independent malformed-image probes and browser runs must identify any residual discrepancy rather than silently relaxing the wire contract.

## Files to create / modify
- plan-DECISIONS.md: takeover decisions and verification order.
- packages/connect-protocol/src/index.ts: Buffer-safe reader, normative origins, async image profile validation and card time parity.
- packages/connect-protocol/src/codes.ts: pinned formatting only.
- packages/connect-protocol/test/*: offset, origin, async codec and image regressions.
- protocol-go/frame.go and regression tests: authenticated hop-control author option.
- protocol-go/go.sum: generated standalone dependency checksums.
- internal/noisesession/session_test.go: real boundary tests for both transport directions.
- .github/workflows/ci.yml: prepare and check the nested module with GOWORK=off.
- README.md and docs/t02-validation.md: correct outdated verification and remaining release gates.

## Build sequence
1. Reproduce existing failures and preserve the frozen hashes.
2. Fix reader, origin, card expiry and framed control handling; run focused regressions.
3. Integrate async profile validation and native-browser malformed image checks; update all callers.
4. Generate standalone sums via Go, run pinned TS formatting and all relevant CI commands.
5. Review correctness and attack paths twice, fixing findings between rounds. Verify G1 separately before any local integration.
6. Advance subsequent implementation only after prerequisites and actual release pins allow it; keep owner/public infrastructure gates explicit.

## Open questions
- Public namespace/MIT attribution and first publication remain owner-gated; do not fabricate pins.
- Real hosts, public service operational review and seven-day observation require external participation.
- Browser/Go image-decoder parity must be verified before closing the image finding.

## Verification recorded 2026-11-01
- Full Go vet/race/spec and module verification pass; nested GOWORK=off boundary passes.
- TS format/lint/typecheck, 12 unit tests, build and 130 native-browser cases pass.
- Two image-container parity regressions found in the second review were fixed.
- A scratch mutant without both Noise record guards fails both new boundary assertions.
- G1 was independently exercised on Node 26.13.0 and in a real local browser; Enter/Leave/re-entry and rendering pass.
- Public namespace/license decision requested from owner; no remote/publication action taken.
