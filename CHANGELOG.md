# Changelog

All notable changes to `@cerberus-ai/core` are documented here. This project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Performance reproduction harness** (`npm run bench`). The overhead benchmark
  now ships in the repository so anyone can reproduce the perf numbers against
  the published package: baseline vs. guarded executor latency across the L1→L2→L3
  tool sequence, with regression thresholds that fail the run if overhead exceeds
  budget.

### Changed / Documentation

- Reworked the Performance section and the detection tables to be reproducible
  and free of unscoped claims. Blocking false positives are reported as **counts
  on a named sample** (e.g. `0 / 30` control runs), never as a bare
  "False Positive Rate: 0%".
- Added an explicit reproducibility note:

  > Perf/overhead is reproducible against the shipped package via `npm run bench`.
  > The ≥99.982% specificity (99% CI, 0 blocking FP) headline is a measured
  > property of the enterprise Verdict-Weight governor, reproducible under the
  > research harness and verifiable under diligence — not part of the open package.

## [3.1.0]

### Added

- Signed delegation authority: time- and purpose-bound authority grants with
  per-edge Ed25519 signing (`enforceGrant`, `canonicalGrant`, `hasGrant`,
  `addSignedAgent`).
- Manifest gate: `verifyManifestBeforeTurn`, `enforceManifestGrantsBeforeTurn`.
- CCP read contracts (typed, types-only on the open surface).
- Zero-config onboarding: `autoGuard()` — auto-wrap + auto-classify +
  observe-only default.

### Notes

- Open detection engine + contracts only. The licensed engine (durable ledger,
  blast-radius, AL3 authorship, OpenTelemetry recorder, enforcement gateways,
  HTTP proxy, Verdict-Weight governor, license/metering) is **not** in this
  package — it ships in the Enterprise tier.
