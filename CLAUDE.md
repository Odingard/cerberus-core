# CLAUDE.md — Cerberus Core

Agent context for `@cerberus-ai/core` — the public, MIT-licensed open core of
Cerberus. Runtime security for AI-agent tool execution: it inspects what an
agent's tools *do* (private data read, untrusted content ingested, outbound
calls) and blocks a prompt-injection exfiltration **before the outbound tool
runs**, at the tool-call level.

This repo is **npm-only** (TypeScript, ESM). There is no Python here — the
`cerberus-ai` PyPI package lives in the enterprise repo (`Odingard/cerberus`).

## Requirements

- Node `>=20` (CI runs on 20). No native deps — the only runtime dependency is `zod`.

## Commands

| Task | Command |
|---|---|
| Install | `npm ci` |
| Build | `npm run build` (`tsc -p tsconfig.build.json` → `dist/`) |
| Typecheck | `npm run typecheck` (`tsc --noEmit`) |
| Lint | `npm run lint` (eslint over `src/ tests/ spec/ examples/ harness/`) |
| Lint fix | `npm run lint:fix` |
| Format | `npm run format` / `npm run format:check` (Prettier) |
| Test | `npm test` (`vitest run`) |
| Coverage | `npm run test:coverage` |
| Full gate | `npm run ci` (typecheck → lint → test) |
| Benchmark | `npm run bench` |
| DSA-PEAS validate | `npm run dsa-peas:validate` |

**Before committing:** run `npm run ci`. It must be green (typecheck + lint with
zero warnings + all tests).

## Directory structure

```
src/
  index.ts                  # public entry (dist/index.js)
  internal.ts               # internal-only exports
  engine/                   # core inspection engine + decision path
  layers/                   # L1 (privileged data) · L2 (untrusted content) · L3 (outbound)
  graph/                    # provenance / authorship / delegation graph
  crypto/                   # signing + verification adapters
  classifiers/              # content / intent classifiers
  middleware/               # guard()/wrap() + trace capture
  adapters/                 # framework adapters (LangChain, etc.)
  enforcement/              # decision → enforcement mapping
  intelligence-validation/  # schema + verdict validation
  types/                    # shared type contracts
tests/                      # vitest suites (mirror src/)
spec/                       # DSA-PEAS open-spec + conformance CLI
examples/                   # runnable snippets
harness/                    # benchmark harness
```

## Code style

- TypeScript strict, ESM, `.js` extensions on relative imports (NodeNext).
- Imports at top of file; no nested/inline imports.
- **No `any`** in `src/` (enforced by review — `grep` returns 0). Prefer precise
  types and `zod` schemas at boundaries.
- Explicit function return types (eslint-enforced).
- Comments are terse and describe intent, not the diff. Default is no comment.
- Prettier is the formatter of record; do not hand-format.

## Invariants (do not break)

- **Open-core isolation:** `src/` must never import `@cerberus-ai/enterprise`.
  Enterprise capabilities (durable ledger, blast-radius B(p), AL3 signing,
  enforcement proxy) are referenced only in doc comments. Enforced by
  `tests/packaging/open-core-isolation.test.ts`.
- This repo is the **sole publisher** of `@cerberus-ai/core` (SLSA provenance
  requires a public source repo). The private monorepo never publishes this name.
