# Signed EGI Manifests

> Status: Phase 1 — `Signer` / `Verifier` protocol, Ed25519 default,
> expanded signing payload. Gateway-backed key custody, FIPS build guide,
> and strict late-registration amendment flow land in subsequent phases.

Cerberus formalizes an agent's intended execution surface — declared
tools, capability flags, schema fingerprints, edges, and late-registration
ledger — as a single manifest that is cryptographically signed at
initialization and verified before every turn. Any mutation after init
breaks the signature and surfaces as a `GRAPH_INTEGRITY_FAILURE` violation.

## Threat model

The signed manifest defends against:

- **Runtime mutation of the capability surface.** An attacker (or a buggy
  integration) cannot quietly add, remove, or modify a declared tool
  without invalidating the signature.
- **Schema drift.** A tool's parameter schema is fingerprinted into the
  manifest; a silent upgrade that changes the schema fails verification.
- **Replay across tenants / sessions.** The manifest binds
  `session_id`, `agent_id`, `graph_id`, and `initialized_at`.
- **Forgery via a leaked library artifact.** Prior to this change the
  TypeScript delegation graph was signed with a constant HMAC key shipped
  inside `@cerberus-ai/core` on npm. That key has been removed; signatures
  now require a Signer (Ed25519 by default, KMS/HSM in enterprise).

It does **not** (yet) defend against a compromised signing key — that
requires KMS/HSM custody, which lands with the gateway-backed signing
service.

## API

### TypeScript (`@cerberus-ai/core`)

```ts
import {
  Ed25519Signer,
  HmacSigner,
  setDefaultSigner,
  createDelegationGraph,
  verifyGraphIntegrity,
} from '@cerberus-ai/core';

// Option 1 — install a process-wide signer (recommended: KMS adapter).
setDefaultSigner(new Ed25519Signer());

const graph = createDelegationGraph('session-1', {
  agentId: 'orchestrator',
  agentType: 'orchestrator',
  declaredTools: ['search', 'send_email'],
  riskState: { l1: false, l2: false, l3: false },
});

verifyGraphIntegrity(graph); // true

// Option 2 — inject a signer per graph.
const signer = new Ed25519Signer();
const g2 = createDelegationGraph('session-2', root, signer);

// Option 3 — verify with a public key only (enterprise gateway path).
import { Ed25519Verifier } from '@cerberus-ai/core';
const verifier = new Ed25519Verifier({ publicKey: signer.publicKey });
verifyGraphIntegrity(g2, verifier); // true
```

### Python (`cerberus-ai`)

```python
from cerberus_ai.egi import EGIEngine, Ed25519Signer, HmacSigner

# Default — process-ephemeral Ed25519 signer.
engine = EGIEngine(session_id, agent_id, declared_tools)

# Inject a signer (e.g. loaded from KMS).
engine = EGIEngine(session_id, agent_id, declared_tools, signer=Ed25519Signer())

# Legacy HMAC path (bytes key) — still supported for one release.
engine = EGIEngine(session_id, agent_id, declared_tools, signing_key=b"\x00" * 32)

engine.verify_graph_integrity()   # bool
```

## Signed payload — what the signature binds

```jsonc
{
  "manifest_version": 2,
  "graph_id": "...",
  "session_id": "...",
  "agent_id": "...",
  "initialized_at": 1700000000000,
  "algorithm": "Ed25519",
  "key_id": "0123456789abcdef",
  "nodes": [
    {
      "node_id": "...",
      "tool_name": "search",
      "description": "Full-text search over the knowledge base",
      "schema_fingerprint": "abcd1234abcd1234",
      "is_network_capable": true,
      "is_data_read": true,
      "is_data_write": false
    }
    // ... sorted by node_id
  ],
  "edges": [ /* sorted by (from, to, condition) */ ],
  "late_registrations": [ /* sorted by node_id */ ]
}
```

Anything not in this payload is not authorized by the signature.

## Algorithms

| Algorithm | Mode | Default | FIPS path |
|---|---|---|---|
| `Ed25519` | Asymmetric (EdDSA / Curve25519) | yes | FIPS 186-5 (validated OpenSSL 3.0 provider) |
| `HMAC-SHA256` | Symmetric | legacy / dev | FIPS 198-1 |

Ed25519 is the default because it allows a separation between the
signing authority (KMS/gateway) and the verifying runtime — the SDK holds
only the public key, never the private one.

## Latency

Measured on an x86-64 Linux VM, Node 22.12 and Python 3.12 with OpenSSL 3:

| Op | Payload | Time |
|---|---|---|
| `Ed25519Signer.verify` | 180 B (delegation graph) | ~122 µs |
| `Ed25519Signer.verify` | 11 KB (50-tool EGI manifest) | ~133 µs |
| `Ed25519Signer.sign`   | 180 B | ~40 µs |
| `Ed25519Signer.sign`   | 11 KB | ~66 µs |
| `HmacSigner.sign`      | 180 B | ~2.5 µs |
| `HmacSigner.verify`    | 180 B | ~2.6 µs |

A typical LLM first-token latency is 100–400 ms and a typical tool
invocation is 10–1000 ms. Ed25519 verification on the hot path adds at
most ~0.1% of a turn's wall time, and is constant in manifest size up to
~10 KB. For ultra-hot paths that amortize well, callers can cache
`verified=true` keyed on `(manifest_version, signature)` and re-verify on
any digest change.

## Roadmap

- **Phase 2** — wire the EGI verify gate into `src/engine/interceptor.ts`
  so a failed verify returns `BLOCKED` before the executor fires, instead
  of only emitting a violation.
- **Phase 3** — enterprise gateway `manifest-signer.ts` with AWS KMS,
  Azure Key Vault, GCP KMS, and Vault Transit adapters; strict
  late-registration amendment flow (runtime cannot re-sign).
- **Phase 4** — FIPS 140-3 build guide and Dockerfile (RHEL UBI +
  OpenSSL FIPS provider); FedRAMP control mapping.
- **Phase 5** — ALEC evidence export includes the signed manifest and
  attestation chain.
